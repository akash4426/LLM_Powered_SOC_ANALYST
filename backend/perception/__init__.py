"""
perception — Perception Layer for the Agentic SOC Investigation Platform.

Responsibilities:
  1. Normalize heterogeneous logs.
  2. Extract structured security events.
  3. Build investigation sessions.
  4. Produce sanitized InvestigationObjects (structured JSON only).
  5. Never expose raw attacker-controlled log text to the planner.

The planner receives only sanitized structured investigation objects.
Raw commands and attacker-controlled strings are quarantined and only
accessible to specialist tools.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.ingestion.log_normalizer import normalize_logs
from backend.processing.event_extractor import (
    SecurityEvent,
    extract_events,
    events_to_sequence,
    get_mitre_query,
)
from backend.processing.session_builder import build_sessions, sessions_summary
from backend.models.lstm_model import (
    score_sequence,
    score_network_flow,
    is_network_flow_model_loaded,
)


# ═══════════════════════════════════════════════════════════════════════════════
# INVESTIGATION OBJECT — Sanitized structured output for the planner
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class TemporalStatistics:
    """Time-based statistics about the event window."""
    first_event_time: Optional[str] = None
    last_event_time: Optional[str] = None
    duration_description: str = "unknown"
    events_per_actor: Dict[str, int] = field(default_factory=dict)


@dataclass
class InvestigationObject:
    """
    Sanitized structured investigation object for the planner.

    Contains only structured metadata — never raw log content.
    Raw data is stored separately in `_raw_data` for specialist tools only.
    """
    # Identity
    investigation_id: str = ""
    entity: str = "unknown"

    # Timeline summary (no raw strings)
    timeline_summary: str = ""
    event_counts: Dict[str, int] = field(default_factory=dict)
    event_types: List[str] = field(default_factory=list)
    total_events: int = 0

    # Actors
    users: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    dest_ips: List[str] = field(default_factory=list)

    # Historical metadata
    historical_metadata: Dict[str, Any] = field(default_factory=dict)

    # Temporal statistics
    temporal_statistics: Optional[TemporalStatistics] = None

    # Session summary
    session_count: int = 0
    sessions_summary: List[Dict[str, Any]] = field(default_factory=list)

    # LSTM anomaly score (pre-computed)
    anomaly_score: float = 0.0

    # MITRE query hint (for specialist tools)
    mitre_query: str = ""

    # Event sequence (integer-encoded for LSTM)
    event_sequence_ints: List[int] = field(default_factory=list)

    # ── Quarantined raw data (NEVER sent to planner) ──────────────────────
    _raw_logs: str = ""
    _raw_events: List[Any] = field(default_factory=list)
    _raw_sessions: List[Any] = field(default_factory=list)
    _normalized_logs: List[Dict[str, Any]] = field(default_factory=list)

    def to_planner_dict(self) -> Dict[str, Any]:
        """
        Return a sanitized dictionary safe for the LLM planner.
        No raw log content, no attacker-controlled strings.
        """
        return {
            "investigation_id": self.investigation_id,
            "entity": self.entity,
            "timeline_summary": self.timeline_summary,
            "event_counts": self.event_counts,
            "event_types": self.event_types,
            "total_events": self.total_events,
            "users": self.users,
            "hosts": self.hosts,
            "source_ips": self.source_ips,
            "dest_ips": self.dest_ips,
            "session_count": self.session_count,
            "anomaly_score": round(self.anomaly_score, 4),
            "temporal_statistics": {
                "first_event_time": self.temporal_statistics.first_event_time,
                "last_event_time": self.temporal_statistics.last_event_time,
                "duration_description": self.temporal_statistics.duration_description,
                "events_per_actor": self.temporal_statistics.events_per_actor,
            } if self.temporal_statistics else {},
        }


# ═══════════════════════════════════════════════════════════════════════════════
# PERCEPTION PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def _detect_network_flow(raw_logs: str) -> bool:
    """Check if input is network flow CSV."""
    first_line = raw_logs.split('\n')[0].lower()
    return 'destination port' in first_line or 'flow duration' in first_line


def _process_network_flow(raw_logs: str) -> tuple:
    """Process network flow CSV data."""
    import pandas as pd
    import io
    from backend.processing.event_extractor import SecurityEvent

    df = pd.read_csv(io.StringIO(raw_logs))
    drop_cols = [c for c in df.columns if df[c].dtype == object]
    features = df.drop(columns=drop_cols).apply(
        pd.to_numeric, errors="coerce"
    ).fillna(0).values

    if is_network_flow_model_loaded():
        anomaly_score = score_network_flow(features)
    else:
        anomaly_score = 0.0

    normalized_logs = [{"raw": "Network flow traffic", "timestamp": None}]
    mitre_hint = "T1071 Application Layer Protocol" if anomaly_score > 0.8 else None
    event_type = "SUSPICIOUS_EXEC" if anomaly_score > 0.8 else "NORMAL"
    event_code = 6 if anomaly_score > 0.8 else 0

    events = [
        SecurityEvent(
            event_type=event_type,
            event_code=event_code,
            source_ip="NetworkFlow",
            dest_ip="NetworkFlow",
            user="Unknown",
            hostname="Unknown",
            timestamp=datetime.now(timezone.utc).isoformat(),
            description=f"Network flow batch ({len(df)} records) anomaly={anomaly_score:.2f}",
            raw="Network flow traffic",
            mitre_hint=mitre_hint,
            severity="high" if anomaly_score > 0.8 else "low",
        )
    ]
    return normalized_logs, events, anomaly_score


def _build_timeline_summary(events: List[SecurityEvent]) -> str:
    """Build a human-readable timeline summary without raw log content."""
    if not events:
        return "No events detected."

    type_counts = Counter(e.event_type for e in events)
    suspicious = {k: v for k, v in type_counts.items() if k != "NORMAL"}

    parts = [f"{len(events)} events analyzed"]
    if suspicious:
        susp_str = ", ".join(f"{v}x {k}" for k, v in suspicious.items())
        parts.append(f"suspicious activity: {susp_str}")
    else:
        parts.append("no suspicious activity detected")

    # Timestamps
    timestamps = [e.timestamp for e in events if e.timestamp]
    if timestamps:
        parts.append(f"time range: {timestamps[0]} to {timestamps[-1]}")

    return ". ".join(parts) + "."


def _build_temporal_statistics(
    events: List[SecurityEvent],
) -> TemporalStatistics:
    """Build temporal statistics for the investigation object."""
    timestamps = [e.timestamp for e in events if e.timestamp]
    actors: Dict[str, int] = {}
    for e in events:
        actor = e.source_ip or e.user or e.hostname or "unknown"
        actors[actor] = actors.get(actor, 0) + 1

    first_time = timestamps[0] if timestamps else None
    last_time = timestamps[-1] if timestamps else None

    if first_time and last_time and first_time != last_time:
        duration_desc = f"from {first_time} to {last_time}"
    elif first_time:
        duration_desc = f"single point: {first_time}"
    else:
        duration_desc = "unknown timeframe"

    return TemporalStatistics(
        first_event_time=first_time,
        last_event_time=last_time,
        duration_description=duration_desc,
        events_per_actor=actors,
    )


def _auto_detect_entity(events: List[SecurityEvent], entity_id: Optional[str] = None) -> str:
    """Auto-detect entity ID from events if not provided."""
    if entity_id:
        return entity_id

    ips = [e.source_ip for e in events if e.source_ip]
    users = [e.user for e in events if e.user]
    hosts = [e.hostname for e in events if e.hostname]

    if ips:
        return Counter(ips).most_common(1)[0][0]
    elif users:
        return Counter(users).most_common(1)[0][0]
    elif hosts:
        return Counter(hosts).most_common(1)[0][0]
    return "unknown_entity"


def perceive(
    raw_logs: str,
    entity_id: Optional[str] = None,
) -> InvestigationObject:
    """
    Main perception pipeline entry point.

    Normalizes logs → extracts events → builds sessions → produces
    a sanitized InvestigationObject.

    The returned object's `to_planner_dict()` is safe for LLM consumption.
    Raw data is quarantined in `_raw_*` fields for specialist tools.
    """
    investigation_id = str(uuid.uuid4())[:8]

    # ── Normalize and extract ─────────────────────────────────────────────
    if _detect_network_flow(raw_logs):
        try:
            normalized_logs, events, anomaly_score = _process_network_flow(raw_logs)
        except Exception:
            # Fallback to standard parsing
            normalized_logs = normalize_logs(raw_logs)
            events = extract_events(normalized_logs)
            event_sequence_ints = events_to_sequence(events)
            anomaly_score = score_sequence(event_sequence_ints)
    else:
        normalized_logs = normalize_logs(raw_logs)
        events = extract_events(normalized_logs)

    event_sequence_ints = events_to_sequence(events)

    # ── LSTM scoring ──────────────────────────────────────────────────────
    if not _detect_network_flow(raw_logs):
        anomaly_score = score_sequence(event_sequence_ints)

    # ── Build sessions ────────────────────────────────────────────────────
    sessions = build_sessions(events)
    session_data = sessions_summary(sessions)

    # ── MITRE query for specialist tools ──────────────────────────────────
    mitre_query = get_mitre_query(events)

    # ── Auto-detect entity ────────────────────────────────────────────────
    entity = _auto_detect_entity(events, entity_id)

    # ── Build structured counts ───────────────────────────────────────────
    event_type_counts = dict(Counter(e.event_type for e in events))
    unique_event_types = list(dict.fromkeys(e.event_type for e in events))
    users = list(dict.fromkeys(e.user for e in events if e.user))
    hosts = list(dict.fromkeys(e.hostname for e in events if e.hostname))
    source_ips = list(dict.fromkeys(e.source_ip for e in events if e.source_ip))
    dest_ips = list(dict.fromkeys(e.dest_ip for e in events if e.dest_ip))

    # ── Build sanitized sessions summary (no raw content) ─────────────────
    sanitized_sessions = []
    for s in session_data.get("sessions", []):
        sanitized_sessions.append({
            "session_id": s.get("session_id", ""),
            "actor": s.get("actor", ""),
            "event_count": s.get("event_count", 0),
            "severity_max": s.get("severity_max", "low"),
            "unique_types": s.get("unique_types", []),
        })

    # ── Assemble InvestigationObject ──────────────────────────────────────
    return InvestigationObject(
        investigation_id=investigation_id,
        entity=entity,
        timeline_summary=_build_timeline_summary(events),
        event_counts=event_type_counts,
        event_types=unique_event_types,
        total_events=len(events),
        users=users,
        hosts=hosts,
        source_ips=source_ips,
        dest_ips=dest_ips,
        session_count=len(sessions),
        sessions_summary=sanitized_sessions,
        anomaly_score=anomaly_score,
        mitre_query=mitre_query,
        event_sequence_ints=event_sequence_ints,
        temporal_statistics=_build_temporal_statistics(events),
        # Quarantined raw data
        _raw_logs=raw_logs,
        _raw_events=events,
        _raw_sessions=sessions,
        _normalized_logs=normalized_logs,
    )
