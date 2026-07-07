"""
perception — Perception Layer for the Agentic SOC Investigation Platform.

Responsibilities:
  1. Normalize heterogeneous logs.
  2. Extract structured security events.
  3. Build investigation sessions.
  4. Produce sanitized InvestigationObject (structured JSON only).
  5. Never expose raw attacker-controlled log text to the planner.
"""

import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.ingestion.log_normalizer import normalize_logs
from backend.processing.event_extractor import (
    SecurityEvent,
    extract_events,
)
from backend.processing.session_builder import build_sessions, sessions_summary
from backend.schemas.investigation import InvestigationObject


def _detect_network_flow(raw_logs: str) -> bool:
    """Check if input is network flow CSV."""
    if not raw_logs:
        return False
    first_line = raw_logs.split('\n')[0].lower()
    return 'destination port' in first_line or 'flow duration' in first_line


def _process_network_flow(raw_logs: str) -> tuple:
    """Process network flow CSV data (deterministic extraction only)."""
    import pandas as pd
    import io
    
    df = pd.read_csv(io.StringIO(raw_logs))
    normalized_logs = [{"raw": "Network flow traffic", "timestamp": None}]
    
    events = [
        SecurityEvent(
            event_type="NETWORK_FLOW",
            event_code=6,
            source_ip="NetworkFlow",
            dest_ip="NetworkFlow",
            user="Unknown",
            hostname="Unknown",
            timestamp=datetime.now(timezone.utc).isoformat(),
            description=f"Network flow batch ({len(df)} records)",
            raw="Network flow traffic",
            mitre_hint=None,
            severity="low",
        )
    ]
    return normalized_logs, events


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
    Normalizes logs -> extracts events -> builds sessions -> produces InvestigationObject.
    """
    investigation_id = str(uuid.uuid4())[:8]

    # ── Normalize and extract ─────────────────────────────────────────────
    if _detect_network_flow(raw_logs):
        try:
            normalized_logs, events = _process_network_flow(raw_logs)
        except Exception:
            normalized_logs = normalize_logs(raw_logs)
            events = extract_events(normalized_logs)
    else:
        normalized_logs = normalize_logs(raw_logs)
        events = extract_events(normalized_logs)

    # ── Build sessions ────────────────────────────────────────────────────
    sessions = build_sessions(events)
    session_data = sessions_summary(sessions)

    # ── Auto-detect entity ────────────────────────────────────────────────
    entity = _auto_detect_entity(events, entity_id)
    
    # ── Structure for InvestigationObject ─────────────────────────────────
    
    event_type_counts = dict(Counter(e.event_type for e in events))
    unique_event_types = list(dict.fromkeys(e.event_type for e in events))
    users = list(dict.fromkeys(e.user for e in events if e.user))
    hosts = list(dict.fromkeys(e.hostname for e in events if e.hostname))
    source_ips = list(dict.fromkeys(e.source_ip for e in events if e.source_ip))
    dest_ips = list(dict.fromkeys(e.dest_ip for e in events if e.dest_ip))

    sanitized_sessions = []
    for s in session_data.get("sessions", []):
        sanitized_sessions.append({
            "session_id": s.get("session_id", ""),
            "actor": s.get("actor", ""),
            "event_count": s.get("event_count", 0),
            "severity_max": s.get("severity_max", "low"),
            "unique_types": s.get("unique_types", []),
        })
        
    session_metadata = {
        "total_events": len(events),
        "event_counts": event_type_counts,
        "unique_event_types": unique_event_types,
        "session_count": len(sessions),
        "sessions_summary": sanitized_sessions
    }
    
    entity_info = {
        "primary_entity": entity,
        "users": users,
        "hosts": hosts,
        "source_ips": source_ips,
        "dest_ips": dest_ips
    }
    
    normalized_events_dict = [e.to_dict() for e in events]
    
    return InvestigationObject(
        investigation_id=investigation_id,
        session_metadata=session_metadata,
        normalized_events=normalized_events_dict,
        entity_info=entity_info,
        raw_logs_quarantine=raw_logs
    )
