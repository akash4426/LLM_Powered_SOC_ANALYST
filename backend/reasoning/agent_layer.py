"""
agent_layer.py
--------------
Elite SOC-style Agentic AI Layer.

Features:
  • Evidence-based confidence scoring (deterministic, no LLM)
  • Multi-step hypothesis loop with compound intelligence
  • Time-aware correlation with decay function
  • Structured incident generation with full decision framework
  • Multi-stage attack detection across sessions
  • Explainability with evidence ledger

Architecture:
  1. Update entity memory with current session
  2. Correlate across historical sessions (time-aware)
  3. Build hypothesis from event patterns
  4. Refine with models (re-run LSTM + RAG on combined sequences)
  5. Compute deterministic confidence from evidence
  6. Apply decision engine (AUTO_REMEDIATE | ESCALATE_L2 | MONITOR)
  7. Generate structured incident with timeline and reasoning

Integration:
  • Called AFTER existing pipeline (Steps 1-9)
  • Consumes LSTM scores, RAG mappings, event types
  • Does NOT modify or bypass LSTM/RAG
  • Returns AgentAnalysisResponse for FastAPI
"""

import logging
import time
import threading
import uuid
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import Counter

from backend.models.lstm_model import score_sequence
from backend.rag.rag_engine import retrieve_context
from backend.processing.event_extractor import SecurityEvent, get_mitre_query

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. SESSION RECORD & ENTITY MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionRecord:
    """Captures a single session's analysis for memory and correlation."""
    session_id: str
    timestamp: str                    # ISO-8601
    epoch: float                      # Unix timestamp for time comparisons
    sequence: List[int]               # Event type integers
    event_types: List[str]            # Event type names (LOGIN, PRIV_ESC, etc.)
    anomaly_score: float
    mitre_mappings: List[str]         # MITRE technique IDs (T1110, etc.)
    events_summary: List[Dict[str, Any]]
    entity_id: str


@dataclass
class CorrelationResult:
    """Result of time-aware correlation across sessions."""
    is_correlated: bool = False
    correlated_sessions: List[SessionRecord] = field(default_factory=list)
    correlation_depth: int = 0
    combined_event_types: List[str] = field(default_factory=list)
    correlation_weight: float = 0.0


@dataclass
class RefinedResult:
    """Result of re-running LSTM + RAG on combined sequences."""
    compound_anomaly_score: float = 0.0
    compound_mitre_mappings: List[str] = field(default_factory=list)
    combined_sequence: List[int] = field(default_factory=list)
    improvement_detail: str = ""


@dataclass
class EvidenceLedger:
    """Structured evidence for confidence scoring."""
    lstm_score: float
    rag_matches: int
    correlation_depth: int
    threat_intel_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "lstm_score": self.lstm_score,
            "rag_matches": self.rag_matches,
            "correlation_depth": self.correlation_depth,
            "threat_intel_score": self.threat_intel_score,
        }


class EntityMemoryStore:
    """Thread-safe store of sessions per entity."""
    MAX_SESSIONS_PER_ENTITY = 50
    TTL_SECONDS = 86400  # 24 hours

    def __init__(self):
        self._store: Dict[str, List[SessionRecord]] = {}
        self._lock = threading.Lock()

    def store_session(self, record: SessionRecord) -> None:
        """Store a session and prune old ones."""
        with self._lock:
            entity = record.entity_id
            if entity not in self._store:
                self._store[entity] = []

            # Remove expired sessions
            cutoff = time.time() - self.TTL_SECONDS
            self._store[entity] = [r for r in self._store[entity] if r.epoch >= cutoff]
            
            self._store[entity].append(record)

            # Keep only most recent MAX_SESSIONS_PER_ENTITY
            if len(self._store[entity]) > self.MAX_SESSIONS_PER_ENTITY:
                self._store[entity] = self._store[entity][-self.MAX_SESSIONS_PER_ENTITY:]

    def get_sessions(self, entity_id: str, window_seconds: int = 21600) -> List[SessionRecord]:
        """Retrieve sessions for entity within time window."""
        with self._lock:
            records = self._store.get(entity_id, [])
            cutoff = time.time() - window_seconds
            return [r for r in records if r.epoch >= cutoff]

    def get_all_entities(self) -> List[str]:
        """List all tracked entities."""
        with self._lock:
            return list(self._store.keys())

    def clear(self) -> None:
        """Clear all memory."""
        with self._lock:
            self._store.clear()


_memory = EntityMemoryStore()

def get_memory_store() -> EntityMemoryStore:
    """Get global memory store instance."""
    return _memory


def update_memory(record: SessionRecord) -> None:
    """Store session record into entity memory."""
    _memory.store_session(record)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TIME-AWARE CORRELATION
# ═══════════════════════════════════════════════════════════════════════════════

# Campaign patterns: multi-stage attack sequences mapped to hypothesis names
CAMPAIGN_PATTERNS: Dict[str, List[str]] = {
    "full_kill_chain": ["LOGIN", "PRIV_ESC", "LATERAL_MOVE", "EXFILTRATION"],
    "privilege_escalation_chain": ["LOGIN", "PRIV_ESC", "SUSPICIOUS_EXEC"],
    "apt_lateral_movement": ["RECON", "LATERAL_MOVE", "EXFILTRATION"],
    "ransomware_deployment": ["DEFENSE_EVADE", "SUSPICIOUS_EXEC", "EXFILTRATION"],
    "brute_force_escalation": ["LOGIN", "LOGIN", "PRIV_ESC"],
    "recon_to_exploit": ["RECON", "SUSPICIOUS_EXEC", "PRIV_ESC"],
    "credential_theft": ["LOGIN", "SUSPICIOUS_EXEC", "EXFILTRATION"],
}


def correlate_events(entity_id: str, window_seconds: int = 21600) -> CorrelationResult:
    """
    Retrieve past sessions for entity, apply time-aware decay, and identify correlations.
    
    Recent events have higher weight. Multiple suspicious sessions indicate attack progression.
    """
    all_sessions = _memory.get_sessions(entity_id, window_seconds)

    # Filter to suspicious sessions (not all NORMAL events)
    suspicious = [s for s in all_sessions if any(et != "NORMAL" for et in s.event_types)]

    if len(suspicious) < 2:
        # No correlation if only single or no suspicious sessions
        return CorrelationResult()

    suspicious.sort(key=lambda s: s.epoch)

    # Combine event types and calculate time-weighted importance
    combined_types: List[str] = []
    total_weight = 0.0
    current_time = time.time()

    for sess in suspicious:
        combined_types.extend(sess.event_types)
        # Linear decay: recent = 1.0, old = 0.0
        age_seconds = current_time - sess.epoch
        weight = max(0.0, 1.0 - (age_seconds / window_seconds))
        total_weight += weight

    return CorrelationResult(
        is_correlated=True,
        correlated_sessions=suspicious,
        correlation_depth=len(suspicious),
        combined_event_types=combined_types,
        correlation_weight=total_weight
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 3. HYPOTHESIS LOOP
# ═══════════════════════════════════════════════════════════════════════════════

def build_hypothesis(combined_event_types: List[str]) -> Optional[str]:
    """
    Analyze combined event types across sessions and match to known campaign patterns.
    Returns hypothesis name (e.g., "full_kill_chain") or None if no match.
    """
    for pattern_name, pattern_sequence in CAMPAIGN_PATTERNS.items():
        idx = 0
        for event_type in combined_event_types:
            if idx < len(pattern_sequence) and event_type == pattern_sequence[idx]:
                idx += 1
            if idx == len(pattern_sequence):
                return pattern_name
    return None


def refine_with_models(
    hypothesis: Optional[str],
    correlation: CorrelationResult,
    individual_anomaly: float,
    individual_mitre: List[str]
) -> RefinedResult:
    """
    Multi-step hypothesis refinement:
    1. Combine event sequences from correlated sessions
    2. Re-run LSTM on combined sequence
    3. Refine RAG query using hypothesis
    4. Re-run RAG for additional MITRE mappings
    5. Merge and report improvements
    """
    if not correlation.is_correlated:
        return RefinedResult(
            compound_anomaly_score=individual_anomaly,
            compound_mitre_mappings=individual_mitre,
        )

    # Step 1: Combine integer sequences
    combined_seq: List[int] = []
    for sess in correlation.correlated_sessions:
        combined_seq.extend(sess.sequence)

    # Step 2: Re-run LSTM on combined sequence
    compound_anomaly = score_sequence(combined_seq)

    # Step 3: Build refined RAG query
    all_mitre_hints: List[str] = []
    for sess in correlation.correlated_sessions:
        for mapping in sess.mitre_mappings:
            if mapping not in all_mitre_hints:
                all_mitre_hints.append(mapping)

    # Incorporate hypothesis into query
    hypothesis_str = f" {hypothesis.replace('_', ' ')} attack campaign" if hypothesis else " multi-stage attack campaign"
    refined_query = " | ".join(all_mitre_hints) + hypothesis_str if all_mitre_hints else hypothesis_str

    # Step 4: Re-run RAG with refined query
    compound_rag_context = retrieve_context(refined_query, k=5)
    
    # Extract MITRE techniques from refined RAG context
    compound_mitre = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", compound_rag_context)))
    merged_mitre = list(dict.fromkeys(individual_mitre + compound_mitre))

    # Step 5: Use best (highest) anomaly score
    final_anomaly = max(compound_anomaly, individual_anomaly)

    # Document improvements
    improvement = ""
    if compound_anomaly > individual_anomaly:
        delta = compound_anomaly - individual_anomaly
        improvement = f"Compound analysis increased anomaly score by {delta:.4f} ({individual_anomaly:.4f} → {compound_anomaly:.4f}). Combined {len(correlation.correlated_sessions)} sessions revealed full attack pattern."
    
    if len(merged_mitre) > len(individual_mitre):
        new_techniques = [t for t in merged_mitre if t not in individual_mitre]
        improvement += f" RAG retrieval discovered {len(new_techniques)} additional MITRE technique(s): {', '.join(new_techniques)}."

    return RefinedResult(
        compound_anomaly_score=final_anomaly,
        compound_mitre_mappings=merged_mitre,
        combined_sequence=combined_seq,
        improvement_detail=improvement or "No improvement from compound analysis.",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 4. EVIDENCE-BASED CONFIDENCE & DECISION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def compute_confidence(evidence: EvidenceLedger) -> float:
    """
    Compute deterministic confidence score from evidence ledger.
    
    Formula:
      confidence = (
        0.4 * lstm_score +
        0.3 * min(rag_matches / 5, 1.0) +
        0.2 * min(correlation_depth / 4, 1.0) +
        0.1 * threat_intel_score
      )
    
    All components normalized to [0, 1], final result rounded to 4 decimals.
    """
    confidence = (
        0.4 * min(evidence.lstm_score, 1.0) +
        0.3 * min(evidence.rag_matches / 5.0, 1.0) +
        0.2 * min(evidence.correlation_depth / 4.0, 1.0) +
        0.1 * min(evidence.threat_intel_score, 1.0)
    )
    return round(min(confidence, 1.0), 4)


def decide_action(confidence: float) -> str:
    """
    Decision logic based on confidence threshold.
    
    - confidence > 0.85  → AUTO_REMEDIATE (immediate action)
    - 0.6 < confidence ≤ 0.85 → ESCALATE_L2 (analyst review + action)
    - confidence ≤ 0.6   → MONITOR (watch and log)
    """
    if confidence > 0.85:
        return "AUTO_REMEDIATE"
    elif confidence > 0.6:
        return "ESCALATE_L2"
    else:
        return "MONITOR"


# ═══════════════════════════════════════════════════════════════════════════════
# 5. STRUCTURED INCIDENT OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

def build_timeline(correlation: CorrelationResult, current_record: SessionRecord) -> List[Dict[str, Any]]:
    """Build chronological timeline of events from session(s)."""
    timeline: List[Dict[str, Any]] = []
    sessions = correlation.correlated_sessions if correlation.is_correlated else [current_record]
    
    for sess in sessions:
        for evt in sess.events_summary:
            timeline.append({
                "timestamp": evt.get("timestamp", sess.timestamp),
                "entity_id": sess.entity_id,
                "event_type": evt.get("event_type", "UNKNOWN"),
                "description": evt.get("description", ""),
                "session_anomaly_score": sess.anomaly_score,
                "session_id": sess.session_id,
            })
    
    # Sort chronologically
    timeline.sort(key=lambda x: x.get("timestamp") or "")
    return timeline


def compute_severity(
    anomaly_score: float,
    correlation_depth: int,
    mitre_count: int,
    campaign_pattern: Optional[str]
) -> str:
    """
    Compute severity based on multiple factors.
    
    Base severity:
      - CRITICAL: anomaly ≥ 0.8 AND depth ≥ 3 AND mitre ≥ 3
      - HIGH: anomaly ≥ 0.6 OR (depth ≥ 2 AND mitre ≥ 2)
      - MEDIUM: anomaly ≥ 0.4 OR mitre ≥ 1
      - LOW: default
    
    Boost if campaign pattern detected:
      LOW → MEDIUM, MEDIUM → HIGH, HIGH → CRITICAL
    """
    if anomaly_score >= 0.8 and correlation_depth >= 3 and mitre_count >= 3:
        base = "CRITICAL"
    elif anomaly_score >= 0.6 or (correlation_depth >= 2 and mitre_count >= 2):
        base = "HIGH"
    elif anomaly_score >= 0.4 or mitre_count >= 1:
        base = "MEDIUM"
    else:
        base = "LOW"
    
    # Boost severity if known campaign pattern
    if campaign_pattern:
        boost_map = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL"}
        base = boost_map.get(base, base)
    
    return base


def _fallback_explanation(incident: Dict[str, Any], severity: str) -> str:
    """Fallback explanation when LLM is unavailable."""
    itype = incident.get("incident_type", "unknown").replace("_", " ")
    depth = incident.get("correlation_depth", 0)
    mitre = incident.get("compound_mitre_mappings", [])
    entities = incident.get("entities", [])
    
    parts = [f"Detected {itype} incident involving {', '.join(entities)}."]
    
    if depth > 1:
        parts.append(f"Cross-session correlation linked {depth} sessions showing progressive attack escalation.")
    
    if mitre:
        parts.append(f"Mapped to MITRE ATT&CK techniques: {', '.join(mitre)}.")
    
    parts.append(f"Severity assessed as {severity}. Decision: {incident.get('decision', 'MONITOR')}. Recommended: isolate affected systems, preserve forensic evidence, and escalate.")
    
    return " ".join(parts)


def generate_agent_explanation(
    incident: Dict[str, Any],
    timeline: List[Dict[str, Any]],
    severity: str,
    confidence: float
) -> str:
    """
    Generate narrative explanation using LLM (if available) or fallback.
    
    LLM is used for narrative only; all scores/severity/confidence are pre-computed.
    """
    try:
        from backend.reasoning.llm_agent import generate_inference
    except ImportError:
        logger.warning("LLM inference not available, using fallback explanation")
        return _fallback_explanation(incident, severity)

    # Build timeline string for LLM context
    timeline_str = ""
    for i, entry in enumerate(timeline[:15], 1):
        timeline_str += f"  {i}. [{entry.get('timestamp', 'N/A')}] {entry['event_type']} — {entry.get('description', 'N/A')} (session: {entry['session_id']})\n"

    mitre_str = ", ".join(incident.get("compound_mitre_mappings", [])) or "None identified"

    prompt = f"""You are a Senior SOC Analyst writing an incident summary.

INCIDENT DATA (pre-computed — do NOT modify these values):
  Incident Type : {incident['incident_type']}
  Severity      : {severity}
  Confidence    : {confidence:.1%}
  Decision      : {incident.get('decision', 'MONITOR')}
  Anomaly Score : {incident['compound_anomaly_score']:.4f}
  MITRE Techniques: {mitre_str}
  Sessions Correlated: {incident['correlation_depth']}
  Campaign Pattern: {incident.get('campaign_pattern', 'None')}

ATTACK TIMELINE (chronological):
{timeline_str}

ENTITIES INVOLVED: {', '.join(incident['entities'])}
DETECTION IMPROVEMENT: {incident.get('detection_improvement', 'N/A')}

INSTRUCTIONS:
1. Write a 3-4 sentence narrative explaining this incident
2. Describe what the attacker likely attempted based on the timeline
3. Provide 3 specific mitigation/response actions
4. Do NOT generate or modify any scores, severity, or confidence values
5. Return ONLY a JSON object with keys: "narrative", "attack_assessment", "mitigations"

Return valid JSON only:"""

    try:
        raw = generate_inference(prompt)
        import json
        parsed = json.loads(raw)
        narrative = parsed.get("narrative", "")
        assessment = parsed.get("attack_assessment", "")
        mitigations = parsed.get("mitigations", [])
        if isinstance(mitigations, list):
            mitigations = "; ".join(mitigations)
        return f"{narrative} {assessment} Recommended actions: {mitigations}"
    except Exception as e:
        logger.warning(f"LLM explanation generation failed: {e}, using fallback")
        return _fallback_explanation(incident, severity)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_with_agent(
    sequence: List[int],
    entity_id: str,
    timestamp: str,
    events: List[SecurityEvent] = None,
    threat_intel_score: float = 0.0
) -> Dict[str, Any]:
    """
    Elite SOC-style agent analysis. Called AFTER existing pipeline completes.
    
    Args:
        sequence: Integer sequence of event types from pipeline
        entity_id: Entity identifier (IP, user, hostname)
        timestamp: ISO-8601 timestamp for this session
        events: SecurityEvent list for context
        threat_intel_score: Threat intelligence risk score [0, 1]
    
    Returns:
        Dict with incident type, severity, confidence, decision, timeline, etc.
    """
    events = events or []
    session_id = str(uuid.uuid4())[:8]

    # ── Step 1: Baseline pipeline outputs for current session ──────────────────
    individual_anomaly = score_sequence(sequence)
    mitre_query = get_mitre_query(events)
    rag_context = retrieve_context(mitre_query, k=3)
    
    # Extract MITRE techniques from both query hints and RAG context
    individual_mitre = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", rag_context)))
    event_mitre_hints = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", mitre_query)))
    individual_mitre = list(dict.fromkeys(individual_mitre + event_mitre_hints))

    event_types = [e.event_type for e in events]
    events_summary = [
        {
            "event_type": e.event_type,
            "description": e.description,
            "timestamp": e.timestamp,
            "source_ip": e.source_ip,
            "dest_ip": e.dest_ip,
            "user": e.user
        }
        for e in events
    ]

    # Parse timestamp to epoch
    try:
        epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        epoch = time.time()

    current_record = SessionRecord(
        session_id=session_id,
        timestamp=timestamp,
        epoch=epoch,
        sequence=sequence,
        event_types=event_types,
        anomaly_score=individual_anomaly,
        mitre_mappings=individual_mitre,
        events_summary=events_summary,
        entity_id=entity_id
    )
    
    # Store in memory for correlation
    update_memory(current_record)

    # ── Step 2: Time-aware correlation ─────────────────────────────────────────
    correlation = correlate_events(entity_id)

    # ── Step 3: Hypothesis loop & compound intelligence ───────────────────────
    hypothesis = build_hypothesis(correlation.combined_event_types)
    compound = refine_with_models(hypothesis, correlation, individual_anomaly, individual_mitre)

    # ── Step 4: Build explainability reasoning ────────────────────────────────
    why_flagged = []
    if compound.compound_anomaly_score > 0.4:
        why_flagged.append("High anomaly deviation detected")
    if compound.compound_mitre_mappings:
        why_flagged.append(f"MITRE techniques matched: {', '.join(compound.compound_mitre_mappings)}")
    if hypothesis:
        why_flagged.append(f"Multi-stage pattern matched: {hypothesis}")
    if correlation.correlation_depth > 1:
        why_flagged.append(f"Cross-session correlation detected: {correlation.correlation_depth} sessions linked")

    # ── Step 5: Evidence-based confidence ──────────────────────────────────────
    evidence = EvidenceLedger(
        lstm_score=compound.compound_anomaly_score,
        rag_matches=len(compound.compound_mitre_mappings),
        correlation_depth=correlation.correlation_depth,
        threat_intel_score=threat_intel_score
    )
    confidence = compute_confidence(evidence)

    # ── Step 6: Decision engine ────────────────────────────────────────────────
    decision = decide_action(confidence)

    # ── Step 7: Build timeline and severity ────────────────────────────────────
    timeline = build_timeline(correlation, current_record)
    severity = compute_severity(
        compound.compound_anomaly_score,
        correlation.correlation_depth,
        len(compound.compound_mitre_mappings),
        hypothesis
    )

    # ── Step 8: Structured incident ────────────────────────────────────────────
    incident = {
        "incident_id": str(uuid.uuid4()),
        "incident_type": hypothesis or ("correlated_multi_session" if correlation.is_correlated else "single_session"),
        "timeline": timeline,
        "entities": list(dict.fromkeys([entity_id] + [s.entity_id for s in correlation.correlated_sessions])),
        "severity": severity,
        "confidence": confidence,
        "decision": decision,
        "why_flagged": why_flagged,
        "correlation_depth": correlation.correlation_depth,
        "campaign_pattern": hypothesis,
        "compound_anomaly_score": compound.compound_anomaly_score,
        "compound_mitre_mappings": compound.compound_mitre_mappings,
        "detection_improvement": compound.improvement_detail,
        "evidence": evidence.to_dict(),
    }

    # ── Step 9: LLM explanation (narrative only) ───────────────────────────────
    llm_explanation = generate_agent_explanation(incident, timeline, severity, confidence)

    # ── Step 10: Return structured response ────────────────────────────────────
    return {
        "anomaly_score": individual_anomaly,
        "compound_anomaly_score": compound.compound_anomaly_score,
        "mitre_mappings": individual_mitre,
        "compound_mitre_mappings": compound.compound_mitre_mappings,
        "correlated_timeline": timeline,
        "incident_type": incident["incident_type"],
        "severity": severity,
        "confidence": confidence,
        "decision": decision,
        "why_flagged": why_flagged,
        "correlation_depth": correlation.correlation_depth,
        "campaign_pattern": hypothesis,
        "entities": incident["entities"],
        "llm_explanation": llm_explanation,
        "detection_improvement": compound.improvement_detail or None,
        "incident_id": incident["incident_id"],
    }
