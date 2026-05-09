"""
agent_layer.py — Next-Level Agentic AI Layer with ReAct-style tool reasoning.

Multi-step reasoning pipeline:
  1. OBSERVE  — Collect initial signals
  2. THINK   — Determine analysis strategy
  3. ACT     — Execute tools (anomaly, RAG, TI, IOC, patterns, playbooks)
  4. SYNTHESIZE — Merge tool outputs into unified evidence
  5. DECIDE  — Compute confidence, severity, decision
  6. EXPLAIN — Generate narrative with full reasoning trace
"""

import logging, time, threading, uuid, re
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import Counter

from backend.models.lstm_model import score_sequence
from backend.rag.rag_engine import retrieve_context
from backend.processing.event_extractor import SecurityEvent, get_mitre_query
from backend.reasoning.agent_tools import (
    ToolResult, ReasoningStep,
    run_anomaly_score_tool, run_rag_lookup_tool, run_threat_intel_tool,
    run_ioc_extractor_tool, run_pattern_match_tool, run_playbook_tool,
)

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. SESSION RECORD & ENTITY MEMORY
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionRecord:
    session_id: str
    timestamp: str
    epoch: float
    sequence: List[int]
    event_types: List[str]
    anomaly_score: float
    mitre_mappings: List[str]
    events_summary: List[Dict[str, Any]]
    entity_id: str

@dataclass
class CorrelationResult:
    is_correlated: bool = False
    correlated_sessions: List[SessionRecord] = field(default_factory=list)
    correlation_depth: int = 0
    combined_event_types: List[str] = field(default_factory=list)
    correlation_weight: float = 0.0

@dataclass
class RefinedResult:
    compound_anomaly_score: float = 0.0
    compound_mitre_mappings: List[str] = field(default_factory=list)
    combined_sequence: List[int] = field(default_factory=list)
    improvement_detail: str = ""

@dataclass
class EvidenceLedger:
    lstm_score: float
    rag_matches: int
    correlation_depth: int
    threat_intel_score: float
    pattern_score: float = 0.0
    ioc_count: int = 0
    def to_dict(self) -> Dict[str, Any]:
        return {
            "lstm_score": self.lstm_score, "rag_matches": self.rag_matches,
            "correlation_depth": self.correlation_depth,
            "threat_intel_score": self.threat_intel_score,
            "pattern_score": self.pattern_score, "ioc_count": self.ioc_count,
        }

class EntityMemoryStore:
    MAX_SESSIONS_PER_ENTITY = 50
    TTL_SECONDS = 86400

    def __init__(self):
        self._store: Dict[str, List[SessionRecord]] = {}
        self._lock = threading.Lock()

    def store_session(self, record: SessionRecord) -> None:
        with self._lock:
            entity = record.entity_id
            if entity not in self._store:
                self._store[entity] = []
            cutoff = time.time() - self.TTL_SECONDS
            self._store[entity] = [r for r in self._store[entity] if r.epoch >= cutoff]
            self._store[entity].append(record)
            if len(self._store[entity]) > self.MAX_SESSIONS_PER_ENTITY:
                self._store[entity] = self._store[entity][-self.MAX_SESSIONS_PER_ENTITY:]

    def get_sessions(self, entity_id: str, window_seconds: int = 21600) -> List[SessionRecord]:
        with self._lock:
            records = self._store.get(entity_id, [])
            cutoff = time.time() - window_seconds
            return [r for r in records if r.epoch >= cutoff]

    def get_all_entities(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

_memory = EntityMemoryStore()
def get_memory_store() -> EntityMemoryStore: return _memory
def update_memory(record: SessionRecord) -> None: _memory.store_session(record)

# ═══════════════════════════════════════════════════════════════════════════════
# 2. CAMPAIGN PATTERNS & CORRELATION
# ═══════════════════════════════════════════════════════════════════════════════

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
    all_sessions = _memory.get_sessions(entity_id, window_seconds)
    suspicious = [s for s in all_sessions if any(et != "NORMAL" for et in s.event_types)]
    if len(suspicious) < 2:
        return CorrelationResult()
    suspicious.sort(key=lambda s: s.epoch)
    combined_types, total_weight = [], 0.0
    current_time = time.time()
    for sess in suspicious:
        combined_types.extend(sess.event_types)
        age = current_time - sess.epoch
        total_weight += max(0.0, 1.0 - (age / window_seconds))
    return CorrelationResult(True, suspicious, len(suspicious), combined_types, total_weight)

def build_hypothesis(combined_event_types: List[str]) -> Optional[str]:
    for name, seq in CAMPAIGN_PATTERNS.items():
        idx = 0
        for et in combined_event_types:
            if idx < len(seq) and et == seq[idx]:
                idx += 1
            if idx == len(seq):
                return name
    return None

def refine_with_models(hypothesis, correlation, individual_anomaly, individual_mitre):
    if not correlation.is_correlated:
        return RefinedResult(individual_anomaly, individual_mitre)
    combined_seq = []
    for sess in correlation.correlated_sessions:
        combined_seq.extend(sess.sequence)
    compound_anomaly = score_sequence(combined_seq)
    all_mitre = []
    for sess in correlation.correlated_sessions:
        for m in sess.mitre_mappings:
            if m not in all_mitre: all_mitre.append(m)
    hyp_str = f" {hypothesis.replace('_',' ')} attack campaign" if hypothesis else " multi-stage attack campaign"
    refined_query = " | ".join(all_mitre) + hyp_str if all_mitre else hyp_str
    compound_ctx = retrieve_context(refined_query, k=5)
    compound_mitre = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", compound_ctx)))
    merged = list(dict.fromkeys(individual_mitre + compound_mitre))
    final = max(compound_anomaly, individual_anomaly)
    improvement = ""
    if compound_anomaly > individual_anomaly:
        improvement = f"Compound analysis increased anomaly by {compound_anomaly-individual_anomaly:.4f}. "
    if len(merged) > len(individual_mitre):
        new_t = [t for t in merged if t not in individual_mitre]
        improvement += f"Discovered {len(new_t)} new technique(s): {', '.join(new_t)}."
    return RefinedResult(final, merged, combined_seq, improvement or "No improvement from compound analysis.")

# ═══════════════════════════════════════════════════════════════════════════════
# 3. CONFIDENCE, SEVERITY & DECISION
# ═══════════════════════════════════════════════════════════════════════════════

def compute_confidence(evidence: EvidenceLedger) -> float:
    c = (0.35 * min(evidence.lstm_score, 1.0) +
         0.20 * min(evidence.rag_matches / 5.0, 1.0) +
         0.15 * min(evidence.correlation_depth / 4.0, 1.0) +
         0.10 * min(evidence.threat_intel_score, 1.0) +
         0.10 * min(evidence.pattern_score, 1.0) +
         0.10 * min(evidence.ioc_count / 10.0, 1.0))
    return round(min(c, 1.0), 4)

def compute_severity(anomaly, corr_depth, mitre_count, ti_score):
    if anomaly < 0.2:
        return "MEDIUM" if (mitre_count >= 1 or ti_score > 0 or corr_depth >= 1) else "LOW"
    elif anomaly < 0.6:
        return "MEDIUM"
    else:
        return "CRITICAL" if (anomaly >= 0.8 or corr_depth >= 2 or mitre_count >= 2 or ti_score > 0.5) else "HIGH"

def compute_risk_score(anomaly, confidence, ti_score, pattern_score, corr_depth):
    raw = (anomaly * 35 + confidence * 25 + ti_score * 20 + pattern_score * 10 + min(corr_depth/4, 1.0) * 10)
    return round(min(raw, 100.0), 1)

def decide_action(confidence, severity="LOW"):
    sev = severity.upper()
    if sev == "CRITICAL" and confidence >= 0.5: return "AUTO_REMEDIATE"
    elif sev in ("HIGH", "CRITICAL") or confidence >= 0.6: return "ESCALATE_L2"
    return "MONITOR"

# ═══════════════════════════════════════════════════════════════════════════════
# 4. TIMELINE & EXPLANATION
# ═══════════════════════════════════════════════════════════════════════════════

def build_timeline(correlation, current_record):
    timeline = []
    sessions = correlation.correlated_sessions if correlation.is_correlated else [current_record]
    for sess in sessions:
        for evt in sess.events_summary:
            timeline.append({
                "timestamp": evt.get("timestamp") or sess.timestamp or "",
                "entity_id": sess.entity_id,
                "event_type": evt.get("event_type", "UNKNOWN"),
                "description": evt.get("description", ""),
                "session_anomaly_score": sess.anomaly_score,
                "session_id": sess.session_id,
            })
    timeline.sort(key=lambda x: x.get("timestamp") or "")
    return timeline

def _fallback_explanation(incident, severity):
    itype = incident.get("incident_type", "unknown").replace("_", " ")
    parts = [f"Detected {itype} incident involving {', '.join(incident.get('entities', []))}."]
    depth = incident.get("correlation_depth", 0)
    mitre = incident.get("compound_mitre_mappings", [])
    anomaly = incident.get("compound_anomaly_score", 0.0)
    if depth > 1: parts.append(f"Cross-session correlation linked {depth} sessions.")
    if mitre: parts.append(f"MITRE techniques: {', '.join(mitre)}.")
    if anomaly >= 0.6: parts.append("Behavior strongly deviates from normal patterns.")
    elif anomaly < 0.2: parts.append("Behavioral analysis shows low deviation.")
    parts.append(f"Severity: {severity}. Decision: {incident.get('decision', 'MONITOR')}.")
    return " ".join(parts)

def generate_agent_explanation(incident, timeline, severity, confidence):
    try:
        from backend.reasoning.llm_agent import generate_inference
    except ImportError:
        return _fallback_explanation(incident, severity)
    timeline_str = ""
    for i, e in enumerate(timeline[:15], 1):
        timeline_str += f"  {i}. [{e.get('timestamp','N/A')}] {e['event_type']} — {e.get('description','N/A')}\n"
    mitre_str = ", ".join(incident.get("compound_mitre_mappings", [])) or "None"
    prompt = f"""You are a Senior SOC Analyst writing an incident summary.
INCIDENT: {incident['incident_type']} | Severity: {severity} | Confidence: {confidence:.1%}
Decision: {incident.get('decision','MONITOR')} | Anomaly: {incident['compound_anomaly_score']:.4f}
MITRE: {mitre_str} | Sessions: {incident['correlation_depth']} | Campaign: {incident.get('campaign_pattern','None')}
TIMELINE:\n{timeline_str}
ENTITIES: {', '.join(incident['entities'])}
Write 3-4 sentence narrative. Return JSON: {{"narrative":"...","attack_assessment":"...","mitigations":["..."]}}"""
    try:
        import json, re as _re
        raw = generate_inference(prompt)
        # Try JSON parse (pure, fenced, or embedded)
        parsed = None
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            fenced = _re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, _re.DOTALL)
            if fenced:
                try: parsed = json.loads(fenced.group(1))
                except json.JSONDecodeError: pass
            if not parsed:
                block = _re.search(r'\{.*\}', raw, _re.DOTALL)
                if block:
                    try: parsed = json.loads(block.group())
                    except json.JSONDecodeError: pass

        if parsed:
            narrative = parsed.get("narrative", "")
            assessment = parsed.get("attack_assessment", "")
            mits = parsed.get("mitigations", [])
            if isinstance(mits, list): mits = "; ".join(mits)
            return f"{narrative} {assessment} Recommended: {mits}"

        # If JSON parse failed entirely, use raw LLM text if it's reasonable
        if raw and len(raw) > 30:
            return raw[:1500]

        return _fallback_explanation(incident, severity)
    except Exception as e:
        logger.warning(f"LLM explanation failed: {e}")
        return _fallback_explanation(incident, severity)

# ═══════════════════════════════════════════════════════════════════════════════
# 5. MAIN ENTRY POINT — MULTI-STEP REASONING
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_with_agent(
    sequence: List[int], entity_id: str, timestamp: str,
    events: List[SecurityEvent] = None, threat_intel_score: float = 0.0,
    anomaly_score: Optional[float] = None, raw_logs: str = "",
) -> Dict[str, Any]:
    """
    Next-level agent analysis with ReAct-style multi-tool reasoning.
    Returns structured incident with full reasoning trace.
    """
    events = events or []
    session_id = str(uuid.uuid4())[:8]
    reasoning_trace: List[Dict[str, Any]] = []
    tool_results_all: List[Dict[str, Any]] = []
    t_start = time.time()

    # ── STEP 1: OBSERVE ────────────────────────────────────────────────────
    step1_start = time.time()
    event_types = [e.event_type for e in events]
    events_summary = [{"event_type": e.event_type, "description": e.description,
                       "timestamp": e.timestamp, "source_ip": e.source_ip,
                       "dest_ip": e.dest_ip, "user": e.user} for e in events]
    try:
        epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except (ValueError, AttributeError):
        epoch = time.time()

    reasoning_trace.append(ReasoningStep(
        1, "observe", f"Collected {len(events)} events for entity {entity_id}",
        duration_ms=(time.time()-step1_start)*1000
    ).to_dict())

    # ── STEP 2: THINK — Select tools ───────────────────────────────────────
    step2_start = time.time()
    suspicious_types = [et for et in event_types if et != "NORMAL"]
    tools_to_run = ["anomaly_score", "pattern_match", "rag_lookup", "threat_intel", "ioc_extractor"]
    reasoning_trace.append(ReasoningStep(
        2, "think", f"Strategy: {len(suspicious_types)} suspicious events detected. Running {len(tools_to_run)} tools.",
        duration_ms=(time.time()-step2_start)*1000
    ).to_dict())

    # ── STEP 3: ACT — Execute tools ────────────────────────────────────────
    step3_start = time.time()
    step3_results = []

    # Tool 1: Anomaly Score
    anomaly_result = run_anomaly_score_tool(sequence, anomaly_score)
    step3_results.append(anomaly_result)
    tool_results_all.append(anomaly_result.to_dict())
    effective_anomaly = anomaly_result.output.get("anomaly_score", anomaly_score or 0.0)

    # Tool 2: Pattern Match
    pattern_result = run_pattern_match_tool(events)
    step3_results.append(pattern_result)
    tool_results_all.append(pattern_result.to_dict())
    pattern_name = pattern_result.output.get("pattern_name")
    pattern_score = pattern_result.output.get("pattern_score", 0.0)
    pattern_indicators = pattern_result.output.get("matched_indicators", [])
    pattern_mitre = pattern_result.output.get("mitre_suggestions", [])

    # Effective anomaly = max of LSTM and pattern
    effective_anomaly = max(effective_anomaly, pattern_score)

    # Tool 3: RAG Lookup
    rag_result = run_rag_lookup_tool(events)
    step3_results.append(rag_result)
    tool_results_all.append(rag_result.to_dict())
    individual_mitre = rag_result.output.get("techniques_found", [])
    # Merge pattern MITRE suggestions
    individual_mitre = list(dict.fromkeys(individual_mitre + pattern_mitre))

    # Tool 4: Threat Intel
    ti_result = run_threat_intel_tool(events)
    step3_results.append(ti_result)
    tool_results_all.append(ti_result.to_dict())
    ti_score_val = ti_result.output.get("max_risk_score", 0) / 100.0

    # Tool 5: IOC Extraction
    ioc_result = run_ioc_extractor_tool(raw_logs)
    step3_results.append(ioc_result)
    tool_results_all.append(ioc_result.to_dict())
    ioc_data = ioc_result.output if ioc_result.status == "success" else {}

    reasoning_trace.append(ReasoningStep(
        3, "act", f"Executed {len(step3_results)} tools. "
        f"Anomaly={effective_anomaly:.4f}, Patterns={pattern_name or 'none'}, "
        f"MITRE={len(individual_mitre)}, TI={ti_result.output.get('malicious_count',0)} malicious, "
        f"IOCs={ioc_data.get('suspicious_count',0)} suspicious",
        tool_results=step3_results,
        duration_ms=(time.time()-step3_start)*1000
    ).to_dict())

    # ── STEP 4: SYNTHESIZE — Merge evidence ────────────────────────────────
    step4_start = time.time()
    current_record = SessionRecord(
        session_id=session_id, timestamp=timestamp, epoch=epoch,
        sequence=sequence, event_types=event_types,
        anomaly_score=effective_anomaly, mitre_mappings=individual_mitre,
        events_summary=events_summary, entity_id=entity_id
    )
    update_memory(current_record)

    correlation = correlate_events(entity_id)
    hypothesis = build_hypothesis(correlation.combined_event_types)

    # Correlation depth
    if hypothesis: actual_depth = 3
    elif correlation.is_correlated: actual_depth = 2
    elif len(suspicious_types) > len(set(suspicious_types)) or pattern_name: actual_depth = 1
    else: actual_depth = 0
    correlation.correlation_depth = actual_depth

    compound = refine_with_models(hypothesis, correlation, effective_anomaly, individual_mitre)

    reasoning_trace.append(ReasoningStep(
        4, "synthesize",
        f"Correlation depth={actual_depth}, Hypothesis={hypothesis or 'none'}, "
        f"Compound anomaly={compound.compound_anomaly_score:.4f}, "
        f"Compound MITRE={len(compound.compound_mitre_mappings)}",
        duration_ms=(time.time()-step4_start)*1000
    ).to_dict())

    # ── STEP 5: DECIDE ─────────────────────────────────────────────────────
    step5_start = time.time()

    # Build why_flagged
    why_flagged = []
    if pattern_name:
        why_flagged.append(f"Heuristic Pattern: {pattern_name} (Score: {pattern_score:.2f})")
    if compound.compound_anomaly_score > 0.4:
        why_flagged.append(f"High anomaly deviation (score: {compound.compound_anomaly_score:.4f})")
    elif compound.compound_anomaly_score > 0.0 and not pattern_name:
        why_flagged.append(f"Anomaly score: {compound.compound_anomaly_score:.4f}")
    if compound.compound_mitre_mappings:
        why_flagged.append(f"MITRE techniques: {', '.join(compound.compound_mitre_mappings)}")
    if hypothesis:
        why_flagged.append(f"Campaign pattern: {hypothesis.replace('_',' ')}")
    if correlation.correlation_depth > 1:
        why_flagged.append(f"Cross-session correlation: {correlation.correlation_depth} sessions")
    if ti_result.output.get("malicious_count", 0) > 0:
        why_flagged.append(f"Threat intel: {ti_result.output['malicious_count']} malicious indicator(s)")
    if ioc_data.get("suspicious_count", 0) > 3:
        why_flagged.append(f"IOC extraction: {ioc_data['suspicious_count']} suspicious indicators")
    if not why_flagged and suspicious_types:
        why_flagged.append(f"Suspicious events: {', '.join(dict.fromkeys(suspicious_types))}")
    if not why_flagged:
        why_flagged.append("Session recorded for baseline monitoring")

    evidence = EvidenceLedger(
        lstm_score=compound.compound_anomaly_score,
        rag_matches=len(compound.compound_mitre_mappings),
        correlation_depth=correlation.correlation_depth,
        threat_intel_score=ti_score_val,
        pattern_score=pattern_score,
        ioc_count=ioc_data.get("suspicious_count", 0),
    )
    confidence = compute_confidence(evidence)
    severity = compute_severity(compound.compound_anomaly_score, correlation.correlation_depth,
                                len(compound.compound_mitre_mappings), ti_score_val)
    decision = decide_action(confidence, severity)
    risk_score = compute_risk_score(compound.compound_anomaly_score, confidence, ti_score_val,
                                    pattern_score, correlation.correlation_depth)

    # Incident type
    if pattern_name == "BRUTE_FORCE": itype = "Brute Force Attack Attempt"
    elif pattern_name == "SUSPICIOUS_EXECUTION_CHAIN": itype = "Suspicious Execution Chain"
    elif pattern_name == "PRIVILEGE_ESCALATION_SPIKE": itype = "Privilege Escalation Attempt"
    elif pattern_name == "CREDENTIAL_HARVESTING": itype = "Credential Harvesting Campaign"
    elif pattern_name == "DEFENSE_EVASION_CHAIN": itype = "Defense Evasion Campaign"
    elif pattern_name == "DATA_STAGING": itype = "Data Staging & Exfiltration"
    elif pattern_name == "RECON_TO_EXPLOIT": itype = "Reconnaissance to Exploitation"
    elif pattern_name == "C2_COMMUNICATION": itype = "Command & Control Communication"
    elif actual_depth == 0: itype = "Single Session Activity"
    elif actual_depth == 1: itype = "Repeated Suspicious Activity"
    elif actual_depth == 2: itype = "Correlated Attack Campaign"
    else: itype = "Multi-Stage Attack"

    reasoning_trace.append(ReasoningStep(
        5, "decide", f"Severity={severity}, Confidence={confidence:.1%}, Decision={decision}, Risk={risk_score}/100",
        duration_ms=(time.time()-step5_start)*1000
    ).to_dict())

    # ── STEP 6: EXPLAIN & PLAYBOOK ─────────────────────────────────────────
    step6_start = time.time()
    timeline = build_timeline(correlation, current_record)
    incident = {
        "incident_id": str(uuid.uuid4()), "incident_type": itype,
        "entities": list(dict.fromkeys([entity_id] + [s.entity_id for s in correlation.correlated_sessions])),
        "severity": severity, "confidence": confidence, "decision": decision,
        "correlation_depth": correlation.correlation_depth,
        "campaign_pattern": hypothesis, "compound_anomaly_score": compound.compound_anomaly_score,
        "compound_mitre_mappings": compound.compound_mitre_mappings,
        "detection_improvement": compound.improvement_detail, "evidence": evidence.to_dict(),
    }
    llm_explanation = generate_agent_explanation(incident, timeline, severity, confidence)

    # Tool 6: Playbook
    playbook_result = run_playbook_tool(itype, severity, hypothesis, pattern_name)
    tool_results_all.append(playbook_result.to_dict())
    playbook_data = playbook_result.output if playbook_result.status == "success" else {}

    reasoning_trace.append(ReasoningStep(
        6, "explain", f"Generated explanation and playbook ({playbook_data.get('name','generic')})",
        duration_ms=(time.time()-step6_start)*1000
    ).to_dict())

    total_ms = (time.time() - t_start) * 1000

    # ── RETURN ─────────────────────────────────────────────────────────────
    return {
        "anomaly_score": effective_anomaly,
        "compound_anomaly_score": compound.compound_anomaly_score,
        "mitre_mappings": individual_mitre,
        "compound_mitre_mappings": compound.compound_mitre_mappings,
        "correlated_timeline": timeline,
        "incident_type": itype,
        "severity": severity,
        "confidence": confidence,
        "decision": decision,
        "risk_score": risk_score,
        "why_flagged": why_flagged,
        "correlation_depth": correlation.correlation_depth,
        "campaign_pattern": hypothesis or pattern_name,
        "entities": incident["entities"],
        "llm_explanation": llm_explanation,
        "detection_improvement": compound.improvement_detail or None,
        "incident_id": incident["incident_id"],
        "reasoning_trace": reasoning_trace,
        "tool_results": tool_results_all,
        "iocs_extracted": ioc_data,
        "response_playbook": playbook_data,
        "total_analysis_ms": round(total_ms, 1),
    }
