"""
agent_layer.py — True Agent-Oriented AI Investigation System

The Agent Orchestrator manages the full lifecycle:
1. OBSERVE  - Collect facts (processed session)
2. THINK    - Heuristic deterministic suspicion assessment
3. PLAN     - Dynamically decide required specialists
4. EXECUTE  - Invoke selected specialists
5. EVALUATE - Assess intermediate evidence and escalate if needed
6. FUSE     - Merge evidence and historical cross-session memory
7. DECIDE   - Compute Severity, Risk, Confidence deterministically
8. EXPLAIN  - LLM generated narrative of the incident
"""

import logging, time, threading, uuid, re, json
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

class EntityMemoryStore:
    MAX_SESSIONS_PER_ENTITY = 50
    TTL_SECONDS = 86400

    def __init__(self):
        self._store: Dict[str, List[SessionRecord]] = {}
        self._lock = threading.Lock()

    def store_session(self, record: SessionRecord) -> None:
        with self._lock:
            entity = record.entity_id
            if entity not in self._store: self._store[entity] = []
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

_memory = EntityMemoryStore()
def get_memory_store() -> EntityMemoryStore: return _memory
def update_memory(record: SessionRecord) -> None: _memory.store_session(record)

# ═══════════════════════════════════════════════════════════════════════════════
# 2. STATE MANAGEMENT & HYPOTHESIS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class InvestigationState:
    session_id: str
    entity_id: str
    suspicion_level: str = "LOW"
    investigation_hypothesis: str = "Awaiting initial assessment"
    
    planned_tools: List[str] = field(default_factory=list)
    skipped_tools: List[str] = field(default_factory=list)
    completed_tools: List[str] = field(default_factory=list)
    escalation_tools: List[str] = field(default_factory=list)
    
    evidence_board: List[Dict[str, Any]] = field(default_factory=list)
    
    # Internal running states
    lstm_score: float = 0.0
    pattern_score: float = 0.0
    pattern_name: Optional[str] = None
    threat_intel_score: float = 0.0
    ioc_count: int = 0
    rag_matches: int = 0
    correlation_depth: int = 0
    mitre_mappings: List[str] = field(default_factory=list)
    compound_mitre_mappings: List[str] = field(default_factory=list)
    compound_anomaly_score: float = 0.0
    
    def add_evidence(self, description: str, source: str, contribution: float):
        self.evidence_board.append({
            "description": description,
            "source": source,
            "contribution": contribution
        })

CAMPAIGN_PATTERNS = {
    "full_kill_chain": ["LOGIN", "PRIV_ESC", "LATERAL_MOVE", "EXFILTRATION"],
    "privilege_escalation_chain": ["LOGIN", "PRIV_ESC", "SUSPICIOUS_EXEC"],
    "apt_lateral_movement": ["RECON", "LATERAL_MOVE", "EXFILTRATION"],
    "ransomware_deployment": ["DEFENSE_EVADE", "SUSPICIOUS_EXEC", "EXFILTRATION"],
    "brute_force_escalation": ["LOGIN", "LOGIN", "PRIV_ESC"],
    "recon_to_exploit": ["RECON", "SUSPICIOUS_EXEC", "PRIV_ESC"],
    "credential_theft": ["LOGIN", "SUSPICIOUS_EXEC", "EXFILTRATION"],
}

def build_hypothesis(combined_event_types: List[str]) -> Optional[str]:
    for name, seq in CAMPAIGN_PATTERNS.items():
        idx = 0
        for et in combined_event_types:
            if idx < len(seq) and et == seq[idx]: idx += 1
            if idx == len(seq): return name
    return None

# ═══════════════════════════════════════════════════════════════════════════════
# 3. DETERMINISTIC DECISIONS
# ═══════════════════════════════════════════════════════════════════════════════

def compute_confidence(state: InvestigationState) -> float:
    c = (0.35 * min(state.compound_anomaly_score, 1.0) +
         0.20 * min(state.rag_matches / 5.0, 1.0) +
         0.15 * min(state.correlation_depth / 4.0, 1.0) +
         0.10 * min(state.threat_intel_score, 1.0) +
         0.10 * min(state.pattern_score, 1.0) +
         0.10 * min(state.ioc_count / 10.0, 1.0))
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
# 4. ORCHESTRATOR ENTRY
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_with_agent(
    sequence: List[int], entity_id: str, timestamp: str,
    events: List[SecurityEvent] = None, threat_intel_score: float = 0.0,
    anomaly_score: Optional[float] = None, raw_logs: str = "",
) -> Dict[str, Any]:
    events = events or []
    session_id = str(uuid.uuid4())[:8]
    reasoning_trace: List[Dict[str, Any]] = []
    tool_results_all: List[Dict[str, Any]] = []
    t_start = time.time()
    
    state = InvestigationState(session_id=session_id, entity_id=entity_id)

    # ── PHASE 1: OBSERVE ───────────────────────────────────────────────────
    step1_start = time.time()
    event_types = [e.event_type for e in events]
    events_summary = [{"event_type": e.event_type, "description": e.description,
                       "timestamp": e.timestamp, "source_ip": e.source_ip,
                       "dest_ip": e.dest_ip, "user": e.user} for e in events]
    try: epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except: epoch = time.time()

    reasoning_trace.append(ReasoningStep(
        1, "observe", f"Collected {len(events)} events for entity {entity_id}. Retrieved facts without reasoning.",
        duration_ms=(time.time()-step1_start)*1000
    ).to_dict())

    # ── PHASE 2: THINK ─────────────────────────────────────────────────────
    step2_start = time.time()
    suspicious_types = [et for et in event_types if et != "NORMAL"]
    ratio = len(suspicious_types) / max(len(event_types), 1)
    
    if ratio > 0.5 or (anomaly_score and anomaly_score > 0.7):
        state.suspicion_level = "CRITICAL"
        state.investigation_hypothesis = "High density of suspicious activity detected. Potential active attack."
    elif ratio > 0.2 or len(set(suspicious_types)) >= 2:
        state.suspicion_level = "HIGH"
        state.investigation_hypothesis = "Multiple suspicious events detected. Investigating potential lateral movement."
    elif ratio > 0:
        state.suspicion_level = "MEDIUM"
        state.investigation_hypothesis = "Isolated suspicious activity detected. Verifying intent."
    else:
        state.suspicion_level = "LOW"
        state.investigation_hypothesis = "Normal baseline activity observed. Performing routine check."

    reasoning_trace.append(ReasoningStep(
        2, "think", f"Deterministic Suspicion: {state.suspicion_level}. Hypothesis: {state.investigation_hypothesis}",
        duration_ms=(time.time()-step2_start)*1000
    ).to_dict())

    # ── PHASE 3: PLAN ──────────────────────────────────────────────────────
    step3_start = time.time()
    ALL_SPECIALISTS = ["Behavior Analyst", "Pattern Analyst", "Threat Context", "IOC Analyst", "MITRE Knowledge"]
    
    state.planned_tools = ["Behavior Analyst", "Pattern Analyst"]
    if state.suspicion_level in ["MEDIUM", "HIGH", "CRITICAL"]:
        state.planned_tools.extend(["Threat Context", "IOC Analyst"])
    if state.suspicion_level in ["HIGH", "CRITICAL"]:
        state.planned_tools.append("MITRE Knowledge")
        
    state.skipped_tools = [s for s in ALL_SPECIALISTS if s not in state.planned_tools]
    
    reasoning_trace.append(ReasoningStep(
        3, "plan", f"Planned {len(state.planned_tools)} specialists based on {state.suspicion_level} suspicion. Skipped {len(state.skipped_tools)}.",
        duration_ms=(time.time()-step3_start)*1000
    ).to_dict())

    # ── PHASE 4: EXECUTE ───────────────────────────────────────────────────
    step4_start = time.time()
    step_results = []
    
    # 1. Behavior Analyst
    if "Behavior Analyst" in state.planned_tools:
        ts = time.time()
        res = run_anomaly_score_tool(sequence, anomaly_score)
        res.tool_name = "Behavior Analyst"
        state.completed_tools.append("Behavior Analyst")
        step_results.append(res)
        tool_results_all.append(res.to_dict())
        state.lstm_score = res.output.get("anomaly_score", anomaly_score or 0.0)
        state.compound_anomaly_score = state.lstm_score
        state.add_evidence(f"Behavioral deviation calculated at {state.lstm_score:.2f}", "Behavior Analyst", state.lstm_score * 0.35)

    # 2. Pattern Analyst
    if "Pattern Analyst" in state.planned_tools:
        ts = time.time()
        res = run_pattern_match_tool(events)
        res.tool_name = "Pattern Analyst"
        state.completed_tools.append("Pattern Analyst")
        step_results.append(res)
        tool_results_all.append(res.to_dict())
        state.pattern_name = res.output.get("pattern_name")
        state.pattern_score = res.output.get("pattern_score", 0.0)
        state.compound_anomaly_score = max(state.compound_anomaly_score, state.pattern_score)
        if state.pattern_name:
            state.add_evidence(f"Detected heuristic campaign pattern: {state.pattern_name}", "Pattern Analyst", state.pattern_score * 0.10)

    # 3. Threat Context
    if "Threat Context" in state.planned_tools:
        ts = time.time()
        res = run_threat_intel_tool(events)
        res.tool_name = "Threat Context"
        state.completed_tools.append("Threat Context")
        step_results.append(res)
        tool_results_all.append(res.to_dict())
        malicious = res.output.get("malicious_count", 0)
        state.threat_intel_score = res.output.get("max_risk_score", 0) / 100.0
        if malicious > 0:
            state.add_evidence(f"Identified {malicious} known malicious indicators", "Threat Context", state.threat_intel_score * 0.10)

    # 4. IOC Analyst
    if "IOC Analyst" in state.planned_tools:
        ts = time.time()
        res = run_ioc_extractor_tool(raw_logs)
        res.tool_name = "IOC Analyst"
        state.completed_tools.append("IOC Analyst")
        step_results.append(res)
        tool_results_all.append(res.to_dict())
        ioc_data = res.output if res.status == "success" else {}
        state.ioc_count = ioc_data.get("suspicious_count", 0)
        if state.ioc_count > 0:
            state.add_evidence(f"Extracted {state.ioc_count} suspicious IOCs from raw logs", "IOC Analyst", min(state.ioc_count/10.0, 1.0) * 0.10)

    # 5. MITRE Knowledge (RAG)
    if "MITRE Knowledge" in state.planned_tools:
        ts = time.time()
        res = run_rag_lookup_tool(events)
        res.tool_name = "MITRE Knowledge"
        state.completed_tools.append("MITRE Knowledge")
        step_results.append(res)
        tool_results_all.append(res.to_dict())
        state.mitre_mappings = res.output.get("techniques_found", [])
        state.rag_matches = len(state.mitre_mappings)
        state.compound_mitre_mappings = state.mitre_mappings
        if state.rag_matches > 0:
            state.add_evidence(f"Mapped {state.rag_matches} events to MITRE ATT&CK DB", "MITRE Knowledge", min(state.rag_matches/5.0, 1.0) * 0.20)

    reasoning_trace.append(ReasoningStep(
        4, "execute", f"Executed {len(state.completed_tools)} specialists. Gathered {len(state.evidence_board)} pieces of evidence.",
        tool_results=step_results,
        duration_ms=(time.time()-step4_start)*1000
    ).to_dict())

    # ── PHASE 5: EVALUATE ──────────────────────────────────────────────────
    step5_start = time.time()
    escalated = False
    escalated_results = []
    
    if state.pattern_name and "MITRE Knowledge" not in state.completed_tools:
        state.escalation_tools.append("MITRE Knowledge")
        res = run_rag_lookup_tool(events)
        res.tool_name = "MITRE Knowledge"
        state.completed_tools.append("MITRE Knowledge")
        escalated_results.append(res)
        tool_results_all.append(res.to_dict())
        state.mitre_mappings = res.output.get("techniques_found", [])
        state.compound_mitre_mappings = state.mitre_mappings
        state.rag_matches = len(state.mitre_mappings)
        state.add_evidence(f"Escalation: Mapped {state.rag_matches} events to MITRE", "MITRE Knowledge", min(state.rag_matches/5.0, 1.0) * 0.20)
        escalated = True

    if state.compound_anomaly_score > 0.4 and "Threat Context" not in state.completed_tools:
        state.escalation_tools.append("Threat Context")
        res = run_threat_intel_tool(events)
        res.tool_name = "Threat Context"
        state.completed_tools.append("Threat Context")
        escalated_results.append(res)
        tool_results_all.append(res.to_dict())
        state.threat_intel_score = res.output.get("max_risk_score", 0) / 100.0
        malicious = res.output.get("malicious_count", 0)
        if malicious > 0:
            state.add_evidence(f"Escalation: Found {malicious} malicious indicators", "Threat Context", state.threat_intel_score * 0.10)
        escalated = True

    eval_msg = f"Escalated investigation with {len(state.escalation_tools)} additional tools." if escalated else "Evidence sufficient. No escalation needed."
    reasoning_trace.append(ReasoningStep(
        5, "evaluate", eval_msg, tool_results=escalated_results,
        duration_ms=(time.time()-step5_start)*1000
    ).to_dict())

    # ── PHASE 6: FUSE ──────────────────────────────────────────────────────
    step6_start = time.time()
    
    current_record = SessionRecord(
        session_id=session_id, timestamp=timestamp, epoch=epoch,
        sequence=sequence, event_types=event_types,
        anomaly_score=state.compound_anomaly_score, mitre_mappings=state.compound_mitre_mappings,
        events_summary=events_summary, entity_id=entity_id
    )
    update_memory(current_record)

    all_sessions = _memory.get_sessions(entity_id)
    suspicious_sessions = [s for s in all_sessions if any(et != "NORMAL" for et in s.event_types)]
    
    if len(suspicious_sessions) > 1:
        state.correlation_depth = len(suspicious_sessions)
        combined_types = []
        for s in suspicious_sessions: combined_types.extend(s.event_types)
        hyp = build_hypothesis(combined_types)
        if hyp: 
            state.investigation_hypothesis = f"Cross-session correlation reveals: {hyp.replace('_',' ')}"
            state.add_evidence(f"Historical memory linked {state.correlation_depth} sessions to a unified campaign", "Investigation Memory", 0.15)
        else:
            state.add_evidence(f"Entity has a history of {state.correlation_depth} suspicious sessions", "Investigation Memory", 0.10)

        # Merge MITRE
        for s in suspicious_sessions:
            for m in s.mitre_mappings:
                if m not in state.compound_mitre_mappings:
                    state.compound_mitre_mappings.append(m)

    reasoning_trace.append(ReasoningStep(
        6, "fuse", f"Fused evidence. Memory correlation depth = {state.correlation_depth}. Total MITRE = {len(state.compound_mitre_mappings)}",
        duration_ms=(time.time()-step6_start)*1000
    ).to_dict())

    # ── PHASE 7: DECIDE ────────────────────────────────────────────────────
    step7_start = time.time()
    
    confidence = compute_confidence(state)
    severity = compute_severity(state.compound_anomaly_score, state.correlation_depth, len(state.compound_mitre_mappings), state.threat_intel_score)
    decision = decide_action(confidence, severity)
    risk_score = compute_risk_score(state.compound_anomaly_score, confidence, state.threat_intel_score, state.pattern_score, state.correlation_depth)

    # Incident type
    actual_depth = state.correlation_depth
    if state.pattern_name == "BRUTE_FORCE": itype = "Brute Force Attack Attempt"
    elif state.pattern_name == "SUSPICIOUS_EXECUTION_CHAIN": itype = "Suspicious Execution Chain"
    elif state.pattern_name == "PRIVILEGE_ESCALATION_SPIKE": itype = "Privilege Escalation Attempt"
    elif state.pattern_name == "CREDENTIAL_HARVESTING": itype = "Credential Harvesting Campaign"
    elif state.pattern_name == "DEFENSE_EVASION_CHAIN": itype = "Defense Evasion Campaign"
    elif state.pattern_name == "DATA_STAGING": itype = "Data Staging & Exfiltration"
    elif state.pattern_name == "RECON_TO_EXPLOIT": itype = "Reconnaissance to Exploitation"
    elif state.pattern_name == "C2_COMMUNICATION": itype = "Command & Control Communication"
    elif actual_depth == 0: itype = "Single Session Activity"
    elif actual_depth == 1: itype = "Repeated Suspicious Activity"
    elif actual_depth == 2: itype = "Correlated Attack Campaign"
    else: itype = "Multi-Stage Attack"

    why_flagged = [ev["description"] for ev in state.evidence_board]
    if not why_flagged: why_flagged = ["Session recorded for baseline monitoring"]

    reasoning_trace.append(ReasoningStep(
        7, "decide", f"Deterministic Decision completed. Severity={severity}, Confidence={confidence:.1%}, Decision={decision}, Risk={risk_score}/100",
        duration_ms=(time.time()-step7_start)*1000
    ).to_dict())

    # ── PHASE 8: EXPLAIN ───────────────────────────────────────────────────
    step8_start = time.time()
    
    timeline = []
    sessions_to_map = suspicious_sessions if state.correlation_depth > 1 else [current_record]
    for sess in sessions_to_map:
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

    incident = {
        "incident_type": itype, "entities": list(dict.fromkeys([entity_id] + [s.entity_id for s in sessions_to_map])),
        "severity": severity, "confidence": confidence, "decision": decision,
        "correlation_depth": state.correlation_depth,
        "campaign_pattern": state.pattern_name, "compound_anomaly_score": state.compound_anomaly_score,
        "compound_mitre_mappings": state.compound_mitre_mappings,
    }
    
    try:
        from backend.reasoning.llm_agent import generate_inference
        timeline_str = ""
        for i, e in enumerate(timeline[:15], 1):
            timeline_str += f"  {i}. [{e.get('timestamp','N/A')}] {e['event_type']} — {e.get('description','N/A')}\n"
        prompt = f"You are a SOC Agent writing a final explanation. INCIDENT: {itype} | Severity: {severity} | Confidence: {confidence:.1%} | Decision: {decision}\nTIMELINE:\n{timeline_str}\nWrite 3-4 sentences. Return JSON: {{\"narrative\":\"...\"}}"
        raw = generate_inference(prompt)
        parsed = None
        try: parsed = json.loads(raw)
        except json.JSONDecodeError:
            fenced = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', raw, re.DOTALL)
            if fenced:
                try: parsed = json.loads(fenced.group(1))
                except: pass
        llm_explanation = parsed.get("narrative", raw[:1500]) if parsed else raw[:1500]
    except:
        llm_explanation = f"Detected {itype}. Severity: {severity}. Decision: {decision}."

    playbook_result = run_playbook_tool(itype, severity, state.investigation_hypothesis, state.pattern_name)
    tool_results_all.append(playbook_result.to_dict())
    playbook_data = playbook_result.output if playbook_result.status == "success" else {}

    reasoning_trace.append(ReasoningStep(
        8, "explain", f"Generated human-readable explanation and response playbook",
        duration_ms=(time.time()-step8_start)*1000
    ).to_dict())

    total_ms = (time.time() - t_start) * 1000

    # ── RETURN ENHANCED STATE ──────────────────────────────────────────────
    return {
        # Core original schema 
        "anomaly_score": state.lstm_score,
        "compound_anomaly_score": state.compound_anomaly_score,
        "mitre_mappings": state.mitre_mappings,
        "compound_mitre_mappings": state.compound_mitre_mappings,
        "correlated_timeline": timeline,
        "incident_type": itype,
        "severity": severity,
        "confidence": confidence,
        "decision": decision,
        "risk_score": risk_score,
        "why_flagged": why_flagged,
        "correlation_depth": state.correlation_depth,
        "campaign_pattern": state.pattern_name,
        "entities": incident["entities"],
        "llm_explanation": llm_explanation,
        "incident_id": session_id,
        
        # New Enterprise Agent Console State
        "investigation_status": "COMPLETED",
        "suspicion_level": state.suspicion_level,
        "investigation_hypothesis": state.investigation_hypothesis,
        "planned_tools": state.planned_tools,
        "completed_tools": state.completed_tools,
        "skipped_tools": state.skipped_tools,
        "escalation_tools": state.escalation_tools,
        "evidence_board": state.evidence_board,

        # Trace and Results
        "reasoning_trace": reasoning_trace,
        "tool_results": tool_results_all,
        "iocs_extracted": ioc_data if 'ioc_data' in locals() else {},
        "response_playbook": playbook_data,
        "total_analysis_ms": round(total_ms, 1),
    }
