"""
agent_layer.py — Agentic AI Investigation Orchestrator
========================================================

Implements the full agentic investigation loop:

  1. PERCEIVE  — Normalize logs → build InvestigationObject
  2. PLAN      — LLM generates investigation hypothesis & tool plan
  3. VALIDATE  — Policy engine validates the plan
  4. EXECUTE   — Tool orchestrator runs approved specialists
  5. AGGREGATE — Evidence aggregator merges results
  6. REFLECT   — LLM evaluates evidence sufficiency & hypothesis validity
  7. REPLAN?   — If more evidence needed AND iterations remaining → goto PLAN
  8. DECIDE    — Deterministic engine computes severity/risk/confidence/action
  9. REPORT    — LLM generates human-readable investigation report

Each phase produces a ReasoningStep with execution time and structured
reasoning for full transparency in the frontend.
"""

import logging
import time
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.perception import perceive, InvestigationObject
from backend.reasoning.planner import generate_plan, InvestigationPlan
from backend.reasoning.reflection import reflect, ReflectionResult
from backend.reasoning.policy_engine import PolicyEngine
from backend.reasoning.evidence_aggregator import EvidenceAggregator
from backend.reasoning.decision_engine import DecisionEngine
from backend.reasoning.report_generator import generate_investigation_report
from backend.reasoning.agent_tools import (
    ToolResult,
    ReasoningStep,
    execute_tools,
    run_playbook_tool,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION RECORD & ENTITY MEMORY (preserved from original architecture)
# ═══════════════════════════════════════════════════════════════════════════════

from dataclasses import dataclass, field


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
            if entity not in self._store:
                self._store[entity] = []
            cutoff = time.time() - self.TTL_SECONDS
            self._store[entity] = [
                r for r in self._store[entity] if r.epoch >= cutoff
            ]
            self._store[entity].append(record)
            if len(self._store[entity]) > self.MAX_SESSIONS_PER_ENTITY:
                self._store[entity] = self._store[entity][
                    -self.MAX_SESSIONS_PER_ENTITY :
                ]

    def get_sessions(
        self, entity_id: str, window_seconds: int = 21600
    ) -> List[SessionRecord]:
        with self._lock:
            records = self._store.get(entity_id, [])
            cutoff = time.time() - window_seconds
            return [r for r in records if r.epoch >= cutoff]

    def get_all_entities(self) -> List[str]:
        with self._lock:
            return list(self._store.keys())


_memory = EntityMemoryStore()


def get_memory_store() -> EntityMemoryStore:
    return _memory


def update_memory(record: SessionRecord) -> None:
    _memory.store_session(record)


# ═══════════════════════════════════════════════════════════════════════════════
# CAMPAIGN PATTERN DETECTION (for cross-session correlation)
# ═══════════════════════════════════════════════════════════════════════════════

CAMPAIGN_PATTERNS = {
    "full_kill_chain": ["LOGIN", "PRIV_ESC", "LATERAL_MOVE", "EXFILTRATION"],
    "privilege_escalation_chain": ["LOGIN", "PRIV_ESC", "SUSPICIOUS_EXEC"],
    "apt_lateral_movement": ["RECON", "LATERAL_MOVE", "EXFILTRATION"],
    "ransomware_deployment": [
        "DEFENSE_EVADE",
        "SUSPICIOUS_EXEC",
        "EXFILTRATION",
    ],
    "brute_force_escalation": ["LOGIN", "LOGIN", "PRIV_ESC"],
    "recon_to_exploit": ["RECON", "SUSPICIOUS_EXEC", "PRIV_ESC"],
    "credential_theft": ["LOGIN", "SUSPICIOUS_EXEC", "EXFILTRATION"],
}


def _build_campaign_hypothesis(combined_event_types: List[str]) -> Optional[str]:
    for name, seq in CAMPAIGN_PATTERNS.items():
        idx = 0
        for et in combined_event_types:
            if idx < len(seq) and et == seq[idx]:
                idx += 1
            if idx == len(seq):
                return name
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# AGENTIC ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════


def analyze_with_agent(
    sequence: List[int],
    entity_id: str,
    timestamp: str,
    events: list = None,
    threat_intel_score: float = 0.0,
    anomaly_score: Optional[float] = None,
    raw_logs: str = "",
) -> Dict[str, Any]:
    """
    Full Agentic AI Investigation Orchestrator.

    Implements the complete investigation loop:
    PERCEIVE → PLAN → VALIDATE → EXECUTE → AGGREGATE →
    REFLECT → (REPLAN?) → DECIDE → REPORT

    Each phase produces structured reasoning for full frontend transparency.
    """
    events = events or []
    session_id = str(uuid.uuid4())[:8]
    reasoning_trace: List[Dict[str, Any]] = []
    plan_history: List[Dict[str, Any]] = []
    reflection_history: List[Dict[str, Any]] = []
    replan_events: List[Dict[str, Any]] = []
    planner_thoughts: List[str] = []
    t_start = time.time()

    # Initialize engines
    policy_engine = PolicyEngine()
    evidence_aggregator = EvidenceAggregator()
    decision_engine = DecisionEngine()

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 1: PERCEIVE
    # ══════════════════════════════════════════════════════════════════════
    step_start = time.time()

    inv_obj = perceive(raw_logs, entity_id=entity_id)

    # Use pre-computed values from the caller if available
    if anomaly_score is not None:
        inv_obj.anomaly_score = anomaly_score

    investigation_data = inv_obj.to_planner_dict()

    event_types = [e.event_type for e in events]
    events_summary = [
        {
            "event_type": e.event_type,
            "description": e.description,
            "timestamp": e.timestamp,
            "source_ip": e.source_ip,
            "dest_ip": e.dest_ip,
            "user": e.user,
        }
        for e in events
    ]

    try:
        epoch = datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        ).timestamp()
    except Exception:
        epoch = time.time()

    reasoning_trace.append(
        ReasoningStep(
            1,
            "perceive",
            f"Perceived {inv_obj.total_events} events for entity {entity_id}. "
            f"Anomaly score: {inv_obj.anomaly_score:.2f}. "
            f"Event types: {', '.join(inv_obj.event_types)}.",
            duration_ms=(time.time() - step_start) * 1000,
        ).to_dict()
    )

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 2: PLAN (LLM Investigation Planner)
    # ══════════════════════════════════════════════════════════════════════
    step_start = time.time()

    plan = generate_plan(investigation_data)
    current_hypothesis = plan.hypothesis
    planner_thoughts.append(plan.planner_reasoning)
    plan_history.append(plan.to_dict())

    reasoning_trace.append(
        ReasoningStep(
            2,
            "plan",
            f"Hypothesis: {current_hypothesis}. "
            f"Strategy: {plan.strategy}. "
            f"Planned {len(plan.tool_sequence)} specialists: "
            f"{', '.join(plan.tool_sequence)}. "
            f"{'(LLM-generated)' if plan.is_llm_generated else '(Deterministic fallback)'}",
            duration_ms=(time.time() - step_start) * 1000,
        ).to_dict()
    )

    # ══════════════════════════════════════════════════════════════════════
    # AGENTIC LOOP: VALIDATE → EXECUTE → AGGREGATE → REFLECT → REPLAN?
    # ══════════════════════════════════════════════════════════════════════
    iteration = 0
    max_iterations = policy_engine.config.max_replan_iterations

    while True:
        iteration += 1
        policy_engine.increment_iteration()

        # ── PHASE 3: VALIDATE PLAN ────────────────────────────────────────
        step_start = time.time()

        validated = policy_engine.validate_plan(plan.to_dict())

        reasoning_trace.append(
            ReasoningStep(
                len(reasoning_trace) + 1,
                "validate",
                f"Iteration {iteration}: Policy validated plan. "
                f"{len(validated.approved_tools)} approved, "
                f"{len(validated.rejected_tools)} rejected. "
                f"Limits: {policy_engine.get_limits_status()}",
                duration_ms=(time.time() - step_start) * 1000,
            ).to_dict()
        )

        # ── PHASE 4: EXECUTE SPECIALISTS ──────────────────────────────────
        step_start = time.time()

        evidence_aggregator.set_pending_tools(validated.approved_tools)

        tool_results = execute_tools(
            approved_tools=validated.approved_tools,
            raw_events=inv_obj._raw_events,
            raw_logs=inv_obj._raw_logs,
            event_sequence=inv_obj.event_sequence_ints,
            anomaly_score=inv_obj.anomaly_score,
        )

        # Aggregate results
        for result in tool_results:
            evidence_aggregator.add_tool_result(result.to_dict())

        policy_engine.record_tool_invocations(len(tool_results))

        reasoning_trace.append(
            ReasoningStep(
                len(reasoning_trace) + 1,
                "execute",
                f"Iteration {iteration}: Executed {len(tool_results)} specialists. "
                f"Gathered {len(evidence_aggregator._evidence_items)} evidence items.",
                tool_results=tool_results,
                duration_ms=(time.time() - step_start) * 1000,
            ).to_dict()
        )

        # ── PHASE 5: REFLECT ─────────────────────────────────────────────
        step_start = time.time()

        accumulated = evidence_aggregator.get_accumulated_evidence()

        reflection = reflect(
            investigation_object=investigation_data,
            current_hypothesis=current_hypothesis,
            accumulated_evidence=accumulated.to_planner_summary(),
            completed_tools=accumulated.completed_tools,
            iteration=iteration,
        )

        reflection_history.append(reflection.to_dict())

        # Update hypothesis if reflection suggests a change
        if not reflection.hypothesis_still_valid and reflection.updated_hypothesis:
            old_hyp = current_hypothesis
            current_hypothesis = reflection.updated_hypothesis
            replan_events.append({
                "iteration": iteration,
                "reason": "Hypothesis updated by reflection",
                "old_hypothesis": old_hyp,
                "new_hypothesis": current_hypothesis,
            })

        reasoning_trace.append(
            ReasoningStep(
                len(reasoning_trace) + 1,
                "reflect",
                f"Iteration {iteration}: {reflection.reasoning}. "
                f"Hypothesis {'still valid' if reflection.hypothesis_still_valid else 'UPDATED'}. "
                f"{'More evidence needed.' if reflection.needs_more_evidence else 'Evidence sufficient.'}",
                duration_ms=(time.time() - step_start) * 1000,
            ).to_dict()
        )

        # ── REPLAN CHECK ──────────────────────────────────────────────────
        if (
            reflection.needs_more_evidence
            and reflection.additional_tools_needed
            and policy_engine.check_iteration_limit()
        ):
            # Generate a follow-up plan
            step_start = time.time()

            replan_events.append({
                "iteration": iteration,
                "reason": f"Reflection requested additional tools: {reflection.additional_tools_needed}",
                "tools_requested": reflection.additional_tools_needed,
            })

            plan = generate_plan(
                investigation_data,
                accumulated_evidence=accumulated.to_planner_summary(),
            )

            # Override with reflection's specific tool requests if planner
            # doesn't include them
            for tool in reflection.additional_tools_needed:
                if tool not in plan.tool_sequence:
                    plan.tool_sequence.append(tool)

            plan.hypothesis = current_hypothesis
            planner_thoughts.append(plan.planner_reasoning)
            plan_history.append(plan.to_dict())

            reasoning_trace.append(
                ReasoningStep(
                    len(reasoning_trace) + 1,
                    "replan",
                    f"Replanning iteration {iteration + 1}: "
                    f"New plan with {len(plan.tool_sequence)} tools. "
                    f"Hypothesis: {current_hypothesis}",
                    duration_ms=(time.time() - step_start) * 1000,
                ).to_dict()
            )

            continue  # Loop back to VALIDATE → EXECUTE → REFLECT
        else:
            break  # Evidence sufficient or limits reached

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 6: CROSS-SESSION MEMORY FUSION
    # ══════════════════════════════════════════════════════════════════════
    step_start = time.time()

    accumulated = evidence_aggregator.get_accumulated_evidence()

    current_record = SessionRecord(
        session_id=session_id,
        timestamp=timestamp,
        epoch=epoch,
        sequence=sequence,
        event_types=event_types,
        anomaly_score=accumulated.compound_anomaly_score,
        mitre_mappings=accumulated.compound_mitre_mappings,
        events_summary=events_summary,
        entity_id=entity_id,
    )
    update_memory(current_record)

    all_sessions = _memory.get_sessions(entity_id)
    suspicious_sessions = [
        s for s in all_sessions if any(et != "NORMAL" for et in s.event_types)
    ]

    if len(suspicious_sessions) > 1:
        evidence_aggregator.correlation_depth = len(suspicious_sessions)

        combined_types: List[str] = []
        for s in suspicious_sessions:
            combined_types.extend(s.event_types)

        campaign_hyp = _build_campaign_hypothesis(combined_types)
        if campaign_hyp:
            current_hypothesis = (
                f"Cross-session correlation reveals: {campaign_hyp.replace('_', ' ')}"
            )

        evidence_aggregator.add_memory_evidence(
            correlation_depth=len(suspicious_sessions),
            hypothesis=campaign_hyp,
        )

        # Merge MITRE mappings from historical sessions
        for s in suspicious_sessions:
            for m in s.mitre_mappings:
                if m not in evidence_aggregator.compound_mitre_mappings:
                    evidence_aggregator.compound_mitre_mappings.append(m)

    reasoning_trace.append(
        ReasoningStep(
            len(reasoning_trace) + 1,
            "fuse",
            f"Memory fusion: correlation depth={evidence_aggregator.correlation_depth}. "
            f"Total MITRE={len(evidence_aggregator.compound_mitre_mappings)}.",
            duration_ms=(time.time() - step_start) * 1000,
        ).to_dict()
    )

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 7: DETERMINISTIC DECISION
    # ══════════════════════════════════════════════════════════════════════
    step_start = time.time()

    final_evidence = evidence_aggregator.get_accumulated_evidence()
    decision = decision_engine.decide(final_evidence)

    reasoning_trace.append(
        ReasoningStep(
            len(reasoning_trace) + 1,
            "decide",
            f"Deterministic decision: Severity={decision.severity}, "
            f"Confidence={decision.confidence:.1%}, "
            f"Risk={decision.risk_score}/100, "
            f"Action={decision.recommended_action}. "
            f"Factors: {', '.join(decision.severity_factors)}",
            duration_ms=(time.time() - step_start) * 1000,
        ).to_dict()
    )

    # ══════════════════════════════════════════════════════════════════════
    # PHASE 8: REPORT GENERATION
    # ══════════════════════════════════════════════════════════════════════
    step_start = time.time()

    # Build timeline
    timeline: List[Dict[str, Any]] = []
    sessions_to_map = (
        suspicious_sessions
        if evidence_aggregator.correlation_depth > 1
        else [current_record]
    )
    for sess in sessions_to_map:
        for evt in sess.events_summary:
            timeline.append(
                {
                    "timestamp": evt.get("timestamp") or sess.timestamp or "",
                    "entity_id": sess.entity_id,
                    "event_type": evt.get("event_type", "UNKNOWN"),
                    "description": evt.get("description", ""),
                    "session_anomaly_score": sess.anomaly_score,
                    "session_id": sess.session_id,
                }
            )
    timeline.sort(key=lambda x: x.get("timestamp") or "")

    # Generate the LLM report
    report = generate_investigation_report(
        decision=decision.to_dict(),
        evidence_summary=final_evidence.to_planner_summary(),
        timeline=timeline,
        plan_history=plan_history,
        hypothesis=current_hypothesis,
    )

    # Generate response playbook
    playbook_result = run_playbook_tool(
        decision.incident_type,
        decision.severity,
        current_hypothesis,
        final_evidence.pattern_name,
    )
    playbook_data = (
        playbook_result.output
        if playbook_result.status == "success"
        else {}
    )

    # Build evidence board
    evidence_board = [e.to_dict() for e in evidence_aggregator._evidence_items]
    why_flagged = [ev["description"] for ev in evidence_board]
    if not why_flagged:
        why_flagged = ["Session recorded for baseline monitoring"]

    reasoning_trace.append(
        ReasoningStep(
            len(reasoning_trace) + 1,
            "report",
            "Generated investigation report and response playbook.",
            duration_ms=(time.time() - step_start) * 1000,
        ).to_dict()
    )

    total_ms = (time.time() - t_start) * 1000

    # ══════════════════════════════════════════════════════════════════════
    # RETURN FULL INVESTIGATION STATE
    # ══════════════════════════════════════════════════════════════════════
    ioc_data = {}
    for tr in final_evidence.tool_results:
        if tr.get("tool_name") == "IOC Analyst" and tr.get("status") == "success":
            ioc_data = tr.get("output", {})
            break

    return {
        # ── Core detection signals ────────────────────────────────────────
        "anomaly_score": final_evidence.lstm_score,
        "compound_anomaly_score": final_evidence.compound_anomaly_score,
        "mitre_mappings": final_evidence.mitre_mappings,
        "compound_mitre_mappings": final_evidence.compound_mitre_mappings,
        "correlated_timeline": timeline,
        "incident_type": decision.incident_type,
        "severity": decision.severity,
        "confidence": decision.confidence,
        "decision": decision.recommended_action,
        "risk_score": decision.risk_score,
        "why_flagged": why_flagged,
        "correlation_depth": final_evidence.correlation_depth,
        "campaign_pattern": final_evidence.pattern_name,
        "entities": list(
            dict.fromkeys(
                [entity_id]
                + [s.entity_id for s in sessions_to_map]
            )
        ),
        "llm_explanation": report.full_narrative,
        "incident_id": session_id,
        # ── Investigation console state ───────────────────────────────────
        "investigation_status": "COMPLETED",
        "suspicion_level": (
            "CRITICAL"
            if decision.severity in ("CRITICAL", "HIGH")
            else "MEDIUM"
            if decision.severity == "MEDIUM"
            else "LOW"
        ),
        "investigation_hypothesis": current_hypothesis,
        "planned_tools": plan_history[0].get("tool_sequence", []) if plan_history else [],
        "completed_tools": final_evidence.completed_tools,
        "skipped_tools": [
            t
            for t in [
                "Behavior Analyst",
                "Pattern Analyst",
                "Threat Context",
                "IOC Analyst",
                "MITRE Knowledge",
            ]
            if t not in final_evidence.completed_tools
        ],
        "escalation_tools": [
            t
            for plan in plan_history[1:]
            for t in plan.get("tool_sequence", [])
        ],
        "evidence_board": evidence_board,
        # ── Reasoning trace ───────────────────────────────────────────────
        "reasoning_trace": reasoning_trace,
        "tool_results": final_evidence.tool_results,
        "iocs_extracted": ioc_data,
        "response_playbook": playbook_data,
        "total_analysis_ms": round(total_ms, 1),
        # ── NEW: Agentic investigation fields ─────────────────────────────
        "reflection_history": reflection_history,
        "replan_events": replan_events,
        "confidence_evolution": final_evidence.confidence_evolution,
        "planner_thoughts": planner_thoughts,
        "investigation_phases": reasoning_trace,
        "investigation_report": report.to_dict(),
        "plan_iterations": iteration,
        "plan_history": plan_history,
        # ── Decision transparency ─────────────────────────────────────────
        "confidence_breakdown": decision.confidence_breakdown,
        "risk_breakdown": decision.risk_breakdown,
        "severity_factors": decision.severity_factors,
    }
