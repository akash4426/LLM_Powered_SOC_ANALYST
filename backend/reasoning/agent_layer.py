"""
agent_layer.py — Autonomous Agentic Investigation Loop
======================================================

Implements the strict, deterministic agentic loop over the InvestigationObject.
All components communicate ONLY through the InvestigationObject.
"""

import time
import logging
from typing import Dict, Any, List

from backend.schemas.investigation import InvestigationObject
from backend.perception import perceive
from backend.reasoning.planner import generate_plan
from backend.reasoning.policy_engine import PolicyEngine
from backend.reasoning.agent_tools import execute_tools
from backend.reasoning.evidence_aggregator import EvidenceAggregator
from backend.reasoning.reflection import reflect_on_evidence
from backend.reasoning.decision_engine import DecisionEngine
from backend.reasoning.report_generator import generate_report

logger = logging.getLogger(__name__)


def run_investigation_loop(raw_logs: str, entity_id: str = None) -> InvestigationObject:
    """
    Main Autonomous Agentic Loop.
    Enforces strict architectural boundaries and shared contracts.
    
    Architecture:
        Perception → [Planner → Policy → Orchestrator → Aggregator → Reflection]* → Decision → Report
    """
    overall_start = time.time()

    # ── Phase 1: Perception (Deterministic) ─────────────────────────────────
    # Parses logs, normalizes events, builds sessions, outputs InvestigationObject.
    # NEVER runs LSTM, RAG, TI, Memory, or LLM.
    inv_obj = perceive(raw_logs, entity_id)
    logger.info(
        f"[Phase 1: PERCEIVE] Entity='{inv_obj.entity_info.get('primary_entity')}' "
        f"Events={inv_obj.session_metadata.get('total_events', 0)}"
    )

    policy_engine = PolicyEngine()
    policy_engine.reset()

    max_loops = policy_engine.config.max_replan_iterations

    # V10 FIX: Track hypothesis evolution across iterations for richer reflection context.
    hypothesis_history: List[str] = []

    # ── The Agentic Loop ─────────────────────────────────────────────────────
    for iteration in range(1, max_loops + 1):
        logger.info(f"{'═'*60}")
        logger.info(f"[Agentic Loop] Iteration {iteration}/{max_loops}")

        # ── Phase 2: Planner (LLM Reasoning) ─────────────────────────────────
        # Generates InvestigationPlan. NEVER executes tools or computes scores.
        from backend.schemas.investigation import PlannerError
        try:
            plan = generate_plan(inv_obj.to_planner_dict())
        except PlannerError as e:
            logger.error(f"[Phase 2: PLAN] Planner failed: {e}")
            inv_obj.severity = "ERROR"
            inv_obj.decision = "PLANNER_FAILURE"
            inv_obj.report = "Investigation terminated due to a fatal Planner Error."
            inv_obj.investigation_report["planner_error"] = {
                "reason": str(e),
                "retry_attempts": 3,
                "provider": "ReasoningProvider"
            }
            inv_obj.plan_iterations = iteration
            return inv_obj

        inv_obj.planner_hypothesis = plan.hypothesis

        # V10: Record hypothesis evolution
        hypothesis_history.append(f"[Iteration {iteration}] {plan.hypothesis}")
        logger.info(f"[Phase 2: PLAN] Hypothesis: {plan.hypothesis[:80]}...")
        logger.info(f"[Phase 2: PLAN] Requested tools: {plan.required_tools}")

        # ── Phase 3: Policy Engine (Deterministic) ────────────────────────────
        # Validates the plan. Rejects forbidden, duplicate, and over-budget tools.
        already_run = [t.tool_name for t in inv_obj.tool_outputs]
        approved_plan = policy_engine.validate_plan(plan, already_run=already_run)

        if not approved_plan.is_valid:
            logger.info("[Phase 3: VALIDATE] No approved tools remaining. Exiting agentic loop.")
            break

        logger.info(f"[Phase 3: VALIDATE] Approved: {approved_plan.approved_tools}")
        if approved_plan.rejected_tools:
            logger.info(f"[Phase 3: VALIDATE] Rejected: {[r['tool'] for r in approved_plan.rejected_tools]}")
            for r in approved_plan.rejected_tools:
                inv_obj.skipped_tools_log.append({
                    "tool": r["tool"],
                    "reason": r["reason"],
                    "iteration": iteration
                })

        # ── Phase 4: Tool Orchestrator (Execution) ────────────────────────────
        # Executes ONLY the approved tools. Each tool receives InvestigationObject.
        tool_results = execute_tools(approved_plan, inv_obj)

        # Record tool invocations in policy engine (for deduplication tracking)
        executed_names = [r.tool_name for r in tool_results]
        policy_engine.record_tool_invocations(executed_names)

        # ── Phase 5: Evidence Aggregator (Deterministic) ──────────────────────
        # Merges ToolResults into InvestigationObject. No LLM, no side effects.
        EvidenceAggregator.aggregate(inv_obj, tool_results)
        logger.info(
            f"[Phase 5: AGGREGATE] Timeline entries: {len(inv_obj.evidence_timeline)}, "
            f"Tool outputs: {len(inv_obj.tool_outputs)}"
        )
        
        # V12 FIX: Compute intermediate confidence to track evolution
        DecisionEngine.evaluate(inv_obj)
        inv_obj.confidence_evolution.append(inv_obj.confidence)

        # ── Phase 6: Reflection Engine (LLM Reasoning) ───────────────────────
        # Asks the LLM: "Do we have enough evidence?"
        needs_replanning = reflect_on_evidence(inv_obj)
        
        # Track rich reflection decision
        reflection_record = {
            "iteration": iteration,
            "needs_more_evidence": needs_replanning,
            "confidence_at_time": inv_obj.confidence,
            "evidence_completeness": inv_obj.evidence_completeness,
            **inv_obj.last_reflection_data
        }
        inv_obj.reflection_history.append(reflection_record)

        if not needs_replanning:
            logger.info("[Phase 6: REFLECT] Evidence is sufficient. Exiting loop.")
            break
        elif iteration == max_loops:
            logger.warning("[Phase 6: REFLECT] Max iterations reached. Forcing exit.")
            break
        else:
            logger.info("[Phase 6: REFLECT] Requesting replan. Continuing loop.")
            # Track replan event
            inv_obj.replan_events.append({
                "iteration": iteration,
                "reason": inv_obj.last_reflection_data.get("reasoning", "More evidence requested"),
                "tools_run_so_far": len(inv_obj.tool_outputs),
                "old_hypothesis": plan.hypothesis,
                "missing_evidence": inv_obj.last_reflection_data.get("missing_evidence", [])
            })
            policy_engine.increment_iteration()

    # Track total iterations
    inv_obj.plan_iterations = iteration

    logger.info(f"{'═'*60}")

    # ── Phase 7: Decision Engine (Deterministic, NO LLM) ─────────────────────
    # Uses only accumulated tool evidence to compute severity, risk, confidence.
    DecisionEngine.evaluate(inv_obj)
    logger.info(
        f"[Phase 7: DECIDE] Severity={inv_obj.severity} Risk={inv_obj.risk} "
        f"Confidence={inv_obj.confidence} Action={inv_obj.decision}"
    )

    # ── Phase 8: Report Generator (LLM Reasoning) ────────────────────────────
    # Generates human-readable Markdown. ONLY runs AFTER deterministic decision.
    # The LLM cannot change the severity, risk, or recommended action.
    generate_report(inv_obj)
    logger.info("[Phase 8: REPORT] Investigation narrative generated.")

    elapsed = time.time() - overall_start
    logger.info(f"[Complete] Investigation finished in {elapsed:.1f}s over {len(inv_obj.tool_outputs)} tool results.")

    return inv_obj
