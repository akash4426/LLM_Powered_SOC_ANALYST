"""
reflection.py — Reflection Engine
===================================

The Reflection engine reasons over the InvestigationObject to determine
if enough evidence has been collected or if replanning is required.

ARCHITECTURAL RULE:
- The Reflection Engine is the ONLY component that decides whether to replan.
- It must NOT have hardcoded bypass logic based on tool count.
- Loop termination is the sole responsibility of the Policy Engine (via max_replan_iterations).
"""

import json
import logging
import time
from typing import Dict, Any, Optional

from backend.schemas.investigation import InvestigationObject

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are the REFLECTION ENGINE.

TASK:
Determine if the investigation needs more evidence.
Analyze the current state, missing critical tools, and any contradictions.

OUTPUT EXACTLY ONE JSON OBJECT:
{
  "needs_more_evidence": <true or false>,
  "missing_evidence": ["<list of what is missing>"],
  "expected_confidence_gain": <float 0.0-1.0>,
  "contradictions_resolved": <boolean>,
  "reasoning": "<detailed explanation of your decision>",
  "additional_tools_needed": ["<tools you want to run>"]
}"""


def reflect_on_evidence(
    inv_obj: InvestigationObject,
    max_retries: int = 2,
) -> bool:
    """
    Evaluate whether replanning is needed.
    Returns True if replanning is needed, False if we should proceed to decision.
    """
    from backend.reasoning.llm_gateway import ReasoningProvider
    from backend.utils.json_parser import repair_and_parse_json

    tool_names_run = [t.tool_name for t in inv_obj.tool_outputs]
    tools_with_errors = [
        t.tool_name for t in inv_obj.tool_outputs
        if isinstance(t.evidence, dict) and "error" in t.evidence
    ]

    contradictions_count = sum(
        1 for e in inv_obj.evidence_timeline
        if e.get("type") == "Contradiction"
    )

    # Enforce deterministic bounds. Reflection NEVER returns Sufficient if these fail.
    from backend.reasoning.decision_engine import DecisionEngine
    DecisionEngine.evaluate(inv_obj)  # Ensure intermediate confidence is calculated

    unmet_conditions = []
    if inv_obj.evidence_completeness < 0.5:
        unmet_conditions.append(f"Evidence completeness ({inv_obj.evidence_completeness}) < 0.5")
    if inv_obj.confidence < 0.5:
        unmet_conditions.append(f"Confidence ({inv_obj.confidence:.2f}) < 0.5")
    if contradictions_count > 0:
        unmet_conditions.append(f"Unresolved contradictions ({contradictions_count})")

    if unmet_conditions:
        logger.info(f"[Reflection] Deterministic bounds unmet: {unmet_conditions}. MUST REPLAN.")
        
        inv_obj.last_reflection_data = {
            "needs_more_evidence": True,
            "missing_evidence": unmet_conditions,
            "expected_confidence_gain": 0.5,
            "contradictions_resolved": False,
            "reasoning": "Deterministic fast-path enforced a replan. Conditions unmet: " + ", ".join(unmet_conditions),
            "additional_tools_needed": []
        }
        return True

    reflection_context = {
        "investigation_id": inv_obj.investigation_id,
        "hypothesis": inv_obj.planner_hypothesis,
        "tools_run": tool_names_run,
        "tools_with_errors": tools_with_errors,
        "evidence_entries": len(inv_obj.evidence_timeline),
        "evidence_completeness": inv_obj.evidence_completeness,
        "contradictions_detected": contradictions_count,
        "confidence": inv_obj.confidence
    }

    prompt = (
        f"{_SYSTEM_PROMPT}\n\n"
        f"CURRENT INVESTIGATION STATE:\n"
        f"{json.dumps(reflection_context, indent=2)}\n"
    )

    for attempt in range(max_retries):
        try:
            raw_output = ReasoningProvider().generate_json(prompt)
            parsed = repair_and_parse_json(raw_output)

            if parsed:
                needs_replanning = bool(parsed.get("needs_more_evidence", parsed.get("needs_replanning", False)))
                
                # Double-check: Even if LLM says False, if bounds were unmet (though handled above), it would be caught.
                inv_obj.last_reflection_data = {
                    "needs_more_evidence": needs_replanning,
                    "missing_evidence": parsed.get("missing_evidence", []),
                    "expected_confidence_gain": float(parsed.get("expected_confidence_gain", 0.0)),
                    "contradictions_resolved": bool(parsed.get("contradictions_resolved", True)),
                    "reasoning": str(parsed.get("reasoning", "No reasoning provided.")),
                    "additional_tools_needed": parsed.get("additional_tools_needed", [])
                }
                
                logger.info(f"[Reflection] Needs Replan: {needs_replanning}. Reason: {inv_obj.last_reflection_data['reasoning']}")
                return needs_replanning
            else:
                logger.warning(f"[Reflection] Failed to parse JSON on attempt {attempt+1}.")

        except Exception as e:
            logger.error(f"[Reflection] Error: {e}")
            
        if attempt < max_retries - 1:
            time.sleep(2)

    logger.warning("[Reflection] All attempts failed. Defaulting to REPLAN to avoid premature termination.")
    
    # Fallback MUST be conservative (True)
    inv_obj.last_reflection_data = {
        "needs_more_evidence": True,
        "missing_evidence": ["Unknown due to LLM failure"],
        "expected_confidence_gain": 0.5,
        "contradictions_resolved": False,
        "reasoning": "Fallback: JSON parsing failed multiple times. Forcing a replan.",
        "additional_tools_needed": []
    }
    
    return True
