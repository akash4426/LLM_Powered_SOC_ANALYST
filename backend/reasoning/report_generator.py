"""
report_generator.py — Incident Report Generator
===============================================

Generates a human-readable incident response report based on the
deterministic InvestigationObject state.
"""

import logging
import json
import time

from backend.schemas.investigation import InvestigationObject

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are the SOC REPORT GENERATOR.

YOUR ROLE:
- Generate a Markdown incident report based ONLY on the provided InvestigationObject.
- The severity, risk, confidence, and recommended action have ALREADY been decided deterministically. Do NOT change them.
- Your job is to translate the technical evidence into a clear, executive summary and technical narrative.

REQUIRED SECTIONS:
1. **Executive Summary**: High-level overview of what happened and the final decision.
2. **Investigation Timeline**: Chronological narrative of events based on the evidence timeline.
3. **MITRE ATT&CK Mapping**: Summary of techniques found.
4. **Action Plan**: Detailed steps for the recommended action.

CRITICAL GUARDRAIL:
Ensure the generated report never invents evidence. Every conclusion MUST be backed by the collected evidence provided in the InvestigationObject. Do not hallucinate IPs, domains, files, or attack techniques that are not explicitly present in the data.

Output ONLY the markdown text.
"""

def generate_report(inv_obj: InvestigationObject) -> str:
    """Generate markdown report and attach it to the InvestigationObject.
    
    ARCHITECTURAL RULE:
    - Only runs AFTER DecisionEngine.evaluate() has been called.
    - The LLM receives the finalized severity, risk, and decision — it CANNOT change them.
    - Uses LLM ONLY for narrative explanation. All security decisions are already made.
    """
    from backend.reasoning.llm_gateway import ReasoningProvider

    # Build a safe dict that includes the final deterministic decisions
    safe_dict = inv_obj.to_planner_dict()
    safe_dict["severity"] = inv_obj.severity
    safe_dict["risk"] = inv_obj.risk
    safe_dict["confidence"] = inv_obj.confidence
    safe_dict["decision"] = inv_obj.decision

    prompt = f"INVESTIGATION OBJECT:\n{json.dumps(safe_dict, indent=2)}\n\nGenerate the markdown report."
    full_prompt = _SYSTEM_PROMPT + "\n\n" + prompt

    try:
        # V6 FIX: Call generate_reasoning directly. The Ollama client already has a 600s
        # timeout configured at the socket level, making the ThreadPoolExecutor redundant.
        report = ReasoningProvider().generate_text(full_prompt)
        inv_obj.report = report.strip()
        return inv_obj.report
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        inv_obj.report = (
            f"## Incident Report\n\n"
            f"**Severity**: {inv_obj.severity}\n"
            f"**Risk Score**: {inv_obj.risk}\n"
            f"**Confidence**: {inv_obj.confidence}\n"
            f"**Decision**: {inv_obj.decision}\n\n"
            f"*Report narrative could not be generated: {e}*"
        )
        return inv_obj.report
