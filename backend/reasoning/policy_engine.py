"""
policy_engine.py — Policy & Guardrail Engine
=============================================

Every LLM-requested tool action passes through policy validation before
execution.  The policy engine enforces:

  • Allowed tools
  • Allowed parameters
  • Maximum replan iterations
  • Investigation depth limits
  • Security policies

Rejects any unauthorized planner outputs with detailed rejection reasons.
All rejections are logged.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class PolicyConfig:
    """Configurable policy rules — not hardcoded for extensibility."""

    # Allowed specialist tool names
    allowed_tools: Set[str] = field(default_factory=lambda: {
        "Behavior Analyst",
        "Pattern Analyst",
        "Threat Context",
        "IOC Analyst",
        "MITRE Knowledge",
    })

    # Maximum replan iterations to prevent infinite loops
    max_replan_iterations: int = 3

    # Maximum total tool invocations per investigation
    max_total_tool_invocations: int = 15

    # Maximum tools per single plan
    max_tools_per_plan: int = 5

    # Tool invocation timeout in seconds
    tool_timeout_seconds: float = 300.0

    # Investigation overall timeout in seconds
    investigation_timeout_seconds: float = 900.0


# ═══════════════════════════════════════════════════════════════════════════════
# VALIDATED PLAN
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ValidatedPlan:
    """A plan that has passed policy validation."""
    approved_tools: List[str] = field(default_factory=list)
    rejected_tools: List[Dict[str, str]] = field(default_factory=list)
    hypothesis: str = ""
    strategy: str = ""
    evidence_requirements: List[str] = field(default_factory=list)
    investigation_goals: List[str] = field(default_factory=list)
    is_valid: bool = True
    rejection_reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approved_tools": self.approved_tools,
            "rejected_tools": self.rejected_tools,
            "hypothesis": self.hypothesis,
            "strategy": self.strategy,
            "evidence_requirements": self.evidence_requirements,
            "investigation_goals": self.investigation_goals,
            "is_valid": self.is_valid,
            "rejection_reasons": self.rejection_reasons,
        }


# ═══════════════════════════════════════════════════════════════════════════════
# POLICY ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class PolicyEngine:
    """
    Validates investigation plans against security policies.
    
    The planner cannot directly execute tools — every requested tool
    passes through this validator first.
    """

    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()
        self._total_tool_invocations = 0
        self._current_iteration = 0

    def reset(self) -> None:
        """Reset counters for a new investigation."""
        self._total_tool_invocations = 0
        self._current_iteration = 0

    def validate_plan(self, plan: Dict[str, Any]) -> ValidatedPlan:
        """
        Validate an investigation plan from the LLM planner.

        Args:
            plan: Raw plan dict from the planner with keys:
                  hypothesis, strategy, tool_sequence, evidence_requirements,
                  investigation_goals

        Returns:
            ValidatedPlan with approved/rejected tools and reasons.
        """
        validated = ValidatedPlan(
            hypothesis=str(plan.get("hypothesis", "")),
            strategy=str(plan.get("strategy", "")),
            evidence_requirements=plan.get("evidence_requirements", []),
            investigation_goals=plan.get("investigation_goals", []),
        )

        requested_tools = plan.get("tool_sequence", [])

        # ── Validate each requested tool ──────────────────────────────────
        for tool_name in requested_tools:
            tool_str = str(tool_name).strip()

            # Check if tool is allowed
            if tool_str not in self.config.allowed_tools:
                reason = f"Tool '{tool_str}' is not in the allowed tools list"
                validated.rejected_tools.append({
                    "tool": tool_str,
                    "reason": reason,
                })
                logger.warning(f"Policy rejection: {reason}")
                continue

            # Check per-plan tool limit
            if len(validated.approved_tools) >= self.config.max_tools_per_plan:
                reason = (
                    f"Tool '{tool_str}' exceeds max tools per plan "
                    f"({self.config.max_tools_per_plan})"
                )
                validated.rejected_tools.append({
                    "tool": tool_str,
                    "reason": reason,
                })
                logger.warning(f"Policy rejection: {reason}")
                continue

            # Check total invocation limit
            projected = self._total_tool_invocations + len(validated.approved_tools) + 1
            if projected > self.config.max_total_tool_invocations:
                reason = (
                    f"Tool '{tool_str}' would exceed total invocation limit "
                    f"({self.config.max_total_tool_invocations})"
                )
                validated.rejected_tools.append({
                    "tool": tool_str,
                    "reason": reason,
                })
                logger.warning(f"Policy rejection: {reason}")
                continue

            # Tool approved
            validated.approved_tools.append(tool_str)

        # ── Log validation result ─────────────────────────────────────────
        if validated.rejected_tools:
            logger.info(
                f"Plan validated: {len(validated.approved_tools)} approved, "
                f"{len(validated.rejected_tools)} rejected"
            )
        else:
            logger.info(
                f"Plan validated: all {len(validated.approved_tools)} tools approved"
            )

        return validated

    def check_iteration_limit(self) -> bool:
        """Check if we can do another replan iteration."""
        return self._current_iteration < self.config.max_replan_iterations

    def increment_iteration(self) -> int:
        """Increment and return the current iteration count."""
        self._current_iteration += 1
        return self._current_iteration

    def record_tool_invocations(self, count: int) -> None:
        """Record completed tool invocations."""
        self._total_tool_invocations += count

    def get_limits_status(self) -> Dict[str, Any]:
        """Return current limits status for debugging/display."""
        return {
            "current_iteration": self._current_iteration,
            "max_iterations": self.config.max_replan_iterations,
            "total_tool_invocations": self._total_tool_invocations,
            "max_tool_invocations": self.config.max_total_tool_invocations,
            "iterations_remaining": max(
                0, self.config.max_replan_iterations - self._current_iteration
            ),
        }
