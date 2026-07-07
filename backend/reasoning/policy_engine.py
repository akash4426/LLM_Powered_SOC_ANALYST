"""
policy_engine.py — Policy & Guardrail Engine
=============================================

Every LLM-requested tool action passes through policy validation before
execution. The policy engine enforces:
  • Allowed tools
  • Execution budget
  • Maximum replan iterations
  • Duplicate tool prevention (V3 FIX: across iterations, not just within a plan)

Outputs an ApprovedPlan.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from backend.schemas.investigation import InvestigationPlan, ToolIntent

logger = logging.getLogger(__name__)


@dataclass
class PolicyConfig:
    """Configurable policy rules."""
    allowed_tools: Set[str] = field(default_factory=lambda: {
        "Behavior Analyst",
        "Pattern Analyst",
        "Threat Context",
        "IOC Analyst",
        "MITRE Knowledge",
        "Attack Graph Builder",
        "Cross Session Memory",
    })
    max_replan_iterations: int = 3
    max_total_tool_invocations: int = 15
    max_tools_per_plan: int = 7


@dataclass
class ApprovedPlan:
    """A plan that has passed policy validation."""
    original_plan: InvestigationPlan
    approved_tools: List[ToolIntent] = field(default_factory=list)
    rejected_tools: List[Dict[str, str]] = field(default_factory=list)
    is_valid: bool = True


class PolicyEngine:
    """Validates investigation plans against security policies."""

    def __init__(self, config: Optional[PolicyConfig] = None):
        self.config = config or PolicyConfig()
        self._total_tool_invocations = 0
        self._current_iteration = 0
        # V3 FIX: Track all tools executed across the entire investigation lifecycle.
        self._executed_tools: Set[str] = set()

    def reset(self) -> None:
        self._total_tool_invocations = 0
        self._current_iteration = 0
        self._executed_tools = set()

    def validate_plan(
        self,
        plan: InvestigationPlan,
        already_run: Optional[List[str]] = None,
    ) -> ApprovedPlan:
        """
        Validate an investigation plan from the LLM planner.

        Args:
            plan: The InvestigationPlan from the Planner LLM.
            already_run: Optional list of tool names already executed (used to
                         sync the internal executed set on first call).
        Returns:
            ApprovedPlan containing only the permitted tools.
        """
        # Sync executed set if caller provides external state
        if already_run:
            self._executed_tools.update(already_run)

        approved = ApprovedPlan(original_plan=plan)

        for tool_intent in plan.required_tools:
            tool_str = str(tool_intent.tool_name).strip()

            # Guard: Only allow tools from the allowlist
            if tool_str not in self.config.allowed_tools:
                reason = f"Tool '{tool_str}' is not in the allowed tools list"
                approved.rejected_tools.append({"tool": tool_str, "reason": reason})
                logger.warning(f"[Policy] Rejected: {reason}")
                continue

            # V3 FIX: Reject tools that have already been executed in a prior iteration.
            if tool_str in self._executed_tools:
                reason = f"Tool '{tool_str}' was already executed in a prior iteration. Skipping."
                approved.rejected_tools.append({"tool": tool_str, "reason": reason})
                logger.info(f"[Policy] Deduplication: {reason}")
                continue

            # Guard: Max tools per single plan
            if len(approved.approved_tools) >= self.config.max_tools_per_plan:
                reason = f"Tool '{tool_str}' exceeds max tools per plan ({self.config.max_tools_per_plan})"
                approved.rejected_tools.append({"tool": tool_str, "reason": reason})
                logger.warning(f"[Policy] Rejected: {reason}")
                continue

            # Guard: Global invocation budget
            projected = self._total_tool_invocations + len(approved.approved_tools) + 1
            if projected > self.config.max_total_tool_invocations:
                reason = f"Tool '{tool_str}' would exceed total invocation budget ({self.config.max_total_tool_invocations})"
                approved.rejected_tools.append({"tool": tool_str, "reason": reason})
                logger.warning(f"[Policy] Rejected: {reason}")
                continue

            approved.approved_tools.append(tool_intent)

        if not approved.approved_tools:
            approved.is_valid = False
            logger.info("[Policy] No new tools approved. Plan is complete.")
        else:
            # User explicitly prohibited default execution without Planner Intent.
            # "No default execution." - Removing force-injection of core components.
            pass

        return approved

    def record_tool_invocations(self, tool_names: List[str]) -> None:
        """Record which tools were executed so they are not re-run in future iterations."""
        self._total_tool_invocations += len(tool_names)
        # V3 FIX: Track tool names, not just counts.
        self._executed_tools.update(tool_names)

    def check_iteration_limit(self) -> bool:
        return self._current_iteration < self.config.max_replan_iterations

    def increment_iteration(self) -> int:
        self._current_iteration += 1
        return self._current_iteration
