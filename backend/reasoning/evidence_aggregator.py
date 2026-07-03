"""
evidence_aggregator.py — Evidence Aggregator
=============================================

Merges all structured evidence from specialist tools and tracks
the full investigation state across the agentic loop lifecycle.

Tracks:
  • completed tools
  • pending tools
  • evidence items
  • contradictions
  • confidence evolution (snapshots over time)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class EvidenceItem:
    """A single piece of evidence from a specialist tool."""
    source: str
    description: str
    contribution: float  # weighted confidence contribution
    tags: List[str] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "description": self.description,
            "contribution": round(self.contribution, 4),
            "tags": self.tags,
        }


@dataclass
class Contradiction:
    """An identified contradiction between evidence items."""
    description: str
    evidence_a: str
    evidence_b: str
    resolution: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "evidence_a": self.evidence_a,
            "evidence_b": self.evidence_b,
            "resolution": self.resolution,
        }


@dataclass
class AccumulatedEvidence:
    """Summary of all accumulated evidence for reflection/decision."""
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    completed_tools: List[str] = field(default_factory=list)
    pending_tools: List[str] = field(default_factory=list)
    contradictions: List[Dict[str, Any]] = field(default_factory=list)
    confidence_evolution: List[float] = field(default_factory=list)

    # Extracted numeric signals for the decision engine
    lstm_score: float = 0.0
    pattern_score: float = 0.0
    pattern_name: Optional[str] = None
    threat_intel_score: float = 0.0
    ioc_count: int = 0
    rag_matches: int = 0
    correlation_depth: int = 0
    mitre_mappings: List[str] = field(default_factory=list)
    compound_anomaly_score: float = 0.0
    compound_mitre_mappings: List[str] = field(default_factory=list)

    # Tool results for frontend display
    tool_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_planner_summary(self) -> Dict[str, Any]:
        """Return a summary safe for the LLM planner/reflector."""
        return {
            "completed_tools": self.completed_tools,
            "pending_tools": self.pending_tools,
            "evidence_count": len(self.evidence_items),
            "evidence_items": self.evidence_items,
            "contradictions": self.contradictions,
            "lstm_score": round(self.lstm_score, 4),
            "pattern_detected": self.pattern_name,
            "threat_intel_score": round(self.threat_intel_score, 4),
            "ioc_count": self.ioc_count,
            "mitre_techniques_found": len(self.mitre_mappings),
            "correlation_depth": self.correlation_depth,
        }


class EvidenceAggregator:
    """
    Stateful evidence aggregator that tracks the full investigation lifecycle.

    Specialist tools return ToolResult objects. The aggregator merges these
    into a unified evidence state, detects contradictions, and tracks
    confidence evolution over time.
    """

    def __init__(self):
        self._evidence_items: List[EvidenceItem] = []
        self._completed_tools: List[str] = []
        self._pending_tools: List[str] = []
        self._contradictions: List[Contradiction] = []
        self._confidence_evolution: List[float] = []
        self._tool_results: List[Dict[str, Any]] = []

        # Running numeric signals
        self.lstm_score: float = 0.0
        self.pattern_score: float = 0.0
        self.pattern_name: Optional[str] = None
        self.threat_intel_score: float = 0.0
        self.ioc_count: int = 0
        self.rag_matches: int = 0
        self.correlation_depth: int = 0
        self.mitre_mappings: List[str] = []
        self.compound_anomaly_score: float = 0.0
        self.compound_mitre_mappings: List[str] = []

    def set_pending_tools(self, tools: List[str]) -> None:
        """Set the list of pending tools from a validated plan."""
        self._pending_tools = list(tools)

    def add_tool_result(self, tool_result: Dict[str, Any]) -> None:
        """
        Process a ToolResult and extract evidence.

        Args:
            tool_result: Dict from ToolResult.to_dict()
        """
        tool_name = tool_result.get("tool_name", "unknown")
        status = tool_result.get("status", "error")
        output = tool_result.get("output", {})

        # Record the tool result
        self._tool_results.append(tool_result)

        # Move from pending to completed
        if tool_name in self._pending_tools:
            self._pending_tools.remove(tool_name)
        if tool_name not in self._completed_tools:
            self._completed_tools.append(tool_name)

        if status != "success":
            return

        # ── Extract evidence by tool type ─────────────────────────────────
        if tool_name == "Behavior Analyst":
            self._process_behavior_result(output)
        elif tool_name == "Pattern Analyst":
            self._process_pattern_result(output)
        elif tool_name == "Threat Context":
            self._process_threat_intel_result(output)
        elif tool_name == "IOC Analyst":
            self._process_ioc_result(output)
        elif tool_name == "MITRE Knowledge":
            self._process_rag_result(output)

        # Snapshot confidence after each tool
        self._snapshot_confidence()

    def _process_behavior_result(self, output: Dict[str, Any]) -> None:
        score = output.get("anomaly_score", 0.0)
        self.lstm_score = score
        self.compound_anomaly_score = max(self.compound_anomaly_score, score)

        self._evidence_items.append(EvidenceItem(
            source="Behavior Analyst",
            description=f"Behavioral deviation calculated at {score:.2f}",
            contribution=score * 0.35,
            tags=output.get("evidence_tags", []),
            data=output,
        ))

    def _process_pattern_result(self, output: Dict[str, Any]) -> None:
        self.pattern_name = output.get("pattern_name")
        self.pattern_score = output.get("pattern_score", 0.0)
        self.compound_anomaly_score = max(
            self.compound_anomaly_score, self.pattern_score
        )

        if self.pattern_name:
            self._evidence_items.append(EvidenceItem(
                source="Pattern Analyst",
                description=f"Detected campaign pattern: {self.pattern_name}",
                contribution=self.pattern_score * 0.10,
                data=output,
            ))

    def _process_threat_intel_result(self, output: Dict[str, Any]) -> None:
        malicious = output.get("malicious_count", 0)
        self.threat_intel_score = output.get("max_risk_score", 0) / 100.0

        if malicious > 0:
            self._evidence_items.append(EvidenceItem(
                source="Threat Context",
                description=f"Identified {malicious} known malicious indicators",
                contribution=self.threat_intel_score * 0.10,
                data=output,
            ))

    def _process_ioc_result(self, output: Dict[str, Any]) -> None:
        self.ioc_count = output.get("suspicious_count", 0)

        if self.ioc_count > 0:
            self._evidence_items.append(EvidenceItem(
                source="IOC Analyst",
                description=f"Extracted {self.ioc_count} suspicious IOCs from raw logs",
                contribution=min(self.ioc_count / 10.0, 1.0) * 0.10,
                data=output,
            ))

    def _process_rag_result(self, output: Dict[str, Any]) -> None:
        techniques = output.get("techniques_found", [])
        self.mitre_mappings = techniques
        self.rag_matches = len(techniques)
        self.compound_mitre_mappings = list(
            dict.fromkeys(self.compound_mitre_mappings + techniques)
        )

        if self.rag_matches > 0:
            self._evidence_items.append(EvidenceItem(
                source="MITRE Knowledge",
                description=f"Mapped {self.rag_matches} events to MITRE ATT&CK DB",
                contribution=min(self.rag_matches / 5.0, 1.0) * 0.20,
                data=output,
            ))

    def add_memory_evidence(
        self, correlation_depth: int, hypothesis: Optional[str] = None
    ) -> None:
        """Add cross-session memory correlation evidence."""
        self.correlation_depth = correlation_depth

        if correlation_depth > 1:
            desc = (
                f"Historical memory linked {correlation_depth} sessions to a unified campaign"
                if hypothesis
                else f"Entity has history of {correlation_depth} suspicious sessions"
            )
            self._evidence_items.append(EvidenceItem(
                source="Investigation Memory",
                description=desc,
                contribution=0.15 if hypothesis else 0.10,
            ))

        self._snapshot_confidence()

    def _snapshot_confidence(self) -> None:
        """Take a confidence snapshot for evolution tracking."""
        c = (
            0.35 * min(self.compound_anomaly_score, 1.0)
            + 0.20 * min(self.rag_matches / 5.0, 1.0)
            + 0.15 * min(self.correlation_depth / 4.0, 1.0)
            + 0.10 * min(self.threat_intel_score, 1.0)
            + 0.10 * min(self.pattern_score, 1.0)
            + 0.10 * min(self.ioc_count / 10.0, 1.0)
        )
        self._confidence_evolution.append(round(min(c, 1.0), 4))

    def detect_contradictions(self) -> List[Contradiction]:
        """Identify conflicting evidence signals."""
        contradictions: List[Contradiction] = []

        # Low anomaly but high threat intel
        if self.lstm_score < 0.3 and self.threat_intel_score > 0.7:
            contradictions.append(Contradiction(
                description="Low behavioral anomaly but high threat intelligence score",
                evidence_a=f"LSTM anomaly score: {self.lstm_score:.2f}",
                evidence_b=f"Threat intel score: {self.threat_intel_score:.2f}",
                resolution="Known malicious indicators may not manifest as behavioral anomalies",
            ))

        # High anomaly but no MITRE matches
        if self.lstm_score > 0.7 and self.rag_matches == 0:
            contradictions.append(Contradiction(
                description="High behavioral anomaly but no MITRE technique matches",
                evidence_a=f"LSTM anomaly score: {self.lstm_score:.2f}",
                evidence_b="No MITRE ATT&CK techniques matched",
                resolution="May indicate novel attack pattern not catalogued in MITRE",
            ))

        # Pattern detected but low anomaly
        if self.pattern_name and self.lstm_score < 0.2:
            contradictions.append(Contradiction(
                description="Attack pattern detected but very low anomaly score",
                evidence_a=f"Pattern: {self.pattern_name}",
                evidence_b=f"LSTM anomaly: {self.lstm_score:.2f}",
                resolution="Pattern may be a false positive or low-impact variant",
            ))

        self._contradictions = contradictions
        return contradictions

    def get_accumulated_evidence(self) -> AccumulatedEvidence:
        """Return full accumulated evidence summary."""
        self.detect_contradictions()

        return AccumulatedEvidence(
            evidence_items=[e.to_dict() for e in self._evidence_items],
            completed_tools=list(self._completed_tools),
            pending_tools=list(self._pending_tools),
            contradictions=[c.to_dict() for c in self._contradictions],
            confidence_evolution=list(self._confidence_evolution),
            lstm_score=self.lstm_score,
            pattern_score=self.pattern_score,
            pattern_name=self.pattern_name,
            threat_intel_score=self.threat_intel_score,
            ioc_count=self.ioc_count,
            rag_matches=self.rag_matches,
            correlation_depth=self.correlation_depth,
            mitre_mappings=list(self.mitre_mappings),
            compound_anomaly_score=self.compound_anomaly_score,
            compound_mitre_mappings=list(self.compound_mitre_mappings),
            tool_results=list(self._tool_results),
        )
