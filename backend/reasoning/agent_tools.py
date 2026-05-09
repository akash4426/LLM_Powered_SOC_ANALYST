"""
agent_tools.py
--------------
Modular tool registry for the Agentic AI reasoning engine.

Each tool is a self-contained function that:
  1. Accepts structured input
  2. Performs a specific analysis
  3. Returns a ToolResult with output, confidence contribution, and evidence tags

Tools:
  • anomaly_score   — LSTM anomaly scoring on event sequences
  • rag_lookup      — MITRE ATT&CK vector DB retrieval
  • threat_intel    — IP/hash/command threat intelligence enrichment
  • ioc_extractor   — Automated IOC extraction from raw text
  • pattern_match   — Heuristic pattern detection
  • playbook        — Response playbook recommendation

The agent layer invokes these tools in a deterministic pipeline,
then synthesizes results into a unified evidence ledger.
"""

import time
import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable

logger = logging.getLogger(__name__)


# ── Tool Result ──────────────────────────────────────────────────────────────

@dataclass
class ToolResult:
    """Structured output from a single tool invocation."""
    tool_name: str
    status: str = "success"            # "success" | "error" | "skipped"
    output: Dict[str, Any] = field(default_factory=dict)
    confidence_contribution: float = 0.0   # how much this tool adds to confidence
    evidence_tags: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    error_message: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "status": self.status,
            "output": self.output,
            "confidence_contribution": round(self.confidence_contribution, 4),
            "evidence_tags": self.evidence_tags,
            "execution_time_ms": round(self.execution_time_ms, 1),
            "error_message": self.error_message,
        }


@dataclass
class ReasoningStep:
    """A single step in the agent's reasoning trace."""
    step_number: int
    phase: str              # "observe", "think", "act", "synthesize", "decide", "explain"
    description: str
    tool_results: List[ToolResult] = field(default_factory=list)
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_number": self.step_number,
            "phase": self.phase,
            "description": self.description,
            "tool_results": [r.to_dict() for r in self.tool_results],
            "duration_ms": round(self.duration_ms, 1),
        }


# ── Tool Implementations ────────────────────────────────────────────────────

def run_anomaly_score_tool(sequence: List[int], anomaly_score: Optional[float] = None) -> ToolResult:
    """
    Tool 1: LSTM Anomaly Scoring.
    Uses pre-computed score if available, otherwise runs LSTM.
    """
    t0 = time.time()
    try:
        if anomaly_score is not None:
            score = anomaly_score
        else:
            from backend.models.lstm_model import score_sequence
            score = score_sequence(sequence)

        tags = []
        if score >= 0.8:
            tags = ["critical_anomaly", "behavioral_deviation"]
        elif score >= 0.6:
            tags = ["high_anomaly", "suspicious_behavior"]
        elif score >= 0.3:
            tags = ["moderate_anomaly"]
        else:
            tags = ["normal_behavior"]

        return ToolResult(
            tool_name="anomaly_score",
            output={
                "anomaly_score": round(score, 4),
                "risk_level": "CRITICAL" if score >= 0.8 else "HIGH" if score >= 0.6 else "MEDIUM" if score >= 0.3 else "LOW",
                "sequence_length": len(sequence),
            },
            confidence_contribution=score * 0.4,  # LSTM contributes 40% to confidence
            evidence_tags=tags,
            execution_time_ms=(time.time() - t0) * 1000,
        )
    except Exception as e:
        return ToolResult(
            tool_name="anomaly_score",
            status="error",
            error_message=str(e),
            execution_time_ms=(time.time() - t0) * 1000,
        )


def run_rag_lookup_tool(events: list, mitre_query: str = "") -> ToolResult:
    """
    Tool 2: MITRE ATT&CK RAG Retrieval.
    Queries the vector DB for relevant attack technique context.
    """
    t0 = time.time()
    try:
        from backend.rag.rag_engine import retrieve_context
        from backend.processing.event_extractor import get_mitre_query

        if not mitre_query and events:
            mitre_query = get_mitre_query(events)

        if not mitre_query:
            return ToolResult(
                tool_name="rag_lookup",
                status="skipped",
                output={"reason": "No MITRE query could be constructed"},
                execution_time_ms=(time.time() - t0) * 1000,
            )

        rag_context = retrieve_context(mitre_query, k=5)
        # Extract T-codes from context
        techniques = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", rag_context)))
        snippets = [s.strip() for s in rag_context.split("\n\n") if s.strip()]

        tags = []
        if techniques:
            tags.append(f"mitre_{len(techniques)}_techniques")
            tags.extend([f"technique_{t}" for t in techniques[:5]])

        return ToolResult(
            tool_name="rag_lookup",
            output={
                "mitre_query": mitre_query,
                "techniques_found": techniques,
                "technique_count": len(techniques),
                "snippets_retrieved": len(snippets),
                "rag_context": rag_context[:1000],  # Truncate for response
            },
            confidence_contribution=min(len(techniques) / 5.0, 1.0) * 0.25,
            evidence_tags=tags,
            execution_time_ms=(time.time() - t0) * 1000,
        )
    except Exception as e:
        return ToolResult(
            tool_name="rag_lookup",
            status="error",
            error_message=str(e),
            execution_time_ms=(time.time() - t0) * 1000,
        )


def run_threat_intel_tool(events: list) -> ToolResult:
    """
    Tool 3: Threat Intelligence Enrichment.
    Checks IPs, hashes, commands against the threat intel database.
    """
    t0 = time.time()
    try:
        from backend.processing.threat_intel import enrich_events

        ti_report = enrich_events(events)
        malicious = [i for i in ti_report.indicators if i.is_malicious]

        tags = []
        if malicious:
            tags.append(f"ti_{len(malicious)}_malicious")
            for ind in malicious[:3]:
                tags.append(f"ti_{ind.indicator_type}_{ind.threat_category or 'unknown'}")

        ti_score = ti_report.max_risk_score / 100.0

        return ToolResult(
            tool_name="threat_intel",
            output={
                "total_indicators": len(ti_report.indicators),
                "malicious_count": len(malicious),
                "max_risk_score": ti_report.max_risk_score,
                "overall_risk": ti_report.overall_risk,
                "malicious_indicators": [
                    {
                        "indicator": i.indicator,
                        "type": i.indicator_type,
                        "category": i.threat_category,
                        "description": i.threat_description,
                        "risk_score": i.risk_score,
                    }
                    for i in malicious[:10]
                ],
                "summary": ti_report.summary_text(),
            },
            confidence_contribution=ti_score * 0.15,
            evidence_tags=tags,
            execution_time_ms=(time.time() - t0) * 1000,
        )
    except Exception as e:
        return ToolResult(
            tool_name="threat_intel",
            status="error",
            error_message=str(e),
            execution_time_ms=(time.time() - t0) * 1000,
        )


def run_ioc_extractor_tool(raw_text: str) -> ToolResult:
    """
    Tool 4: IOC Extraction.
    Extracts IPs, domains, hashes, URLs, emails, file paths from raw logs.
    """
    t0 = time.time()
    try:
        from backend.processing.ioc_extractor import extract_iocs

        ioc_report = extract_iocs(raw_text)

        tags = []
        if ioc_report.suspicious_count > 0:
            tags.append(f"ioc_{ioc_report.suspicious_count}_suspicious")
        if ioc_report.ipv4:
            public_ips = [i for i in ioc_report.ipv4 if not i.is_private]
            if public_ips:
                tags.append(f"ioc_{len(public_ips)}_public_ips")
        if ioc_report.hashes:
            tags.append(f"ioc_{len(ioc_report.hashes)}_hashes")
        if ioc_report.domains:
            sus_domains = [d for d in ioc_report.domains if not d.is_benign]
            if sus_domains:
                tags.append(f"ioc_{len(sus_domains)}_suspicious_domains")
        if ioc_report.urls:
            tags.append(f"ioc_{len(ioc_report.urls)}_urls")

        return ToolResult(
            tool_name="ioc_extractor",
            output=ioc_report.to_dict(),
            confidence_contribution=min(ioc_report.suspicious_count / 10.0, 1.0) * 0.05,
            evidence_tags=tags,
            execution_time_ms=(time.time() - t0) * 1000,
        )
    except Exception as e:
        return ToolResult(
            tool_name="ioc_extractor",
            status="error",
            error_message=str(e),
            execution_time_ms=(time.time() - t0) * 1000,
        )


def run_pattern_match_tool(events: list) -> ToolResult:
    """
    Tool 5: Heuristic Pattern Detection.
    Runs enhanced pattern matching against event sequences.
    """
    t0 = time.time()
    try:
        from backend.processing.pattern_detector import detect_patterns

        pattern_name, pattern_score, matched_indicators, mitre_suggestions = detect_patterns(events)

        tags = []
        if pattern_name:
            tags.append(f"pattern_{pattern_name.lower()}")
            if pattern_score >= 0.8:
                tags.append("high_confidence_pattern")

        return ToolResult(
            tool_name="pattern_match",
            output={
                "pattern_name": pattern_name,
                "pattern_score": round(pattern_score, 2),
                "matched_indicators": matched_indicators,
                "mitre_suggestions": mitre_suggestions,
            },
            confidence_contribution=pattern_score * 0.1 if pattern_name else 0.0,
            evidence_tags=tags,
            execution_time_ms=(time.time() - t0) * 1000,
        )
    except Exception as e:
        return ToolResult(
            tool_name="pattern_match",
            status="error",
            error_message=str(e),
            execution_time_ms=(time.time() - t0) * 1000,
        )


def run_playbook_tool(
    incident_type: str,
    severity: str,
    campaign_pattern: Optional[str] = None,
    pattern_name: Optional[str] = None,
) -> ToolResult:
    """
    Tool 6: Response Playbook Recommendation.
    Selects appropriate response playbook based on incident classification.
    """
    t0 = time.time()
    try:
        from backend.reasoning.playbooks import get_playbook

        playbook = get_playbook(
            incident_type=incident_type,
            severity=severity,
            campaign_pattern=campaign_pattern,
            pattern_name=pattern_name,
        )

        return ToolResult(
            tool_name="playbook",
            output=playbook.to_dict(),
            evidence_tags=[f"playbook_{playbook.playbook_id.lower()}"],
            execution_time_ms=(time.time() - t0) * 1000,
        )
    except Exception as e:
        return ToolResult(
            tool_name="playbook",
            status="error",
            error_message=str(e),
            execution_time_ms=(time.time() - t0) * 1000,
        )
