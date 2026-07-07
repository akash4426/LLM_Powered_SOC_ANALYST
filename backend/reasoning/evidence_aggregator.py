"""
evidence_aggregator.py — Evidence Aggregator
=============================================

Merges ToolResults directly into the InvestigationObject.
Maintains the evidence timeline, provenance, and detects contradictions.
Does NOT create a separate state object.
"""

import time
from typing import List, Dict, Any

from backend.schemas.investigation import InvestigationObject, ToolResult


class EvidenceAggregator:
    """
    Enriches the InvestigationObject in place with new ToolResults.
    """
    
    @staticmethod
    def aggregate(inv_obj: InvestigationObject, new_results: List[ToolResult]) -> None:
        """
        Merge new tool results into the InvestigationObject.
        Updates tool_outputs, evidence_timeline, and detects contradictions.
        """
        if not new_results:
            return

        inv_obj.tool_outputs.extend(new_results)
        
        # 1. Merge evidence into timeline
        for result in new_results:
            summary = EvidenceAggregator._format_summary(result)
            timeline_entry = {
                "timestamp": time.time(),
                "source": result.tool_name,
                "confidence_contribution": result.confidence,
                "evidence_summary": summary,
                "provenance": result.provenance,
                "metadata": result.metadata
            }
            inv_obj.evidence_timeline.append(timeline_entry)
            
        # 2. Detect contradictions
        contradictions = EvidenceAggregator._detect_contradictions(inv_obj)
        if contradictions:
            for c in contradictions:
                inv_obj.evidence_timeline.append({
                    "timestamp": time.time(),
                    "source": "EvidenceAggregator",
                    "type": "Contradiction",
                    "evidence_summary": c,
                })
                
        # 3. Compute evidence completeness
        inv_obj.evidence_completeness = EvidenceAggregator._compute_completeness(inv_obj)
                
    @staticmethod
    def _format_summary(result: ToolResult) -> str:
        """Format the evidence dictionary into a human-readable summary string."""
        if not isinstance(result.evidence, dict):
            return str(result.evidence)
            
        if "error" in result.evidence:
            return f"Error: {result.evidence['error']}"
            
        if result.tool_name == "Behavior Analyst":
            score = result.evidence.get("anomaly_score", 0)
            return f"Behavioral Anomaly Score: {score} ({result.evidence.get('risk_level', 'UNKNOWN')}). Analyzed {result.evidence.get('sequence_length', 0)} events."
            
        if result.tool_name == "Pattern Analyst":
            pattern = result.evidence.get("pattern_name", "No pattern detected")
            return f"Detected Pattern: {pattern}" if pattern else "No known campaign patterns detected."
            
        if result.tool_name == "Threat Context":
            return result.evidence.get("summary", "No threat intel summary available.")
            
        if result.tool_name == "IOC Analyst":
            suspicious = result.evidence.get("suspicious_count", 0)
            total = result.evidence.get("total_count", 0)
            return f"Extracted {suspicious} suspicious indicators out of {total} total."
            
        if result.tool_name == "MITRE Knowledge":
            techs = result.evidence.get("techniques_found", [])
            return f"Mapped to {len(techs)} MITRE ATT&CK techniques: {', '.join(techs)}"
            
        if result.tool_name == "Attack Graph Builder":
            return result.evidence.get("summary", "Attack graph generated.")
            
        return str(result.evidence)

    @staticmethod
    def _compute_completeness(inv_obj: InvestigationObject) -> float:
        """Calculate the percentage of total available tools utilized."""
        # Total available specialist tools registered in agent_tools.py TOOL_REGISTRY
        TOTAL_AVAILABLE_TOOLS = 7
        
        unique_tools_run = len(set(r.tool_name for r in inv_obj.tool_outputs))
        return round(min(unique_tools_run / TOTAL_AVAILABLE_TOOLS, 1.0), 2)
    @staticmethod
    def _detect_contradictions(inv_obj: InvestigationObject) -> List[str]:
        """Identify conflicting evidence signals among all tool outputs."""
        contradictions = []
        
        # Extract basic signals
        lstm_score = 0.0
        ti_score = 0.0
        pattern_found = False
        rag_matches = 0
        ioc_suspicious = 0
        ti_ran = False
        
        for r in inv_obj.tool_outputs:
            if r.tool_name == "Behavior Analyst" and isinstance(r.evidence, dict):
                lstm_score = r.evidence.get("anomaly_score", 0.0)
            elif r.tool_name == "Threat Context" and isinstance(r.evidence, dict):
                ti_ran = True
                ti_score = r.evidence.get("max_risk_score", 0.0) / 100.0
            elif r.tool_name == "Pattern Analyst" and isinstance(r.evidence, dict):
                pattern_found = bool(r.evidence.get("pattern_name"))
            elif r.tool_name == "MITRE Knowledge" and isinstance(r.evidence, dict):
                rag_matches = len(r.evidence.get("techniques_found", []))
            elif r.tool_name == "IOC Analyst" and isinstance(r.evidence, dict):
                ioc_suspicious = r.evidence.get("suspicious_count", 0)
                
        # 1. Behavior LOW + Pattern HIGH
        if lstm_score < 0.3 and pattern_found:
            contradictions.append(f"Behavior LOW ({lstm_score:.2f}) but Pattern HIGH (Campaign matched)")
            
        # 2. Behavior LOW + IOC HIGH
        if lstm_score < 0.3 and ioc_suspicious > 0:
            contradictions.append(f"Behavior LOW ({lstm_score:.2f}) but IOC HIGH ({ioc_suspicious} suspicious IOCs)")

        # 3. MITRE NONE + Threat Intel HIGH
        if rag_matches == 0 and ti_score > 0.7:
            contradictions.append(f"MITRE NONE (0 techniques) but Threat Intel HIGH ({ti_score:.2f} risk)")

        # 4. Pattern HIGH + Threat Intel NONE
        if pattern_found and ti_ran and ti_score == 0.0:
            contradictions.append(f"Pattern HIGH (Campaign matched) but Threat Intel NONE (0.0 risk)")
            
        return contradictions
