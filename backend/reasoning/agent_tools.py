"""
agent_tools.py — Tool Orchestrator and Specialist Tools
========================================================

Every tool is independent, receives the InvestigationObject, 
and returns exactly the ToolResult schema.
The orchestrator executes the ApprovedPlan.
"""

import time
import re
import logging
from typing import List, Dict, Any, Callable
import concurrent.futures

from backend.schemas.investigation import ToolResult, InvestigationObject
from backend.reasoning.policy_engine import ApprovedPlan

logger = logging.getLogger(__name__)


def _hydrate_events(inv_obj: InvestigationObject) -> List[Any]:
    from backend.processing.event_extractor import SecurityEvent
    return [SecurityEvent(**e) for e in inv_obj.normalized_events]


# ── Specialist Tools ────────────────────────────────────────────────────────

def run_anomaly_score_tool(inv_obj: InvestigationObject) -> ToolResult:
    """Tool 1: LSTM Anomaly Scoring."""
    t0 = time.time()
    try:
        from backend.models.lstm_model import score_sequence
        
        events = _hydrate_events(inv_obj)
        # V12 FIX: Filter out NORMAL (code 0) padding events to prevent dilution.
        # Multi-line logs create many NORMAL fragments that drown out the attack signal.
        # The LSTM should only see the meaningful event sequence.
        full_sequence = [e.event_code for e in events]
        attack_sequence = [c for c in full_sequence if c != 0]
        
        # Score the attack-only sequence if we have attack events;
        # otherwise fall back to the full sequence (which will be all-normal → score 0).
        sequence = attack_sequence if attack_sequence else full_sequence
        score = score_sequence(sequence)

        return ToolResult(
            tool_name="Behavior Analyst",
            evidence={
                "anomaly_score": round(score, 4),
                "risk_level": "CRITICAL" if score >= 0.8 else "HIGH" if score >= 0.6 else "MEDIUM" if score >= 0.3 else "LOW",
                "sequence_length": len(full_sequence),
                "attack_event_count": len(attack_sequence),
            },
            confidence=score * 0.4,
            metadata={"tags": ["behavioral_anomaly"] if score >= 0.6 else []},
            execution_time=(time.time() - t0) * 1000,
            provenance="lstm_v1"
        )
    except Exception as e:
        return ToolResult(
            tool_name="Behavior Analyst", evidence={"error": str(e)}, confidence=0.0,
            execution_time=(time.time() - t0) * 1000, provenance="lstm_v1"
        )


def run_rag_lookup_tool(inv_obj: InvestigationObject) -> ToolResult:
    """Tool 2: MITRE ATT&CK RAG Retrieval."""
    t0 = time.time()
    try:
        from backend.rag.rag_engine import retrieve_context
        from backend.processing.event_extractor import get_mitre_query

        events = _hydrate_events(inv_obj)
        mitre_query = get_mitre_query(events)

        if not mitre_query:
            return ToolResult(
                tool_name="MITRE Knowledge", evidence={"reason": "No query"}, confidence=0.0,
                execution_time=(time.time() - t0) * 1000, provenance="rag_v1"
            )

        rag_context = retrieve_context(mitre_query, k=5)
        techniques = list(dict.fromkeys(re.findall(r"T\d{4}(?:\.\d{3})?", rag_context)))

        return ToolResult(
            tool_name="MITRE Knowledge",
            evidence={
                "techniques_found": techniques,
                "rag_context": rag_context[:1000],
            },
            confidence=min(len(techniques) / 5.0, 1.0) * 0.25,
            metadata={"tags": [f"technique_{t}" for t in techniques[:5]]},
            execution_time=(time.time() - t0) * 1000,
            provenance="chromadb"
        )
    except Exception as e:
        return ToolResult(
            tool_name="MITRE Knowledge", evidence={"error": str(e)}, confidence=0.0,
            execution_time=(time.time() - t0) * 1000, provenance="chromadb"
        )


def run_threat_intel_tool(inv_obj: InvestigationObject) -> ToolResult:
    """Tool 3: Threat Intelligence Enrichment."""
    t0 = time.time()
    try:
        from backend.processing.threat_intel import enrich_events
        events = _hydrate_events(inv_obj)
        ti_report = enrich_events(events)
        malicious = [i for i in ti_report.indicators if i.is_malicious]

        ti_score = ti_report.max_risk_score / 100.0

        return ToolResult(
            tool_name="Threat Context",
            evidence={
                "malicious_count": len(malicious),
                "max_risk_score": ti_report.max_risk_score,
                "summary": ti_report.summary_text(),
            },
            confidence=ti_score * 0.15,
            metadata={"tags": [f"ti_malicious"] if malicious else []},
            execution_time=(time.time() - t0) * 1000,
            provenance="ti_module"
        )
    except Exception as e:
        return ToolResult(
            tool_name="Threat Context", evidence={"error": str(e)}, confidence=0.0,
            execution_time=(time.time() - t0) * 1000, provenance="ti_module"
        )


def run_ioc_extractor_tool(inv_obj: InvestigationObject) -> ToolResult:
    """Tool 4: IOC Extraction."""
    t0 = time.time()
    try:
        from backend.processing.ioc_extractor import extract_iocs
        ioc_report = extract_iocs(inv_obj.raw_logs_quarantine)
        evidence = ioc_report.to_dict()
        
        # V9 FIX: Normalize the key name. ioc_extractor may emit 'suspicious_count'
        # or 'total_suspicious'. We unify under 'suspicious_count' so the
        # DecisionEngine can reliably read it.
        suspicious_count = (
            evidence.get("suspicious_count")
            or evidence.get("total_suspicious")
            or 0
        )
        evidence["suspicious_count"] = suspicious_count
        
        return ToolResult(
            tool_name="IOC Analyst",
            evidence=evidence,
            confidence=min(suspicious_count / 10.0, 1.0) * 0.05,
            metadata={"tags": ["suspicious_iocs"] if suspicious_count > 0 else []},
            execution_time=(time.time() - t0) * 1000,
            provenance="ioc_regex"
        )
    except Exception as e:
        return ToolResult(
            tool_name="IOC Analyst", evidence={"error": str(e)}, confidence=0.0,
            execution_time=(time.time() - t0) * 1000, provenance="ioc_regex"
        )


def run_pattern_match_tool(inv_obj: InvestigationObject) -> ToolResult:
    """Tool 5: Heuristic Pattern Detection."""
    t0 = time.time()
    try:
        from backend.processing.pattern_detector import detect_patterns
        events = _hydrate_events(inv_obj)
        pattern_name, pattern_score, matched, mitre = detect_patterns(events)

        return ToolResult(
            tool_name="Pattern Analyst",
            evidence={
                "pattern_name": pattern_name,
                "pattern_score": round(pattern_score, 2),
            },
            confidence=pattern_score * 0.1 if pattern_name else 0.0,
            metadata={"tags": [f"pattern_{pattern_name}"] if pattern_name else []},
            execution_time=(time.time() - t0) * 1000,
            provenance="heuristic_engine"
        )
    except Exception as e:
        return ToolResult(
            tool_name="Pattern Analyst", evidence={"error": str(e)}, confidence=0.0,
            execution_time=(time.time() - t0) * 1000, provenance="heuristic_engine"
        )


def run_attack_graph_tool(inv_obj: InvestigationObject) -> ToolResult:
    """Tool 6: Attack Graph Builder."""
    t0 = time.time()
    try:
        from backend.models.attack_graph import build_attack_graph, attack_graph_summary
        events = _hydrate_events(inv_obj)
        graph_dict = build_attack_graph(events)
        
        # V12 FIX: build_attack_graph returns a dict, not a NetworkX graph object.
        node_count = graph_dict.get("node_count", len(graph_dict.get("nodes", [])))
        edge_count = graph_dict.get("edge_count", len(graph_dict.get("edges", [])))
        kill_chain = graph_dict.get("kill_chain_stage", "Benign")
        stages = graph_dict.get("stages", [])
        attack_path = graph_dict.get("attack_path", [])
        
        return ToolResult(
            tool_name="Attack Graph Builder",
            evidence={
                "summary": attack_graph_summary(graph_dict),
                "node_count": node_count,
                "edge_count": edge_count,
                "kill_chain_stage": kill_chain,
                "stages": stages,
                "attack_path": attack_path,
            },
            confidence=0.05 if node_count > 1 else 0.0,
            metadata={"tags": ["attack_graph", f"kill_chain_{kill_chain}"]},
            execution_time=(time.time() - t0) * 1000,
            provenance="networkx"
        )
    except Exception as e:
        return ToolResult(
            tool_name="Attack Graph Builder", evidence={"error": str(e)}, confidence=0.0,
            execution_time=(time.time() - t0) * 1000, provenance="networkx"
        )


def run_cross_session_memory_tool(inv_obj: InvestigationObject) -> ToolResult:
    """Tool 7: Cross Session Memory."""
    t0 = time.time()
    try:
        from backend.reasoning.memory import get_memory_store
        
        entity_id = inv_obj.entity_info.get("primary_entity", "")
        memory = get_memory_store()
        all_sessions = memory.get_sessions(entity_id)
        suspicious_sessions = [s for s in all_sessions if any(et != "NORMAL" for et in s.event_types)]
            
        return ToolResult(
            tool_name="Cross Session Memory",
            evidence={
                "total_sessions": len(all_sessions),
                "suspicious_sessions": len(suspicious_sessions),
            },
            confidence=min(len(suspicious_sessions) / 4.0, 1.0) * 0.15,
            metadata={"tags": ["historical_sessions"] if len(suspicious_sessions) > 1 else []},
            execution_time=(time.time() - t0) * 1000,
            provenance="memory_store"
        )
    except Exception as e:
        return ToolResult(
            tool_name="Cross Session Memory", evidence={"error": str(e)}, confidence=0.0,
            execution_time=(time.time() - t0) * 1000, provenance="memory_store"
        )


# ── Tool Orchestrator ───────────────────────────────────────────────────

TOOL_REGISTRY: Dict[str, Callable] = {
    "Behavior Analyst": run_anomaly_score_tool,
    "Pattern Analyst": run_pattern_match_tool,
    "Threat Context": run_threat_intel_tool,
    "IOC Analyst": run_ioc_extractor_tool,
    "MITRE Knowledge": run_rag_lookup_tool,
    "Attack Graph Builder": run_attack_graph_tool,
    "Cross Session Memory": run_cross_session_memory_tool,
}


def execute_tools(
    approved_plan: ApprovedPlan,
    inv_obj: InvestigationObject,
) -> List[ToolResult]:
    """
    Execute tools from the ApprovedPlan, passing the InvestigationObject.
    
    V4 FIX: Replaced broken parallel group algorithm.
    - If execution_strategy is 'Parallel': all tools run concurrently in a ThreadPoolExecutor.
    - If execution_strategy is 'Sequential': tools run one at a time.
    """
    results: List[ToolResult] = []
    tools_to_run = [t for t in approved_plan.approved_tools if t.tool_name in TOOL_REGISTRY]

    if not tools_to_run:
        logger.info("[Orchestrator] No tools to execute.")
        return results

    def _run(tool_intent) -> ToolResult:
        tool_name = tool_intent.tool_name
        func = TOOL_REGISTRY[tool_name]
        logger.info(f"[Orchestrator] Executing: {tool_name}")
        try:
            result = func(inv_obj)
            result.reason_selected = tool_intent.reason_selected
            result.expected_evidence = tool_intent.expected_evidence
            logger.info(f"[Orchestrator] Completed: {tool_name} (confidence={result.confidence:.3f})")
            return result
        except Exception as e:
            logger.error(f"[Orchestrator] Tool '{tool_name}' crashed: {e}")
            return ToolResult(
                tool_name=tool_name,
                reason_selected=tool_intent.reason_selected,
                expected_evidence=tool_intent.expected_evidence,
                evidence={"error": f"Crash: {str(e)}"},
                confidence=0.0,
                execution_time=0.0,
                provenance="orchestrator"
            )

    strategy = approved_plan.original_plan.execution_strategy.lower()
    
    if strategy == "parallel" and len(tools_to_run) > 1:
        logger.info(f"[Orchestrator] Running {len(tools_to_run)} tools in PARALLEL.")
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(tools_to_run), 4)) as executor:
            future_map = {executor.submit(_run, t): t for t in tools_to_run}
            for future in concurrent.futures.as_completed(future_map):
                tool_intent = future_map[future]
                try:
                    results.append(future.result(timeout=None))  # No timeout for local models
                except Exception as e:
                    logger.error(f"[Orchestrator] Future for '{tool_intent.tool_name}' raised: {e}")
                    results.append(ToolResult(
                        tool_name=tool_intent.tool_name, 
                        reason_selected=tool_intent.reason_selected,
                        expected_evidence=tool_intent.expected_evidence,
                        evidence={"error": str(e)}, confidence=0.0,
                        execution_time=0.0, provenance="orchestrator"
                    ))
    else:
        logger.info(f"[Orchestrator] Running {len(tools_to_run)} tools SEQUENTIALLY.")
        for tool_intent in tools_to_run:
            results.append(_run(tool_intent))

    return results
