"""
main.py
-------
FastAPI application — Autonomous Agentic SOC Investigation Platform.

Architecture (8-Phase Agentic Loop):
  POST /investigate
  1. PERCEIVE  — Parse & normalize logs into InvestigationObject (deterministic)
  2. PLAN      — Planner LLM generates InvestigationPlan (hypothesis + tools)
  3. VALIDATE  — Policy Engine enforces tool allowlists & budget guardrails
  4. EXECUTE   — Tool Orchestrator dispatches approved specialist tools
  5. AGGREGATE — Evidence Aggregator merges ToolResults into InvestigationObject
  6. REFLECT   — Reflection LLM evaluates evidence sufficiency (may loop to Phase 2)
  7. DECIDE    — Decision Engine deterministically computes Severity/Risk/Confidence
  8. REPORT    — Report Generator LLM writes executive summary & timeline
"""

# Load environment variables from .env FIRST before any other imports
from dotenv import load_dotenv
load_dotenv(override=True)

import os
import concurrent.futures
from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional as _Optional

from backend.schemas import LogRequest, InvestigateResponse, AgentLogRequest, AgentAnalysisResponse
from backend.ingestion.log_normalizer import normalize_logs
from backend.processing.event_extractor import extract_events, events_to_sequence, get_mitre_query
from backend.processing.session_builder import build_sessions, sessions_summary
from backend.processing.threat_intel import enrich_events
from backend.models.attack_graph import build_attack_graph, attack_graph_summary
from backend.models.lstm_model import score_sequence, score_network_flow, is_network_flow_model_loaded
from backend.rag.rag_engine import retrieve_context
from backend.reasoning.agent_layer import run_investigation_loop
from backend.evaluation.evaluator import run_evaluation as _run_evaluation

# Authentication imports
from backend.api.auth import (
    get_current_user,
    AuthService,
    TokenData,
    TokenResponse,
    JWTConfig,
)


app = FastAPI(
    title="LLM-Powered SOC Analyst",
    description=(
        "AI-assisted Security Operations Center that automatically analyzes "
        "security logs, detects suspicious behaviour via LSTM anomaly detection, "
        "retrieves MITRE ATT&CK knowledge, and generates incident investigation reports."
    ),
    version="5.0.0",
)

# Explicit origins required when allow_credentials=True
# (browsers reject wildcard "*" combined with credentials)
CORS_ORIGINS = [
    "https://llm-powered-soc-analyst.vercel.app",  # Vercel production
    "http://localhost:5173",                         # Vite dev server
    "http://localhost:3000",                         # alternate dev port
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Private Network Access header (kept for any local file:// fallback) ────────
@app.middleware("http")
async def add_private_network_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    import os
    return {
        "status": "SOC Analyst API running",
        "version": "8.0.0",
        "architecture": "Hybrid Agentic AI SOC Investigation Platform",
        "investigation_phases": [
            "PERCEIVE", "PLAN", "EXECUTE",
            "REFLECT", "REPLAN", "VALIDATE", "REPORT"
        ],
        "specialists": [
            "Behavior Analyst", "Pattern Analyst",
            "Threat Context", "IOC Analyst", "MITRE Knowledge"
        ],
        "agent_entities_tracked": 0, # Temporarily disabled
        "llm_model": os.getenv("OPENROUTER_MODEL", "Agentic Gateway"),
        "gemini_fallback_available": bool(os.getenv("GEMINI_API_KEY")),
        "features": [
            "LLM Investigation Planner",
            "Dynamic Reflection & Replanning",
            "Deterministic Decision Engine",
            "Policy & Guardrail Engine",
            "Prompt Injection Defense",
            "Evidence Aggregation",
            "Cross-session Correlation",
            "Gemini Fallback LLM",
        ],
    }


# ── Dashboard stats endpoint ──────────────────────────────────────────────────
@app.get("/dashboard/stats")
def dashboard_stats():
    """
    Aggregate system statistics for the Dashboard frontend page.
    Returns entity counts, pipeline component status, and agent configuration.
    No authentication required (public health/stats endpoint).
    """
    from backend.reasoning.memory import get_memory_store
    memory = get_memory_store()
    entities = memory.get_all_entities()

    # Count sessions across all entities
    total_sessions = 0
    for eid in entities:
        total_sessions += len(memory.get_sessions(eid))

    return {
        "version": "8.0.0",
        "status": "operational",
        "components": {
            "lstm_model": "loaded",
            "rag_chromadb": "loaded",
            "llm_api": os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free"),
            "agent_engine": "hybrid_agentic_v8",
            "jwt_auth": "enabled",
            "policy_engine": "enabled",
            "reflection_engine": "enabled",
            "decision_engine": "deterministic",
        },
        "investigation_phases": 7,
        "specialist_count": 5,
        "campaign_patterns": 7,
        "attack_event_types": 10,
        "mitre_techniques_indexed": 500,
        "entities_tracked": len(entities),
        "active_sessions": total_sessions,
        "agents": [
            {"id": 1, "name": "Behavior Analyst",  "role": "LSTM behavioral anomaly scoring",    "weight": 0.35},
            {"id": 2, "name": "MITRE Knowledge",    "role": "MITRE ATT&CK semantic retrieval",   "weight": 0.20},
            {"id": 3, "name": "Threat Context",     "role": "IP/hash/command reputation",        "weight": 0.10},
            {"id": 4, "name": "Pattern Analyst",    "role": "8 heuristic attack patterns",       "weight": 0.10},
            {"id": 5, "name": "IOC Analyst",        "role": "Automated indicator extraction",    "weight": 0.10},
            {"id": 6, "name": "Playbook Generator", "role": "Severity-adaptive response gen",    "weight": 0.15},
        ],
        "confidence_formula": "0.35·LSTM + 0.20·RAG + 0.15·Correlation + 0.10·ThreatIntel + 0.10·Pattern + 0.10·IOC",
        "risk_formula": "anomaly·35 + confidence·25 + TI·20 + pattern·10 + correlation·10",
    }


# ── Authentication Endpoints ──────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """User login credentials."""
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class TokenResponseModel(BaseModel):
    """Token response model for OpenAPI documentation."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@app.post("/auth/token", response_model=TokenResponseModel)
def login(credentials: LoginRequest):
    """
    Authenticate user and get JWT token.
    
    **Demo Users (change passwords in production):**
    - username: `analyst` password: `password123`
    - username: `admin` password: `admin123`
    - username: `soc_team` password: `team123`
    
    **Usage:**
    ```bash
    # Get token
    curl -X POST "http://localhost:8000/auth/token" \\
      -H "Content-Type: application/json" \\
      -d '{"username": "analyst", "password": "password123"}'
    
    # Use token in protected endpoints
    curl -X POST "http://localhost:8000/investigate" \\
      -H "Authorization: Bearer <your_token>" \\
      -H "Content-Type: application/json" \\
      -d '{"logs": "your logs here"}'
    ```
    """
    # Authenticate user
    user_id = AuthService.authenticate_user(
        credentials.username,
        credentials.password
    )
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create JWT token
    token = AuthService.create_access_token(
        user_id=user_id,
        username=credentials.username
    )
    
    return TokenResponseModel(
        access_token=token,
        token_type="bearer",
        expires_in=JWTConfig.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@app.get("/auth/me")
async def get_current_user_info(current_user: TokenData = Depends(get_current_user)):
    """
    Get current authenticated user information.
    
    **Requires JWT token in Authorization header:**
    ```
    Authorization: Bearer <your_token>
    ```
    """
    return {
        "user_id": current_user.user_id,
        "username": current_user.username,
        "scopes": current_user.scopes,
        "issued_at": current_user.issued_at.isoformat(),
        "expires_at": current_user.expires_at.isoformat(),
    }


@app.get("/")
def root():
    """Root endpoint with API information."""
    return {
        "message": "LLM-Powered SOC Analyst API",
        "version": "2.0.0",
        "docs": "/docs",
        "auth": "/auth/token",
        "health": "/health",
    }


def _process_raw_logs(raw_logs: str):
    """
    Detects if input is network flow CSV or standard logs, and processes accordingly.
    Returns: (normalized_logs, events, event_sequence_ints, event_sequence_types, anomaly_score)
    """
    from backend.processing.event_extractor import SecurityEvent
    
    # Check if network flow CSV by looking for typical CIC-IDS2017 headers
    first_line = raw_logs.split('\\n')[0].lower()
    is_network_flow = 'destination port' in first_line or 'flow duration' in first_line

    if is_network_flow:
        import pandas as pd
        import io
        import logging
        logger = logging.getLogger(__name__)
        
        try:
            df = pd.read_csv(io.StringIO(raw_logs))
            # drop non numeric
            drop_cols = [c for c in df.columns if df[c].dtype == object]
            features = df.drop(columns=drop_cols).apply(pd.to_numeric, errors="coerce").fillna(0).values
            
            if is_network_flow_model_loaded():
                anomaly_score = score_network_flow(features)
            else:
                anomaly_score = 0.0
                
            # Create a mock sequence for the rest of the pipeline
            normalized_logs = [{"raw": "Network flow traffic", "timestamp": None}]
            # Determine MITRE mapping based on score
            mitre_hint = "T1071 Application Layer Protocol" if anomaly_score > 0.8 else None
            event_type = "SUSPICIOUS_EXEC" if anomaly_score > 0.8 else "NORMAL"
            event_code = 6 if anomaly_score > 0.8 else 0
            
            from datetime import datetime, timezone
            events = [
                SecurityEvent(
                    event_type=event_type,
                    event_code=event_code,
                    source_ip="NetworkFlow",
                    dest_ip="NetworkFlow",
                    user="Unknown",
                    hostname="Unknown",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    description=f"Network flow batch ({len(df)} records) with anomaly score {anomaly_score:.2f}",
                    raw="Network flow traffic",
                    mitre_hint=mitre_hint,
                    severity="high" if anomaly_score > 0.8 else "low"
                )
            ]
            event_sequence_ints = [e.event_code for e in events]
            event_sequence_types = [e.event_type for e in events]
            return normalized_logs, events, event_sequence_ints, event_sequence_types, anomaly_score
            
        except Exception as e:
            logger.error(f"Failed to parse network flow CSV: {e}")
            # Fall back to standard parsing
            pass

    # Standard text log parsing
    normalized_logs = normalize_logs(raw_logs)
    events = extract_events(normalized_logs)
    event_sequence_ints = events_to_sequence(events)
    event_sequence_types = [e.event_type for e in events]
    anomaly_score = score_sequence(event_sequence_ints)
    
    return normalized_logs, events, event_sequence_ints, event_sequence_types, anomaly_score


def _build_rich_agentic_response(inv_obj, logs_snippet, start_t, end_t):
    # Extract stats from tools
    anomaly_score = 0.0
    threat_intel = {}
    attack_graph = {}
    mitre_techniques = []
    rag_snippets = []
    iocs_extracted = {}
    campaign_pattern = None
    
    for t in inv_obj.tool_outputs:
        if t.tool_name == "Behavior Analyst" and isinstance(t.evidence, dict):
            anomaly_score = t.evidence.get("anomaly_score", 0.0)
        elif t.tool_name == "Threat Context":
            threat_intel = t.evidence if isinstance(t.evidence, dict) else {}
        elif t.tool_name == "Attack Graph Builder":
            attack_graph = t.evidence if isinstance(t.evidence, dict) else {}
        elif t.tool_name == "MITRE Knowledge" and isinstance(t.evidence, dict):
            mitre_techniques = t.evidence.get("techniques_found", [])
            rag_snippets = [t.evidence.get("rag_context", "")]
        elif t.tool_name == "IOC Analyst" and isinstance(t.evidence, dict):
            # Extract just the arrays (ipv4, domains, etc.) from the evidence dictionary
            iocs_extracted = {k: v for k, v in t.evidence.items() if k not in ("total_count", "suspicious_count")}
        elif t.tool_name == "Pattern Analyst" and isinstance(t.evidence, dict):
            campaign_pattern = t.evidence.get("pattern_name", None)

    # Reconstruct reasoning_trace with hierarchical details
    phases = []
    phases.append({
        "phase": "PERCEIVE", 
        "desc": "Parsed logs and built InvestigationObject."
    })
    
    tool_names = [t.tool_name for t in inv_obj.tool_outputs]
    
    if inv_obj.investigation_report.get("planner_error"):
        err = inv_obj.investigation_report["planner_error"]
        phases.append({
            "phase": "PLAN (ERROR)",
            "desc": "Planner failed after all retries.",
            "details": {
                "Reason": err.get("reason", "Unknown"),
                "Action": "Investigation Terminated"
            }
        })
    elif inv_obj.planner_hypothesis:
        phases.append({
            "phase": "PLAN", 
            "desc": f"Generated investigation plan.",
            "details": {
                "Hypothesis": inv_obj.planner_hypothesis,
                "Required Tools": ", ".join(tool_names),
                "Execution Strategy": "Parallel tool dispatch"
            }
        })
        
    if tool_names:
        phases.append({
            "phase": "EXECUTE", 
            "desc": f"Executed specialist tools.",
            "details": {
                "Execution Order": ", ".join(tool_names),
                "Skipped Tools": str(len(inv_obj.skipped_tools_log))
            }
        })
        
    phases.append({
        "phase": "FUSE", 
        "desc": "Aggregated evidence.",
        "details": {
            "Evidence Completeness": f"{int(inv_obj.evidence_completeness * 100)}%",
            "Timeline Entries": str(len(inv_obj.evidence_timeline))
        }
    })
    
    if inv_obj.last_reflection_data:
        phases.append({
            "phase": "REFLECT", 
            "desc": "Evaluated evidence sufficiency.",
            "details": {
                "Needs Replan": str(inv_obj.last_reflection_data.get("needs_more_evidence")),
                "Reasoning": inv_obj.last_reflection_data.get("reasoning", "")
            }
        })
        
    phases.append({
        "phase": "DECIDE", 
        "desc": "Computed final deterministic decision.",
        "details": {
            "Risk": str(inv_obj.risk),
            "Severity": inv_obj.severity,
            "Factors": ", ".join(inv_obj.severity_factors)
        }
    })
    
    if inv_obj.report:
        phases.append({"phase": "REPORT", "desc": "Generated investigation narrative."})
    
    # Tool results for the trace tab (both executed and skipped)
    tool_results = []
    for t in inv_obj.tool_outputs:
        tool_results.append({
            "tool_name": t.tool_name,
            "status": "success" if not isinstance(t.evidence, dict) or "error" not in t.evidence else "error",
            "reason": getattr(t, "reason_selected", "Executed successfully"),
            "expected_evidence": getattr(t, "expected_evidence", "No expected evidence provided"),
            "execution_time_ms": t.execution_time,
            "confidence_contribution": t.confidence,
            "evidence_tags": []
        })
        
    for s in inv_obj.skipped_tools_log:
        tool_results.append({
            "tool_name": s["tool"],
            "status": "skipped",
            "reason": s.get("reason", "Not selected"),
            "execution_time_ms": 0,
            "confidence_contribution": 0.0,
            "evidence_tags": []
        })
        
    # Build dynamic progressive confidence evolution
    simulated_conf_evol = [0.0]  # Start before Planner
    if inv_obj.tool_outputs:
        from backend.reasoning.decision_engine import DecisionEngine
        from backend.schemas.investigation import InvestigationObject as InvObj
        import copy
        
        # We need a dummy to replay the tools
        dummy_inv = InvObj(investigation_id="dummy")
        # Ensure we capture any contradictions that apply to the real object
        dummy_inv.evidence_timeline = copy.deepcopy(inv_obj.evidence_timeline)
        
        for t in inv_obj.tool_outputs:
            dummy_inv.tool_outputs.append(t)
            dummy_inv.evidence_completeness = min(len(dummy_inv.tool_outputs) / 7.0, 1.0)
            DecisionEngine.evaluate(dummy_inv)
            simulated_conf_evol.append(dummy_inv.confidence)
            
    simulated_conf_evol.append(inv_obj.confidence) # Reflection phase
    simulated_conf_evol.append(inv_obj.confidence) # Decision phase

    def _extract_section(text, titles):
        import re
        for title in titles:
            match = re.search(r'(?i)\*{0,2}' + re.escape(title) + r'\*{0,2}[:\n]+(.*?)(?=\n\n\*{0,2}|\Z)', text, re.DOTALL)
            if match:
                return match.group(1).strip()
        return ""

    raw_report = inv_obj.report or ""
    investigation_report = {
        "executive_summary": _extract_section(raw_report, ["Executive Summary", "Summary"]),
        "root_cause": _extract_section(raw_report, ["Investigation Timeline", "Timeline", "Root Cause"]),
        "mitre_explanation": _extract_section(raw_report, ["MITRE ATT&CK Mapping", "MITRE"]),
        "recommendations": _extract_section(raw_report, ["Action Plan", "Recommendations", "Response"])
    }
    
    # If parsing failed, fallback to dumping it all in executive summary
    if not any(investigation_report.values()):
        investigation_report["executive_summary"] = raw_report

    return {
        "incident_id": inv_obj.investigation_id,
        "investigation_status": "COMPLETED",
        "severity": inv_obj.severity,
        "decision": inv_obj.decision,
        "risk_score": int(inv_obj.risk),
        "confidence": inv_obj.confidence,
        "anomaly_score": anomaly_score,
        "entities": [inv_obj.entity_info.get("primary_entity", "Unknown")],
        "investigation_hypothesis": inv_obj.planner_hypothesis,
        "planned_tools": tool_names,
        "completed_tools": tool_names,
        "escalation_tools": [],
        "skipped_tools": [s["tool"] for s in inv_obj.skipped_tools_log],
        "mitre_mappings": mitre_techniques,
        "campaign_pattern": campaign_pattern,
        "iocs_extracted": iocs_extracted,
        "reasoning_trace": phases,
        "reflection_history": inv_obj.reflection_history,
        "confidence_evolution": simulated_conf_evol,
        "confidence_breakdown": inv_obj.confidence_breakdown,
        "risk_breakdown": inv_obj.risk_breakdown,
        "severity_factors": inv_obj.severity_factors,
        "investigation_report": investigation_report,
        "evidence_board": [
            {"source": e.get("source"), "description": e.get("evidence_summary")} 
            for e in inv_obj.evidence_timeline
        ],
        "correlation_depth": 1,
        "llm_explanation": inv_obj.report,
        "response_playbook": {"name": "Deterministic Policy", "ACTIONS": [inv_obj.decision]},
        "tool_results": tool_results,
        "total_analysis_ms": (end_t - start_t) * 1000,
        "plan_iterations": inv_obj.plan_iterations,
        
        # Legacy fields for dashboard compatibility
        "timestamp": inv_obj.session_metadata.get("start_time", ""),
        "attack_stage": "Detection",
        "kill_chain_stage": "Analysis",
        "mitre_techniques": mitre_techniques,
        "event_types": [],
        "session_count": 1,
        "events_analyzed": inv_obj.session_metadata.get("total_events", 0),
        "threat_intel": threat_intel,
        "attack_graph": attack_graph,
        "rag_query": "",
        "rag_snippets": rag_snippets,
        "recommended_response": [inv_obj.decision],
        "raw_log_sample": logs_snippet,
    }


# ── Main investigation endpoint ───────────────────────────────────────────────
@app.post("/investigate")
async def investigate(
    request: LogRequest,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Agentic SOC Investigation Pipeline.
    """
    import time
    start_t = time.time()
    inv_obj = run_investigation_loop(raw_logs=request.logs)
    end_t = time.time()
    
    return _build_rich_agentic_response(inv_obj, request.logs[:200], start_t, end_t)


# ── Agentic AI Layer endpoint ─────────────────────────────────────────────────
@app.post("/investigate/agent")
async def investigate_with_agent(
    request: AgentLogRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Autonomous Agentic AI SOC Investigation Platform.
    """
    import time
    start_t = time.time()
    inv_obj = run_investigation_loop(raw_logs=request.logs, entity_id=request.entity_id)
    end_t = time.time()
    
    return _build_rich_agentic_response(inv_obj, request.logs[:200], start_t, end_t)


# ── Auxiliary endpoints ───────────────────────────────────────────────────────

class _ParseRequest(BaseModel):
    logs: str = Field(..., min_length=1, description="Raw log text or query string")
    k: _Optional[int] = Field(default=3, ge=1, le=20, description="Max RAG snippets to return")


@app.post("/parse")
def parse_only(request: _ParseRequest):
    """
    Parse and normalize logs without running LLM investigation.
    Useful for testing the extraction pipeline.
    Also runs RAG retrieval so you can inspect what MITRE context would be used.
    Accepts optional `k` field (1-20) to control number of RAG snippets returned.
    """
    k = max(1, min(int(request.k or 3), 20))
    normalized = normalize_logs(request.logs)
    events = extract_events(normalized)
    sessions = build_sessions(events)
    anomaly_score = score_sequence(events_to_sequence(events))
    ti_report = enrich_events(events)
    graph = build_attack_graph(events)
    mitre_query = get_mitre_query(events)
    rag_context = retrieve_context(mitre_query, k=k)
    rag_snippets = [s.strip() for s in rag_context.split("\n\n") if s.strip()]
    rag_source = "vector_db" if rag_snippets else "none"

    return {
        "normalized_count": len(normalized),
        "events": [e.to_dict() for e in events],
        "sessions": sessions_summary(sessions),
        "anomaly_score": anomaly_score,
        "threat_intel": ti_report.to_dict(),
        "attack_graph": graph,
        "rag_query": mitre_query,
        "rag_source": rag_source,
        "rag_snippets": rag_snippets,
        "rag_context": rag_context,
    }


class _RagTestRequest(BaseModel):
    query: str = Field(..., min_length=1, description="Direct semantic search query against the MITRE ATT&CK vector DB")
    k: _Optional[int] = Field(default=3, ge=1, le=20, description="Number of results to retrieve")


@app.post("/rag-test")
def rag_test(request: _RagTestRequest):
    """
    Direct RAG query endpoint — bypass log parsing and query the vector DB directly.
    Useful for testing what the MITRE ATT&CK ChromaDB retrieves for a given query.
    """
    k = max(1, min(int(request.k or 3), 20))
    rag_context = retrieve_context(request.query, k=k)
    rag_snippets = [s.strip() for s in rag_context.split("\n\n") if s.strip()]
    rag_source = "vector_db" if rag_snippets else "none"

    return {
        "query": request.query,
        "k": k,
        "rag_source": rag_source,
        "rag_snippets": rag_snippets,
        "rag_context": rag_context,
        "snippet_count": len(rag_snippets),
    }


# ── Evaluation endpoint ────────────────────────────────────────────────────────

@app.get("/evaluate")
def evaluate(
    current_user: TokenData = Depends(get_current_user),
):
    """
    Run the built-in evaluation suite against the labelled test dataset.

    Uses the heuristic mock detector (no LLM inference required) so the endpoint
    responds quickly and can be used for CI/CD health-checks.

    Returns precision, recall, F1, FPR, accuracy and per-sample confusion matrix.

    **Requires JWT authentication.**
    """
    metrics = _run_evaluation(detection_func=None, verbose=False)
    return {
        "status": "ok",
        "dataset_size": metrics["total_samples"],
        "metrics": {
            "precision":           metrics["precision"],
            "recall":              metrics["recall"],
            "f1_score":            metrics["f1_score"],
            "false_positive_rate": metrics["false_positive_rate"],
            "specificity":         metrics["specificity"],
            "accuracy":            metrics["accuracy"],
        },
        "confusion_matrix": {
            "true_positives":  metrics["true_positives"],
            "false_positives": metrics["false_positives"],
            "true_negatives":  metrics["true_negatives"],
            "false_negatives": metrics["false_negatives"],
        },
    }