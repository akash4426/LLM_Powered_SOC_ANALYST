"""
main.py
-------
FastAPI application — LLM-Powered SOC Analyst API.

Full pipeline:
  POST /investigate
  1. Parse & normalize logs
  2. Extract typed security events
  3. Build behavioral sessions
  4. Score with LSTM anomaly detector (with heuristic fallback)
  5. Enrich with threat intelligence
  6. Retrieve MITRE ATT&CK RAG context  ← using get_mitre_query()
  7. LLM investigation (Phi-3.5 local) — receives pre-fetched RAG context
  8. Reconstruct attack graph (NetworkX)
  9. Generate structured incident report  ← includes rag_context
  10. Return full JSON
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
from backend.reasoning.llm_agent import investigate_logs
from backend.rag.rag_engine import retrieve_context
from backend.incident_report import generate_report
from backend.reasoning.agent_layer import analyze_with_agent, get_memory_store
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
    from backend.reasoning.llm_agent import MODEL_NAME
    from backend.reasoning.gemini_agent import is_gemini_available
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
        "agent_entities_tracked": len(get_memory_store().get_all_entities()),
        "llm_model": MODEL_NAME,
        "gemini_fallback_available": is_gemini_available(),
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


# ── Main investigation endpoint ───────────────────────────────────────────────
@app.post("/investigate", response_model=InvestigateResponse)
async def investigate(
    request: LogRequest,
    current_user: TokenData = Depends(get_current_user)
):
    """
    Full SOC investigation pipeline.
    
    **Requires JWT authentication.**
    
    1. Get token: POST /auth/token
    2. Use token: Add `Authorization: Bearer <token>` header
    
    Accepts raw security logs (text, JSON array, or JSON Lines).
    Returns a structured incident report with:
      - LSTM anomaly score
      - MITRE ATT&CK techniques
      - Threat intelligence enrichment
      - Attack graph (NetworkX)
      - RAG-retrieved MITRE ATT&CK passages
      - LLM-generated explanation and recommendations
    """
    raw_logs = request.logs

    # ── Steps 1-4: Parse, Extract, Session Build, LSTM Scoring ────────────
    normalized_logs, events, event_sequence_ints, event_sequence_types, anomaly_score = _process_raw_logs(raw_logs)

    sessions = build_sessions(events)
    session_data = sessions_summary(sessions)

    # ── Step 5: Threat Intelligence Enrichment ────────────────────────────
    ti_report = enrich_events(events)
    ti_dict = ti_report.to_dict()
    ti_summary = ti_report.summary_text()

    # ── Step 6: MITRE ATT&CK RAG Retrieval ───────────────────────────────
    # Build a targeted query from the MITRE hints embedded in each detected
    # event type (e.g. "T1110 Brute Force | T1059 Command Scripting |…")
    # instead of using raw log text — much better semantic matching.
    mitre_query = get_mitre_query(events)
    rag_context = retrieve_context(mitre_query)

    # Keep individual snippets so the frontend can display them
    rag_snippets = [
        s.strip() for s in rag_context.split("\n\n") if s.strip()
    ]

    # ── Step 7: Attack Graph Reconstruction ──────────────────────────────
    graph = build_attack_graph(events)
    graph_summary = attack_graph_summary(graph)

    # ── Step 8: LLM Investigation (receives pre-fetched RAG context) ──────
    llm_warning = ""
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            investigate_logs,
            log_text=raw_logs,
            event_sequence=event_sequence_types,
            anomaly_score=anomaly_score,
            threat_intel_summary=ti_summary,
            attack_graph_summary=graph_summary,
            rag_context=rag_context,         # <— RAG context passed explicitly
        )
        # Timeout after 60 seconds for OpenRouter API
        llm_output = future.result(timeout=60.0)
        executor.shutdown(wait=False)
    except concurrent.futures.TimeoutError:
        llm_warning = "OpenRouter LLM generation timed out. The API request took too long."
        llm_output = {
            "attack_stage": "Unknown",
            "mitre_technique": ["Unknown"],
            "severity": "MEDIUM",
            "confidence": "50%",
            "explanation": "OpenRouter LLM generation timed out.\nThe API request to OpenRouter took too long to complete.",
            "recommended_actions": ["Check OpenRouter API status or check your internet connection."]
        }
    except Exception as e:  # catches RuntimeError, etc.
        llm_warning = f"OpenRouter LLM unavailable: {e}"
        llm_output = {
            "attack_stage": "Unknown",
            "mitre_technique": ["Unknown"],
            "severity": "MEDIUM",
            "confidence": "50%",
            "explanation": "OpenRouter LLM could not execute successfully.\nCore detections (events, sessions, anomaly score, threat intel, RAG, attack graph) were still processed.\nReview technical indicators and enrichment data in this report for triage.",
            "recommended_actions": ["Ensure your API key is valid and configured.", "Ensure you have stable internet connection."]
        }

    # ── Step 9: Incident Report Generation ───────────────────────────────
    report = generate_report(
        sessions=session_data["sessions"],
        anomaly_score=anomaly_score,
        threat_intel=ti_dict,
        attack_graph=graph,
        llm_parsed=llm_output,
        raw_logs=raw_logs,
        rag_snippets=rag_snippets,       # <— RAG passages now in report
        mitre_query=mitre_query,         # <— show what query was used
        events=events,                   # ← for MITRE technique fallback
    )

    if llm_warning:
        report["llm_warning"] = llm_warning

    # ── Step 10: Add legacy field for frontend backward-compat ────────────
    import json
    report["investigation"] = json.dumps(llm_output)

    return InvestigateResponse(**report)


# ── Agentic AI Layer endpoint ─────────────────────────────────────────────────
@app.post("/investigate/agent", response_model=AgentAnalysisResponse)
async def investigate_with_agent(
    request: AgentLogRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Full SOC investigation pipeline + Agentic AI correlation layer.

    **Requires JWT authentication.**

    Runs the complete pipeline (Steps 1-9), then applies the Agent Layer:
      - Stores session in entity memory
      - Correlates across historical sessions for the same entity
      - Applies compound intelligence (re-runs LSTM + RAG on combined sequences)
      - Builds structured timeline and incident
      - Computes deterministic severity and confidence
      - Generates LLM explanation (narrative only)

    Submit multiple requests for the same entity_id to see cross-session
    correlation in action.
    """
    from datetime import datetime as _dt, timezone as _tz

    raw_logs = request.logs

    # ── Steps 1-4: Parse, Extract, Session Build, LSTM Scoring ───────────
    normalized_logs, events, event_sequence_ints, event_sequence_types, anomaly_score = _process_raw_logs(raw_logs)
    sessions = build_sessions(events)

    # ── Auto-detect entity_id if not provided ────────────────────────────
    entity_id = request.entity_id
    if not entity_id:
        # Use most common source_ip, then user, then hostname
        from collections import Counter
        ips = [e.source_ip for e in events if e.source_ip]
        users = [e.user for e in events if e.user]
        hosts = [e.hostname for e in events if e.hostname]
        if ips:
            entity_id = Counter(ips).most_common(1)[0][0]
        elif users:
            entity_id = Counter(users).most_common(1)[0][0]
        elif hosts:
            entity_id = Counter(hosts).most_common(1)[0][0]
        else:
            entity_id = "unknown_entity"

    timestamp = request.timestamp or _dt.now(_tz.utc).isoformat()

    # ── Steps 5-9: Run existing pipeline (TI, RAG, LLM, Report) ──────────
    ti_report = enrich_events(events)
    ti_summary = ti_report.summary_text()
    mitre_query = get_mitre_query(events)
    rag_context = retrieve_context(mitre_query)
    rag_snippets = [s.strip() for s in rag_context.split("\n\n") if s.strip()]
    graph = build_attack_graph(events)
    graph_summary = attack_graph_summary(graph)

    llm_warning = ""
    try:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(
            investigate_logs,
            log_text=raw_logs,
            event_sequence=event_sequence_types,
            anomaly_score=anomaly_score,
            threat_intel_summary=ti_summary,
            attack_graph_summary=graph_summary,
            rag_context=rag_context,
        )
        llm_output = future.result(timeout=60.0)
        executor.shutdown(wait=False)
    except concurrent.futures.TimeoutError:
        llm_warning = "LLM generation timed out."
        llm_output = {
            "attack_stage": "Unknown", "mitre_technique": ["Unknown"],
            "severity": "MEDIUM", "confidence": "50%",
            "explanation": "LLM timed out.",
            "recommended_actions": ["Retry or check API status."],
        }
    except Exception as e:
        llm_warning = f"LLM unavailable: {e}"
        llm_output = {
            "attack_stage": "Unknown", "mitre_technique": ["Unknown"],
            "severity": "MEDIUM", "confidence": "50%",
            "explanation": "LLM could not execute.",
            "recommended_actions": ["Check API key and connection."],
        }

    session_data = sessions_summary(sessions)
    pipeline_report = generate_report(
        sessions=session_data["sessions"],
        anomaly_score=anomaly_score,
        threat_intel=ti_report.to_dict(),
        attack_graph=graph,
        llm_parsed=llm_output,
        raw_logs=raw_logs,
        rag_snippets=rag_snippets,
        mitre_query=mitre_query,
        events=events,
    )
    if llm_warning:
        pipeline_report["llm_warning"] = llm_warning

    # ── Step 10: Agentic AI Layer ─────────────────────────────────────────
    agent_result = analyze_with_agent(
        sequence=event_sequence_ints,
        entity_id=entity_id,
        timestamp=timestamp,
        events=events,
        threat_intel_score=ti_report.max_risk_score / 100.0,
        anomaly_score=anomaly_score,
        raw_logs=raw_logs,
    )

    # Attach the pipeline report for full context
    agent_result["pipeline_report"] = pipeline_report

    return AgentAnalysisResponse(**agent_result)


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