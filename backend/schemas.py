"""
schemas.py
----------
Pydantic request / response models for the FastAPI SOC Analyst API.
"""

from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional


class LogRequest(BaseModel):
    """Request body for POST /investigate"""
    logs: str = Field(
        ...,
        description="Raw security logs (multi-line text, JSON array, or JSON Lines)",
        min_length=1,
    )


class ThreatIntelIndicator(BaseModel):
    indicator: str
    indicator_type: str
    is_malicious: bool
    threat_category: Optional[str] = None
    threat_description: Optional[str] = None
    confidence: float
    source: str
    risk_score: int


class ThreatIntelSummary(BaseModel):
    malicious_indicators: int
    total_indicators: int
    max_risk_score: int
    overall_risk: str
    indicators: List[ThreatIntelIndicator] = Field(default_factory=list)


class AttackGraphSummary(BaseModel):
    node_count: int
    edge_count: int
    attack_path: List[str] = Field(default_factory=list)
    stages: List[str] = Field(default_factory=list)
    nodes: List[Dict[str, Any]] = Field(default_factory=list)
    edges: List[Dict[str, Any]] = Field(default_factory=list)


class InvestigateResponse(BaseModel):
    """Full structured response from POST /investigate"""

    # Core identifiers
    incident_id: str
    timestamp: str

    # Risk assessment
    severity: str
    confidence: float
    anomaly_score: float

    # Attack characterization
    attack_stage: str
    kill_chain_stage: str
    kill_chain_path: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)

    # Event summary
    event_types: List[str] = Field(default_factory=list)
    session_count: int
    events_analyzed: int

    # Enrichment data
    threat_intel: Dict[str, Any] = Field(default_factory=dict)
    attack_graph: Dict[str, Any] = Field(default_factory=dict)

    # RAG retrieval results (MITRE ATT&CK knowledge base)
    rag_query: str = ""
    rag_snippets: List[str] = Field(default_factory=list)

    # LLM outputs
    llm_explanation: str
    recommended_response: List[str] = Field(default_factory=list)

    # Original input (truncated)
    raw_log_sample: str = ""

    # Legacy field for backwards-compat with existing frontend
    investigation: Optional[str] = None

    # Optional warning when fallback logic is used (e.g. LLM unavailable)
    llm_warning: Optional[str] = None


# ── Agentic AI Layer Models ──────────────────────────────────────────────────

class AgentLogRequest(BaseModel):
    """Request body for POST /investigate/agent"""
    logs: str = Field(
        ...,
        description="Raw security logs (multi-line text, JSON array, or JSON Lines)",
        min_length=1,
    )
    entity_id: Optional[str] = Field(
        default=None,
        description="Entity identifier (IP/user/host). Auto-detected from logs if omitted.",
    )
    timestamp: Optional[str] = Field(
        default=None,
        description="ISO-8601 timestamp for this session. Defaults to current time.",
    )


class AgentAnalysisResponse(BaseModel):
    """Response from the Agentic AI Layer — incident-level intelligence."""

    # Individual session scores (from existing pipeline)
    anomaly_score: float
    compound_anomaly_score: Optional[float] = None

    # MITRE mappings
    mitre_mappings: List[str] = Field(default_factory=list)
    compound_mitre_mappings: List[str] = Field(default_factory=list)

    # Cross-session correlation
    correlated_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    correlation_depth: int = 0
    campaign_pattern: Optional[str] = None

    # Incident classification
    incident_id: str = ""
    incident_type: str = "single_session"
    severity: str = "LOW"
    confidence: float = 0.0
    decision: str = "MONITOR"
    risk_score: float = 0.0
    why_flagged: List[str] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)

    # LLM-generated explanation (narrative only)
    llm_explanation: str = ""

    # Shows improvement from compound analysis
    detection_improvement: Optional[str] = None

    # ── NEW: Enterprise Agent Console State ──
    investigation_status: str = "COMPLETED"
    suspicion_level: str = "LOW"
    investigation_hypothesis: Optional[str] = None
    planned_tools: List[str] = Field(default_factory=list)
    completed_tools: List[str] = Field(default_factory=list)
    skipped_tools: List[str] = Field(default_factory=list)
    escalation_tools: List[str] = Field(default_factory=list)
    evidence_board: List[Dict[str, Any]] = Field(default_factory=list)

    # ── Legacy/Core Agent trace ──
    reasoning_trace: List[Dict[str, Any]] = Field(default_factory=list)
    tool_results: List[Dict[str, Any]] = Field(default_factory=list)
    iocs_extracted: Dict[str, Any] = Field(default_factory=dict)
    response_playbook: Dict[str, Any] = Field(default_factory=dict)
    total_analysis_ms: float = 0.0

    # Original pipeline report (full InvestigateResponse data)
    pipeline_report: Optional[Dict[str, Any]] = None