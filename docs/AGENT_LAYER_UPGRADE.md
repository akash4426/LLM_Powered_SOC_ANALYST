# Agent Layer Upgrade — Elite SOC-Style Reasoning

## Overview

The agent layer has been upgraded from basic correlation to **elite SOC-analyst-style reasoning** with multi-step hypothesis testing, evidence-based confidence scoring, and actionable decision-making.

## Key Features

### 1. **Evidence-Based Confidence (Deterministic)**
- No LLM scoring — all computed deterministically
- **Formula:**
  ```
  confidence = (
    0.4 * lstm_score +
    0.3 * min(rag_matches / 5, 1.0) +
    0.2 * min(correlation_depth / 4, 1.0) +
    0.1 * threat_intel_score
  )
  ```
- Returns values in [0, 1] rounded to 4 decimals
- Captures **LSTM anomaly**, **MITRE knowledge**, **cross-session patterns**, and **threat intel**

### 2. **Multi-Step Hypothesis Loop**
- **Build hypothesis** from correlated event types using pattern matching
- **Patterns detected:**
  - `full_kill_chain`: LOGIN → PRIV_ESC → LATERAL_MOVE → EXFILTRATION
  - `privilege_escalation_chain`: LOGIN → PRIV_ESC → SUSPICIOUS_EXEC
  - `apt_lateral_movement`: RECON → LATERAL_MOVE → EXFILTRATION
  - `ransomware_deployment`: DEFENSE_EVADE → SUSPICIOUS_EXEC → EXFILTRATION
  - `brute_force_escalation`: LOGIN → LOGIN → PRIV_ESC
  - `recon_to_exploit`: RECON → SUSPICIOUS_EXEC → PRIV_ESC
  - `credential_theft`: LOGIN → SUSPICIOUS_EXEC → EXFILTRATION

- **Refine on hypothesis:** Re-run LSTM + RAG on combined sequences to detect pattern improvements

### 3. **Time-Aware Correlation**
- Sessions decay in importance over time (linear decay)
- Window: 6 hours by default
- Combines anomaly scores, MITRE techniques across sessions
- Tracks up to 50 sessions per entity (thread-safe memory store)

### 4. **Decision Engine**
```python
if confidence > 0.85:
    decision = "AUTO_REMEDIATE"  # Immediate action
elif confidence > 0.6:
    decision = "ESCALATE_L2"     # Analyst review + action
else:
    decision = "MONITOR"          # Watch and log
```

### 5. **Structured Incident Output**
Returns complete incident object with:
- **incident_id**: Unique identifier
- **incident_type**: single_session | correlated_multi_session | {campaign_pattern}
- **severity**: LOW | MEDIUM | HIGH | CRITICAL (boosted by campaign pattern)
- **confidence**: Float [0, 1] from evidence ledger
- **decision**: AUTO_REMEDIATE | ESCALATE_L2 | MONITOR
- **timeline**: Chronological attack sequence
- **entities**: All entities involved
- **why_flagged**: List of reasoning (anomaly deviation, MITRE matches, pattern)
- **compound_anomaly_score**: Best score across sessions
- **compound_mitre_mappings**: All MITRE techniques discovered
- **campaign_pattern**: Detected pattern (if any)
- **detection_improvement**: Shows LSTM/RAG improvements from compound analysis

### 6. **Explainability**
- **why_flagged**: Reasons for incident classification
  - "High anomaly deviation detected"
  - "MITRE techniques matched: T1110, T1078, ..."
  - "Multi-stage pattern matched: {pattern_name}"
  - "Cross-session correlation detected: N sessions linked"

- **LLM explanation**: Narrative summary (uses LLM if available, fallback to heuristic)

## Architecture

### Session Storage
```python
SessionRecord(
    session_id: str,
    timestamp: str,           # ISO-8601
    epoch: float,             # Unix timestamp
    sequence: List[int],      # Event type codes
    event_types: List[str],   # Event type names
    anomaly_score: float,
    mitre_mappings: List[str],
    events_summary: List[Dict],
    entity_id: str
)
```

### Memory Store
- **Thread-safe** (uses threading.Lock)
- **Per-entity session history** (last 24 hours)
- **Max 50 sessions per entity**
- **TTL pruning** (86400 seconds = 24 hours)

### Pipeline Integration

```
Existing Pipeline (Steps 1-9)
    ↓
    [LSTM Score, RAG Mappings, Event Types, Threat Intel]
    ↓
analyze_with_agent()
    ├─ Step 1: Get baseline pipeline outputs
    ├─ Step 2: Time-aware correlation
    ├─ Step 3: Build hypothesis
    ├─ Step 4: Refine with models (re-run LSTM + RAG)
    ├─ Step 5: Evidence-based confidence
    ├─ Step 6: Decision engine
    ├─ Step 7: Timeline & severity
    ├─ Step 8: Structured incident
    ├─ Step 9: LLM explanation
    └─ Step 10: Return response
```

## API Usage

### Endpoint: POST `/investigate/agent`

**Request:**
```json
{
  "logs": "raw security logs (multi-line text, JSON array, or JSON Lines)",
  "entity_id": "optional — IP/user/host; auto-detected if omitted",
  "timestamp": "optional — ISO-8601; defaults to now"
}
```

**Response (AgentAnalysisResponse):**
```json
{
  "incident_id": "uuid",
  "incident_type": "full_kill_chain | correlated_multi_session | single_session",
  "severity": "CRITICAL | HIGH | MEDIUM | LOW",
  "confidence": 0.8234,
  "decision": "AUTO_REMEDIATE | ESCALATE_L2 | MONITOR",
  "correlation_depth": 3,
  "campaign_pattern": "full_kill_chain",
  "anomaly_score": 0.65,
  "compound_anomaly_score": 0.82,
  "mitre_mappings": ["T1110", "T1078"],
  "compound_mitre_mappings": ["T1110", "T1078", "T1021", "T1486"],
  "why_flagged": [
    "High anomaly deviation detected",
    "MITRE techniques matched: T1110, T1078, T1021, T1486",
    "Multi-stage pattern matched: full_kill_chain",
    "Cross-session correlation detected: 3 sessions linked"
  ],
  "entities": ["192.168.1.105", "WORKSTATION-01"],
  "correlated_timeline": [
    {
      "timestamp": "2024-01-15T03:22:11Z",
      "entity_id": "192.168.1.105",
      "event_type": "LOGIN",
      "description": "Failed password for admin",
      "session_anomaly_score": 0.45,
      "session_id": "abc12345"
    },
    ...
  ],
  "llm_explanation": "Narrative explanation from LLM or fallback...",
  "detection_improvement": "Compound analysis increased anomaly score by 0.17... RAG retrieval discovered 2 additional MITRE techniques...",
  "pipeline_report": { /* full InvestigateResponse data */ }
}
```

## Testing

### 1. Single Session (No Correlation)
```bash
curl -X POST http://localhost:8000/investigate/agent \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": "2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2",
    "entity_id": "185.220.101.5"
  }'
```

**Expected:** Single session with low correlation_depth, basic severity

### 2. Multi-Session Correlation
Submit 3+ requests for same entity with suspicious events:

```bash
# Session 1: Brute force
curl ... -d '{"logs": "Failed password ... x5 times", "entity_id": "185.220.101.5"}'

# Session 2: Privilege escalation
curl ... -d '{"logs": "Sudo: ... COMMAND=/bin/bash", "entity_id": "185.220.101.5"}'

# Session 3: Lateral movement
curl ... -d '{"logs": "PsExec to FILESERVER-02 ... Pass-the-hash", "entity_id": "185.220.101.5"}'
```

**Expected:**
- correlation_depth = 3
- campaign_pattern = "full_kill_chain"
- severity boosted to CRITICAL
- confidence > 0.7
- decision = "ESCALATE_L2" or "AUTO_REMEDIATE"

### 3. Threshold Testing

Use the frontend at `http://localhost:8000/frontend/index.html` (or build your own):

1. Load "SSH Brute Force" scenario → expect MONITOR (low confidence)
2. Load "Lateral Movement" scenario → expect ESCALATE_L2 (medium confidence)
3. Load "Ransomware Deploy" scenario → expect AUTO_REMEDIATE (high confidence)
4. Submit same entity multiple times → see correlation_depth increase

## Code Quality

### Production Features
- ✅ Type hints throughout (Python 3.7+)
- ✅ Deterministic scoring (no randomness, reproducible)
- ✅ Thread-safe memory store (concurrent access safe)
- ✅ Clear error handling (fallback explanations)
- ✅ Comprehensive docstrings
- ✅ No external dependencies beyond existing stack (LSTM, RAG, LLM)

### Modularity
Functions are independent and reusable:
- `update_memory()` — persist session
- `correlate_events()` — find correlated sessions
- `build_hypothesis()` — pattern matching
- `refine_with_models()` — LSTM + RAG re-run
- `compute_confidence()` — deterministic scoring
- `decide_action()` — decision engine
- `compute_severity()` — severity mapping
- `generate_agent_explanation()` — LLM narrative

### Performance
- **Memory:** O(n) where n = sessions per entity (max 50)
- **Time:** Correlation O(n log n), LSTM/RAG runtime dominated by model execution
- **Correlation window:** 6 hours default (configurable)

## Frontend Integration

### Agent Mode Toggle
- Checkbox in left column enables/disables agent analysis
- Shows "ENTITIES TRACKED" counter
- Allows custom entity_id input

### Agent Intelligence Panel
Displays when agent mode is ON and analysis completes:
- **Compound Anomaly**: Best anomaly score from compound analysis
- **Correlation Depth**: Number of sessions linked
- **Campaign Pattern**: Detected multi-stage pattern
- **Incident Type**: Categorization of incident
- **Decision**: AUTO_REMEDIATE | ESCALATE_L2 | MONITOR

### Additional Sections
- **Compound MITRE Mappings**: MITRE techniques discovered via compound analysis
- **Correlated Attack Timeline**: Chronological view across sessions
- **Agent Incident Narrative**: LLM-generated explanation

## Backwards Compatibility

- ✅ Existing `/investigate` endpoint unchanged
- ✅ Agent analysis runs AFTER pipeline (steps 1-9)
- ✅ LSTM and RAG are NOT modified (only consumed)
- ✅ Can disable agent mode via frontend toggle
- ✅ All existing integrations continue to work

## Configuration

### Entity Memory Store
```python
from backend.reasoning.agent_layer import get_memory_store

store = get_memory_store()
store.MAX_SESSIONS_PER_ENTITY = 50    # Change if needed
store.TTL_SECONDS = 86400             # 24 hours
```

### Correlation Window
```python
correlation = correlate_events(entity_id, window_seconds=21600)  # 6 hours
```

### Confidence Weights
Edit in `compute_confidence()`:
```python
confidence = (
    0.4 * lstm_score +              # 40% weight
    0.3 * rag_matches / 5.0 +       # 30% weight
    0.2 * correlation_depth / 4.0 + # 20% weight
    0.1 * threat_intel_score        # 10% weight
)
```

### Decision Thresholds
Edit in `decide_action()`:
```python
if confidence > 0.85:        # Change to 0.75 for more aggressive
    return "AUTO_REMEDIATE"
elif confidence > 0.6:       # Change to 0.5 for lower threshold
    return "ESCALATE_L2"
else:
    return "MONITOR"
```

## Troubleshooting

### Agent memory not persisting
- Check ThreadLocal isn't being reset between requests
- Verify FastAPI app is not spawning new processes
- Use `get_memory_store()` to access singleton

### Campaign pattern not detected
- Check event_types match CAMPAIGN_PATTERNS keys (case-sensitive, uppercase)
- Verify sequence is long enough (min 2-4 events)
- Look at `combined_event_types` in correlation result

### Confidence score too low/high
- Check LSTM score (first 40% weight)
- Count RAG matches (should be ≤ 5 for full 30%)
- Verify correlation_depth (should be 1-4 range)
- Confirm threat_intel_score is normalized [0, 1]

### LLM explanation failing
- Check if llm_agent module is available
- Verify fallback explanation is used (doesn't cause errors)
- Check OpenRouter API key if using LLM

## Files Modified

- `backend/reasoning/agent_layer.py` — Complete rewrite (production-quality)
- `backend/main.py` — Already has `/investigate/agent` endpoint (unchanged)
- `backend/schemas.py` — Already has AgentAnalysisResponse (unchanged)
- `frontend/app.js` — Enhanced renderAgentReport() function
- `frontend/style.css` — Added why-flagged styles
- `frontend/index.html` — Already has agent panel UI (unchanged)

## Next Steps

1. **Test the system** using the provided test scenarios
2. **Tune thresholds** based on your environment
3. **Monitor decision accuracy** and adjust weights if needed
4. **Integrate with SOAR/orchestration** for AUTO_REMEDIATE actions
5. **Extend campaign patterns** with custom attack chains

---

**Version:** 3.0.0 (Agent Layer Upgrade)  
**Date:** 2024  
**Status:** Production-Ready
