# LLM-Powered SOC Analyst

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://reactjs.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.x-EE4C2C?logo=pytorch)](https://pytorch.org/)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-RAG-orange)](https://www.trychroma.com/)
[![Version](https://img.shields.io/badge/Version-7.0.0-brightgreen)]()
[![Architecture](https://img.shields.io/badge/Architecture-Agent--Oriented-purple)]()

> **The Agent is the central intelligence.** Not a pipeline. Not a chain of fixed steps.  
> An autonomous SOC Investigation Manager that observes, reasons, plans, executes specialists on-demand, evaluates evidence, fuses memory, decides, and explains — all without human intervention.

---

## Architecture Overview

```
Raw Logs
   │
   ▼
[Log Normalizer]  ← Regex + JSON parser, 10 event types
   │
   ▼
[Event Extractor] ← Rule-based classifier
   │
   ▼
[Session Builder] ← Entity-scoped session window
   │
   ▼
┌──────────────────────────────────────────────────────────────┐
│                     AGENT ORCHESTRATOR                        │
│  (ReAct-style: Observe → Think → Plan → Execute → Evaluate   │
│               → Fuse → Decide → Explain)                     │
│                                                              │
│  ┌─────────────────┐    ┌──────────────────┐                │
│  │ Behavior Analyst│    │ Pattern Analyst   │  Always run    │
│  │ (LSTM Autoenc.) │    │ (8 heuristics)   │                │
│  └─────────────────┘    └──────────────────┘                │
│                                                              │
│  ┌─────────────────┐    ┌──────────────────┐  On MEDIUM+    │
│  │ Threat Context  │    │ IOC Analyst       │  suspicion     │
│  │ (IP/hash rep.)  │    │ (regex extractor) │                │
│  └─────────────────┘    └──────────────────┘                │
│                                                              │
│  ┌──────────────────────────────────────────┐  On HIGH+      │
│  │ MITRE Knowledge (ChromaDB RAG)           │  suspicion     │
│  └──────────────────────────────────────────┘                │
│                                                              │
│  ┌──────────────────────────────────────────┐  Auto-escalate │
│  │ Investigation Memory (cross-session)     │  always        │
│  └──────────────────────────────────────────┘                │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
[Evidence Fusion] ← Weighted evidence board
   │
   ▼
[Decision Engine] ← Deterministic severity + risk (NO LLM)
   │
   ▼
[LLM Explanation] ← GPT-OSS 120B narrative + playbook
   │
   ▼
[Enterprise SOC Console] ← React frontend
```

---

## The 8-Phase Agent Orchestration Loop

| # | Phase | What Happens |
|---|-------|-------------|
| 1 | **OBSERVE** | Collect raw facts from the processed session. No reasoning yet. |
| 2 | **THINK** | Compute a deterministic suspicion level (LOW / MEDIUM / HIGH / CRITICAL) from event ratios and anomaly hints. |
| 3 | **PLAN** | Dynamically select which specialists to invoke. Low suspicion → skip expensive tools. |
| 4 | **EXECUTE** | Run only the planned specialists in sequence. Collect structured `EvidenceItem` objects. |
| 5 | **EVALUATE** | Assess intermediate evidence. If patterns detected but MITRE not queried → escalate. |
| 6 | **FUSE** | Merge current evidence with cross-session Investigation Memory. Discover campaign patterns. |
| 7 | **DECIDE** | Deterministic formula computes Severity, Confidence, Risk Score, and Action. LLM never decides. |
| 8 | **EXPLAIN** | LLM generates human-readable narrative and structured response playbook. |

---

## Dynamic Tool Selection (Key Innovation)

The Agent **never runs all tools every time**. It plans based on real signals:

| Suspicion Level | Planned Specialists |
|-----------------|---------------------|
| **LOW** | Behavior Analyst, Pattern Analyst |
| **MEDIUM** | + Threat Context, IOC Analyst |
| **HIGH** | + MITRE Knowledge |
| **CRITICAL** | All 5 + auto-escalation logic |

**Mid-investigation escalation** — if a campaign pattern is detected after EXECUTE, MITRE Knowledge is automatically escalated even if it was originally skipped.

---

## Project Structure

```
LLM_Powered_SOC_ANALYST/
│
├── backend/
│   ├── main.py                        # FastAPI app, all endpoints
│   ├── schemas.py                     # Pydantic models (AgentAnalysisResponse)
│   ├── models/
│   │   └── lstm_model.py              # PyTorch LSTM sequence autoencoder
│   ├── processing/
│   │   ├── log_normalizer.py          # Raw log → structured events
│   │   └── event_extractor.py         # Rule-based event classifier (10 types)
│   ├── rag/
│   │   ├── rag_engine.py              # ChromaDB retrieval engine
│   │   ├── build_mitre_db.py          # Build ChromaDB from MITRE ATT&CK JSON
│   │   └── rebuild_mitre_db.py        # Rebuild/refresh script
│   └── reasoning/
│       ├── agent_layer.py             # ⭐ 8-phase Agent Orchestrator (main logic)
│       ├── agent_tools.py             # Specialist implementations + ToolResult
│       └── llm_agent.py              # OpenRouter LLM inference wrapper
│
├── soc-react-frontend/
│   └── src/
│       ├── constants/
│       │   └── scenarios.js           # AGENT_PHASES, SPECIALISTS, SCENARIOS
│       ├── api/
│       │   └── socApi.js              # API client (investigateAgent, getDashboardStats)
│       ├── pages/
│       │   ├── Dashboard/
│       │   │   └── Dashboard.jsx      # System stats, specialist cards, ReAct flow
│       │   ├── Investigate/
│       │   │   ├── Investigate.jsx    # Main investigation page
│       │   │   └── components/
│       │   │       ├── InvestigationConsole.jsx  # ⭐ New Enterprise SOC console
│       │   │       ├── AgentPhaseTracker.jsx     # Live 8-phase progress tracker
│       │   │       ├── LoadingState.jsx           # Agent orchestration loading UI
│       │   │       └── EmptyState.jsx
│       │   └── Evaluate/              # Model evaluation dashboard
│       └── context/
│           └── AuthContext.jsx        # JWT auth context
│
├── tests/
│   └── test_agent.py                  # Agent integration tests
├── .env                               # Environment variables (not committed)
└── readme.md                          # This file
```

---

## Setup & Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- Conda / venv (recommended)
- OpenRouter API key (free tier works)

### 1. Clone & Backend Setup

```bash
git clone https://github.com/YOUR_USERNAME/LLM_Powered_SOC_ANALYST.git
cd LLM_Powered_SOC_ANALYST

# Create and activate environment
conda create -n rag_env python=3.11
conda activate rag_env

# Install dependencies
pip install fastapi uvicorn torch chromadb sentence-transformers \
            python-jose passlib python-multipart openai requests pydantic
```

### 2. Environment Variables

Create a `.env` file in the project root:

```env
OPENROUTER_API_KEY=sk-or-v1-YOUR_KEY_HERE
OPENROUTER_MODEL=openai/gpt-oss-120b:free
JWT_SECRET_KEY=your-super-secret-key-here
```

### 3. Build the MITRE ATT&CK Knowledge Base

```bash
python -m backend.rag.build_mitre_db
```

This downloads the MITRE ATT&CK enterprise matrix and indexes ~500+ techniques into ChromaDB.

### 4. Start the Backend

```bash
uvicorn backend.main:app --reload
```

Backend runs at `http://localhost:8000`

### 5. Start the Frontend

```bash
cd soc-react-frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`

### Default Login Credentials

```
Username: analyst
Password: password123
```

---

## Frontend Pages

### `/dashboard` — System Overview
- Live agent orchestration phase animator
- Specialist registry cards with roles
- System component status (LSTM, ChromaDB, LLM API)
- Confidence scoring formula display
- Cross-session memory statistics

### `/investigate` — Autonomous Investigation Console
- 6 preloaded attack scenarios (Brute Force, Lateral Movement, Ransomware, etc.)
- Raw log paste / file upload
- Entity ID input for cross-session correlation
- **Agent Phase Tracker** — live 8-phase progress indicator
- **Investigation Console** showing:
  - Severity / Risk Score / Confidence / Decision header
  - Investigation Hypothesis + Strategy (planned vs. skipped specialists)
  - Evidence Board (accumulated fact cards)
  - Cross-Session Memory panel (correlation depth)
  - Executive Narrative (LLM-generated)
  - Response Playbook (IMMEDIATE / SHORT_TERM actions)
  - Specialist Execution Log (per-tool timing)

### `/evaluate` — Model Evaluation
- LSTM model performance metrics
- Confusion matrix visualization
- Precision / Recall / F1 scores

---

## API Reference

### Authentication

```bash
POST /auth/login
Body: { "username": "analyst", "password": "password123" }
Returns: { "access_token": "...", "token_type": "bearer" }
```

### Agent Investigation (Primary Endpoint)

```bash
POST /investigate/agent
Headers: Authorization: Bearer <token>
Body: {
  "raw_logs": "2024-01-15 03:22:11 sshd Failed password...",
  "entity_id": "host-192.168.1.45"   # optional, for cross-session correlation
}

Returns: AgentAnalysisResponse {
  # Core Detection
  "severity": "CRITICAL",
  "confidence": 0.847,
  "decision": "AUTO_REMEDIATE",
  "risk_score": 82.3,
  "incident_type": "Brute Force Attack Attempt",

  # Agent Investigation State (NEW in v7.0)
  "investigation_status": "COMPLETED",
  "suspicion_level": "CRITICAL",
  "investigation_hypothesis": "High density suspicious activity...",
  "planned_tools": ["Behavior Analyst", "Pattern Analyst", "Threat Context", "IOC Analyst", "MITRE Knowledge"],
  "completed_tools": [...],
  "skipped_tools": [],
  "escalation_tools": [],
  "evidence_board": [
    { "description": "Behavioral deviation at 0.89", "source": "Behavior Analyst", "contribution": 0.31 },
    ...
  ],

  # Evidence
  "mitre_mappings": ["T1110", "T1078"],
  "compound_mitre_mappings": ["T1110", "T1078", "T1021"],
  "why_flagged": [...],
  "correlation_depth": 3,

  # LLM Output
  "llm_explanation": "...",
  "response_playbook": { "name": "...", "IMMEDIATE": [...], "SHORT_TERM": [...] },

  # Agent Trace
  "reasoning_trace": [...],
  "tool_results": [...],
  "total_analysis_ms": 8234.5
}
```

### Health & Stats

```bash
GET /health           # System health + orchestration phases list
GET /dashboard/stats  # Full system stats for dashboard
GET /evaluate         # Model evaluation metrics
```

---

## Testing

```bash
# Run agent integration test (benign + attack scenarios)
python -m pytest tests/test_agent.py -v

# Or directly
python tests/test_agent.py
```

Tests verify:
- Benign sessions → LOW suspicion, few specialists used, MONITOR decision
- Attack sessions → HIGH/CRITICAL suspicion, full specialist set, ESCALATE/AUTO_REMEDIATE decision
- Cross-session memory triggers multi-session correlation

---

## Key Design Decisions

### Decision is Never LLM-Generated
The `DECIDE` phase uses a deterministic formula:
```
Confidence = 0.35·LSTM + 0.20·RAG + 0.15·Correlation + 0.10·TI + 0.10·Pattern + 0.10·IOC
Severity   = threshold-based on anomaly score × correlation depth × MITRE count
Risk Score = anomaly·35 + confidence·25 + TI·20 + pattern·10 + correlation·10
Decision   = CRITICAL+conf≥0.5 → AUTO_REMEDIATE | HIGH/CRITICAL → ESCALATE_L2 | else MONITOR
```

The LLM **only writes the narrative** after the decision has been made.

### Investigation Memory is First-Class
The `EntityMemoryStore` persists sessions in-process with TTL (24h). Every investigation automatically queries and updates memory. This allows the agent to correlate a single suspicious login with a pattern discovered 6 hours ago.

### Specialists are Stateless Tools
Each specialist (`agent_tools.py`) takes inputs and returns a `ToolResult`. They have no state. The `InvestigationState` object in `agent_layer.py` is the single source of truth for the investigation's running context.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Backend API | FastAPI + Uvicorn |
| Auth | JWT (python-jose + passlib) |
| LSTM Model | PyTorch (sequence autoencoder) |
| Vector DB | ChromaDB + sentence-transformers |
| Threat Intel | Custom IP/hash reputation DB |
| LLM | OpenRouter → GPT-OSS 120B (free tier) |
| Frontend | React 18 + Vite |
| Styling | Vanilla CSS Modules (dark theme) |
| Icons | Lucide React |

---

## Security Notes

- Rotate `JWT_SECRET_KEY` before any production deployment
- The `.env` file is in `.gitignore` — never commit API keys
- The default credentials (`analyst` / `password123`) are for local demo only
- CORS is configured for `localhost:5173` — update `origins` in `main.py` for production

---

## Roadmap

- [ ] Real-time WebSocket investigation feed
- [ ] Persistent SQLite/PostgreSQL backend for historical investigations
- [ ] Multi-tenant entity isolation
- [ ] MITRE ATT&CK Navigator integration
- [ ] Streaming LLM narrative (token-by-token)
- [ ] Slack/Teams alert integration for `AUTO_REMEDIATE` decisions

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

- [MITRE ATT&CK®](https://attack.mitre.org/) — Threat knowledge base
- [ChromaDB](https://www.trychroma.com/) — Open-source vector database
- [OpenRouter](https://openrouter.ai/) — LLM API aggregator
- [FastAPI](https://fastapi.tiangolo.com/) — Modern Python web framework
