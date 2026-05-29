<div align="center">

# 🛡️ LLM-Powered SOC Analyst

<br>

**Autonomous AI-Driven Security Investigation Platform**

ReAct-style multi-tool reasoning, LSTM anomaly detection, MITRE ATT&CK RAG retrieval, automated IOC extraction, and response playbook generation — built for production SOC workflows.

<br>

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)](https://pytorch.org/)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-0.5-6A1B9A?style=for-the-badge&logo=databricks&logoColor=white)](https://www.trychroma.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Enterprise-ED1C24?style=for-the-badge&logo=shield&logoColor=white)](https://attack.mitre.org/)

<br>

[![Status](https://img.shields.io/badge/Status-Production_Ready-00C853?style=flat-square)](#)
[![License](https://img.shields.io/badge/License-MIT-FFC107?style=flat-square)](#-license)
[![GitHub Stars](https://img.shields.io/github/stars/akash4426/LLM_Powered_SOC_ANALYST?style=flat-square&logo=github)](https://github.com/akash4426/LLM_Powered_SOC_ANALYST)

<br>

[🚀 Quick Start](#-quick-start) • [✨ Features](#-key-features) • [🏗️ Architecture](#%EF%B8%8F-system-architecture) • [📡 API](#-api-reference) • [📚 Docs](#-documentation)

</div>

---

## 📑 Quick Navigation

| Section | Description |
|---------|-------------|
| [🚀 Quick Start](#-quick-start) | Get the system running in 5 minutes |
| [✨ Features](#-key-features) | Core capabilities and innovations |
| [🏗️ Architecture](#%EF%B8%8F-system-architecture) | System design and component overview |
| [🔄 Pipeline](#-investigation-pipeline) | Step-by-step analysis flow |
| [🤖 Agent Layer](#-agentic-ai-layer-v40) | ReAct reasoning engine deep-dive |
| [📡 API Reference](#-api-reference) | Endpoint documentation |
| [🎮 Frontend](#-frontend) | Web UI for investigations |
| [🛠️ Tech Stack](#%EF%B8%8F-tech-stack) | Technologies used |
| [📚 Documentation](#-documentation) | Detailed technical guides |

---

## 🚀 Quick Start

### Prerequisites
- **Python** 3.10+
- **Docker** & **Docker Compose** (optional)
- **OpenAI API Key** (for LLM features)

### Installation (Local)

```bash
# Clone repository
git clone https://github.com/akash4426/LLM_Powered_SOC_ANALYST.git
cd LLM_Powered_SOC_ANALYST

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # macOS/Linux
# or: .venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Download LSTM model
python scripts/download_models.py

# Set up environment
cp .env.example .env
# Edit .env with your OpenAI API key

# Initialize RAG database (MITRE ATT&CK)
python backend/rag/build_mitre_db.py

# Start the API server
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Open frontend in browser
# http://localhost:8000/frontend/index.html
```

### Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# API runs on http://localhost:8000
# Frontend: http://localhost:8000/frontend/index.html
```

---

## ✨ Key Features

### 🧠 Multi-Stage Analysis Pipeline

```
RAW LOGS
   ↓
[1] Log Normalization        → Regex + JSON parsing
   ↓
[2] Event Classification     → Rule-based extraction (10 event types)
   ↓
[3] LSTM Anomaly Detection   → PyTorch sequence autoencoder
   ↓
[4] Threat Intel Enrichment  → IP/hash/command reputation lookup
   ↓
[5] MITRE RAG Retrieval      → ChromaDB semantic search
   ↓
[6] LLM Investigation        → Structured incident analysis
   ↓
[7] Attack Graph Building    → NetworkX kill-chain reconstruction
   ↓
[8] Agentic AI Reasoning     → ReAct multi-tool investigation ⭐ NEW
   ↓
STRUCTURED INCIDENT REPORT + RESPONSE PLAYBOOK
```

### 🤖 Agentic AI Layer (v4.0) — ReAct Reasoning Engine

The agent operates via a **6-step autonomous reasoning loop** inspired by the [ReAct paradigm](https://arxiv.org/abs/2210.03629):

| Step | Phase | Description |
|------|-------|-------------|
| 1 | **OBSERVE** | Collect events, identify entity, build session context |
| 2 | **THINK** | Evaluate suspicious signals, select analysis strategy |
| 3 | **ACT** | Execute 5 specialized tools in parallel |
| 4 | **SYNTHESIZE** | Merge tool outputs, run cross-session correlation, build hypotheses |
| 5 | **DECIDE** | Compute confidence, severity, risk score, and autonomous decision |
| 6 | **EXPLAIN** | Generate LLM narrative + select response playbook |

**6 Modular Investigation Tools:**

| Tool | Function | Confidence Weight |
|------|----------|-------------------|
| `anomaly_score` | LSTM behavioral anomaly scoring | 35% |
| `rag_lookup` | MITRE ATT&CK semantic retrieval | 20% |
| `threat_intel` | IP/hash/command reputation enrichment | 10% |
| `pattern_match` | Heuristic pattern detection (8 attack types) | 10% |
| `ioc_extractor` | Automated IOC extraction from raw logs | 10% |
| `playbook` | Severity-adaptive response playbook generation | — |

**Full Explainability:** Every investigation produces a `reasoning_trace` — a step-by-step log of tool invocations, execution times, and intermediate decisions.

### 🔎 8 Heuristic Attack Patterns

| Pattern | Detection Logic | MITRE Mapping |
|---------|----------------|---------------|
| **Brute Force** | 3+ failed logins from same source | T1110, T1110.001 |
| **Suspicious Execution Chain** | Mimikatz / PowerShell / known evil tools | T1059, T1059.001 |
| **Privilege Escalation Spike** | 2+ privilege escalation events | T1548, T1548.002 |
| **Data Staging** | File access + compression + outbound connection | T1074, T1560 |
| **Credential Harvesting** | LSASS dump / mimikatz / pass-the-hash | T1003, T1003.001 |
| **Defense Evasion Chain** | Shadow copy delete + AV disable | T1070, T1562 |
| **Recon to Exploit** | Reconnaissance → execution → priv esc | T1595, T1059, T1548 |
| **C2 Communication** | Beacon / C2 keywords + outbound connections | T1071, T1071.001 |

### 🧩 Automated IOC Extraction

Parses raw log text to automatically extract:
- **IPv4 / IPv6 addresses** — with RFC1918 private range filtering
- **Domain names** — with benign domain allowlist
- **File hashes** — MD5, SHA1, SHA256, hash-like prefixes
- **URLs** — full HTTP/HTTPS with path
- **Email addresses** and **file paths** (Windows + Unix)

Each IOC is classified as `SUSPICIOUS`, `PRIVATE`, or `BENIGN` with context snippets.

### 📋 Response Playbooks

7 severity-adaptive playbooks with prioritized response actions:

| Playbook | Trigger | SLA |
|----------|---------|-----|
| Brute Force Response | LOGIN pattern | 15 min |
| Lateral Movement Response | LATERAL_MOVE pattern | 15 min |
| Data Exfiltration Response | EXFIL pattern | 15 min |
| Ransomware Response | Ransomware indicators | 5 min |
| Privilege Escalation Response | PRIV_ESC pattern | 30 min |
| Defense Evasion Response | Evasion indicators | 30 min |
| Generic Incident Response | Fallback | 60 min |

Each includes `IMMEDIATE`, `SHORT_TERM`, and `LONG_TERM` prioritized actions, plus escalation criteria.

### 🔍 Detection Capabilities

| Detection Method | How It Works | Accuracy |
|-----------------|------------|----------|
| **LSTM Anomaly** | Sequence autoencoder identifies abnormal patterns | ~92% on test set |
| **Rule-Based Classification** | Regex patterns extract 10 security event types | 100% (deterministic) |
| **MITRE RAG** | Semantic search links events to ATT&CK techniques | Context-aware |
| **Threat Intel** | Reputation DB for IPs, commands, file hashes | Signature-based |
| **LLM Analysis** | OpenAI generates structured investigation narrative | Contextual & explainable |
| **Pattern Detection** | 8 heuristic rules with multi-signal scoring | Campaign-level insights |
| **IOC Extraction** | Automated indicator parsing from raw logs | Regex + classification |
| **Agent Correlation** | Cross-session attack pattern matching | Multi-session intelligence |

### 🎯 SOC-Ready Features

- ✅ **JWT Authentication** — Secure API access
- ✅ **Multi-Format Log Support** — Syslog, JSON, CSV, Windows Event Log
- ✅ **Structured Output** — Machine-readable incident reports
- ✅ **Entity Memory** — 24-hour session history with TTL
- ✅ **Real-Time Analysis** — Sub-second response
- ✅ **Full Explainability** — Reasoning trace + why_flagged for every decision
- ✅ **Automated IOC Extraction** — IPs, domains, hashes, URLs parsed automatically
- ✅ **Response Playbooks** — Severity-adaptive containment & recovery actions
- ✅ **Autonomous Decisions** — AUTO_REMEDIATE | ESCALATE_L2 | MONITOR
- ✅ **Risk Scoring** — Unified 0–100 risk score across all signals
- ✅ **SOAR Integration** — Auto-remediation hooks
- ✅ **RESTful API** — OpenAPI/Swagger documentation

---

## 🏗️ System Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│                      FRONTEND (Web UI)                                │
│  Pipeline Animation · Agent Panel · IOC Table · Playbook · Trace     │
└────────────────────────────┬──────────────────────────────────────────┘
                             │ HTTP / JWT Auth
┌────────────────────────────▼──────────────────────────────────────────┐
│                    FASTAPI SERVER (Port 8000)                         │
│         Authentication · Investigation API · Health Check             │
└────────────────────────────┬──────────────────────────────────────────┘
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
  ┌──────────┐       ┌────────────┐       ┌────────────┐
  │ RAG DB   │       │  LSTM      │       │ Threat     │
  │ (Chroma) │       │ (PyTorch)  │       │ Intel DB   │
  └────┬─────┘       └─────┬──────┘       └─────┬──────┘
       │                   │                     │
       └───────────────────┼─────────────────────┘
                           ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    AGENTIC AI LAYER (ReAct Engine)                   │
  │                                                                     │
  │  ┌─────────────────────────────────────────────────────────────┐    │
  │  │ TOOL REGISTRY                                               │    │
  │  │                                                             │    │
  │  │  anomaly_score ─► LSTM behavioral scoring                   │    │
  │  │  rag_lookup    ─► MITRE ATT&CK semantic search              │    │
  │  │  threat_intel  ─► IP/hash/command reputation                │    │
  │  │  pattern_match ─► 8 heuristic attack patterns               │    │
  │  │  ioc_extractor ─► Automated indicator parsing               │    │
  │  │  playbook      ─► Severity-adaptive response                │    │
  │  └─────────────────────────────────────────────────────────────┘    │
  │                                                                     │
  │  OBSERVE → THINK → ACT → SYNTHESIZE → DECIDE → EXPLAIN             │
  │                                                                     │
  │  Outputs: reasoning_trace, risk_score, confidence, decision,        │
  │           iocs_extracted, response_playbook, llm_explanation         │
  └─────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Investigation Pipeline

### Stage 1: Log Ingestion & Normalization
- Accepts raw logs: Syslog, JSON, CSV, Windows Event Log
- Regex-based parsing into structured events
- Timestamp normalization to ISO-8601

### Stage 2: Event Classification
Extracts 10 security event types:
```
NORMAL, LOGIN, FILE_ACCESS, OUTBOUND_CONNECTION, RECONNAISSANCE,
PRIVILEGE_ESCALATION, SUSPICIOUS_EXECUTION, LATERAL_MOVEMENT,
DEFENSE_EVASION, EXFILTRATION
```

### Stage 3: Behavioral Analysis (LSTM)
- PyTorch autoencoder trained on normal sequences
- Outputs anomaly score [0, 1]
- Identifies deviation from baseline behavior

### Stage 4: Threat Intelligence Enrichment
- Queries reputation DB for IPs, commands, file hashes
- Returns risk scores and threat categories

### Stage 5: MITRE ATT&CK Retrieval (RAG)
- Semantic search via ChromaDB + HuggingFace embeddings
- Returns technique descriptions and tactics

### Stage 6: LLM Investigation
- Structures incident analysis with expert SOC analyst rules
- Generates narrative explanations with hallucination prevention

### Stage 7: Attack Graph Reconstruction
- NetworkX builds kill-chain visualization
- Maps events to kill-chain stages

### Stage 8: Agentic AI Reasoning ⭐
- 6-step ReAct reasoning loop
- 6 modular tools with full execution trace
- Cross-session correlation with entity memory
- Campaign pattern detection (7 attack campaigns)
- Automated IOC extraction
- Severity-adaptive response playbooks
- Autonomous decision: AUTO_REMEDIATE | ESCALATE_L2 | MONITOR

---

## 🤖 Agentic AI Layer (v4.0)

### ReAct Reasoning Loop

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│   ┌──────────┐    ┌──────────┐    ┌──────────────────────┐  │
│   │ OBSERVE  │───►│  THINK   │───►│        ACT           │  │
│   │          │    │          │    │                      │  │
│   │ Collect  │    │ Strategy │    │ anomaly_score        │  │
│   │ events   │    │ selection│    │ pattern_match        │  │
│   └──────────┘    └──────────┘    │ rag_lookup           │  │
│                                   │ threat_intel         │  │
│   ┌──────────┐    ┌──────────┐    │ ioc_extractor        │  │
│   │ EXPLAIN  │◄───│  DECIDE  │◄───└──────────┬───────────┘  │
│   │          │    │          │               │              │
│   │ LLM      │    │ Risk     │    ┌──────────▼───────────┐  │
│   │ narrative │    │ scoring  │◄───│    SYNTHESIZE        │  │
│   │ playbook │    │ decision │    │                      │  │
│   └──────────┘    └──────────┘    │ Merge tool outputs   │  │
│                                   │ Cross-session corr.  │  │
│                                   │ Hypothesis building  │  │
│                                   └──────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Confidence Scoring Formula

```
confidence = (0.35 × LSTM_score)
           + (0.20 × RAG_match_ratio)
           + (0.15 × correlation_depth_ratio)
           + (0.10 × threat_intel_score)
           + (0.10 × pattern_score)
           + (0.10 × IOC_count_ratio)
```

### Risk Score Calculation

```
risk_score = (anomaly × 35) + (confidence × 25) + (TI_score × 20)
           + (pattern_score × 10) + (correlation_depth × 10)
```

### Campaign Pattern Detection

The agent detects 7 multi-stage attack campaigns through event sequence matching:

| Campaign | Event Sequence |
|----------|---------------|
| Full Kill Chain | LOGIN → PRIV_ESC → LATERAL_MOVE → EXFILTRATION |
| Privilege Escalation | LOGIN → PRIV_ESC → SUSPICIOUS_EXEC |
| APT Lateral Movement | RECON → LATERAL_MOVE → EXFILTRATION |
| Ransomware Deployment | DEFENSE_EVADE → SUSPICIOUS_EXEC → EXFILTRATION |
| Brute Force Escalation | LOGIN → LOGIN → PRIV_ESC |
| Recon to Exploit | RECON → SUSPICIOUS_EXEC → PRIV_ESC |
| Credential Theft | LOGIN → SUSPICIOUS_EXEC → EXFILTRATION |

---

## 📡 API Reference

### Authentication
```bash
# Get token
curl -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "password123"}'

# Use in request
curl -X POST http://localhost:8000/investigate \
  -H "Authorization: Bearer <token>" \
  -d '{"logs": "..."}'
```

### Main Endpoints

#### `POST /investigate`
Full pipeline analysis (stages 1–7)

```bash
curl -X POST http://localhost:8000/investigate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"logs": "raw security logs here"}'
```

#### `POST /investigate/agent` ⭐
Full pipeline + Agentic AI reasoning (stages 1–8)

```bash
curl -X POST http://localhost:8000/investigate/agent \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": "2024-01-15 03:22:11 Failed password for admin from 185.220.101.5",
    "entity_id": "185.220.101.5"
  }'
```

**Response includes:**

| Field | Description |
|-------|-------------|
| `risk_score` | Unified 0–100 risk score |
| `severity` | CRITICAL \| HIGH \| MEDIUM \| LOW |
| `confidence` | Evidence-based score [0, 1] |
| `decision` | AUTO_REMEDIATE \| ESCALATE_L2 \| MONITOR |
| `reasoning_trace` | Step-by-step tool execution log |
| `tool_results` | Individual tool outputs with timing |
| `iocs_extracted` | Parsed IPs, domains, hashes, URLs |
| `response_playbook` | Prioritized response actions |
| `campaign_pattern` | Detected multi-stage attack pattern |
| `compound_mitre_mappings` | MITRE techniques from compound analysis |
| `correlated_timeline` | Chronological attack event sequence |
| `llm_explanation` | LLM-generated incident narrative |

#### `GET /health`
System status check

#### `POST /auth/token`
Get JWT authentication token

---

## 🎮 Frontend

**Interactive Web UI** at `frontend/index.html`

### Features
- 📋 **Scenario Picker** — Pre-loaded brute force, lateral movement, exfiltration, ransomware scenarios
- 📝 **Raw Log Input** — Paste, type, or drag-and-drop file upload (.log, .txt, .csv, .json)
- 🔧 **Agent Mode Toggle** — Enables cross-session correlation and ReAct reasoning
- 📊 **8-Stage Pipeline Animation** — Real-time progress through all analysis stages
- 📈 **Agent Intelligence Panel:**
  - Compound anomaly score with visual bar
  - Risk score (0–100) with color-coded indicator
  - Correlation depth and campaign pattern
  - Decision recommendation (AUTO_REMEDIATE / ESCALATE_L2 / MONITOR)
  - Analysis timing breakdown
- 🧩 **IOC Table** — Extracted indicators with type badges and status classification
- 📋 **Response Playbook** — Priority-tagged actions with escalation criteria
- 🔍 **Reasoning Trace** — Color-coded timeline of the 6-step agent reasoning process
- 🔗 **Attack Graph** — Kill-chain path visualization
- 📊 **Correlated Timeline** — Cross-session event sequence
- 📄 **Raw Output** — Full JSON response for debugging

---

## 🛠️ Tech Stack

### Backend
| Component | Technology |
|-----------|-----------|
| **API Framework** | FastAPI |
| **Authentication** | JWT (PyJWT) |
| **LSTM Model** | PyTorch |
| **RAG Database** | ChromaDB + HuggingFace Embeddings |
| **LLM Integration** | OpenAI API via OpenRouter |
| **Graph Analysis** | NetworkX |
| **Agent Engine** | Custom ReAct reasoning loop |
| **Data Processing** | Pandas, NumPy |

### Frontend
| Component | Technology |
|-----------|-----------|
| **UI Framework** | Vanilla HTML5/CSS3/JavaScript |
| **Design** | IBM Plex Mono + dense operator console aesthetic |
| **Visualization** | CSS Grid + Flexbox + animated pipeline |

### DevOps
| Component | Technology |
|-----------|-----------|
| **Containerization** | Docker |
| **Orchestration** | Docker Compose |
| **Hosting** | Render / Hugging Face Spaces |

---

## 📊 Project Structure

```
LLM_Powered_SOC_ANALYST/
├── backend/
│   ├── main.py                      # FastAPI application & pipeline orchestration
│   ├── schemas.py                   # Pydantic request/response models
│   ├── incident_report.py           # Incident generation
│   ├── api/
│   │   └── auth.py                  # JWT authentication
│   ├── ingestion/
│   │   ├── log_normalizer.py        # Log parsing & normalization
│   │   └── log_parser.py            # Format-specific parsers
│   ├── processing/
│   │   ├── event_extractor.py       # Event classification (10 types)
│   │   ├── session_builder.py       # Session aggregation
│   │   ├── threat_intel.py          # Reputation lookups
│   │   ├── pattern_detector.py      # ⭐ 8 heuristic attack patterns
│   │   └── ioc_extractor.py         # ⭐ Automated IOC extraction (NEW)
│   ├── models/
│   │   ├── lstm_model.py            # PyTorch autoencoder
│   │   └── lstm_anomaly.pt          # Pre-trained weights
│   ├── rag/
│   │   ├── build_mitre_db.py        # Build ChromaDB from MITRE data
│   │   └── rag_engine.py            # Semantic search engine
│   ├── reasoning/
│   │   ├── llm_agent.py             # LLM integration (OpenRouter)
│   │   ├── agent_layer.py           # ⭐ ReAct reasoning engine (v4.0)
│   │   ├── agent_tools.py           # ⭐ 6 modular investigation tools (NEW)
│   │   └── playbooks.py             # ⭐ Response playbook engine (NEW)
│   ├── utils/
│   │   └── json_parser.py           # LLM output parsing & validation
│   └── evaluation/
│       └── evaluator.py             # Evaluation metrics
├── frontend/
│   ├── index.html                   # Main UI with agent visualizations
│   ├── app.js                       # JS logic + IOC/playbook/trace renderers
│   ├── style.css                    # Dense SOC terminal styling
│   └── rag_test.html                # RAG testing page
├── scripts/
│   ├── download_models.py           # Download model weights
│   ├── train_lstm.py                # Train LSTM autoencoder
│   ├── evaluate_lstm.py             # Evaluate model performance
│   └── generate_dataset.py          # Create training datasets
├── data/
│   ├── enterprise-attack.json       # MITRE ATT&CK dataset
│   └── sample_logs.json             # Example logs
├── models/
│   └── lstm_anomaly.pt              # Pre-trained LSTM model
├── vector_db/
│   └── chroma.sqlite3               # ChromaDB storage
├── Dockerfile                       # Docker config
├── docker-compose.yml               # Docker Compose
├── requirements.txt                 # Dependencies
├── .env.example                     # Environment template
└── README.md                        # This file
```

---

## ⚙️ Configuration

### Environment Variables (`.env`)

```bash
# LLM API (OpenRouter)
OPEN_ROUTER_API=sk-or-...
OPENROUTER_MODEL=openai/gpt-4o-mini

# System
DEBUG=false
LOG_LEVEL=INFO
JWT_SECRET=your-secret-key-change-in-production
```

### Demo Credentials

```
Username: analyst    Password: password123
Username: admin      Password: admin123
Username: soc_team   Password: team123
```

⚠️ **Change these in production!**

---

## 📚 Documentation

For detailed technical documentation, see:

- **[Agent Layer Architecture](docs/AGENT_LAYER_UPGRADE.md)** — ReAct reasoning engine design
- **[API Specification](docs/API_REFERENCE.md)** — Complete endpoint documentation
- **[Deployment Guide](docs/DEPLOYMENT.md)** — Docker, Kubernetes, cloud
- **[Contributing](CONTRIBUTING.md)** — Developer setup

---

## 🚨 System Requirements

### Minimum
- **CPU**: 2+ cores
- **RAM**: 4 GB
- **Disk**: 2 GB
- **Python**: 3.10+

### Recommended
- **CPU**: 4+ cores
- **RAM**: 8 GB
- **GPU**: NVIDIA CUDA 11.8+ (optional)
- **Disk**: 10 GB

---

## 🗺️ Roadmap

### Current (v4.0) ✅
- ✅ ReAct-style agentic reasoning engine
- ✅ 6 modular investigation tools
- ✅ 8 heuristic attack pattern detectors
- ✅ Automated IOC extraction
- ✅ Response playbook generation
- ✅ Reasoning trace explainability
- ✅ Risk scoring (0–100)
- ✅ Frontend visualization (IOC table, playbook, trace timeline)

### Previous (v3.0) ✅
- ✅ Agent correlation layer
- ✅ Campaign pattern detection
- ✅ Evidence-based confidence scoring

### Next (v4.1)
- 🔄 Real-time log streaming via WebSockets
- 🔄 YARA rule integration
- 🔄 Advanced visualization (D3.js attack graphs)

### Future (v5.0)
- 🔜 Multi-agent collaboration
- 🔜 Kubernetes operator
- 🔜 Multi-tenant SaaS
- 🔜 SIEM integrations (Splunk, Elastic, QRadar)

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/akash4426/LLM_Powered_SOC_ANALYST.git
cd LLM_Powered_SOC_ANALYST
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 📧 Contact & Support

- **Issues**: [GitHub Issues](https://github.com/akash4426/LLM_Powered_SOC_ANALYST/issues)
- **Email**: [akash4426@gmail.com](mailto:akash4426@gmail.com)

---

<div align="center">

**Made with ❤️ for the cybersecurity community**

[⬆ Back to top](#-llm-powered-soc-analyst)

</div>

---

---

# 🆕 v5.0 — React Frontend & RAG Accuracy Upgrade

> This section documents every change introduced in the v5.0 update.  
> Use it as a revision guide to quickly understand **what changed, why it changed, and how it fits the system**.

---

## 📑 v5.0 Change Index

| Change | Area | File(s) |
|--------|------|---------|
| [React Frontend](#-react-frontend-architecture) | Frontend | `soc-react-frontend/` |
| [RAG Query Enrichment](#-rag-query-enrichment-event_extractorpy) | Backend | `backend/processing/event_extractor.py` |
| [MMR Retrieval (RAG Engine)](#-mmr-retrieval-rag_enginepy) | Backend | `backend/rag/rag_engine.py` |
| [Reasoning Trace Fix](#-reasoning-trace-ui-fix) | Frontend | `ReportPanel.jsx` |
| [Favicon](#-favicon) | Frontend | `public/favicon.svg` |
| [Evaluate Section Removed](#-evaluate-section-removed) | Frontend | `App.jsx`, `Topbar.jsx` |

---

## ⚛️ React Frontend Architecture

The original `frontend/index.html + app.js` vanilla stack has been replaced with a fully featured **React 18 + Vite** application living in `soc-react-frontend/`.

### Why React?
The old vanilla frontend had all state in global DOM variables, making it impossible to add features like real-time loading states, collapsible sections, or per-component re-rendering without rewriting the whole file. React's component model solves this cleanly.

### Project Structure

```
soc-react-frontend/
├── index.html                        ← Vite entry (favicon, meta tags, fonts)
├── vite.config.js                    ← Vite config (port 5173)
├── public/
│   └── favicon.svg                   ← Custom SOC shield favicon
└── src/
    ├── main.jsx                      ← React DOM root
    ├── App.jsx                       ← Auth gate + page router
    ├── App.module.css                ← Splash screen
    ├── index.css                     ← Global design system (CSS variables)
    │
    ├── api/
    │   └── socApi.js                 ← Axios client with JWT interceptor
    │
    ├── constants/
    │   └── scenarios.js              ← Pre-loaded scenarios, pipeline steps, colors
    │
    ├── context/
    │   └── AuthContext.jsx           ← JWT auth state + API health polling
    │
    ├── components/
    │   └── Topbar/
    │       ├── Topbar.jsx            ← Nav bar (live clock, status, user chip)
    │       └── Topbar.module.css
    │
    └── pages/
        ├── Login/
        │   ├── Login.jsx             ← JWT login form + demo credentials
        │   └── Login.module.css
        │
        ├── Investigate/
        │   ├── Investigate.jsx       ← 3-panel investigation page
        │   ├── Investigate.module.css
        │   └── components/
        │       ├── EmptyState.jsx/.module.css    ← Idle placeholder
        │       ├── LoadingState.jsx/.module.css  ← Animated pipeline progress
        │       ├── PipelineProgress.jsx          ← Stub (inlined)
        │       └── ReportPanel.jsx/.module.css   ← Full incident report renderer
        │
        └── RagTest/
            ├── RagTest.jsx           ← MITRE ATT&CK RAG semantic search UI
            └── RagTest.module.css
```

### How to Run

```bash
cd soc-react-frontend
npm install
npm run dev          # → http://localhost:5173

# Backend must be running on port 8000 first:
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
```

### Design System (`index.css`)

All colors, fonts, and spacing live as CSS custom properties on `:root`:

```css
--bg-0: #050709;          /* page background */
--bg-1: #0a0d12;          /* panel background */
--cyan: #00d4ff;          /* primary accent */
--blue: #4488ff;          /* secondary accent */
--green: #00e676;         /* success / low severity */
--orange: #ff9800;        /* medium severity */
--red: #ff4444;           /* critical / errors */
--font-mono: 'JetBrains Mono', monospace;
```

### Authentication Flow

```
User loads app
   ↓
AuthContext checks localStorage for JWT token
   ↓
If no token → render <Login />
   ↓
User submits credentials → POST /auth/token
   ↓
Token stored in localStorage + AuthContext state
   ↓
Every API request automatically adds Authorization: Bearer <token>
   ↓
AuthContext polls GET /health every 10s → shows ONLINE/OFFLINE in Topbar
```

### Investigation Page — 3-Panel Layout

```
┌─────────────────┬──────────────────────────────┬─────────────────┐
│   LEFT PANEL    │       CENTER PANEL           │   RIGHT PANEL   │
│                 │                              │                 │
│ Scenario picker │ [idle]  → EmptyState         │ Event taxonomy  │
│ Log textarea    │ [run]   → LoadingState       │ Detection feed  │
│ Pipeline stack  │ [done]  → ReportPanel        │ Severity scale  │
│ Agent mode      │ [error] → Error + retry      │                 │
│                 │                              │                 │
│ [RUN ⌘↵]        │                              │                 │
└─────────────────┴──────────────────────────────┴─────────────────┘
```

**Left Panel — controls:**
- **Scenario Picker**: 4 pre-loaded attack scenarios (brute force, ransomware, lateral movement, APT). Clicking one fills the textarea automatically.
- **Log Textarea**: Terminal-styled with file count, char count footer. Accepts paste or file upload (`.log .txt .csv .json`).
- **Pipeline Stack**: Static reference table showing what each stage does.
- **Agent Mode Toggle**: When on, calls `POST /investigate/agent` (8-stage). When off, calls `POST /investigate` (7-stage).
- **Entity ID**: Optional — if supplied, the agent correlates across past sessions for that entity.

**Center Panel — states:**
- `idle` — ASCII art empty state with instructions.
- `loading` — Animated step list showing which pipeline stage is running, with elapsed timer.
- `success` — Full `ReportPanel` rendered from API response.
- `error` — Error message + retry button.

**Right Panel — reference:**
- **Event Taxonomy**: Color-coded list of all 10 event types with codes (EXFIL, EVADE, etc.).
- **Detection Log**: Live feed of system messages, info, and investigation events. Autoscrolls.
- **Severity Scale**: Reference card for CRITICAL / HIGH / MEDIUM / LOW with action guidance.

### API Client (`socApi.js`)

```javascript
// All calls go through this axios instance
const api = axios.create({ baseURL: 'http://localhost:8000' });

// Automatically attaches JWT to every request
api.interceptors.request.use(config => {
  const token = localStorage.getItem('soc_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Exported functions used by pages:
investigate(logs)                    // POST /investigate
investigateAgent(logs, entityId)     // POST /investigate/agent
ragTest(query, k)                    // POST /rag-test
healthCheck()                        // GET /health
login(username, password)            // POST /auth/token
```

### ReportPanel — Data Rendering

The `ReportPanel` component handles both standard (`/investigate`) and agent (`/investigate/agent`) responses:

```javascript
// Agent response structure:
{
  severity, risk_score, confidence, decision,   // top-level agent fields
  pipeline_report: {                             // standard pipeline output
    incident_id, kill_chain_path, mitre_techniques,
    threat_intel, rag_snippets, llm_explanation,
    recommended_response, attack_graph, ...
  },
  reasoning_trace,      // 6 ReAct steps
  iocs_extracted,       // IOC table data
  response_playbook,    // IMMEDIATE/SHORT_TERM/LONG_TERM actions
  correlated_timeline,  // cross-session events
  why_flagged,          // human-readable flag reasons
  campaign_pattern,     // detected attack campaign
}

// Standard response structure (no agent wrapper):
{
  incident_id, severity, anomaly_score, confidence,
  kill_chain_path, mitre_techniques, threat_intel,
  rag_snippets, llm_explanation, recommended_response,
  attack_graph, events_analyzed, session_count, ...
}
```

The component auto-detects which mode it's in via `agentMode` prop and renders/hides agent-specific sections accordingly.

---

## 🎯 RAG Query Enrichment (`event_extractor.py`)

### The Problem

The original `get_mitre_query()` function built a simple pipe-separated string of short MITRE hints:

```python
# OLD output (weak signal for embedder):
"T1562 Impair Defenses | T1059 Command and Scripting Interpreter"
```

A sentence-transformer embedding model like `all-MiniLM-L6-v2` works best with **full natural-language sentences**, not short IDs. The IDs alone don't give enough context for the embedding to find the most relevant ATT&CK technique documents.

### The Fix

Added `_MITRE_RICH_CONTEXT` — a dictionary mapping each event type to 2 expanded natural-language descriptions:

```python
_MITRE_RICH_CONTEXT: Dict[str, List[str]] = {
    SUSPICIOUS_EXEC: [
        "malicious code execution PowerShell mimikatz credential dumping LSASS",
        "T1059 command scripting interpreter T1003 OS credential dumping",
    ],
    LATERAL_MOVE: [
        "lateral movement remote services pass the hash SMB WMI PsExec",
        "T1021 remote services T1550 use alternate authentication material",
    ],
    # ... one entry per event type
}
```

`get_mitre_query()` now combines:
1. The short MITRE hint from the matched rule (e.g. `"T1562 Impair Defenses"`)
2. Both natural-language expansion phrases for that event type

Result for the same scenario:

```
# NEW output (rich semantic signal):
"T1562 Impair Defenses
 defense evasion shadow copy deletion antivirus disable log clearing
 T1562 impair defenses T1070 indicator removal T1485 data destruction
 T1059 Command and Scripting Interpreter
 malicious code execution PowerShell mimikatz credential dumping LSASS
 T1059 command scripting interpreter T1003 OS credential dumping"
```

This gives the embedding model a multi-sentence paragraph per event type, dramatically increasing the chance of matching the correct ATT&CK technique vectors in ChromaDB.

**Fallback logic** (when no typed events are detected):
1. Raw text of `high`/`critical` severity events
2. Raw text of any non-NORMAL events
3. Static string `"suspicious activity detection"`

---

## 🔍 MMR Retrieval (`rag_engine.py`)

### The Problem

The original engine used `similarity_search(query, k=3)`, which:
- Returned only 3 snippets (often not enough context for LLM)
- Could return near-duplicate snippets (e.g. 3 slightly different versions of the same T1059 paragraph)
- Had no diversity mechanism

### The Fix — Max Marginal Relevance (MMR)

MMR is an algorithm that picks results maximizing **both relevance AND diversity**:

```
MMR score = λ · relevance(doc, query) − (1−λ) · max_similarity(doc, selected_docs)
```

- `λ = 1.0` → pure relevance (same as similarity search)
- `λ = 0.0` → pure diversity
- `λ = 0.6` ← our setting (favours relevance but penalises near-duplicates)

**What changed in the code:**

```python
# OLD:
results = vector_db.similarity_search(cleaned_query, k=3)

# NEW:
results = vector_db.max_marginal_relevance_search(
    cleaned_query,
    k=5,           # more snippets (was 3)
    fetch_k=20,    # consider 20 candidates before MMR re-ranking
    lambda_mult=0.6
)
```

**Also improved:**

| Improvement | Detail |
|-------------|--------|
| `k` raised `3 → 5` | More context for the LLM to work with |
| Snippet deduplication | Compares first 80 chars to remove near-duplicates |
| Better SQLite FTS fallback | Extracts `T1xxx` IDs explicitly + stops words filter |
| Graceful MMR fallback | If ChromaDB version doesn't support MMR, falls back to `similarity_search` silently |

### Full Retrieval Flow

```
get_mitre_query(events)        ← enriched multi-sentence query
        ↓
_get_vector_db()               ← lazy-init ChromaDB + HuggingFace embedder
        ↓
max_marginal_relevance_search  ← fetch 20 candidates, MMR picks best 5
        ↓
_deduplicate_snippets()        ← remove near-duplicates by first 80 chars
        ↓
return context string          ← fed into LLM prompt as RAG context
        ↓
[if ChromaDB fails]
_retrieve_context_sqlite()     ← FTS on chroma.sqlite3 (guaranteed fallback)
```

---

## 🔧 Reasoning Trace UI Fix

### The Problem

The agent's `reasoning_trace` contains 6 steps. The `act` step includes a `tool_results` array with full tool output objects — some of which contain large nested JSON. The original code fell back to `JSON.stringify(step)` when no summary field was found:

```javascript
// OLD (caused massive JSON blobs in the UI):
<div>{step.summary || step.result || step.thought || JSON.stringify(step)}</div>
```

The `act` step has no `summary` field at the top level, causing the entire step object (including nested tool outputs) to be dumped as a wall of raw JSON text.

### The Fix

Replaced the fallback with a smart `extractTraceContent()` function:

```javascript
function extractTraceContent(step) {
  // 1. Use step.description (the clean human-readable field)
  if (step.description) return step.description;
  // 2. Use summary or thought
  if (step.summary)     return step.summary;
  if (step.thought)     return step.thought;
  // 3. For tool_results arrays, show "Ran N tool(s): name1, name2"
  if (Array.isArray(step.tool_results) && step.tool_results.length) {
    return `Ran ${step.tool_results.length} tool(s): ${names}`;
  }
  // 4. For output objects, show key: value pairs (strings/numbers only)
  if (step.output && typeof step.output === 'object') {
    return Object.entries(step.output)
      .filter(([, v]) => typeof v === 'string' || typeof v === 'number')
      .slice(0, 3)
      .map(([k, v]) => `${k}: ${v}`)
      .join(' · ');
  }
  // 5. Last resort: truncate to 120 chars (no full dump)
  return JSON.stringify(step).slice(0, 120) + '…';
}
```

**Also:** The trace section now starts **collapsed** by default via a `CollapsibleTrace` accordion. It shows a `"AGENT REASONING TRACE — 6 steps"` button; clicking expands it with a `max-height: 300px` scrollable area. This prevents it from dominating the screen.

Phase labels are now color-coded:
- OBSERVE → blue
- THINK → purple
- ACT → orange
- SYNTHESIZE → cyan
- DECIDE → red
- EXPLAIN → green

---

## 🔖 Favicon

Replaced the default Vite favicon with a custom SVG designed for the project:

**File:** `soc-react-frontend/public/favicon.svg`

Design elements:
- **Dark `#050709` background** — matches the app's page background
- **Shield shape** — standard security/SOC icon, `#00d4ff` cyan stroke matching the primary accent
- **Detection eye** — circle with solid centre dot representing active threat monitoring
- **Horizontal scan line** — dashed line across the shield evoking SIEM radar scanning
- **Corner circuit tick marks** — cybersecurity/technical grid aesthetic
- **Radial gradient glow** — subtle interior glow for depth

---

## 🗑️ Evaluate Section Removed

The `/evaluate` page and nav button were removed because:
- The evaluation suite runs against a mock dataset and doesn't reflect real-world performance
- It was confusing (implied the model was being evaluated live)
- It cluttered the navigation

**Files changed:**
- `App.jsx` — removed `import Evaluate` and `case 'evaluate'` from the router
- `Topbar.jsx` — removed the EVALUATE nav button

The backend `GET /evaluate` endpoint still exists if needed via direct API call.

---

## 🔄 Complete End-to-End Data Flow

Here is the full journey of a request through the system, from browser click to rendered report:

```
USER clicks "RUN INVESTIGATION"
           │
           ▼
[React] Investigate.jsx
  - Validates logs not empty
  - Sets status = 'loading', starts pipeline animation timer
  - Calls investigateAgent(logs, entityId) from socApi.js
           │
           ▼ HTTP POST /investigate/agent
           │  Headers: Authorization: Bearer <JWT>
           │  Body: { logs: "...", entity_id: "..." }
           │
           ▼
[FastAPI] backend/main.py → /investigate/agent endpoint
  - Validates JWT token
  - Calls run_agent_investigation(logs, entity_id)
           │
           ▼
[Stage 1] backend/ingestion/log_normalizer.py
  - Regex + JSON parsing of raw log lines
  - Normalizes timestamps to ISO-8601
  - Extracts: source_ip, dest_ip, user, hostname, raw
           │
           ▼
[Stage 2] backend/processing/event_extractor.py
  - classify_event() applies 9 rule sets in priority order
  - Each rule: regex patterns + MITRE hint
  - Output: List[SecurityEvent] with event_type, mitre_hint, severity
  - get_mitre_query() builds enriched multi-sentence RAG query
    using _MITRE_RICH_CONTEXT expansion phrases
           │
           ▼
[Stage 3] backend/models/lstm_model.py
  - events_to_sequence() → [0, 1, 6, 5, 8, ...] integer codes
  - LSTM autoencoder computes reconstruction error
  - anomaly_score = normalized reconstruction loss [0, 1]
           │
           ▼
[Stage 4] backend/processing/threat_intel.py
  - Checks IPs, commands, hashes against reputation DB
  - Returns: is_malicious, risk_score, category per indicator
           │
           ▼
[Stage 5] backend/rag/rag_engine.py
  - retrieve_context(query, k=5) called
  - _get_vector_db() lazily inits ChromaDB + HuggingFace embedder
  - max_marginal_relevance_search() fetches 20 candidates, MMR picks 5
  - _deduplicate_snippets() removes near-duplicates
  - Returns MITRE ATT&CK technique text as context string
           │
           ▼
[Stage 6] backend/reasoning/llm_agent.py
  - Builds structured prompt: events + anomaly + TI + RAG context
  - Calls OpenRouter API (OpenAI GPT-4o-mini)
  - Parses JSON response: kill_chain, mitre_techniques, explanation, response
           │
           ▼
[Stage 7] backend/incident_report.py + NetworkX
  - Builds attack graph from events
  - Maps events to kill-chain stages
  - Reconstructs attack_path list
           │
           ▼
[Stage 8] backend/reasoning/agent_layer.py (ReAct Engine)

  OBSERVE:
    - Collects all events for entity_id from session store
    - Builds session context: event counts, severity distribution

  THINK:
    - Counts suspicious signal types
    - Selects which tools to run and in what order

  ACT (runs 5 tools):
    ├── anomaly_score  → LSTM score (weight: 35%)
    ├── pattern_match  → 8 heuristic patterns (weight: 10%)
    ├── rag_lookup     → MITRE RAG with enriched query (weight: 20%)
    ├── threat_intel   → IP/hash reputation (weight: 10%)
    └── ioc_extractor  → parse IPs, domains, hashes, URLs from raw logs

  SYNTHESIZE:
    - Merges tool outputs
    - Cross-session correlation (compares with entity history)
    - Detects campaign patterns from event sequences
    - Builds compound_mitre_mappings and correlated_timeline
    - Computes correlation_depth

  DECIDE:
    - confidence = weighted sum of tool scores
    - risk_score = anomaly(35) + confidence(25) + TI(20) + pattern(10) + corr(10)
    - severity = CRITICAL(>0.75) | HIGH(>0.5) | MEDIUM(>0.25) | LOW
    - decision = AUTO_REMEDIATE | ESCALATE_L2 | MONITOR

  EXPLAIN:
    - Calls LLM with full context to generate narrative
    - Selects response playbook from backend/reasoning/playbooks.py
    - Builds why_flagged list of human-readable reasons
           │
           ▼
[Response JSON] returned to React
  {
    severity, risk_score, confidence, decision,
    compound_anomaly_score, correlation_depth,
    pipeline_report: { incident_id, kill_chain_path, mitre_techniques,
                       threat_intel, rag_snippets, llm_explanation,
                       recommended_response, attack_graph },
    reasoning_trace: [ {phase, description, duration_ms}, ... ],
    iocs_extracted: { ipv4: [...], domains: [...], hashes: [...] },
    response_playbook: { name, sla, immediate: [...], short_term: [...] },
    correlated_timeline: [ {timestamp, event_type, description}, ... ],
    why_flagged: [...],
    campaign_pattern: "Full Kill Chain" | null
  }
           │
           ▼
[React] status = 'success', renders ReportPanel
  ├── Report header bar (incident ID, timestamp, severity pill, decision)
  ├── Metric strip (anomaly, confidence, risk score, events, sessions, correlation)
  ├── Left column sections (kill chain, MITRE, attack graph, threat intel, RAG, IOCs)
  ├── Right column sections (findings, recommendations, playbook, timeline, why flagged)
  ├── CollapsibleTrace accordion (collapsed by default, 6-step reasoning)
  └── Raw JSON toggle
```

---

## 📁 Updated Project Structure (v5.0)

```
LLM_Powered_SOC_ANALYST/
│
├── backend/                              ← FastAPI backend (unchanged structure)
│   ├── main.py
│   ├── processing/
│   │   └── event_extractor.py           ← ✏️ UPDATED: _MITRE_RICH_CONTEXT + enriched get_mitre_query()
│   └── rag/
│       └── rag_engine.py                ← ✏️ UPDATED: MMR retrieval, k=5, deduplication, better FTS fallback
│
├── frontend/                            ← Original vanilla JS frontend (kept for reference)
│   ├── index.html
│   ├── app.js
│   └── style.css
│
└── soc-react-frontend/                  ← 🆕 NEW: React + Vite frontend (active)
    ├── index.html                       ← Entry point with SEO meta tags
    ├── vite.config.js
    ├── package.json                     ← Dependencies: react, axios, lucide-react, framer-motion
    ├── public/
    │   └── favicon.svg                  ← 🆕 NEW: Custom SOC shield favicon
    └── src/
        ├── index.css                    ← 🆕 NEW: Global design system
        ├── main.jsx                     ← 🆕 NEW: React DOM root
        ├── App.jsx                      ← 🆕 NEW: Auth gate + router
        ├── api/socApi.js                ← 🆕 NEW: Axios client + JWT interceptor
        ├── constants/scenarios.js       ← 🆕 NEW: Scenarios + pipeline step defs
        ├── context/AuthContext.jsx      ← 🆕 NEW: Auth state + health polling
        ├── components/Topbar/           ← 🆕 NEW: Navigation bar
        └── pages/
            ├── Login/                   ← 🆕 NEW: Auth form
            ├── Investigate/             ← 🆕 NEW: 3-panel investigation UI
            │   └── components/
            │       ├── EmptyState.jsx   ← 🆕 NEW: Idle state
            │       ├── LoadingState.jsx ← 🆕 NEW: Pipeline progress animation
            │       └── ReportPanel.jsx  ← 🆕 NEW: Full incident report renderer
            └── RagTest/                 ← 🆕 NEW: MITRE RAG test page
```

---

## 🚀 Running v5.0 (Both Frontend + Backend)

```bash
# Terminal 1 — Backend
conda activate rag_env   # or your env with PyTorch + FastAPI
cd LLM_Powered_SOC_ANALYST
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Terminal 2 — React Frontend
cd LLM_Powered_SOC_ANALYST/soc-react-frontend
npm install              # first time only
npm run dev              # → http://localhost:5173
```

**Login credentials (demo):**
```
analyst   / password123
admin     / admin123
soc_team  / team123
```

---

<div align="center">

[⬆ Back to top](#-llm-powered-soc-analyst)

</div>
