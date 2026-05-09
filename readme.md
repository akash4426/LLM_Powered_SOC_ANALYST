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
