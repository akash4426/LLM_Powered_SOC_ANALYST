<div align="center">

# 🛡️ LLM-Powered SOC Analyst

<br>

**Enterprise-Grade AI-Driven Security Investigation Platform**

Autonomous log analysis, threat detection, and incident correlation powered by LLMs, LSTM anomaly detection, and MITRE ATT&CK RAG retrieval.

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

[🚀 Quick Start](#-quick-start) • [📖 Features](#-key-features) • [🏗️ Architecture](#-system-architecture) • [📡 API](#-api-reference) • [📚 Docs](#-documentation)

</div>

---

## 📑 Quick Navigation

| Section | Description |
|---------|-------------|
| [🚀 Quick Start](#-quick-start) | Get the system running in 5 minutes |
| [✨ Features](#-key-features) | Core capabilities and innovations |
| [🏗️ Architecture](#-system-architecture) | System design and component overview |
| [🔄 Pipeline](#-investigation-pipeline) | Step-by-step analysis flow |
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
[1] Log Normalization      → Regex + JSON parsing
   ↓
[2] Event Classification   → Rule-based extraction (10 event types)
   ↓
[3] LSTM Anomaly Detection → PyTorch sequence autoencoder
   ↓
[4] Threat Intel Enrichment→ IP/hash/command reputation lookup
   ↓
[5] MITRE RAG Retrieval    → ChromaDB semantic search
   ↓
[6] LLM Investigation      → Structured incident analysis
   ↓
[7] Attack Graph Building  → NetworkX kill-chain reconstruction
   ↓
[8] Agent Correlation      → Cross-session pattern matching ⭐
   ↓
STRUCTURED INCIDENT REPORT
```

### 🤖 Elite SOC-Style Agent Layer (v3.0)

**Multi-step reasoning with evidence-based confidence scoring:**

- **Evidence-Based Confidence**: Deterministic formula combining LSTM (40%) + RAG (30%) + Correlation (20%) + Threat Intel (10%)
- **Cross-Session Correlation**: Link related incidents across time with decay functions
- **Campaign Pattern Detection**: Recognize multi-stage attacks (kill chains, privilege escalation chains, ransomware patterns, etc.)
- **Automated Decisions**: AUTO_REMEDIATE | ESCALATE_L2 | MONITOR based on confidence thresholds
- **Timeline & Severity**: Chronological attack sequences with pattern-boosted severity

**Supported Attack Patterns:**
- Full kill chain
- Privilege escalation chains
- APT lateral movement
- Ransomware deployment
- Brute force escalation
- Reconnaissance-to-exploit
- Credential theft

### 🔍 Detection Capabilities

| Detection Method | How It Works | Accuracy |
|-----------------|------------|----------|
| **LSTM Anomaly** | Sequence autoencoder identifies abnormal patterns | ~92% on test set |
| **Rule-Based Classification** | Regex patterns extract 10 security event types | 100% (deterministic) |
| **MITRE RAG** | Semantic search links events to ATT&CK techniques | Context-aware |
| **Threat Intel** | Reputation DB for IPs, commands, file hashes | Signature-based |
| **LLM Analysis** | OpenAI generates structured investigation narrative | Contextual & explainable |
| **Agent Correlation** | Detects multi-session attack patterns | Campaign-level insights |

### 🎯 SOC-Ready Features

- ✅ **JWT Authentication** — Secure API access
- ✅ **Multi-Format Log Support** — Syslog, JSON, CSV, Windows Event Log
- ✅ **Structured Output** — Machine-readable incident reports
- ✅ **Entity Memory** — 24-hour session history
- ✅ **Real-Time Analysis** — Sub-second response
- ✅ **Explainability** — Why_flagged reasons for every decision
- ✅ **SOAR Integration** — Auto-remediation hooks
- ✅ **RESTful API** — OpenAPI/Swagger documentation

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────┐
│              FRONTEND (Web UI)                  │
└──────────────────┬──────────────────────────────┘
                   │ HTTP
┌──────────────────▼──────────────────────────────┐
│           FASTAPI SERVER (Port 8000)            │
│    • Authentication  • Investigation API        │
└──────────────────┬──────────────────────────────┘
         ┌─────────┼─────────┐
         ▼         ▼         ▼
    ┌────────┐ ┌─────────┐ ┌──────────┐
    │ RAG DB │ │ LSTM    │ │ Threat   │
    │(Chroma)│ │(PyTorch)│ │ Intel DB │
    └────────┘ └─────────┘ └──────────┘
         ▲         ▲         ▲
         └─────────┼─────────┘
              ┌────▼────┐
              │ PIPELINE│
              │ LAYER   │
              └─────────┘
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

### Stage 5: MITRE ATT&CK Retrieval (RAG)
- Semantic search via ChromaDB
- Returns technique descriptions and tactics

### Stage 6: LLM Investigation
- Structures incident analysis
- Generates narrative explanations

### Stage 7: Attack Graph Reconstruction
- NetworkX builds kill-chain visualization

### Stage 8: Agent Correlation ⭐
- Cross-session pattern matching
- Multi-stage attack detection
- Evidence-based confidence scoring
- Automated decision generation

---

## 📡 API Reference

### Base URL
```
http://localhost:8000
```

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
Full pipeline analysis

```bash
curl -X POST http://localhost:8000/investigate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"logs": "raw security logs here"}'
```

#### `POST /investigate/agent` ⭐
Pipeline + Agent correlation analysis

```bash
curl -X POST http://localhost:8000/investigate/agent \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": "raw logs",
    "entity_id": "192.168.1.105"
  }'
```

Returns:
- `correlation_depth` — Number of linked sessions
- `campaign_pattern` — Detected attack pattern
- `decision` — AUTO_REMEDIATE | ESCALATE_L2 | MONITOR
- `confidence` — Evidence-based score [0,1]

#### `GET /health`
System status check

#### `POST /auth/token`
Get JWT authentication token

---

## 🎮 Frontend

**Interactive Web UI** at `frontend/index.html`

### Features
- 📋 Scenario picker (brute force, lateral movement, exfiltration, ransomware)
- 📝 Raw log input with drag-and-drop file upload
- 🔧 Agent Mode toggle (enables cross-session correlation)
- 📊 Real-time pipeline animation
- 📈 Agent Intelligence Panel:
  - Compound anomaly score
  - Correlation depth
  - Campaign pattern detection
  - Decision recommendation
- 🔗 Attack graph visualization
- 📋 Structured incident timeline

---

## 🛠️ Tech Stack

### Backend
| Component | Technology |
|-----------|-----------|
| **API Framework** | FastAPI |
| **Authentication** | JWT (PyJWT) |
| **LSTM Model** | PyTorch |
| **RAG Database** | ChromaDB |
| **LLM Integration** | OpenAI API |
| **Graph Analysis** | NetworkX |
| **Data Processing** | Pandas, NumPy |

### Frontend
| Component | Technology |
|-----------|-----------|
| **UI Framework** | Vanilla HTML5/CSS3/JavaScript |
| **Visualization** | CSS Grid + Flexbox |

### DevOps
| Component | Technology |
|-----------|-----------|
| **Containerization** | Docker |
| **Orchestration** | Docker Compose |

---

## 📊 Project Structure

```
LLM_Powered_SOC_ANALYST/
├── backend/
│   ├── main.py                 # FastAPI application
│   ├── schemas.py              # Pydantic models
│   ├── incident_report.py      # Incident generation
│   ├── api/
│   │   └── auth.py             # JWT authentication
│   ├── ingestion/
│   │   ├── log_normalizer.py   # Log parsing
│   │   └── log_parser.py       # Format-specific parsers
│   ├── processing/
│   │   ├── event_extractor.py  # Event classification
│   │   ├── session_builder.py  # Session aggregation
│   │   └── threat_intel.py     # Reputation lookups
│   ├── models/
│   │   ├── lstm_model.py       # PyTorch autoencoder
│   │   └── lstm_anomaly.pt     # Pre-trained weights
│   ├── rag/
│   │   ├── build_mitre_db.py   # Build ChromaDB
│   │   └── rag_engine.py       # Semantic search
│   ├── reasoning/
│   │   ├── llm_agent.py        # LLM integration
│   │   └── agent_layer.py      # ⭐ Agent correlation
│   └── evaluation/
│       └── evaluator.py        # Evaluation metrics
├── frontend/
│   ├── index.html              # Main UI
│   ├── app.js                  # JavaScript logic
│   └── style.css               # Styling
├── scripts/
│   ├── download_models.py      # Download weights
│   ├── train_lstm.py           # Train LSTM
│   ├── evaluate_lstm.py        # Evaluate model
│   └── generate_dataset.py     # Create datasets
├── data/
│   ├── enterprise-attack.json  # MITRE dataset
│   └── sample_logs.json        # Example logs
├── models/
│   └── lstm_anomaly.pt         # Pre-trained model
├── vector_db/
│   └── chroma.sqlite3          # ChromaDB storage
├── Dockerfile                  # Docker config
├── docker-compose.yml          # Docker Compose
├── requirements.txt            # Dependencies
├── .env.example                # Environment template
└── README.md                   # This file
```

---

## ⚙️ Configuration

### Environment Variables (`.env`)

```bash
# OpenAI API
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini

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

- **[Agent Layer Architecture](docs/AGENT_LAYER_UPGRADE.md)** — Elite SOC-style reasoning
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

### Current (v3.0)
- ✅ Agent correlation layer
- ✅ Campaign pattern detection
- ✅ Evidence-based confidence scoring

### Next (v3.1)
- 🔄 Real-time log streaming
- 🔄 GraphQL API support
- 🔄 Advanced visualization

### Future (v4.0)
- 🔜 Kubernetes operator
- 🔜 Multi-tenant SaaS
- 🔜 SIEM integrations

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
