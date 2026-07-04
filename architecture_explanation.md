# Architecture Overview

The **LLM‑Powered SOC Analyst** is a hybrid, agentic AI system that automates security log investigation, threat intelligence enrichment, MITRE ATT&CK contextualisation, and incident report generation. It is built as a **FastAPI** backend with a separate **React** frontend (`soc-react-frontend`). The core pipeline is composed of modular stages that can be executed independently or orchestrated by an **agentic reasoning layer**.

---

## Table of Contents

1. [High‑level Pipeline](#high-level-pipeline)
2. [Backend Package Structure](#backend-package-structure)
   - [Entry point – `main.py`](#entry-point-mainpy)
   - [Authentication – `api/auth.py`](#authentication-apiauthpy)
   - [Schemas – `schemas.py`](#pydantic‑schemas)
   - [Ingestion](#ingestion)
   - [Processing](#processing)
   - [Reasoning / Agentic Layer](#reasoning‑agentic‑layer)
   - [Models](#models)
   - [Perception](#perception)
   - [Utilities & Helpers](#utils)
3. [Vector DB & RAG](#vector-db‑rag)
4. [Frontend](#frontend)
5. [Dev / Deployment Aids](#dev‑deployment-aids)
6. [Data & Results](#data‑results)
7. [Documentation & Walkthroughs](#documentation‑walkthroughs)

---

## High‑level Pipeline {#high-level-pipeline}

```mermaid
flowchart TD
    A[POST /investigate] --> B[Parse & Normalise Logs]
    B --> C[Extract Typed Security Events]
    C --> D[Build Behavioural Sessions]
    D --> E[Score with LSTM Anomaly Detector]
    E --> F[Enrich with Threat Intelligence]
    F --> G[Build MITRE ATT&CK Query]
    G --> H[Retrieve RAG Context (ChromaDB)]
    H --> I[Reconstruct Attack Graph (NetworkX)]
    I --> J[LLM Investigation (Phi‑3.5 / OpenRouter)]
    J --> K[Generate Structured Incident Report]
    K --> L[Return JSON response]
```

The **agentic layer** (`/investigate/agent`) wraps the same pipeline and adds:
- Memory store for entity‑wise sessions
- Cross‑session correlation & compound scoring
- Deterministic decision engine & policy enforcement
- Reflection & replanning loop for iterative analysis
- Playbook generation and evidence aggregation

---

## Backend Package Structure {#backend-package-structure}

```
backend/
├─ __init__.py
├─ main.py                # FastAPI app, routes & orchestration
├─ api/                   # Authentication endpoints & JWT handling
│   └─ auth.py
├─ ingestion/             # Log normalisation & parsing
│   ├─ log_normalizer.py
│   └─ log_parser.py
├─ processing/            # Event extraction, session building, threat intel
│   ├─ event_extractor.py
│   ├─ ioc_extractor.py
│   ├─ pattern_detector.py
│   ├─ session_builder.py
│   └─ threat_intel.py
├─ rag/                   # Retrieval‑augmented generation engine
│   └─ rag_engine.py
├─ reasoning/             # Agentic AI core (planner, LLM, policy, etc.)
│   ├─ agent_layer.py
│   ├─ llm_agent.py
│   ├─ planner.py
│   ├─ decision_engine.py
│   ├─ evidence_aggregator.py
│   ├─ policy_engine.py
│   ├─ reflection.py
│   ├─ report_generator.py
│   ├─ playbooks.py
│   ├─ gemini_agent.py
│   └─ ...
├─ models/                # ML models & graph utilities
│   ├─ lstm_model.py
│   ├─ attack_graph.py
│   └─ train_lstm.py
├─ perception/            # Perception‑level utilities (e.g., embeddings)
│   └─ __init__.py
├─ schemas.py            # Pydantic request/response models
└─ utils/                # Shared helpers (logging, typing, etc.)
```

### Entry point – `main.py` {#entry-point-mainpy}

*Creates the FastAPI instance, configures CORS, and defines the public routes:*  
- `GET /health` – health check with system stats.  
- `GET /dashboard/stats` – operational metrics (model loading status, entity counts, etc.).  
- `POST /auth/token` – JWT login using demo users defined in `AuthService`.  
- `POST /investigate` – orchestrates the full pipeline (steps 1‑9) and returns an `InvestigateResponse`.  
- `POST /investigate/agent` – runs the same pipeline then hands the result to the **agentic AI layer** (`analyze_with_agent`).  
- Helper endpoints (`/parse`, `/rag-test`, `/evaluate`) for debugging and CI.

Key internal helpers:
- `_process_raw_logs` detects network‑flow CSV vs. text logs, normalises them, extracts events, builds a sequence, and scores with the LSTM model.
- The pipeline stages are implemented as thin wrappers around modules in `processing`, `rag`, `models`, and `reasoning`.
- Concurrency is used for the LLM call (`ThreadPoolExecutor`) with a 60 s timeout.

### Authentication – `api/auth.py` {#authentication-apiauthpy}

Provides a **JWT‑based security scheme** using **PyJWT**:
- `JWTConfig` loads secret key, algorithm, and expiry from `.env`.  
- `TokenData` stores the decoded payload and offers `to_dict` / `from_dict`.  
- `JWTHandler` creates and verifies tokens, raising appropriate HTTP errors.  
- `AuthService` contains a hard‑coded demo user map (`analyst`, `admin`, `soc_team`).  
- FastAPI dependencies `get_current_user` and `get_current_user_optional` enforce authentication on protected routes.

### Pydantic Schemas – `schemas.py` {#pydantic‑schemas}

Defines the request and response models for the API:
- `LogRequest` – raw log input.  
- `InvestigateResponse` – detailed structured output (incident ID, severity, MITRE techniques, RAG snippets, LLM explanation, etc.).  
- `AgentLogRequest` / `AgentAnalysisResponse` – extended models for the agentic endpoint, including correlation fields, reflection history, and playbook data.

All models use explicit `Field` metadata for OpenAPI documentation.

### Ingestion {#ingestion}

*`ingestion/log_normalizer.py`* – normalises raw log lines, extracts timestamps, source/destination IPs, usernames, etc., and returns a list of dicts ready for downstream processing.

*`ingestion/log_parser.py`* – contains low‑level parsers for specific log formats (e.g., Syslog, JSON) used by the normaliser.

### Processing {#processing}

| Module | Responsibility |
|--------|----------------|
| `event_extractor.py` | Converts normalised logs into `SecurityEvent` objects, assigns a typed `event_type` and numeric `event_code`. |
| `ioc_extractor.py` | Detects Indicators of Compromise (hashes, IPs, URLs) within events. |
| `pattern_detector.py` | Matches sequences of events against a set of heuristic attack patterns. |
| `session_builder.py` | Groups events into behavioural **sessions** (by IP/user/host) and summarises them. |
| `threat_intel.py` | Enriches events with external reputation data (e.g., VirusTotal, OpenCTI) and produces a `ThreatIntelReport`. |

These modules are pure Python and return plain data structures that downstream modules consume.

### Reasoning – Agentic Layer {#reasoning‑agentic‑layer}

The `reasoning/` package implements the **autonomous analyst** that can reflect, re‑plan, and generate playbooks.
- **`agent_layer.py`** – entry point for the agentic API. It stores sessions in a **memory store**, calls the deterministic **decision engine**, and assembles the final `AgentAnalysisResponse`.
- **`llm_agent.py`** – wrapper around the LLM service (OpenRouter/Phi‑3.5). Handles prompt construction, timeout handling, and parses the LLM JSON output.
- **`planner.py`** – creates a multi‑step plan (PERCEIVE → PLAN → EXECUTE → REFLECT …) and records `planner_thoughts`.
- **`decision_engine.py`** – deterministic scoring that combines LSTM anomaly, RAG confidence, threat‑intel risk, and pattern scores into a single **risk formula**.
- **`policy_engine.py`** – enforces guardrails (e.g., maximum severity thresholds) and injects mitigation actions.
- **`reflection.py`** – after the first LLM pass, analyses the explanation, identifies gaps, and may trigger a **re‑plan** iteration.
- **`evidence_aggregator.py`** – collates all artefacts (RAG snippets, IOC tables, attack graph) into an `evidence_board` for the final report.
- **`playbooks.py`** – maps detected techniques to response playbooks (contain procedural steps, tool commands, and escalation paths).
- **`report_generator.py`** – formats the final incident report (JSON + optional HTML) and injects legacy fields for backward compatibility.
- **`gemini_agent.py`** – placeholder for future integration with Google Gemini agents.

Collectively these modules give the system **self‑reflection**, **dynamic replanning**, and **policy‑driven decision making** – the hallmarks of a hybrid agentic AI platform.

### Models {#models}

- **`lstm_model.py`** – loads a pretrained PyTorch LSTM that scores a sequence of event codes (`score_sequence`). Also provides a separate **network‑flow** model for CSV flow data.
- **`attack_graph.py`** – builds a directed graph (NetworkX) linking events to MITRE techniques, then produces a human‑readable `graph_summary`.
- **`train_lstm.py`** – script used during development to train the LSTM on labelled sessions (not used at runtime).

Model files (`*.pt`) are stored alongside the Python code for easy loading.

### Perception {#perception}

Currently contains only an `__init__.py` that initialises **embedding models** (e.g., sentence‑transformers) used by the RAG engine for semantic similarity. The heavy lifting resides in `rag/rag_engine.py`.

### Utilities & Helpers {#utils}

The `utils/` package holds generic helpers such as:
- Logging configuration
- Type aliases and common constants
- Small wrappers for filesystem access used across the codebase.

---

## Vector DB & RAG {#vector-db‑rag}

The `vector_db/` directory hosts a **ChromaDB** instance populated with the full MITRE ATT&CK knowledge base. The RAG engine (`rag/rag_engine.py`) performs the following steps:
1. Encode the MITRE query (produced by `processing/event_extractor.get_mitre_query`).
2. Perform a **semantic similarity search** against the Chroma collection.
3. Return the top‑k passages as `rag_context` (used by the LLM and also exposed via `/rag-test`).

---

## Frontend {#frontend}

`soc-react-frontend/` is a standard **Vite‑powered React** application (TypeScript) that:
- Provides a UI for log upload, investigation, and dashboard statistics.
- Consumes the FastAPI endpoints (`/investigate`, `/dashboard/stats`, `/health`).
- Renders RAG snippets, attack graph visualisation, and the AI‑generated incident report.
- Includes a **playbook console** that shows the actions recommended by the agentic layer.

---

## Dev / Deployment Aids {#dev‑deployment-aids}

- **Dockerfile** & **docker‑compose.yml** – containerise the API, the vector DB, and the React dev server. Environment variables (including `JWT_SECRET_KEY`) are injected via `.env`.
- **scripts/** – contains utility scripts such as `quick_start.sh`, `validate_production.sh`, and model conversion helpers.
- **start-system.sh** – orchestrates the full stack locally (starts DB, API, and frontend).
- **walkthrough.md** – step‑by‑step guide for a new developer (located in `docs/`).

---

## Data & Results {#data‑results}

- `data/` – sample log datasets used for evaluation and CI tests. Includes both text logs and network‑flow CSV files.
- `results/` – stores evaluation JSON reports generated by the `/evaluate` endpoint.

---

## Documentation & Walkthroughs {#documentation‑walkthroughs}

- `readme.md` – high‑level project description.
- `CONTRIBUTING.md` – guidelines for contributors.
- `DEPLOYMENT_GUIDE.md` – instructions for production deployment (Kubernetes, Docker, Env variables).
- `RELEASE_NOTES.md` – changelog per version.
- **This file** – `docs/architecture_explanation.md` (the one you are reading) provides a full architectural map for newcomers and reviewers.

---

## Summary

The codebase follows a **modular, domain‑driven design**:
- **Ingestion → Processing → Reasoning → Reporting** is a clear, linear flow.
- The **agentic reasoning layer** adds a feedback loop (reflection → replanning) that enables dynamic adaptation without manual intervention.
- All heavy ML/RAG components are encapsulated behind thin service functions, making them easily replaceable (e.g., swapping Phi‑3.5 for another LLM).
- Security is handled via **JWT authentication** with FastAPI dependencies.
- The system is container‑ready and includes CI‑friendly evaluation endpoints.

With this documentation, developers can navigate the repository, extend individual pipeline stages, or integrate new data sources while preserving the overall architecture.

---

*Generated by Antigravity – LLM‑Powered Coding Assistant*
