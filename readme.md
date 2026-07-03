# LLM-Powered SOC Analyst — Hybrid Agentic AI Investigation Platform

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react)](https://reactjs.org/)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.x-EE4C2C?logo=pytorch)](https://pytorch.org/)
[![ChromaDB](https://img.shields.io/badge/ChromaDB-RAG-orange)](https://www.trychroma.com/)
[![Version](https://img.shields.io/badge/Version-8.0.0-brightgreen)]()
[![Architecture](https://img.shields.io/badge/Architecture-Hybrid_Agentic_AI-purple)]()

> **This is NOT a chatbot. This is NOT a pipeline.**  
> The system is an autonomous SOC analyst that plans investigations, dynamically orchestrates specialist tools, continuously reflects on collected evidence, validates decisions deterministically, and produces a human-readable investigation report.

---

## Architecture Overview

The system strictly separates five responsibilities: **Perception, Investigation Planning, Evidence Collection, Deterministic Validation, and Communication.**

The LLM does **not** directly make security decisions (Severity, Risk Score, Confidence). The LLM is strictly the **Investigation Planner and Reasoner**, while security-critical actions are validated through deterministic engines.

```
Raw Logs
   │
   ▼
[Perception Layer]  ← Normalizes logs, extracts events, and sanitizes data. 
   │                  Quarantines raw log strings from the LLM planner.
   ▼
┌──────────────────────────────────────────────────────────────┐
│                  AGENTIC ORCHESTRATOR                        │
│                                                              │
│  [Planner] ← LLM generates hypotheses & tool plans           │
│      │                                                       │
│      ▼                                                       │
│  [Policy Engine] ← Validates plan against security guardrails│
│      │                                                       │
│      ▼                                                       │
│  [Tool Orchestrator] ← Dispatches approved specialists       │
│      │                 (Behavior, Pattern, TI, IOC, MITRE)   │
│      ▼                                                       │
│  [Evidence Aggregator] ← Merges tool results, detects        │
│      │                   contradictions, updates confidence  │
│      ▼                                                       │
│  [Reflection Engine] ← LLM evaluates evidence sufficiency.   │
│                        If insufficient → Replan (Loop)       │
└──────────────────────────────────────────────────────────────┘
   │
   ▼
[Decision Engine] ← Deterministic formulas compute Severity, Risk,
   │                and Confidence based on accumulated evidence. (NO LLM)
   ▼
[Report Generator] ← LLM generates final human-readable executive
   │                 summary and incident narrative.
   ▼
[Enterprise SOC Console] ← React frontend visualization
```

---

## The 7-Phase Agentic Investigation Loop

| # | Phase | What Happens |
|---|-------|-------------|
| 1 | **PERCEIVE** | The perception layer normalizes heterogeneous logs into a sanitized `InvestigationObject`. Raw strings are quarantined to prevent prompt injection. |
| 2 | **PLAN** | The LLM planner analyzes the sanitized data and generates an investigation hypothesis, strategy, and a sequence of specialist tools to run. |
| 3 | **VALIDATE** | The Policy Engine intercepts the LLM's plan, validating requested tools against allowlists and enforcing iteration limits. |
| 4 | **EXECUTE** | The orchestrator executes the approved specialist tools (often in parallel) to gather evidence. |
| 5 | **REFLECT** | The LLM evaluates the new evidence. It asks: *Is my hypothesis still valid? Do I need more evidence?* |
| 6 | **REPLAN** | If reflection determines more evidence is needed, the system loops back to generate a new tool plan. |
| 7 | **DECIDE & REPORT** | The deterministic Decision Engine computes final severity and risk. The LLM Report Generator then writes a human-readable summary. |

---

## Key Innovations

### 1. Prompt Injection Defense (Quarantined Perception)
All logs are treated as untrusted, attacker-controlled input. The Perception Layer sanitizes logs into a structured metadata format. The LLM Planner only ever sees event counts, anomaly scores, and structural summaries — never the raw log strings that could contain `IGNORE PREVIOUS INSTRUCTIONS` attacks.

### 2. LLM as Planner, Not Decider
The LLM generates hypotheses and selects tools, but it never sets the incident's `Severity`, `Risk Score`, or `Confidence`. These are calculated deterministically by the Decision Engine using a strict, weighted formula based on tool evidence:
```
Confidence = 0.35·LSTM + 0.20·RAG + 0.15·Correlation + 0.10·ThreatIntel + 0.10·Pattern + 0.10·IOC
Risk Score = anomaly·35 + confidence·25 + TI·20 + pattern·10 + correlation·10
```

### 3. Dynamic Reflection & Replanning
Instead of a linear chain, the agent uses a dynamic reflection loop. If the initial evidence contradicts the hypothesis (e.g., high anomaly score but no threat intelligence hits), the LLM can reflect, adjust its hypothesis, and request additional tools (e.g., query the MITRE RAG DB).

### 4. Policy Engine Guardrails
The LLM cannot directly execute tools. Every plan is intercepted by the `PolicyEngine` which enforces configurable security policies, prevents unauthorized tools, and limits maximum replanning iterations to prevent infinite loops.

---

## Project Structure

```text
LLM_Powered_SOC_ANALYST/
├── backend/
│   ├── main.py                        # FastAPI entry point
│   ├── schemas.py                     # API response schemas
│   ├── models/
│   │   └── lstm_model.py              # PyTorch LSTM autoencoder
│   ├── perception/
│   │   └── __init__.py                # Phase 1: Data sanitation & object building
│   ├── rag/
│   │   ├── rag_engine.py              # ChromaDB semantic search
│   │   └── build_mitre_db.py          
│   └── reasoning/
│       ├── agent_layer.py             # Agentic Orchestrator (Main Loop)
│       ├── planner.py                 # Phase 2: LLM Investigation Planner
│       ├── policy_engine.py           # Phase 3: Tool Guardrails
│       ├── agent_tools.py             # Phase 4: Specialist Implementations
│       ├── evidence_aggregator.py     # State management & contradiction detection
│       ├── reflection.py              # Phase 5/6: LLM Reflection & Replanning
│       ├── decision_engine.py         # Phase 7: Deterministic Scoring
│       ├── report_generator.py        # Final LLM Report Generation
│       └── llm_agent.py               # OpenRouter Integration
│
├── soc-react-frontend/
│   └── src/
│       ├── api/socApi.js              # API bindings
│       ├── constants/scenarios.js     # Preloaded attack logs
│       └── pages/
│           ├── Dashboard/             # System health & architecture view
│           └── Investigate/
│               └── components/
│                   ├── InvestigationConsole.jsx  # Rich agentic UI visualization
│                   └── AgentPhaseTracker.jsx     # Live 7-phase timeline
```

---

## Setup & Installation

### Prerequisites
- Python 3.11+
- Node.js 18+
- OpenRouter API key (free tier works)

### 1. Clone & Backend Setup

```bash
git clone https://github.com/YOUR_USERNAME/LLM_Powered_SOC_ANALYST.git
cd LLM_Powered_SOC_ANALYST

# Create and activate environment
conda create -n rag_env python=3.11
conda activate rag_env

# Install dependencies
pip install fastapi uvicorn torch chromadb sentence-transformers python-jose passlib python-multipart openai requests pydantic pandas
```

### 2. Environment Variables

Create a `.env` file in the project root:

```env
OPENROUTER_API_KEY=sk-or-v1-YOUR_KEY_HERE
OPENROUTER_MODEL=openai/gpt-oss-120b:free
JWT_SECRET_KEY=your-super-secret-key-here
```

### 3. Build the MITRE ATT&CK DB

```bash
python -m backend.rag.build_mitre_db
```

### 4. Start the Backend

```bash
uvicorn backend.main:app --reload
```
API runs at `http://localhost:8000`

### 5. Start the Frontend

```bash
cd soc-react-frontend
npm install
npm run dev
```
Frontend runs at `http://localhost:5173`

**Default Credentials:** `analyst` / `password123`

---

## API Reference

### Agent Investigation

```bash
POST /investigate/agent
Headers: Authorization: Bearer <token>
Body: {
  "logs": "2024-01-15 03:22:11 sshd Failed password...",
  "entity_id": "host-192.168.1.45"
}

Returns: AgentAnalysisResponse {
  "severity": "CRITICAL",
  "confidence": 0.84,
  "risk_score": 82.3,
  
  "investigation_phases": [...],      # The 7-phase timeline with ms timing
  "reflection_history": [...],        # LLM replanning and hypothesis adjustments
  "replan_events": [...],             # Triggers that caused dynamic replanning
  "confidence_evolution": [...],      # Sparkline data for confidence over time
  "investigation_report": {           # Final LLM executive summary
     "executive_summary": "...",
     "mitre_explanation": "..."
  }
}
```

---

## License
MIT License
