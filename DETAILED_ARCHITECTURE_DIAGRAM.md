# LLM-Powered SOC Analyst — Comprehensive Architecture Diagram

This document contains a highly detailed, granular architecture diagram of the entire **LLM-Powered SOC Analyst** platform. It explicitly maps out all pipelines, internal engines, specific frameworks, and the tools used to power the system.

## Detailed Architecture Flow

```mermaid
flowchart TB
    %% ==========================================
    %% FRAMEWORKS & TOOLS LEGEND
    %% ==========================================
    classDef react fill:#00d4ff,stroke:#007acc,stroke-width:2px,color:#000
    classDef fastapi fill:#059669,stroke:#047857,stroke-width:2px,color:#fff
    classDef llm fill:#8b5cf6,stroke:#7c3aed,stroke-width:2px,color:#fff
    classDef ml fill:#ea580c,stroke:#c2410c,stroke-width:2px,color:#fff
    classDef db fill:#facc15,stroke:#ca8a04,stroke-width:2px,color:#000

    %% ==========================================
    %% 1. FRONTEND LAYER (React + Vite)
    %% ==========================================
    subgraph Frontend["Frontend Client (React, Vite, CSS Modules)"]
        UI_Dash["Investigate Dashboard\n(React)"]:::react
        UI_Summary["Investigation Summary Tab\n(Visualizes Outputs)"]:::react
        UI_Trace["Agentic Trace Tab\n(Visualizes LLM Logs)"]:::react
        UI_Auth["JWT Authentication\n(Login/Sessions)"]:::react
        
        UI_Dash --> UI_Summary
        UI_Dash --> UI_Trace
    end

    %% ==========================================
    %% 2. API & INGESTION (FastAPI)
    %% ==========================================
    subgraph API_Layer["API Gateway & Auth (FastAPI, Uvicorn, PyJWT)"]
        API_Main["REST API Routes\n(/api/investigate)"]:::fastapi
        Validator["Data Validation\n(Pydantic)"]:::fastapi
        
        API_Main --> Validator
    end

    subgraph Data_Processing["Data Ingestion & Processing (Python)"]
        Log_Norm["Log Normalizer & Parser\n(Syslog/JSON)"]
        Session_Build["Session Builder\n(Groups by IP/Entity)"]
        Event_Extract["Event & IOC Extractor"]
        
        Log_Norm --> Session_Build
        Session_Build --> Event_Extract
    end

    %% ==========================================
    %% 3. ML & HEURISTICS LAYER
    %% ==========================================
    subgraph ML_Layer["ML & Feature Engineering"]
        LSTM["LSTM Anomaly Detector\n(PyTorch)"]:::ml
        Graph["Attack Graph Builder\n(NetworkX)"]:::ml
        Intel["Threat Intel Enricher\n(VirusTotal, OpenCTI mocks)"]
    end

    %% ==========================================
    %% 4. AGENTIC REASONING LAYER
    %% ==========================================
    subgraph Agentic_Layer["Agentic AI Core (Python Orchestration)"]
        Planner["Planner\n(Hypothesis & Execution Plan)"]
        ReAct["Agent Loop (ReAct)\n(Coordinates Thinking & Acting)"]
        
        subgraph Tools["Specialist Tools (Functions)"]
            T1["Behavior Analyst"]
            T2["Pattern Analyst"]
            T3["Threat Context"]
            T4["IOC Analyst"]
            T5["MITRE Knowledge\n(RAG Search)"]
        end
        
        Reflection["Reflection Engine\n(Evaluates Confidence -> Replan)"]
        Evidence["Evidence Aggregator\n(Memory Store & Correlation)"]
        Decision["Decision Engine\n(Severity & Risk Math)"]
        Report_Gen["Report & Playbook Generators"]
    end

    %% ==========================================
    %% 5. LLM & KNOWLEDGE STORAGE
    %% ==========================================
    subgraph Infra_Layer["Infrastructure (LLM & Vector Storage)"]
        Ollama["Local LLM Engine\n(Ollama: Llama3/Phi)"]:::llm
        Embed["Embedding Model\n(Sentence-Transformers)"]:::ml
        Chroma["Vector Database\n(ChromaDB - MITRE Framework)"]:::db
    end

    %% ==========================================
    %% RELATIONSHIPS & FLOW
    %% ==========================================
    UI_Dash -- "1. Submit Logs (HTTP POST)" --> API_Main
    Validator -- "2. Raw Data" --> Log_Norm
    
    Event_Extract -- "3. Extract Features" --> LSTM
    Event_Extract --> Graph
    Event_Extract --> Intel
    
    LSTM -- "4. Anomaly Scores" --> Planner
    Graph -- "4. Topologies" --> Planner
    Intel -- "4. Risk Data" --> Planner
    
    Planner -- "5. Initial Plan" --> ReAct
    ReAct <-->|6. Tool Calls| Tools
    ReAct <-->|7. Prompt/Response| Ollama
    
    T5 <-->|8. Semantic Search| Embed
    Embed <-->|9. Vector Match| Chroma
    
    Tools -- "10. Post Evidence" --> Evidence
    ReAct -- "11. Trigger Reflection" --> Reflection
    Reflection -- "12. Low Confidence = Replan" --> ReAct
    
    Evidence -- "13. Final Board" --> Decision
    Decision -- "14. Final Score" --> Report_Gen
    Report_Gen -- "15. JSON Payload" --> API_Main
    API_Main -- "16. Return Data" --> UI_Dash

```

---

## 3. Technology Stack Breakdown

### Frontend (Client-Side)
- **React.js**: Core component framework.
- **Vite**: Ultra-fast build tool and development server.
- **CSS Modules**: Scoped, component-level styling (used for the cyberpunk/neon dark-mode aesthetic).
- **Lucide React**: Vector icons used throughout the dashboard.

### Backend (Server-Side)
- **FastAPI**: Asynchronous Python web framework serving the REST API.
- **Uvicorn**: ASGI web server implementation.
- **Pydantic**: Data validation for strict typing of the frontend/backend JSON contracts.
- **PyJWT**: JSON Web Token implementation for analyst authentication.

### Machine Learning & Data Processing
- **PyTorch**: Deep learning framework powering the LSTM (Long Short-Term Memory) sequence anomaly detector.
- **NetworkX**: Graph theory library used to rebuild and map attack topologies from disparate log events.

### Agentic AI & Knowledge Base
- **Ollama**: Local execution environment for running Large Language Models (LLMs) completely offline, ensuring data privacy for security logs.
- **ChromaDB**: The vector database used for the RAG (Retrieval-Augmented Generation) pipeline.
- **Sentence-Transformers**: Generates semantic embeddings of the logs to query the MITRE ATT&CK framework stored in ChromaDB. 
