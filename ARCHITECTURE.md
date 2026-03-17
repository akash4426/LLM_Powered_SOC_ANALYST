# LLM-Powered SOC Analyst — Architecture & Codebase Guide

> **Who this is for:** Anyone reading or contributing to this project.  
> **Goal:** Understand every component, why it exists, and how data flows through the system.

---

## 1. What This System Does

The **LLM-Powered SOC Analyst** is an AI system that acts as a Tier-1 security analyst. You paste raw security logs (from SSH, Windows Event Log, etc.) and the system:

1. Reads and understands the logs
2. Detects if something abnormal is happening (using a trained neural network)
3. Looks up relevant attack techniques from its cybersecurity knowledge base
4. Asks Google Gemini (an LLM) to write a full incident report
5. Returns a structured JSON report with severity rating, MITRE ATT&CK techniques, attack graph, and recommended actions

---

## 2. Technology Stack at a Glance

| Layer | What | Why |
|-------|------|-----|
| API Server | **FastAPI** (Python) | Fast, async, auto-docs at `/docs` |
| Neural Network | **PyTorch LSTM Autoencoder** | Detects anomalous event sequences |
| Knowledge Base | **ChromaDB** + **Sentence Transformers** | Stores and searches MITRE ATT&CK tactics |
| Retrieval | **LangChain** RAG pipeline | Finds relevant attack techniques |
| LLM | **Google Gemini 2.5 Flash** | Writes the incident investigation report |
| Graph Analysis | **NetworkX** | Maps events to kill-chain stages |
| Frontend | **HTML + CSS + Vanilla JS** | Operator console UI |

---

## 3. Project Folder Structure

```
LLM_Powered_SOC_ANALYST/
│
├── backend/                  ← All Python logic
│   ├── main.py               ← FastAPI app + pipeline orchestrator
│   ├── log_normalizer.py     ← Step 1: Parse raw logs
│   ├── event_extractor.py    ← Step 2: Classify events (LOGIN, PRIV_ESC…)
│   ├── session_builder.py    ← Step 3: Group events into sessions
│   ├── lstm_model.py         ← Step 4: Anomaly detection (PyTorch)
│   ├── threat_intel.py       ← Step 5: IP/hash/command enrichment
│   ├── rag_engine.py         ← Step 6: ChromaDB vector search
│   ├── llm_agent.py          ← Step 7: Gemini prompt + call
│   ├── attack_graph.py       ← Step 8: Kill-chain graph (NetworkX)
│   ├── incident_report.py    ← Step 9: Assemble final JSON report
│   ├── models.py             ← Pydantic request/response models
│   └── log_parser.py         ← (legacy placeholder)
│
├── scripts/                  ← Training & testing tools
│   ├── generate_dataset.py   ← Creates 4,000 synthetic sequences
│   ├── train_lstm.py         ← Trains the LSTM autoencoder
│   ├── evaluate_lstm.py      ← Measures AUC, F1, confusion matrix
│   └── test_pipeline.py      ← End-to-end test (no server needed)
│
├── data/                     ← Data files
│   ├── sequences_normal.npy  ← Training sequences (normal activity)
│   ├── sequences_attack.npy  ← Training sequences (attack patterns)
│   └── sample_logs.json      ← 5 labeled test scenarios
│
├── models/
│   └── lstm_anomaly.pt       ← Trained LSTM checkpoint
│
├── vector_db/                ← ChromaDB persistent store (MITRE ATT&CK)
├── frontend/                 ← UI files
│   ├── index.html
│   ├── style.css
│   └── app.js
│
├── .env                      ← GEMINI_API_KEY goes here
└── requirements.txt
```

---

## 4. The Complete Pipeline (Step by Step)

When you POST a log to `/investigate`, this exact sequence runs:

```
Raw Logs (text string)
       │
       ▼
 ┌─────────────────┐
 │ 1. log_normalizer│  → Unified dicts [{timestamp, ip, user, action, severity, raw}]
 └────────┬────────┘
          │
          ▼
 ┌─────────────────┐
 │ 2. event_extractor│ → SecurityEvent objects with type (LOGIN, PRIV_ESC…)
 └────────┬────────┘    + integer codes for LSTM + MITRE hints
          │
          ▼
 ┌─────────────────┐
 │ 3. session_builder│ → Sessions grouped by actor+time window
 └────────┬────────┘   + integer sequences for LSTM
          │
          ├──────────────────────────────────┐
          ▼                                  ▼
 ┌────────────────┐               ┌─────────────────────┐
 │ 4. lstm_model  │               │ 5. threat_intel      │
 │ anomaly score  │               │ IP/hash/cmd lookup   │
 └───────┬────────┘               └──────────┬──────────┘
         │                                   │
         └─────────────┬─────────────────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ 6. rag_engine    │  → Top-3 MITRE ATT&CK passages
              │ (ChromaDB)       │    from semantic search
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ 7. llm_agent     │  → Gemini prompt with ALL context
              │ (Gemini)         │    returns structured text report
              └────────┬────────┘
                       │
                       ▼
              ┌─────────────────┐
              │ 8. attack_graph  │  → NetworkX DAG of event flow
              │ (NetworkX)       │    kill-chain stage mapping
              └────────┬────────┘
                       │
                       ▼
              ┌──────────────────┐
              │ 9. incident_report│  → Final JSON (severity, confidence,
              └────────┬─────────┘    MITRE, graph, RAG snippets, actions)
                       │
                       ▼
               HTTP JSON response
```

---

## 5. Each Component Explained

---

### Step 1 — `log_normalizer.py` — Parsing Raw Logs

**What it does:** Takes whatever the user pasted (plain text, JSON array, or JSON Lines) and converts every line into a standard Python dict.

**Output shape:**
```python
{
  "timestamp": "2024-01-15T03:22:31Z",
  "source_ip": "185.220.101.5",
  "dest_ip":   None,
  "user":      "admin",
  "hostname":  None,
  "action":    "successful_login",
  "target":    "sshd",
  "severity":  "high",
  "raw":       "2024-01-15 03:22:31 Accepted password for admin from 185.220.101.5..."
}
```

**How it works:**
- If the input starts with `[` → parse as JSON array
- If each line is valid JSON → parse as JSON Lines
- Otherwise → apply regex patterns to extract fields from text

**Key function:** `normalize_logs(raw: str) → List[dict]`

---

### Step 2 — `event_extractor.py` — Classifying Events

**What it does:** Reads each normalized log dict and decides *what type of security event it represents*.

**10 event types (ordered by severity):**

| Code | Type | Example trigger |
|------|------|----------------|
| 9 | `EXFILTRATION` | "DLP alert", "dns tunnel", "large transfer" |
| 8 | `DEFENSE_EVADE` | "vssadmin delete shadows", "AV kill" |
| 7 | `LATERAL_MOVE` | "psexec", "pass-the-hash", "wmiexec" |
| 6 | `SUSPICIOUS_EXEC` | "mimikatz", "IEX(…)", "c2 beacon" |
| 5 | `PRIV_ESC` | "sudo", "SYSTEM", "UAC bypass" |
| 4 | `RECON` | "nmap", "whoami", "net user /domain" |
| 3 | `OUTBOUND_CONN` | "outbound traffic", "wget", "curl" |
| 2 | `FILE_ACCESS` | file open/read/write patterns |
| 1 | `LOGIN` | "Accepted password", "Failed password" |
| 0 | `NORMAL` | anything else |

**How classification works:** A **prioritized rule table** with regex patterns. Rules are checked top-to-bottom; first match wins. Each rule also carries a MITRE ATT&CK hint (e.g. `"T1110 Brute Force"`) used in the RAG query later.

**Output:** A `SecurityEvent` object per log line.

**Key functions:**
- `extract_events(normalized_logs) → List[SecurityEvent]`
- `events_to_sequence(events) → List[int]` (for LSTM)
- `get_mitre_query(events) → str` (for RAG, e.g. `"T1110 Brute Force | T1059 Command Scripting"`)

---

### Step 3 — `session_builder.py` — Grouping Into Sessions

**What it does:** Groups related events together into *behavioral sessions*. A session is a window of activity from the same IP or user within 30 minutes of inactivity.

**Why this matters:** An attacker's brute force + login + sudo represents *one coherent attack session*, not 3 unrelated events. The LSTM needs the sequence of events within a session, not just individual events.

**Session output:**
```python
{
  "session_id":    "bbbf9d0b",
  "actor":         "185.220.101.5",
  "start_time":    "2024-01-15T03:22:11Z",
  "end_time":      "2024-01-15T03:23:10Z",
  "event_count":   6,
  "unique_types":  ["LOGIN", "PRIV_ESC", "SUSPICIOUS_EXEC"],
  "severity_max":  "high",
  "event_sequence": [1, 1, 1, 1, 5, 6]  # integer codes
}
```

**Key functions:**
- `build_sessions(events) → List[Session]`
- `sessions_summary(sessions) → dict`

---

### Step 4 — `lstm_model.py` — Anomaly Detection

**What it does:** Scores the event sequence from 0.0 (completely normal) to 1.0 (highly anomalous).

**What is an LSTM Autoencoder?**

An autoencoder is trained to *reconstruct* normal sequences. When it sees a normal sequence (like `LOGIN → FILE_ACCESS → OUTBOUND_CONN`), it reconstructs it almost perfectly → low error. When it sees an attack sequence (like `LOGIN → PRIV_ESC → SUSPICIOUS_EXEC → EXFILTRATION`), it struggles → high reconstruction error → high anomaly score.

```
Input sequence → [Encoder LSTM] → Compressed representation → [Decoder LSTM] → Reconstructed sequence
                                                                                       ↓
                                                               Compare with input → Reconstruction Error = Anomaly Score
```

**Training (offline, via `scripts/train_lstm.py`):**
- Train ONLY on normal sequences (3,000 examples)
- Model learns what "normal" looks like
- Never sees attack sequences during training

**Scoring at inference:**
- Feed the integer event sequence
- Compute reconstruction loss
- Normalize against thresholds from training
- Return score in [0.0, 1.0]

**Heuristic fallback:** If model file (`models/lstm_anomaly.pt`) is not found, uses a rule-based scorer based on presence of high-risk event types.

**Performance (on test set):**
- ROC-AUC: **1.0000** (perfect separation)
- Normal vs Attack loss separation: **418×**

**Key function:** `score_sequence(sequence: List[int]) → float`

---

### Step 5 — `threat_intel.py` — Threat Intelligence Enrichment

**What it does:** Checks every IP address, file hash, and command found in the events against a threat intelligence database.

**What is in the database?**

| Category | Example entries |
|----------|----------------|
| Malicious IPs | `185.220.101.5`, `91.108.4.1` (known Tor exit nodes, C2 servers) |
| Malicious CIDR ranges | `185.220.101.0/24`, `45.33.32.0/24` |
| Malware hashes | `d38e2f6b…` (Mimikatz hash) |
| Suspicious commands | `mimikatz`, `psexec`, `vssadmin delete` |

**For each indicator found:**
```python
IndicatorResult(
  indicator="185.220.101.5",
  indicator_type="ip",
  is_malicious=True,
  risk_score=85,         # out of 100
  threat_description="Known Tor exit node used in attacks",
  source="StaticThreatDB"
)
```

**Output:** A `ThreatIntelReport` with all indicators, overall risk level (LOW/MEDIUM/HIGH/CRITICAL), and max risk score.

**Key function:** `enrich_events(events) → ThreatIntelReport`

---

### Step 6 — `rag_engine.py` — MITRE ATT&CK Knowledge Retrieval

**What is RAG?**  
RAG = **Retrieval-Augmented Generation**. Instead of asking the LLM to rely purely on its training memory, we *retrieve* relevant documents first and *include them in the prompt*. This makes the LLM's answers grounded in specific, factual knowledge.

**How it works in this system:**

```
Events detected        →   get_mitre_query()   →   "T1110 Brute Force | T1548 Privilege Esc"
                                                              ↓
ChromaDB vector DB     ←   semantic similarity search
(MITRE ATT&CK stored)  →   Top 3 matching passages
                                   ↓
               Injected into Gemini prompt as context
```

**ChromaDB** stores each MITRE ATT&CK technique description as a vector embedding using `sentence-transformers/all-MiniLM-L6-v2`. When a query comes in, it finds the 3 most semantically similar technique descriptions.

**Why `get_mitre_query()` matters:** Instead of searching with raw log text ("Failed password for admin from 185.220.101.5"), we search with the MITRE hint strings discovered during event classification ("T1110 Brute Force | T1548 Abuse Elevation Control"). This gives much better semantic matching with the ATT&CK knowledge base.

**What gets returned:** Text snippets like:
> *"T1110 Brute Force — Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account…"*

**Key function:** `retrieve_context(query: str) → str`  
**Called from:** `main.py` (not from `llm_agent.py` — the context is pre-fetched and passed in)

---

### Step 7 — `llm_agent.py` — LLM Investigation (Gemini)

**What it does:** Assembles a rich prompt containing ALL previous pipeline outputs and sends it to **Gemini 2.5 Flash** to write the incident investigation report.

**Prompt structure:**
```
=== SECURITY LOGS ===
[raw log text]

=== BEHAVIOURAL ANALYSIS ===
Event Sequence: LOGIN → PRIV_ESC → SUSPICIOUS_EXEC
LSTM Anomaly Assessment: CRITICAL ANOMALY (score=0.901)

=== THREAT INTELLIGENCE ENRICHMENT ===
3 malicious indicators: 185.220.101.5 (risk=85), mimikatz hash (risk=95)…

=== ATTACK PROGRESSION ===
[attack graph summary text]

=== MITRE ATT&CK KNOWLEDGE BASE (ChromaDB RAG) ===
[top 3 retrieved passages about T1110, T1548, T1059…]

=== YOUR TASK ===
Produce a structured report with these sections:
  attack_stage:
  mitre_technique:
  severity:
  confidence:
  explanation:
  recommended_actions:
```

**Gemini's output** is a structured text string. Downstream (`incident_report.py`) parses each labeled section with regex.

**Key function:** `investigate_logs(log_text, event_sequence, anomaly_score, threat_intel_summary, attack_graph_summary, rag_context) → str`

---

### Step 8 — `attack_graph.py` — Attack Path Reconstruction

**What it does:** Builds a **directed graph** showing the sequence of attack stages, then maps those to the **MITRE ATT&CK Kill Chain**.

**Graph construction:**
- Each *unique event type* becomes a **node** (e.g. `LOGIN`, `PRIV_ESC`)
- Each *consecutive pair* of events becomes a **directed edge** (e.g. `LOGIN → PRIV_ESC`)
- Uses **NetworkX** (`DiGraph`)

**Kill-chain mapping:**

| Event type | Kill-chain stage |
|------------|-----------------|
| RECON | Reconnaissance |
| LOGIN | Initial Access / Credential Access |
| SUSPICIOUS_EXEC | Execution |
| PRIV_ESC | Privilege Escalation |
| DEFENSE_EVADE | Defense Evasion |
| LATERAL_MOVE | Lateral Movement |
| FILE_ACCESS | Collection |
| OUTBOUND_CONN | Command and Control |
| EXFILTRATION | Exfiltration |
| NORMAL | Benign |

**Output:**
```python
{
  "nodes": [{"id": "LOGIN", "count": 5}, {"id": "PRIV_ESC", "count": 1}],
  "edges": [{"source": "LOGIN", "target": "PRIV_ESC"}],
  "attack_path": ["LOGIN", "PRIV_ESC", "SUSPICIOUS_EXEC"],
  "kill_chain_stage": "Privilege Escalation",
  "stages": ["Initial Access", "Execution", "Privilege Escalation"],
  "node_count": 3,
  "edge_count": 2
}
```

**Key function:** `build_attack_graph(events) → dict`

---

### Step 9 — `incident_report.py` — Assembling the Final Report

**What it does:** Takes all outputs from all previous steps and assembles them into one clean, structured JSON report. Also extracts structured fields from the LLM's text output using regex.

**Confidence score formula:**
```
confidence = (anomaly_score × 0.40)
           + (threat_intel_risk/100 × 0.35)
           + (unique_attack_events/5 × 0.25)
```

**Severity resolution:** Takes the *maximum* across three sources:
- LLM's stated severity (e.g. "HIGH")  
- Threat intel overall risk (e.g. "CRITICAL")
- Anomaly score threshold

**Final report JSON includes:**
- `severity`, `confidence`, `incident_id`, `timestamp`
- `attack_stage`, `kill_chain_stage`, `kill_chain_path`
- `mitre_techniques` (extracted T-codes from LLM text)
- `anomaly_score`, `event_types`, `session_count`, `events_analyzed`
- `threat_intel` → full indicator list
- `attack_graph` → nodes, edges, path, stages
- `rag_query` → the query used for MITRE retrieval
- `rag_snippets` → actual ChromaDB passages retrieved
- `llm_explanation` → full Gemini output
- `recommended_response` → extracted action list

---

## 6. The API Endpoints

The FastAPI server (started with `uvicorn backend.main:app`) exposes:

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/` | Health check, list pipeline stages |
| `POST` | `/investigate` | Full 9-stage pipeline, returns complete report |
| `POST` | `/parse` | Pipeline stages 1–6 only (no LLM). For debugging. |
| `GET` | `/docs` | Auto-generated Swagger UI |

**Request body:**
```json
{ "logs": "2024-01-15 03:22:11 Failed password for admin from 185.220.101.5 port 54231 ssh2\n..." }
```

---

## 7. LSTM Training Pipeline

The anomaly detector is trained offline using three scripts:

```bash
# Step 1: Generate 3,000 normal + 1,000 attack synthetic sequences
python scripts/generate_dataset.py

# Step 2: Train the LSTM autoencoder on normal sequences only
python scripts/train_lstm.py

# Step 3: Measure ROC-AUC, F1, confusion matrix
python scripts/evaluate_lstm.py
```

**`generate_dataset.py`** creates sequences using 6 attack templates:
- Brute force and escalate
- Lateral movement
- Data exfiltration
- Ransomware deployment
- Full APT kill chain
- Insider threat

Normal sequences use 3 activity templates (office worker, developer, admin).

**`train_lstm.py`** trains with:
- Adam optimizer, 30 epochs, early stopping (patience = 5)
- Batch size = 64, learning rate = 0.001
- Saves checkpoint to `models/lstm_anomaly.pt`
- Computes calibration thresholds (normal p95 vs attack mean)

**`evaluate_lstm.py`** computes without sklearn:
- Manual ROC-AUC via trapezoidal rule
- Youden's J optimal threshold
- Precision, Recall, F1 at optimal threshold
- ASCII histogram of loss distributions

---

## 8. The Frontend

**`frontend/index.html`** — Three-column layout:

| Column | Contents |
|--------|----------|
| Left | Scenario picker, raw log terminal input, pipeline stack reference, RUN button |
| Center | Empty state / loading tracker / full report output |
| Right | Event taxonomy legend, real-time detection log feed, severity scale |

**`frontend/app.js`** handles:
- Loading the 4 preset attack scenarios into terminal
- API health check on load (`GET /`)
- `investigate()` — POST to `/investigate` with timeout
- Animated 7-step pipeline progress tracker (timed to LSTM + LLM latency)
- Full report rendering: metric bars, MITRE tags, RAG snippets, attack graph path, threat intel table, numbered response actions
- Detection log feed with timestamped, color-coded entries

**Keyboard shortcut:** `Ctrl+Enter` / `⌘+Enter` triggers investigation.

---

## 9. Configuration

**`.env` file** (required):
```
GEMINI_API_KEY=your_key_here
```

Get an API key at [ai.google.dev](https://ai.google.dev).

**`requirements.txt`** key dependencies:

| Package | Purpose |
|---------|---------|
| `fastapi`, `uvicorn` | API server |
| `google-genai` | Gemini LLM |
| `langchain-community`, `chromadb` | RAG framework |
| `langchain-huggingface`, `sentence-transformers` | Embeddings |
| `torch` | LSTM model |
| `networkx` | Attack graph |
| `numpy`, `pandas` | Data handling |
| `python-dotenv` | API key loading |

---

## 10. How to Run From Scratch

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Add your API key
echo "GEMINI_API_KEY=your_key_here" > .env

# 3. Build MITRE ATT&CK vector database (one time)
python backend/build_mitre_db.py

# 4. Train the LSTM model (one time, ~3 minutes)
python scripts/generate_dataset.py
python scripts/train_lstm.py

# 5. Verify everything works (no server needed)
python scripts/test_pipeline.py

# 6. Start the API
uvicorn backend.main:app --reload --port 8000

# 7. Open the dashboard
# Open frontend/index.html in your browser
```

---

## 11. Data Flow Diagram (Full System)

```
┌──────────────┐         POST /investigate        ┌─────────────────────────────────────┐
│   BROWSER    │ ──────── { logs: "…" } ─────────▶│           FastAPI (main.py)          │
│  (index.html)│ ◀──────── JSON report ─────────── │                                     │
└──────────────┘                                   │  normalize → extract → session      │
                                                   │   → LSTM → threat_intel → RAG       │
                                                   │   → LLM  → graph → report           │
                                                   └──────────┬──────────────────────────┘
                                                              │
                    ┌─────────────────────────────────────────┼───────────────────────────┐
                    │                                         │                           │
                    ▼                                         ▼                           ▼
       ┌────────────────────┐               ┌────────────────────────┐    ┌──────────────────────┐
       │   LSTM Model       │               │   ChromaDB             │    │   Google Gemini API  │
       │  (lstm_anomaly.pt) │               │   (MITRE ATT&CK)       │    │   (gemini-2.5-flash) │
       │  Anomaly scoring   │               │   Semantic similarity  │    │   Writes the report  │
       └────────────────────┘               └────────────────────────┘    └──────────────────────┘
```

---

## 12. Key Design Decisions

**Why LSTM Autoencoder instead of a classifier?**  
A supervised classifier needs labeled attack data, which is scarce and scenario-specific. An autoencoder is trained only on normal data — it generalizes to *any* novel attack pattern without needing labeled attack examples.

**Why is RAG done in `main.py`, not inside `llm_agent.py`?**  
Doing it in `main.py` lets us (a) use `get_mitre_query()` which builds a precise query from event MITRE hints rather than raw log text, and (b) return the retrieved snippets in the API response so the frontend and tests can inspect them. If the RAG step was internal to the LLM agent, it would be a black box.

**Why is confidence a weighted formula, not just the anomaly score?**  
Anomaly score alone could be misleading. A weird-but-harmless access pattern might score as anomalous. Combining it with threat intel (is this IP known malicious?) and event diversity (how many distinct attack-type events?) gives a more reliable signal.

**Why `NetworkX` for the attack graph?**  
It handles cycles gracefully (same event type can appear multiple times), supports topological sort for ordering the kill-chain path, and is easy to serialize to JSON for the API response.
