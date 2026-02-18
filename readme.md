# 🛡️ LLM-Powered SOC Analyst
### Autonomous Security Investigation using Gemini LLM and Retrieval-Augmented Generation (RAG)

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-green.svg)
![LLM](https://img.shields.io/badge/LLM-Gemini-orange.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 📖 Overview

LLM-Powered SOC Analyst is an autonomous cybersecurity investigation system that uses Large Language Models (Gemini) to analyze security logs, reconstruct attack timelines, map threats to MITRE ATT&CK techniques, and generate explainable incident reports.

Traditional SIEM tools like Splunk generate alerts but require human analysts to investigate. This system performs autonomous investigation, reasoning over complete attack sequences and providing actionable intelligence.

---

## 🎯 Problem Statement

Security Operations Centers face:

- Massive volumes of security logs
- High false positive rates
- Manual investigation workload
- Alert fatigue among analysts
- Slow incident response times

This project solves these problems using LLM-powered reasoning.

---

## 🚀 Key Features

- Autonomous log investigation using Gemini LLM
- Retrieval-Augmented Generation (RAG) knowledge grounding
- MITRE ATT&CK technique mapping
- Attack timeline reconstruction
- Structured incident report generation
- Confidence scoring and severity classification
- Explainable AI security analysis
- Human-in-the-loop decision support

---

## 🏗️ Architecture


---

### Component Description

#### 1. Log Sources
Provides raw security telemetry such as:

- Authentication logs  
- Process execution logs  
- Network activity logs  

---

#### 2. Log Ingestion Layer
Responsible for:

- Collecting logs  
- Cleaning and normalizing data  
- Converting logs into structured format  

---

#### 3. FastAPI Orchestrator
Acts as the central controller that:

- Receives logs
- Coordinates processing
- Calls Gemini LLM agent
- Retrieves knowledge from RAG system

---

#### 4. Gemini LLM Agent (Reasoning Core)
Performs:

- Autonomous log investigation
- Threat reasoning and analysis
- Attack pattern identification

---

#### 5. RAG Knowledge Base
Provides grounded cybersecurity knowledge using:

- MITRE ATT&CK framework
- Vector database (ChromaDB)
- Semantic retrieval

---

#### 6. Investigation Engine
Responsible for:

- Timeline reconstruction
- Event correlation
- Attack sequence analysis

---

#### 7. Incident Report Generator
Generates structured reports containing:

- Attack stage
- MITRE technique mapping
- Severity level
- Confidence score
- Recommended remediation actions

---

#### 8. SOC Analyst Interface
Allows human analyst to:

- Review investigation results
- Validate findings
- Take response actions

---

### Architecture Highlights

- Modular and scalable design  
- Agent-based investigation model  
- LLM-powered reasoning engine  
- Knowledge-grounded threat analysis  
- Explainable incident reporting  

---

---

---

## 🔄 Project Workflow

### Step 1: Log Ingestion
Security logs are received from authentication systems, endpoints, and network activity.

### Step 2: Log Processing
Logs are cleaned, normalized, and converted into structured format.

### Step 3: Autonomous Investigation
Gemini LLM analyzes logs and detects suspicious patterns.

### Step 4: Knowledge Retrieval (RAG)
System retrieves MITRE ATT&CK knowledge to validate threats.

### Step 5: Timeline Reconstruction
System reconstructs full attack sequence.

### Step 6: Incident Report Generation
System generates structured incident report.

### Step 7: Human Analyst Review
SOC analyst reviews and approves actions.

---


## ⚙️ System Requirements

### Hardware

- CPU: Minimum 4 cores
- RAM: Minimum 8 GB (Recommended 16 GB)
- Storage: Minimum 5 GB free
- Internet connection required

---

### Software

Required software:

- Python 3.10+
- pip
- Git
- Virtual environment (recommended)

Check Python version:

bash
python --version

Clone the project from GitHub:

git clone https://github.com/akash4426/LLM_Powered_SOC_Analyst.git

Create Virtual Environment (Recommended)
Windows
python -m venv venv
venv\Scripts\activate

Linux / macOS
python3 -m venv venv
source venv/bin/activate

Install all required Python packages:

pip install -r requirements.txt

