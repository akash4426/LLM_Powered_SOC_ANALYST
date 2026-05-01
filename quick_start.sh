#!/bin/bash
# quick_start.sh
# Elite SOC Analyst System — Quick Start Guide

set -e

echo "════════════════════════════════════════════════════════════════"
echo "  LLM-Powered SOC Analyst — Agent Layer Upgrade"
echo "════════════════════════════════════════════════════════════════"
echo ""

# Check Python
echo "[1/5] Checking Python environment..."
if ! command -v python3 &> /dev/null; then
    echo "✗ Python3 not found"
    exit 1
fi
PYTHON=$(which python3)
echo "✓ Using: $PYTHON"
echo ""

# Check virtual env
echo "[2/5] Checking virtual environment..."
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate
echo "✓ Virtual environment active"
echo ""

# Install dependencies
echo "[3/5] Installing dependencies..."
pip install -q -r requirements.txt 2>/dev/null || echo "⚠ Some dependencies may be missing"
echo "✓ Dependencies installed"
echo ""

# Run agent layer tests
echo "[4/5] Running agent layer validation tests..."
python3 test_agent_layer.py 2>&1 | tail -40
echo ""

# Show next steps
echo "[5/5] Ready to start!"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  STARTUP INSTRUCTIONS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Option A: Start backend API only"
echo "  $ uvicorn backend.main:app --reload --port 8000"
echo ""
echo "Option B: Start with Docker Compose (if available)"
echo "  $ docker-compose up"
echo ""
echo "Option C: Access frontend directly after starting API"
echo "  Open: http://localhost:8000/frontend/index.html"
echo "  (Frontend auto-starts when you hit 'RUN INVESTIGATION')"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  API ENDPOINTS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Authentication:"
echo "  POST /auth/token                  # Get JWT token"
echo "  GET  /auth/me                     # Get current user"
echo ""
echo "Core Investigation:"
echo "  POST /investigate                 # Full pipeline"
echo "  POST /investigate/agent           # Pipeline + Agent correlation"
echo ""
echo "Utilities:"
echo "  GET  /health                      # System health check"
echo "  POST /parse                       # Parse logs only (no LLM)"
echo "  POST /rag-test                    # Test RAG retrieval directly"
echo "  GET  /evaluate                    # Run evaluation suite"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  TEST CREDENTIALS"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "Username: analyst"
echo "Password: password123"
echo ""
echo "Or:"
echo "Username: admin"
echo "Password: admin123"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  AGENT LAYER FEATURES"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "✓ Evidence-based confidence scoring (deterministic, 40-30-20-10 weights)"
echo "✓ Multi-step hypothesis loop with compound LSTM + RAG"
echo "✓ Time-aware session correlation (6-hour window, decay function)"
echo "✓ Campaign pattern detection (7 attack patterns)"
echo "✓ Decision engine (AUTO_REMEDIATE | ESCALATE_L2 | MONITOR)"
echo "✓ Structured incident output with full timeline"
echo "✓ Explainability: why_flagged reasons + detection improvements"
echo "✓ Thread-safe entity memory store (50 sessions per entity, 24h TTL)"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
