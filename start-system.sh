#!/bin/bash
# Quick Start: React Frontend + Backend
# Starts the backend API and optionally the React dev server

set -e

PROJECT_DIR="/Users/akashmacbook/Desktop/LLM_Powered_SOC_ANALYST"
cd "$PROJECT_DIR"

echo "🚀 LLM-Powered SOC Analyst — Full Stack Start"
echo "================================================"
echo ""

# Check if venv exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Run: python3 -m venv .venv"
    exit 1
fi

# Activate venv
source .venv/bin/activate

# Check if vector_db exists (MITRE database)
if [ ! -f "vector_db/chroma.sqlite3" ]; then
    echo "⚠️  MITRE vector database not found. Building now..."
    python backend/rag/build_mitre_db.py
    echo "✅ MITRE database built"
fi

echo ""
echo "📊 System Check"
echo "==============="

# Check API
echo -n "Checking API... "
python verify_rag.py 2>/dev/null | grep "RAG System Status" && echo "✓ RAG System Ready" || echo "⚠ May need initialization"

echo ""
echo "🎯 Starting Backend API"
echo "======================"
echo "FastAPI will run on: http://localhost:8000"
echo "API docs:            http://localhost:8000/docs"
echo ""

# Start the API server in background
uvicorn backend.main:app --reload --port 8000 &
API_PID=$!

# Give API time to start
sleep 2

echo ""
echo "✅ Backend API started (PID: $API_PID)"
echo ""

# ── React Frontend ──────────────────────────────────────────────────
REACT_DIR="$PROJECT_DIR/soc-react-frontend"

echo "🎨 React Frontend"
echo "================="

if [ -d "$REACT_DIR/node_modules" ]; then
    echo "Starting React dev server (Vite)..."
    cd "$REACT_DIR"
    npm run dev &
    VITE_PID=$!
    cd "$PROJECT_DIR"
    echo ""
    echo "✅ React frontend started (PID: $VITE_PID)"
    echo "   → Open: http://localhost:5173"
else
    echo "⚠️  node_modules not found. Installing dependencies..."
    cd "$REACT_DIR"
    npm install
    npm run dev &
    VITE_PID=$!
    cd "$PROJECT_DIR"
    echo ""
    echo "✅ React frontend started (PID: $VITE_PID)"
    echo "   → Open: http://localhost:5173"
fi

echo ""
echo "📚 Docs"
echo "======="
echo "  Backend API:  http://localhost:8000/docs"
echo "  React App:    http://localhost:5173"
echo ""
echo "✅ System Ready!"
echo ""
echo "To stop everything:"
echo "  kill $API_PID $VITE_PID"
echo ""
echo "Waiting… (Ctrl+C to stop both servers)"
echo ""

# Wait for background jobs
wait
