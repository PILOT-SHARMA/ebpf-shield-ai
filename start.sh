#!/bin/bash
# ──────────────────────────────────────────────
# start.sh — One-command startup for eBPF-Shield AI prototype
# ──────────────────────────────────────────────

set -e

echo "🛡️  eBPF-Shield AI — Starting Prototype"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Change to script directory
cd "$(dirname "$0")"

# Train ML model if not exists
if [ ! -f "models/isolation_forest.joblib" ]; then
    echo "🧠 Training Isolation Forest model..."
    python3 detection/train_model.py
    echo ""
fi

# Remove old database for clean demo
if [ -f "ebpf_shield.db" ]; then
    echo "🗑️  Removing old database for clean demo..."
    rm ebpf_shield.db
fi

echo "🚀 Starting FastAPI backend..."
echo "   Dashboard: http://localhost:8000"
echo "   API docs:  http://localhost:8000/docs"
echo ""
echo "📡 In another terminal, run:"
echo "   python3 replay.py"
echo ""

python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
