#!/bin/bash
# Start the HemisX DAST Engine
set -e

cd "$(dirname "$0")"

# Create venv if not exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

source .venv/bin/activate

# Install deps
pip install -q -r requirements.txt

echo ""
echo "🔒 Starting HemisX DAST Engine on http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo ""

python -m uvicorn dast_engine.main:app --host 0.0.0.0 --port 8000 --reload
