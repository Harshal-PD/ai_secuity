# HackerSec

> AI-Driven Security Code Review & Vulnerability Analysis System

HackerSec is a research-grade pipeline for detecting vulnerabilities in source code using multi-layer static analysis, Code Property Graphs (CPG), RAG-grounded LLM reasoning, and an ML fusion classifier — all running locally.

## Architecture

```
Code Input → Static Analysis (Semgrep + Bandit)
          → CPG (Joern taint flows)
          → RAG (CWE/OWASP retrieval via FAISS)
          → LLM Reasoning (DeepSeek-Coder via Ollama)
          → Fusion Classifier (scikit-learn + SHAP)
          → Patch Generator
          → Dashboard
```

## Prerequisites

- Python 3.11+
- Redis (for Celery task queue): `brew install redis` or `apt install redis-server`
- Ollama (for LLM inference): https://ollama.ai
- Joern (for CPG): https://joern.io (Phase 2)

## Setup

```bash
# Clone repo
git clone <repo-url> && cd hackersec

# Create virtualenv
python -m venv .venv && source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env as needed

# Start Redis
redis-server &

# Initialize database
python -c "from hackersec.db.store import init_db; init_db()"

# Start Celery worker
celery -A hackersec.worker.celery_app worker --loglevel=info &

# Start API server
uvicorn hackersec.main:app --reload --port 8000
```

## Usage

```bash
# Upload a file for analysis
curl -X POST http://localhost:8000/api/upload -F "file=@your_code.py"
# Response: {"job_id": "abc123", "status": "pending"}

# Check status
curl http://localhost:8000/api/status/abc123

# Get results
curl http://localhost:8000/api/results/abc123
```

## Development

```bash
make test       # Run tests
make lint       # Run linter
make dev        # Start all services (requires Redis)
```

## Research

See `.planning/` for project context, requirements, roadmap, and per-phase research.
