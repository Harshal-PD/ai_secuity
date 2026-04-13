#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# HackerSec DGX Startup Script
# Usage: ssh into DGX, clone repo, run this script
# ──────────────────────────────────────────────────────────────────────────

set -e

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       HackerSec — AI Security Code Reviewer             ║"
echo "║       Starting all services on DGX...                   ║"
echo "╚══════════════════════════════════════════════════════════╝"

# Check prerequisites
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Install Docker first."
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found. Install Docker Compose plugin."
    exit 1
fi

# Check NVIDIA runtime (optional but recommended on DGX)
if command -v nvidia-smi &> /dev/null; then
    echo "✅ NVIDIA GPU detected:"
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
    echo ""
else
    echo "⚠️  No NVIDIA GPU detected. Ollama will run on CPU (slower)."
    echo "   If on DGX, ensure nvidia-container-toolkit is installed."
    echo ""
fi

# Create .env.docker if missing
if [ ! -f .env.docker ]; then
    echo "⚠️  .env.docker not found, using defaults..."
fi

# Build and start all services
echo "🔨 Building containers..."
docker compose build

echo "🚀 Starting all services..."
docker compose up -d

echo ""
echo "⏳ Waiting for services to become healthy..."
sleep 10

# Show status
echo ""
docker compose ps

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Services:                                              ║"
echo "║    Frontend:  http://$(hostname -I | awk '{print $1}'):3000       ║"
echo "║    API:       http://$(hostname -I | awk '{print $1}'):8000       ║"
echo "║    API Docs:  http://$(hostname -I | awk '{print $1}'):8000/docs  ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Useful commands:"
echo "   docker compose logs -f          # Follow all logs"
echo "   docker compose logs -f worker   # Follow worker logs only"
echo "   docker compose ps               # Check service status"
echo "   docker compose down             # Stop everything"
echo "   docker compose down -v          # Stop + remove volumes"
echo ""
echo "🔍 Ollama model pull may take a few minutes on first run."
echo "   Check progress: docker compose logs -f ollama-pull"
