#!/bin/bash
# HackerSec Auto-GPU Selector
# This script interrogates the DGX Host's NVIDIA-SMI to find the GPU with the most free VRAM,
# dynamically injects the ID into the Docker Compose context, and then launches the cluster.

echo "🔍 Scanning DGX Host for the optimal GPU..."

# Execute nvidia-smi, format the output to memory.free and index,
# sort numerically descending, grab the top line, and extract specifically the index ID.
BEST_GPU=$(nvidia-smi --query-gpu=memory.free,index --format=csv,noheader,nounits | sort -nr | head -n 1 | awk -F', ' '{print $2}')

echo "✅ Auto-detected GPU $BEST_GPU as having the most free VRAM!"
echo "🚀 Booting HackerSec Docker cluster bound to GPU $BEST_GPU..."

# Export for docker compose to intercept
export HACKERSEC_GPU_ID=$BEST_GPU

# Rebuild if requested, otherwise bring up asynchronously
docker compose build --no-cache backend worker
docker compose up -d

echo ""
echo "HackerSec is online. Ollama is isolated to GPU $BEST_GPU."
