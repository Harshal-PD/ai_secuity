#!/bin/bash
# Select GPUs on the DGX, then recreate the Ollama container so it sees them.
#
#   ./start.sh              # 1 GPU with the most free VRAM (default, shared-lab safe)
#   ./start.sh --count 2    # 2 emptiest GPUs; Ollama shards the model across them
#   ./start.sh --all         # every GPU on the node (do not do this on a busy DGX)
#   ./start.sh --gpu 0,3    # pin explicit indices from nvidia-smi
#
# Then: docker compose up -d
# Only Ollama is recreated. Backend/frontend images are not rebuilt.

set -euo pipefail

COUNT=1
EXPLICIT=""
USE_ALL=0

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \?//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)   USE_ALL=1; shift ;;
    --count) COUNT="${2:?--count needs a number}"; shift 2 ;;
    --gpu)   EXPLICIT="${2:?--gpu needs an id such as 0 or 0,1}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown flag: $1" >&2; usage ;;
  esac
done

if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "nvidia-smi not found. Cannot auto-select a GPU." >&2
  exit 1
fi

echo "GPU status:"
nvidia-smi --query-gpu=index,name,memory.used,memory.free --format=csv

if [[ -n "$EXPLICIT" ]]; then
  NVIDIA_VISIBLE_DEVICES="$EXPLICIT"
elif [[ "$USE_ALL" -eq 1 ]]; then
  NVIDIA_VISIBLE_DEVICES="all"
else
  if ! [[ "$COUNT" =~ ^[0-9]+$ ]] || [[ "$COUNT" -lt 1 ]]; then
    echo "--count must be a positive integer" >&2
    exit 1
  fi
  NVIDIA_VISIBLE_DEVICES="$(
    nvidia-smi --query-gpu=memory.free,index --format=csv,noheader,nounits \
      | sed 's/ //g' \
      | sort -t, -k1,1nr \
      | head -n "$COUNT" \
      | awk -F, '{print $2}' \
      | paste -sd, -
  )"
  if [[ -z "$NVIDIA_VISIBLE_DEVICES" ]]; then
    echo "Could not parse GPU list from nvidia-smi." >&2
    exit 1
  fi
fi

export NVIDIA_VISIBLE_DEVICES
export HACKERSEC_GPU_ID="$NVIDIA_VISIBLE_DEVICES"

echo ""
echo "Ollama will use NVIDIA_VISIBLE_DEVICES=${NVIDIA_VISIBLE_DEVICES}"
echo "Recreating the Ollama container (no image rebuild)..."

docker compose up -d --force-recreate ollama
docker compose up -d

echo ""
echo "Done. Confirm inside the container:"
echo "  docker compose exec ollama nvidia-smi -L"
