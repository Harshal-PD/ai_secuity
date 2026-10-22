#!/bin/bash
# Select GPUs on the DGX, then recreate the Ollama container(s) so they see them.
#
#   ./start.sh                 # 1 GPU with the most free VRAM (default, shared-lab safe)
#   ./start.sh --count 2       # 2 emptiest GPUs; one Ollama shards the model across them
#   ./start.sh --all           # every GPU for one Ollama (do not do this on a busy DGX)
#   ./start.sh --gpu 0,3       # pin explicit indices from nvidia-smi
#   ./start.sh --replicas 4    # 4 emptiest GPUs, one Ollama + Joern per GPU, for a
#                              # fast evaluation (combine with --gpu to pick them)
#   --parallel N               # requests each Ollama serves at once (default 4 with
#                              # --replicas, else 1); eval workers = replicas x N
#   --ctx N                    # context length (default 4096; 8192 needs ~1.5 GB
#                              # more VRAM per parallel slot)
#
# The choice is saved to .env, so later `docker compose` and ./eval.sh calls
# keep the same GPUs instead of falling back to every GPU.
# Only Ollama/Joern are recreated. Backend/frontend images are not rebuilt.

set -euo pipefail
cd "$(dirname "$0")"

COUNT=1
EXPLICIT=""
USE_ALL=0
REPLICAS=0
PARALLEL=""
CTX=4096
MAX_REPLICAS=4

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \?//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)      USE_ALL=1; shift ;;
    --count)    COUNT="${2:?--count needs a number}"; shift 2 ;;
    --gpu)      EXPLICIT="${2:?--gpu needs an id such as 0 or 0,1}"; shift 2 ;;
    --replicas) REPLICAS="${2:?--replicas needs a number}"; shift 2 ;;
    --parallel) PARALLEL="${2:?--parallel needs a number}"; shift 2 ;;
    --ctx)      CTX="${2:?--ctx needs a number}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown flag: $1" >&2; usage ;;
  esac
done

for v in "$COUNT" "$REPLICAS" "$CTX" ${PARALLEL:+"$PARALLEL"}; do
  if ! [[ "$v" =~ ^[0-9]+$ ]]; then
    echo "--count, --replicas, --parallel and --ctx take positive integers" >&2
    exit 1
  fi
done
if [[ "$REPLICAS" -gt "$MAX_REPLICAS" ]]; then
  echo "--replicas is at most $MAX_REPLICAS (ollama-2..ollama-$MAX_REPLICAS in docker-compose.yml)" >&2
  exit 1
fi

if ! command -v nvidia-smi >/dev/null 2>&1; then
  echo "nvidia-smi not found. Cannot auto-select a GPU." >&2
  exit 1
fi

echo "GPU status:"
nvidia-smi --query-gpu=index,name,memory.used,memory.free --format=csv

emptiest() {
  nvidia-smi --query-gpu=memory.free,index --format=csv,noheader,nounits \
    | sed 's/ //g' \
    | sort -t, -k1,1nr \
    | head -n "$1" \
    | awk -F, '{print $2}' \
    | paste -sd, -
}

set_env() {
  if grep -q "^$1=" .env; then
    sed -i "s|^$1=.*|$1=$2|" .env
  else
    echo "$1=$2" >> .env
  fi
}

GPUS=()
if [[ "$REPLICAS" -ge 1 ]]; then
  if [[ -n "$EXPLICIT" ]]; then
    IFS=, read -r -a GPUS <<< "$EXPLICIT"
  else
    IFS=, read -r -a GPUS <<< "$(emptiest "$REPLICAS")"
  fi
  if [[ "${#GPUS[@]}" -lt "$REPLICAS" ]]; then
    echo "Need $REPLICAS GPUs for $REPLICAS replicas, got: ${GPUS[*]:-none}" >&2
    exit 1
  fi
  NVIDIA_VISIBLE_DEVICES="${GPUS[0]}"
  PARALLEL="${PARALLEL:-2}"
elif [[ -n "$EXPLICIT" ]]; then
  NVIDIA_VISIBLE_DEVICES="$EXPLICIT"
  REPLICAS=1
elif [[ "$USE_ALL" -eq 1 ]]; then
  NVIDIA_VISIBLE_DEVICES="all"
  REPLICAS=1
else
  if [[ "$COUNT" -lt 1 ]]; then
    echo "--count must be a positive integer" >&2
    exit 1
  fi
  NVIDIA_VISIBLE_DEVICES="$(emptiest "$COUNT")"
  REPLICAS=1
fi
if [[ -z "$NVIDIA_VISIBLE_DEVICES" ]]; then
  echo "Could not parse GPU list from nvidia-smi." >&2
  exit 1
fi
PARALLEL="${PARALLEL:-1}"

WORKERS=$(( REPLICAS * PARALLEL ))
JOERNS="$REPLICAS"
if [[ "$WORKERS" -gt 1 && "$JOERNS" -lt 2 ]]; then
  JOERNS=2
fi
[[ "$JOERNS" -gt "$MAX_REPLICAS" ]] && JOERNS="$MAX_REPLICAS"

OLLAMA_URLS="http://ollama:11434"
OLLAMA_SERVICES="ollama"
for ((i = 2; i <= REPLICAS; i++)); do
  OLLAMA_URLS="$OLLAMA_URLS,http://ollama-$i:11434"
  OLLAMA_SERVICES="$OLLAMA_SERVICES ollama-$i"
done
JOERN_URLS="http://joern:8080"
JOERN_SERVICES="joern"
for ((i = 2; i <= JOERNS; i++)); do
  JOERN_URLS="$JOERN_URLS,http://joern-$i:8080"
  JOERN_SERVICES="$JOERN_SERVICES joern-$i"
done

touch .env
mkdir -p "${HOME}/.ollama/models"
set_env HOST_UID "$(id -u)"
set_env HOST_GID "$(id -g)"
set_env USER_HOME "${HOME}"
set_env OLLAMA_HOST_DIR "${HOME}/.ollama"
set_env NVIDIA_VISIBLE_DEVICES "$NVIDIA_VISIBLE_DEVICES"
for ((i = 2; i <= REPLICAS; i++)); do
  set_env "OLLAMA_GPU_$i" "${GPUS[$((i - 1))]}"
done
set_env OLLAMA_REPLICAS "$REPLICAS"
set_env JOERN_REPLICAS "$JOERNS"
set_env OLLAMA_NUM_PARALLEL "$PARALLEL"
set_env OLLAMA_NUM_CTX "$CTX"
set_env OLLAMA_BASE_URLS "$OLLAMA_URLS"
set_env JOERN_BASE_URLS "$JOERN_URLS"
set_env REALWORLD_WORKERS "$WORKERS"

echo ""
echo "Ollama servers : $OLLAMA_SERVICES"
echo "  GPUs         : main=${NVIDIA_VISIBLE_DEVICES}$(for ((i = 2; i <= REPLICAS; i++)); do printf ' ollama-%s=%s' "$i" "${GPUS[$((i - 1))]}"; done)"
echo "  per server   : $PARALLEL parallel requests, context $CTX"
echo "Joern servers  : $JOERN_SERVICES"
echo "Eval workers   : $WORKERS"
echo "(saved to .env)"
echo ""

DC="docker compose --profile replicas"
# Replicas left over from an earlier, larger --replicas would keep their GPUs.
for ((i = REPLICAS + 1; i <= MAX_REPLICAS; i++)); do
  $DC rm -sf "ollama-$i" >/dev/null 2>&1 || true
done
for ((i = JOERNS + 1; i <= MAX_REPLICAS; i++)); do
  $DC rm -sf "joern-$i" >/dev/null 2>&1 || true
done

echo "Recreating Ollama and Joern (no image rebuild)..."
# shellcheck disable=SC2086
$DC up -d --force-recreate $OLLAMA_SERVICES $JOERN_SERVICES

echo ""
echo "Done. Confirm every server runs the model on GPU:"
echo "  ./eval.sh check        # tokens/s and share of the model on GPU, per server"
echo "  docker compose exec ollama nvidia-smi -L"
