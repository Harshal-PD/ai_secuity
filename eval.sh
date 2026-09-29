#!/bin/bash
# Real-world evaluation (CVEfixes + VUDENC) running in the background on the DGX.
#
#   ./eval.sh start     check GPU + Joern, then start in background (survives SSH drops)
#   ./eval.sh check     is the model on GPU at a usable speed, and is Joern up?
#   ./eval.sh status    progress, ETA, and what it is waiting for
#   ./eval.sh logs      follow the log (Ctrl+C only stops watching)
#   ./eval.sh report    write eval_results/<run>/report_latest.{md,json} now
#   ./eval.sh stop      stop it; `start` later resumes from the checkpoint
#   ./eval.sh retry     after completion: re-run samples whose LLM calls failed
#   ./eval.sh smoke     ~20 min foreground test on 3+2 pairs (separate dirs)
#
# Results go to eval_results/$REALWORLD_RUN (default realworld_v2); the dataset
# in workspace/realworld is built once and shared by every run.
# Pick the GPU first with ./start.sh (it writes NVIDIA_VISIBLE_DEVICES to .env).
# FORCE=1 ./eval.sh start skips the GPU check.

set -euo pipefail
cd "$(dirname "$0")"

export REALWORLD_GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
export REALWORLD_RUN="${REALWORLD_RUN:-realworld_v2}"
DC="docker compose --profile eval"
M="python -m hackersec.evaluation.realworld"
RESULTS="eval_results/$REALWORLD_RUN"
STATUS_FILE="$RESULTS/status.json"

running() {
  [[ -n "$($DC ps -q --status running eval 2>/dev/null)" ]]
}

check() {
  $DC run --rm --no-deps eval $M check --wait "${1:-0}"
}

case "${1:-status}" in
  start)
    mkdir -p "$RESULTS"
    # Ollama/Joern are started if missing but never recreated here, so a
    # running Ollama keeps the GPU ./start.sh gave it.
    $DC up -d ollama joern
    $DC build eval
    if [[ "${FORCE:-0}" != "1" ]]; then
      if ! check 300; then
        echo ""
        echo "Not starting: the model is not usable on GPU (or Joern is down)."
        echo "  nvidia-smi                       # find a free GPU"
        echo "  ./start.sh --gpu <id>            # move Ollama onto it"
        echo "  docker compose exec ollama ollama ps   # PROCESSOR should say 100% GPU"
        echo "Then run ./eval.sh start again (or FORCE=1 ./eval.sh start to skip this check)."
        exit 1
      fi
    fi
    $DC up -d --no-deps eval
    echo ""
    echo "Started run '$REALWORLD_RUN' in the background. You can close SSH now."
    echo "Check later with:  ./eval.sh status"
    ;;
  check)
    check 0
    ;;
  status)
    if running; then
      $DC exec -T eval $M status
    else
      echo "eval container is NOT running."
      [[ -f "$STATUS_FILE" ]] && { echo "Last recorded status:"; cat "$STATUS_FILE"; }
      echo "Start or resume with: ./eval.sh start"
    fi
    ;;
  logs)
    if [[ -f "$RESULTS/eval.log" ]]; then
      tail -n 60 -f "$RESULTS/eval.log"
    else
      $DC logs -f --tail 60 eval
    fi
    ;;
  report)
    if running; then
      $DC exec -T eval env HF_HUB_OFFLINE=1 $M report
    else
      $DC run --rm --no-deps eval env HF_HUB_OFFLINE=1 $M report
    fi
    echo ""
    echo "Markdown: $RESULTS/report_latest.md"
    ;;
  stop)
    $DC stop eval
    echo "Stopped. Progress is saved; ./eval.sh start resumes."
    ;;
  retry)
    running || { echo "Start the container first: ./eval.sh start"; exit 1; }
    phase="$($DC exec -T eval python -c "import json,os;print(json.load(open(os.environ['REALWORLD_RESULTS_DIR']+'/status.json')).get('phase',''))" 2>/dev/null || true)"
    if [[ "$phase" != "evaluate_done" ]]; then
      echo "Main run still in progress (phase=$phase). Retry only after it completes."
      exit 1
    fi
    $DC exec -d eval sh -c "HF_HUB_OFFLINE=1 $M run --retry-failed && HF_HUB_OFFLINE=1 $M report"
    echo "Retrying failed samples in the background. Watch: ./eval.sh logs"
    ;;
  smoke)
    mkdir -p eval_results
    $DC up -d ollama joern
    $DC build eval
    check 300
    $DC run --rm --no-deps \
      -e REALWORLD_DIR=/app/workspace/realworld_smoke \
      -e REALWORLD_RESULTS_DIR=/app/eval_results/realworld_smoke \
      -e SEMGREP_RULES_DIR=/app/workspace/realworld_smoke/semgrep_rules \
      eval sh -c "$M build --target-cvefixes 3 --target-vudenc 2 \
                  && HF_HUB_OFFLINE=1 $M run \
                  && HF_HUB_OFFLINE=1 $M report"
    echo ""
    echo "Smoke report: eval_results/realworld_smoke/report_latest.md"
    ;;
  *)
    sed -n '2,17p' "$0" | sed 's/^# \?//'
    exit 1
    ;;
esac
