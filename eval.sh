#!/bin/bash
# Real-world evaluation (CVEfixes + VUDENC) running in the background on the DGX.
#
#   ./eval.sh start     build image, start in background (survives SSH drops)
#   ./eval.sh status    progress, ETA, and what it is waiting for
#   ./eval.sh logs      follow the log (Ctrl+C only stops watching)
#   ./eval.sh report    write eval_results/realworld/report_latest.{md,json} now
#   ./eval.sh stop      stop it; `start` later resumes from the checkpoint
#   ./eval.sh retry     after completion: re-run samples whose LLM calls failed
#   ./eval.sh smoke     ~15 min foreground test on 3+2 pairs (separate dirs)
#
# Sizes: REALWORLD_TARGET_CVEFIXES=500 REALWORLD_TARGET_VUDENC=250 ./eval.sh start

set -euo pipefail
cd "$(dirname "$0")"

export REALWORLD_GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
DC="docker compose --profile eval"
M="python -m hackersec.evaluation.realworld"
STATUS_FILE="eval_results/realworld/status.json"

running() {
  [[ -n "$($DC ps -q --status running eval 2>/dev/null)" ]]
}

case "${1:-status}" in
  start)
    mkdir -p eval_results
    $DC up -d --build eval
    echo ""
    echo "Started in the background. You can close SSH now."
    echo "Check later with:  ./eval.sh status"
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
    if [[ -f eval_results/realworld/eval.log ]]; then
      tail -n 60 -f eval_results/realworld/eval.log
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
    echo "Markdown: eval_results/realworld/report_latest.md"
    ;;
  stop)
    $DC stop eval
    echo "Stopped. Progress is saved; ./eval.sh start resumes."
    ;;
  retry)
    running || { echo "Start the container first: ./eval.sh start"; exit 1; }
    phase="$($DC exec -T eval python -c "import json;print(json.load(open('/app/eval_results/realworld/status.json')).get('phase',''))" 2>/dev/null || true)"
    if [[ "$phase" != "evaluate_done" ]]; then
      echo "Main run still in progress (phase=$phase). Retry only after it completes."
      exit 1
    fi
    $DC exec -d eval sh -c "HF_HUB_OFFLINE=1 $M run --retry-failed && HF_HUB_OFFLINE=1 $M report"
    echo "Retrying failed samples in the background. Watch: ./eval.sh logs"
    ;;
  smoke)
    mkdir -p eval_results
    $DC build eval
    $DC run --rm \
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
    sed -n '2,13p' "$0" | sed 's/^# \?//'
    exit 1
    ;;
esac
