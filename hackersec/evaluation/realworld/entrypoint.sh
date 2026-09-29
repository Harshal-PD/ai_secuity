#!/bin/sh
# Entrypoint for the `eval` container. Safe to restart at any point:
# every phase resumes from its checkpoint.
set -u
cd /app

M="python -m hackersec.evaluation.realworld"

# Phase 1 — needs internet. Waits out outages internally; the loop only
# covers an unexpected crash.
until $M build; do
  echo "[entrypoint] build exited with an error; retrying in 60s"
  sleep 60
done

# Phase 2 — fully offline, so the college link dropping cannot affect it.
until HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 $M run; do
  echo "[entrypoint] run exited with an error; restarting in 60s"
  sleep 60
done

HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 $M report

# Idle instead of exiting: with restart=unless-stopped an exit would loop.
echo "[entrypoint] evaluation complete; report in ${REALWORLD_RESULTS_DIR:-eval_results/realworld}/"
exec sleep infinity
