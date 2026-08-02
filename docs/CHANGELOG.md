# Changelog

## 2026-08-02 (Phase 1a) — Anti-hardcoding differential oracle

Novel-core start. Hardens `verify/` against the POC-GYM cheat class (a PoC that prints the success
marker regardless of input, faking a trigger).

- `analysis/verify/oracles.py` — `build_probe` now returns a **differential** probe:
  `{files, marker, payload_driver, control_driver}`. Same target function driven with exploit
  payloads vs. benign control inputs (`_control_inputs`). Dropped the undetectable `$()` payload variant.
- `analysis/verify/__init__.py` — `verify_finding` runs payload THEN control; `reproduced=True` only
  if the marker fires under the payload and NOT under the control. New evidence status
  `hardcoded_rejected` when the marker fires under both (fake/hardcoded PoC).

**Verified:** `python test_verify.py` → 8 checks (added `test_hardcoded_poc_rejected`): genuine
exploit reproduced, sanitized not-triggered, hardcoded PoC rejected, verdict/CWE/driver gating intact.

**Pending (Phase 1b, needs Ollama):** `verify/poc_agent.py` — CPG-taint-path-guided PoC synthesis for
sinks the heuristic can't drive, validated through this same differential oracle; + `queries.py`
taint-source refinement.

## 2026-08-02 (Phase 0) — Unblock: language-aware SAST + verify/dataset fixes

Prerequisite phase of the research roadmap (`~/.claude/plans/cosmic-wandering-grove.md`).

- `analysis/static.py` — **Semgrep rules are now language-aware.** Replaced the hardcoded
  `SEMGREP_CONFIGS` with `SEMGREP_BASE_CONFIGS` (p/security-audit, p/owasp-top-ten, p/secrets) +
  `SEMGREP_LANG_CONFIGS` (python→p/python, c/cpp→p/c [registry-verified], js/ts/go/java/…). New
  `select_semgrep_configs()` picks packs from the target's detected language(s) via the previously
  orphaned `ingestion/detector.py`. Fixes: dead `p/python`-on-C, the C-dataset measures-nothing blocker.
- `analysis/patch/validator.py` — re-validate patches with the SAME language-aware configs the scan
  used (not fixed `p/ci`); temp file now keeps the finding's extension (was hardcoded `.py` → broke
  non-Python). Fixes false `fixed` verdicts when the flagging rule wasn't in `p/ci`.
- `evaluation/huggingface_loader.py` — stratified sampling (per-label quota, bounded stream walk) so
  the eval set has real negatives; datasets are often label-sorted.
- `docker-compose.yml` + `Dockerfile` — mount `/var/run/docker.sock` into the worker + install the
  `docker.io` CLI, so the exploit-verification sandbox runs in production (was a silent no-op).

**Verified**
- `python test_static_lang.py` → 6 checks pass (config selection: py→p/python, c→p/c-not-p/python,
  mixed-dir union, unknown→base-only, no dups, well-formed slugs).
- `python test_verify.py` → 7 checks still pass (anchor test, no regression).
- NOT verified here (no semgrep/docker in dev box): actual C scan producing findings, and worker
  `docker_available()==True` — both confirmed on the DGX.

## 2026-08-02 (later) — Frontend: live observability + exploit-confirmation UX

**Backend**
- `db/store.py` — `Job.stage` + `FindingRecord.reproduced`/`repro_evidence` columns; `update_job(stage=)`;
  `get_job` returns `stage`; `save_findings`/`get_findings` map the verify fields; idempotent
  `_ensure_columns()` ALTER-migration in `init_db()`. (Closes the "verify evidence not persisted" review item.)
- `analysis/pipeline.py` — `STAGES` constant + `_stage()` emits live progress per stage (no-op for eval).
- `worker/tasks.py` — sets `stage="static"` before static analysis.

**Frontend** (`hackersec-web/`, App.jsx split from 438 lines → orchestrator + 7 components + 3 libs)
- `lib/api.js`, `lib/constants.js` (mirrors backend STAGES), `lib/diff.js`.
- `components/`: `PipelineTimeline` (live stage stepper from `status.stage`), `ScanSummary`
  ("Confirmed Exploitable" headline stat), `MetricsPanel` (3-way baseline/HackerSec/+Verify),
  `FindingsList` (severity+verdict filter, search, severity sort), `FindingCard` (exploit-confirmed
  badge + repro evidence + red/green diff view), `UploadPanel` (file + git-URL, wires `/api/analyze`),
  `StatBox`.
- `index.css` — added component classes (pipeline, stat-tile, toolbar, diff, verify-block, etc.),
  reusing existing tokens. No new npm deps.

**Verified**
- `npm run build` → clean (2452 modules; recharts 575kB chunk warning is pre-existing).
- `npm run lint` → clean.
- Preview server served the built app (HTTP 200, no log errors).
- Visual/live-flow check NOT done — browser extension not connected here; needs the extension or a
  DGX run with the full stack (Redis/Ollama/Joern/Docker) to watch stages advance end-to-end.

## 2026-08-02

**Added**
- `hackersec/analysis/pipeline.py` — shared `analyze_findings()` (CPG→RAG→LLM→fusion→verify→patch),
  called by both the worker and the eval runner.
- `hackersec/analysis/verify/` — dynamic exploit-verification stage:
  - `sandbox.py` — hardened, ephemeral Docker runner (no network, non-root, read-only, cap-drop).
  - `oracles.py` — per-CWE probes for the injection/RCE family (CWE-78/77/94/95).
  - `__init__.py` — `verify_finding()` orchestrator; sets `Finding.reproduced` / `repro_evidence`.
- `hackersec/evaluation/huggingface_loader.py` — real dataset loader (Big-Vul/DiverseVul/Juliet).
- `test_verify.py` — assert-based self-check (7 checks; passes without Docker via injected runner).

**Changed**
- `worker/tasks.py` — steps 3.5–3.10 replaced by one `analyze_findings(..., enable_verify=True)` call.
- `evaluation/runner.py` — removed the CPG/LLM mock; now runs the real pipeline. Fixed broken
  `run_sast` import → `run_static_analysis`. Emits `verified_pred`.
- `evaluation/metrics.py` — added the `hackersec_verified` column (precision under the repro gate).
- `evaluation/dataset.py` — `generate_test_suite(source=...)` delegates to the HF loader.
- `eval_run.py` — argparse CLI (`--dataset/--samples/--limit/--no-cpg/--no-llm/--verify`).
- `analysis/schema.py` — `Finding` gains `reproduced` + `repro_evidence`.
- `ARCHITECTURE.md` — documented Phase 6 (Dynamic Exploit Verification) + the shared-pipeline seam.

**Verified**
- `python test_verify.py` → 7 checks pass (real-docker case auto-skipped; daemon absent here).
- `python eval_run.py --dataset mock --no-cpg --no-llm` → real pipeline path runs end-to-end,
  degrades gracefully with tools absent, writes `eval_results/2026-08-02_run.json`.
- Not yet run on the DGX with semgrep/bandit/faiss/joblib/Ollama/Joern + a real dataset — that
  produces the actual Precision/Recall/F1/FPR (baseline vs HackerSec vs HackerSec+Verify).
