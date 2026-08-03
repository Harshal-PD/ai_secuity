# State

**HackerSec** — local AI SAST pipeline that now also *proves* findings by reproducing
exploits in a sandbox.

Pipeline: `Semgrep/Bandit → Joern CPG → FAISS RAG → Ollama LLM → ML fusion → dynamic verify → patch`,
orchestrated by `hackersec/analysis/pipeline.py::analyze_findings` (called by both the Celery
worker and the eval harness — one code path).

## Run

```bash
# Full stack (needs Redis, Ollama, Joern, Docker)
uvicorn hackersec.main:app --reload --port 8000
celery -A hackersec.worker.celery_app worker --loglevel=info

# Evaluation (real pipeline, no mocks)
python eval_run.py --dataset bigvul --limit 50 --verify   # → eval_results/YYYY-MM-DD_run.json
python eval_run.py --dataset mock --no-cpg --no-llm        # fast offline smoke

# LLM model (env-configurable; default qwen2.5-coder:7b, fits a 6GB GPU at Q4)
export OLLAMA_MODEL=qwen2.5-coder:7b   # then: ollama pull "$OLLAMA_MODEL"

# Self-checks (no Docker/GPU needed)
python test_verify.py        # differential oracle
python test_poc_agent.py     # CPG-guided PoC synthesis (fake LLM)

# Frontend
cd hackersec-web && npm install && npm run dev
```

## Known issues / blockers (from 2026-08-02 review — fix before trusting DGX numbers)

- ✅ ~~Prod verify no-op~~ — **fixed** (Phase 0): worker mounts `/var/run/docker.sock` + `docker.io`
  CLI in the image. Confirm `docker_available()==True` on the DGX.
- ✅ ~~C datasets vs Python-tuned pipeline~~ — **fixed** (Phase 0): `static.py` now selects
  language-aware Semgrep packs (`p/c` for C). Bandit still Python-only by design (Semgrep covers C).
- ✅ ~~Sandbox image not pre-pulled~~ — non-issue: `docker run` auto-pulls `python:3.12-slim` on
  first use (the pull uses the host daemon's network; the container's `--network none` doesn't block it).
- ✅ ~~Streaming head class-imbalanced~~ — **fixed** (Phase 0): stratified per-label sampling.
- 🟡 **Big-Vul label semantics unverified** — `func_before`/`vul` mapping may not yield clean
  negatives; confirm against the HF schema before trusting precision. (Phase 2 concern.)
- 🟡 **Verify runs serially**, 20s timeout each → 50 findings ≈ 16min worst case. Fine for eval;
  parallelize before live use.
- ✅ ~~Verify evidence not persisted~~ — **fixed** 2026-08-02: `db/store.py` now has
  `reproduced`/`repro_evidence` columns + idempotent ALTER migration; surfaced in `/results`.
- 🔵 `oracles.py` `$(echo MARKER)` payload variant is undetectable (substitution result isn't printed);
  `;` and `|` variants work. Harmless — drop the `$()` variant.

See `DECISIONS.md` for why, `CHANGELOG.md` for what changed.
