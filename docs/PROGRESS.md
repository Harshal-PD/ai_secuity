# Progress Tracker

**Updated:** 2026-08-03 · Legend: ✅ done · 🔄 in progress · ⬜ not started · ⚠️ blocked/needs-DGX

Live status of the research roadmap (`~/.claude/plans/cosmic-wandering-grove.md`). Keep this current
in the same change as the code. Deep explanation of each piece → `OVERVIEW.md`. Why → `DECISIONS.md`.

---

## Foundation (pre-roadmap) — ✅ built, ⚠️ unvalidated on real data

- ✅ Ingestion (file/zip/git URL), language detection, multi-file split
- ✅ Static analysis (Semgrep + Bandit), dedup, normalized `Finding` schema
- ✅ CPG taint flow (Joern client + queries)
- ✅ RAG (FAISS + all-MiniLM-L6-v2, CWE/OWASP KB)
- ✅ LLM reasoning (Ollama client, prompt, parser)
- ✅ ML fusion classifier (+ SHAP), trained `data/fusion_model.joblib`
- ✅ Patch generation (prompt, diff, validator)
- ✅ Shared `analyze_findings()` pipeline (worker + eval use one path)
- ✅ Honest eval harness (de-mocked runner, HF dataset loader, metrics)
- ✅ Frontend dashboard (live pipeline timeline, exploit-confirmed badge, filters, 3-way metrics, diff view)
- ⚠️ Real Precision/Recall/F1 numbers — **not yet produced** (needs DGX full stack)

## Phase 0 — Unblock + language-aware SAST — ✅ DONE (2026-08-02)

- ✅ Language-aware Semgrep config selection (`static.py`, reuses `detect_language`); `p/c` verified
- ✅ Patch validator uses scan configs (not `p/ci`) + preserves file extension
- ✅ Dataset stratified sampling (real negatives)
- ✅ Worker docker.sock mount + `docker.io` CLI (prod verify unblocked)
- ✅ `test_static_lang.py` → 6/6 pass
- ⚠️ Exit gate items needing DGX: real non-zero C-scan findings; worker `docker_available()==True`

## Phase 1 — Anti-hardcoding oracle + CPG-guided PoC — 🔄 PARTIAL

- ✅ **1a** Differential anti-hardcoding oracle (`verify/oracles.py`, `__init__.py`); rejects hardcoded
  PoCs (`hardcoded_rejected`). `test_verify.py` → 8/8 pass
- ⬜ **1b** CPG-guided PoC agent (`verify/poc_agent.py`) — synthesize driver from CPG taint path when
  the heuristic can't build one; validate via the differential oracle. **Needs Ollama** (fake-LLM testable)
- ⬜ Refine `joern/queries.py` taint sources (currently every identifier is a source)

## Phase 2 — Reproduction-gated benchmark + metric — ⬜ NOT STARTED

- ⬜ `precision@reproduced` / verified-F1 + per-CWE breakdown in `metrics.py`
- ⬜ 3-way comparison table with CIs; run on a real Python benchmark ⚠️ (DGX)
- ⬜ `test_metrics.py` synthetic self-check

## Phase 3 — Re-exploit patch-validation loop — ⬜ NOT STARTED

- ⬜ After patch, re-run the Phase-1 PoC in sandbox; `fixed` only if PoC no longer triggers + regression holds
- ⬜ `test_patch_loop.py` (correct fix vs cosmetic non-fix)

## Phase 4 — LLMxCPG-style minimal slicing — ⬜ NOT STARTED

- ⬜ `joern/slicer.py` — LLM→CPGQL slice → classify slice; feature-flag `enable_slicing`
- ⬜ `test_slicer.py`; A/B slice-vs-full F1 delta ⚠️ (DGX)

## Phase 5 — Live web/service DAST agent ("buttons") — ⬜ NOT STARTED

- ⬜ `verify/dast/` — drive DVWA/Juice-Shop/WebGoat (Playwright / claude-in-chrome), differential oracle over HTTP
- ⬜ New "Live DAST" stage in the frontend timeline
- ⬜ `test_dast_dvwa.py` ⚠️ (Docker + app image)

## Open issues (see `STATE.md` for detail)

- 🟡 Big-Vul label semantics unverified (Phase 2 concern)
- 🔵 `oracles.py` covers injection/RCE only; other CWEs → `reproduced=None` by design

## What ships as the paper

Phases 1 + 2 (+ 3 as a section) = **"Reproduction-Gated, Program-Analysis-Guided Vulnerability
Detection."** Phase 4 = accuracy delta vs LLMxCPG. Phase 5 = future work / second paper.
