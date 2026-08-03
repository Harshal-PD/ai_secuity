# Codebase Review — Broken / Unfinished

**Date:** 2026-08-03 · Scope: whole repo, correctness + completeness (not style). Report only — no fixes applied.
Severity: 🔴 broken/security · 🟡 unfinished-or-degraded · 🔵 minor/hardening.
Status column updated as items are addressed.

---

## 🔴 Broken / security — fix before any real (DGX) run

### R1 — CPG stage non-functional in the deployed stack (Joern host+port mismatch)
- **Where:** `hackersec/analysis/joern/client.py:10`, `docker-compose.yml:57-72`
- **What:** Client defaults to `http://localhost:9000`; compose runs Joern on `:8080` as service `joern`, and nothing sets `JOERN_BASE_URL`. In the worker container `localhost:9000` is nothing → every CPG call fails → `cpg_context` is always `{"cpg_status": "failed"}`.
- **Impact:** LLM + fusion never receive the taint signal; the Phase-1b PoC agent gets no taint path. The CPG layer — a core selling point — is effectively dead end-to-end.
- **Deeper risk:** Even with the URL fixed, the client assumes synchronous `POST /query → {"response": ...}`. Joern's server API is async (submit → poll / websocket, possibly auth). The protocol is likely wrong too — **unverified without a live Joern**. Needs a real integration test against the `joern` container.
- **Fix sketch:** set `JOERN_BASE_URL=http://joern:8080` in `.env.docker`; change the client default to match; verify the actual Joern server request/response contract and adapt `_execute_raw`.
- **Status:** OPEN

### R2 — Zip-slip: arbitrary file write from an uploaded archive
- **Where:** `hackersec/worker/tasks.py:37` — `zip_ref.extractall(extract_dir)`
- **What:** No path validation. A zip member named `../../evil` writes outside `extract_dir` on the worker.
- **Impact:** Arbitrary file write from untrusted input — on a security scanner. Real vulnerability.
- **Fix sketch:** validate each member resolves inside `extract_dir` before extraction (reject absolute paths and `..`), or use a vetted safe-extract routine. Add a unit test with a malicious member.
- **Status:** OPEN

---

## 🟡 Unfinished / degraded — works, but not what the docs claim

### R3 — Fusion classifier trained on synthetic random data, not real vulnerabilities
- **Where:** `hackersec/analysis/ml/train.py`
- **What:** Generates 1000 rows of `np.random` features labeled by hand-written if/else rules, then fits GradientBoosting. `data/fusion_model.joblib` just re-encodes those heuristics — nothing is learned from real data.
- **Impact:** The "ML fusion verdict" is a fuzzy heuristic, not ML. Roadmap **FUSE-03** ("trained with `class_weight='balanced'` on Big-Vul") is unmet — no Big-Vul, no `class_weight`. Undercuts the ML-fusion research claim.
- **Fix sketch:** train on a real labeled dataset (Big-Vul / DiverseVul) with `class_weight='balanced'`; report held-out metrics; keep the synthetic path only as a bootstrap fallback.
- **Status:** OPEN

### R4 — RAG knowledge base is 34 docs, not "1000+"
- **Where:** `data/kb_meta.json` (34 entries: 10 OWASP `A0x:2021` + ~24 CWE); `ARCHITECTURE.md` claims "over 1,000 MITRE dictionary vulnerabilities"
- **What:** `ingestion/cwe_ingest.py` exists to ingest the full MITRE CWE dictionary but was never run. Retrieval works; corpus is a small seed.
- **Impact:** Doc overclaims vs reality; RAG grounding is shallow (may miss CWEs outside the 34).
- **Fix sketch:** run `cwe_ingest` to populate the full dictionary and rebuild the FAISS index, or correct the ARCHITECTURE claim to match reality.
- **Status:** OPEN

### R5 — No real evaluation has ever run → zero actual metrics
- **Where:** `eval_results/` (absent); eval needs full stack
- **What:** Every precision/recall/F1 claim is hypothetical. Requires the DGX (Semgrep/Bandit/Joern/Ollama/Docker) + a real dataset.
- **Impact:** The static pipeline and the reproduction-gating claim are unvalidated on real data.
- **Status:** OPEN (blocked on DGX; also gated by R1)

---

## 🔵 Minor / hardening

| ID | Where | Issue | Status |
|----|-------|-------|--------|
| R6 | `analysis/patch/differ.py:16` | Diff labels hardcode `vulnerable_code.py`/`patched_code.py` — wrong for non-Python (cosmetic) | OPEN |
| R7 | `ingestion/git_clone.py` | No size/time bound; clones any URL; `no_single_branch=True` fetches all branches — DoS/SSRF surface | OPEN |
| R8 | `main.py:25` | CORS `allow_origins=["*"]` — fine local, loosen-risk for real deploys | OPEN |
| R9 | `worker/tasks.py:9` | `summarize_findings` imported, never called (dead import) | OPEN |

---

## Already tracked elsewhere (see `STATE.md` / `PROGRESS.md`)

- Prod verify needs the docker socket mounted (added in compose; confirm on DGX).
- C-scan findings unconfirmed without semgrep installed.
- Big-Vul label semantics unverified (Phase 2 concern).
- Dynamic verification covers injection/RCE only (CWE-78/77/94/95) — by design; other CWEs → `reproduced=None`.
- Phases 1a/1b code-complete + unit-tested; GPU/real-run pending on the RTX 3050.

---

## Priority

1. **R1 + R2** before any DGX run (CPG must actually work; zip-slip is a live vuln).
2. **R3** next — it's the biggest "looks finished but isn't"; needed for a credible fusion claim.
3. **R4/R5** as part of the Phase-2 evaluation work.
4. R6–R9 opportunistically.
