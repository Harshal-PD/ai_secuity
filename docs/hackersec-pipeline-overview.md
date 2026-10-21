# HackerSec SAST-Gated Adversarial Pipeline & 6-Run Evolution

End-to-end technical reference covering how the SAST-gated 3-seat LLM board works, how the 8-feature dev-trained fusion classifier makes its final decision, and what changed across all 6 evaluation campaigns (from synthetic tests through v6 pooled real-world commits).

| Metric | Value |
|---|---|
| Pooled Functions (v6) | 2,506 |
| Clean Test MCC (Fusion) | 0.192 |
| Static FPs Removed (Clean) | 78.4% |
| Functions Skipping LLM | 77.9% |

Tabs in the canvas: 1. Pipeline Architecture · 2. All 6 Test Runs · 3. v6 Results & Cost · 4. Fusion Model & Next Steps.

---

## 1. Pipeline Architecture

### Runtime Execution Flow (v6-sast-gate)

Architecture flow of pipeline `v6-sast-gate` (`hackersec/evaluation/realworld/runner.py`). 77.9% of functions exit at Stage 2 with zero LLM tokens.

```text
Target Function
  Python file + line span
  100% funcs
        |
        v
Semgrep + Bandit Gate
  10 packs + Bandit -l -i
  0 tokens
        |
        +------------------------------+
        |                              |
        v                              v
Predict SAFE (0)                 AST + Joern CPG + RAG
  No SAST finding in span          Callers + Taint + CWE KB
  77.9% exit                       22.1% flagged
                                         |
                        +----------------+----------------+
                        |                                 |
                        v                                 v
              Seat 1: Attacker                   Seat 2: Defender
                Exploit claim (temp 0.6)           Guard quote (temp 0.5)
                Parallel                           Parallel
                        |                                 |
                        |                                 v
                        |                          Quote Verifier
                        |                            >=50% token match check
                        |                            Deterministic
                        |                                 |
                        +----------------+----------------+
                                         |
                                         v
                                 Seat 3: Judge
                                   Arbitrates (temp 0.0)
                                   p_vulnerable
                                         |
                                         v
                                 Dev-Trained Fusion
                                   8-feature LogReg (t=0.597)
                                   Final Verdict
```

Edges:

- Target Function → Semgrep + Bandit Gate
- Semgrep + Bandit Gate → Predict SAFE (0)
- Semgrep + Bandit Gate → AST + Joern CPG + RAG
- AST + Joern CPG + RAG → Seat 1: Attacker
- AST + Joern CPG + RAG → Seat 2: Defender
- Seat 2: Defender → Quote Verifier
- Seat 1: Attacker → Seat 3: Judge
- Quote Verifier → Seat 3: Judge
- Seat 3: Judge → Dev-Trained Fusion

### Stage inspector

#### Stage 1: Paired Commit Ingestion & Repo-Disjoint Split

Gate behavior: 2,506 functions (1,253 vuln/fixed pairs) across 3 datasets.

Source: `hackersec/evaluation/realworld/build.py:1`

Extracts pre-fix (vulnerable, label=1) and post-fix (fixed, label=0) versions of the exact same Python function from real security commits, then partitions repositories 20% dev / 80% test with zero repo overlap.

- Inputs: CVEfixes (500 pairs), ReposVul (503 pairs), VUDENC (250 pairs)
- Outputs: samples.jsonl + split.json (502 dev functions, 2,004 test functions, 676 clean single-function subset)

Details:

- Tangled commits touching > 5 functions are dropped; commits touching exactly 1 function are marked clean=True.
- Repo-disjoint split (split.py) guarantees no repository appears in both dev calibration and held-out test.
- Balanced pairs mean flagging everything gives F1 = 0.667, Accuracy = 0.500, MCC = 0.000, and J = 0.000.

#### Stage 2: Widened Static Gate & Multi-Tool Deduplication

Gate behavior: 77.9% of test functions stop here (0 LLM tokens, predicted SAFE).

Source: `hackersec/analysis/static.py:20`

Runs Semgrep (10 rule packs, including INFO mapped to low) and Bandit (-l -i, all severities and confidences) in batches, filters findings to the function's line span, and merges multi-tool collisions.

- Inputs: Whole source file + target function (line_start..line_end)
- Outputs: Deduplicated Finding[] inside function; sast_pred, semgrep_pred, bandit_pred

Details:

- 10 offline-vendored Semgrep packs: security-audit, owasp-top-ten, python, flask, django, sql-injection, xss, command-injection, trailofbits, secrets.
- Deduplication keys by (file, line_start, cwe_category), keeping max severity while tagging [also flagged by bandit ...] so multi-tool agreement is preserved.
- If n_findings == 0, evaluation stops immediately: prediction = 0, p_vulnerable = None, 0 Joern queries, 0 LLM calls.

#### Stage 3: AST Context, Joern CPG Taint & Hybrid CWE RAG

Gate behavior: Runs only on the 22.1% SAST-flagged functions (442 in test).

Source: `hackersec/analysis/enrich.py:22`

Enriches static findings with three structural signals before any LLM sees the code: same-file AST callers/callees, Joern inter-statement data-flow paths, and exact/vector CWE remediation guidance.

- Inputs: Flagged function source + SAST findings
- Outputs: Enriched Finding[] with cpg_context (verified_taint / no_flow_found), rag_docs, and AST context string

Details:

- AST Context (context.py): extracts signatures and call sites of same-file callers and callees (up to 1,200 chars).
- Joern CPG (joern/queries.py): checks reachableByFlows from parameters of the enclosing method (method_line) to sink lines (line_start..line_end +/- 2 lines). 100% CPG success rate in v5/v6.
- Hybrid RAG (rag.py): matches exact CWE/OWASP IDs in data/kb_meta.json first, then falls back to FAISS MiniLM embeddings including the finding message.

#### Stage 4: 3-Seat Function-Level Adversarial Board + Quote Verifier

Gate behavior: 3 LLM calls per flagged function (Attacker || Defender -> Judge).

Source: `hackersec/analysis/llm/board.py:209`

Runs a structured debate over all findings in the function at once. Attacker and Defender submit independent first-round briefs in parallel; a deterministic verifier checks Defender's code quote; Judge arbitrates.

- Inputs: Numbered function code + AST context + Enriched SAST/Joern/RAG packet
- Outputs: Judge p_vulnerable, attacker_confidence, defender_safety, evidence_grounded (VERIFIED/NONE/FAILED)

Details:

- Parallel Round 1: Attacker (temp 0.6) argues exploitability; Defender (temp 0.5, attacker=None) argues neutralization and quotes a verbatim sanitizer line.
- Quote Verifier (evidence.py): deterministically checks that Defender's quote is >= 8 chars, matches >= 50% of tokens in the function, and is not just the sink line.
- Judge (temp 0.0, 1 vote): receives Automated quote check status (VERIFIED / NONE / FAILED) and rules against assuming unseen caller validation or treating no_flow_found as proof of safety.

#### Stage 5: Dev-Trained Logistic Regression Fusion

Gate behavior: 0 LLM tokens (fitted on dev split, applied in <1ms at report time).

Source: `hackersec/evaluation/realworld/fusion.py:170`

Combines 8 signals from the SAST gate, Joern, quote verifier, and all three board seats using an L2-regularized logistic regression fitted via 5-fold CV on the dev split to maximize MCC.

- Inputs: 8 features: p_vulnerable, attacker_confidence, defender_safety, evidence_grounded, log_findings, max_severity, any_taint, both_tools_flagged
- Outputs: fusion_score in [0, 1] and binary fusion_pred (v6 threshold = 0.597)

Details:

- Trained strictly on the 79 SAST-flagged dev functions (5-fold CV selects C=0.4, threshold=0.597).
- Heavily weights defender_safety (-0.835) alongside Judge p_vulnerable (+0.208), max_severity (+0.195), and evidence_grounded (-0.190).
- On the clean test subset, removes 78.4% of static false positives while keeping 58.3% of true positives (Precision 0.778, MCC 0.192).

### Evaluated Pipeline vs Live Celery Worker

The evaluation harness (`hackersec/evaluation/realworld/runner.py`) runs the function-level pipeline (`deliberate_function` + dev-fitted `fusion.py`). The background Celery worker (`hackersec/worker/tasks.py`) used by the web upload UI still calls the earlier per-finding `board.deliberate(finding)` and synthetic `FusionClassifier`.

### How Each Decision Mode Works on a Function

| System Row in Report | Uses SAST Gate? | Uses Joern + RAG? | LLM Calls / Flagged Func | Decision Rule | Test MCC (Combined / Clean) |
|---|---|---|---|---|---|
| Semgrep + Bandit | Yes (is the gate) | No | 0 | Flag if any Semgrep or Bandit rule matches inside the function span | 0.075 / 0.075 |
| SAST board: Judge vote | Yes | Yes | 3 (Attacker \|\| Defender -> Judge) | Flag if Judge verdict == VULNERABLE (p_vulnerable >= 0.50) | 0.097 / 0.110 |
| SAST board + evidence override | Yes | Yes | 3 | Ablation: overturn Judge SAFE to VULNERABLE if Defender sanitizer quote check failed | 0.087 / 0.082 |
| SAST board: dev-tuned threshold | Yes | Yes | 3 | Flag if Judge p_vulnerable >= 0.800 (tuned on dev split to max MCC) | 0.098 / 0.108 |
| SAST board + fusion (Complete Pipeline) | Yes | Yes | 3 | Flag if 8-feature Logistic Regression score >= 0.597 (fitted on dev split) | 0.133 / 0.192 |
| LLM only (whole function, no SAST) | No (runs on 100% of funcs) | No | 1 (on every function) | Single prompt asking Qwen2.5-Coder-14B if the function is vulnerable (dev threshold 0.200) | 0.076 / 0.082 |
| LLM only + same-file context | No (runs on 100% of funcs) | AST callers only | 1 (on every function) | Single prompt with function + same-file callers/callees (dev threshold 0.900) | 0.091 / 0.097 |

---

## 2. All 6 Test Runs

### Chronological History of All 6 Evaluation Tests

Every design change in v6 was driven by a specific failure mode uncovered in the preceding 5 evaluation phases.

| Test / Phase | Dataset & Scale | Pipeline Architecture Tested | Headline Result | What Failed / Root Cause Discovered | Fix Applied in Next Phase |
|---|---|---|---|---|---|
| Test 1: Synthetic Benchmark (eval_run.py) | 24 functions (12 CWE pairs in data/eval_set) | Per-finding sequential board (deliberate) + citation override + synthetic FusionClassifier | High precision/recall on textbook snippets; 5-way ablation validated seat mechanics | Synthetic 5-10 line snippets did not test real commit diffs, multi-finding functions, or cross-function context | Built realworld commit pair harness (CVEfixes + VUDENC) |
| Test 2: Real-World v1 (realworld · Sep 27-28) | 1,498 / 1,500 functions (500 CVEfixes + 250 VUDENC pairs), 4 DGX runs | Per-finding board + mandatory citation override + pre-shipped synthetic FusionClassifier (no dev/test split) | SAST F1 0.329; Board F1 0.328 (removed only 4.6% of FPs, kept 98.8% TPs); Fusion F1 0.329 | 1) Evidence override flipped almost every SAFE verdict back to VULNERABLE. 2) Synthetic fusion reproduced SAST 100% (0% FPs removed). 3) Uncached SAST + Joern timeouts. | Moved to function-level board, dev-trained fusion, repo-disjoint split, and SAST caching |
| Test 3: Phase 0-2 Foundation (Commit 354fdf58 · Sep 29) | Architecture & metric overhaul on CVEfixes + VUDENC | Function-level board (5 Judge votes), EVIDENCE_MODE='signal', repo-disjoint 20/80 split, batched SAST cache, Joern taint fix | Established clean single-function subset, bootstrap CIs, VD-S metric, and CWE family breakdown | SAST recall ceiling was still ~23.7% because static rules miss logic/semantic bugs (only 13.3% flagged in logic families) | Added Phase 3 LLM candidate generators (IRIS taint + GPTLens auditor) to test uncapped recall |
| Test 4: v3-candidates-board (realworld_v3 · Sep 29-30) | 1,500 functions (300 dev / 1,200 test on CVEfixes + VUDENC) | SAST board + Phase 3: LLM-spec taint (IRIS-style) + LLM auditor (GPTLens-style) + Candidates Board (5 votes) | SAST Board Vote removed 40.2% FPs / kept 71.1% TPs; Candidates Board Vote hit P-C = 22.0% (vs 6.2% SAST) | 1) F1 calibration trap: maximizing F1 on balanced 50/50 pairs picked threshold 0.013 (flagging 100%). 2) Auditor flagged 96.7% of all functions (96.8% FPR). 3) ~21 min/func latency. | Switched calibration to MCC & Youden's J; 5 votes -> 1 vote; added ReposVul dataset + Judge guard check |
| Test 5: v5-guard-check (reposvul_v5 · Oct 3) | 1,006 functions (503 ReposVul Python pairs: 202 dev / 804 test) | MCC/J calibration, 1 Judge vote, Joern retry/redo (100% CPG success), Judge Guard Check (required_check quote), tightened Auditor | SAST Board Calibrated (t=0.900) hit MCC 0.146 (CI [0.093, 0.205], dMCC [+0.012, +0.102]), removing 53.4% FPs & keeping 71.8% TPs | 1) LLM-spec taint was anti-informative (J = -0.042, MCC = -0.048). 2) Guard check conceded 85% of the time and parroted prompt text (J = +0.010). 3) Candidates board (J = +0.052) lost to SAST (+0.075). | Pruned Phase 3 & Guard Check; added 7 architectural upgrades + token/LLM-only baselines for v6 |
| Test 6: v6-sast-gate (python_v6 · Oct 15) | 2,506 functions (1,253 pairs across CVEfixes + ReposVul + VUDENC: 502 dev / 2,004 test) + 10-sample smoke run | Pure SAST-gated board, parallel Attacker\|\|Defender, AST context, Judge sees quote check, 10 Semgrep packs + Bandit -l -i, 8-feature Fusion, LLM-only baselines | SAST Board + Fusion hit Combined MCC 0.133 (dMCC [+0.027, +0.088]) and Clean MCC 0.192 (Precision 0.778, LR+ 3.50, 78.4% FPs removed) | 1) 3-seat board uses 1,312 mean tokens/func vs 1,052 for 1-call LLM-only. 2) Blind parallel Defender slightly softened raw Judge calibration on ReposVul. 3) Joern taint is sanitizer-blind (coef -0.154). | Next (v7 candidates): Drop Attacker LLM call (2-seat board), sanitizer-aware CPG query, zero-token AST sink gate |

### False-Positive Removal vs True-Positive Retention Across Runs (SAST-Flagged Functions)

Source: `eval_results/*/report_latest.md`. SAST-flagged test subset per run. Removing the mandatory override rule after v1 unlocked 40–78% false-positive suppression.

| Run | Static FPs Removed (%) | Static TPs Kept (%) |
|---|---:|---:|
| v1 Board (Sep 28) | 4.6 | 98.8 |
| v3 Board Vote (Sep 30) | 40.2 | 71.1 |
| v5 Board Calib (Oct 3) | 53.4 | 71.8 |
| v6 Board Vote (Oct 15) | 39.5 | 73.0 |
| v6 Fusion Combined | 64.2 | 59.9 |
| v6 Fusion Clean | 78.4 | 58.3 |

### Mean Deliberation Latency per Flagged Function (Seconds)

Source: Pipeline telemetry in realworld_v3, reposvul_v5, and python_v6 reports. Dropping 5 Judge votes to 1, pruning Phase 3, and running Attacker || Defender in parallel reduced runtime by 13.9x.

| Configuration | Mean Seconds / Function |
|---|---:|
| v3 Total w/ Phase 3 (5 votes) | 1285.7 |
| v3 SAST Board (5 votes) | 445.5 |
| v5 SAST Board (1 vote, seq) | 190.0 |
| v6 SAST Board (1 vote, parallel) | 92.6 |

### Detailed Breakdown of Each Evaluation Campaign

#### Test 1 & Test 2: Synthetic Eval (eval_run.py) & Initial Real-World Runs (Sep 27–28, 2026)

1,498 functions · F1 0.328

- **Four checkpoints in `eval_results/realworld/`**: `2026-09-27_083643`, `2026-09-27_132111`, `2026-09-27_150231`, and `2026-09-28_073211` (500 CVEfixes pairs + 250 VUDENC pairs).
- **Why the board barely filtered anything**: In v1, `use_evidence_rule=True` acted as a hard override on every finding. Whenever the Judge voted `FALSE_POSITIVE` without an exact substring match from the Defender, the code forcibly flipped the verdict back to `TRUE_POSITIVE`. As a result, only **4.6%** of false positives were removed (6 out of 130 fixed functions).
- **Why Fusion did nothing**: The initial `FusionClassifier` had been trained on synthetic feature distributions before real-world evaluation existed; on CVEfixes and VUDENC it predicted `1` on 100% of SAST-flagged functions.

#### Test 3 & Test 4: Function-Level Board & Phase 3 Candidates Board (realworld_v3 · Sep 29–30, 2026)

1,500 functions · v3-candidates-board

- **Two checkpoints in `eval_results/realworld_v3/`**: `2026-09-29_185842` and `2026-09-30_001429`.
- **What worked**: Switching from per-finding debates to a single function-level debate (`deliberate_function`) and changing `EVIDENCE_MODE` to `"signal"` allowed the SAST board majority vote to remove **40.2% of static false positives** while keeping **71.1% of true positives** (Precision rose from `0.559` to `0.601`).
- **What failed**: Phase 3 added an LLM Auditor (`hunter.py`) and LLM-spec taint (`taint_specs.py`) on every function. The Auditor flagged **96.7%** of all functions (`FPR = 0.968`), and LLM-spec taint flagged **67.9%** (`FPR = 0.685`). Furthermore, tuning thresholds on dev to maximize **F1** fell into the balanced-pair trap: because flagging 100% of functions gets `F1 = 0.667`, the optimizer chose threshold `0.013` for SAST fusion and `0.040` for the candidates board.

#### Test 5: ReposVul Benchmark, MCC Calibration & Guard Check Diagnostic (reposvul_v5 · Oct 3, 2026)

1,006 functions · MCC 0.146

- **Two checkpoints in `eval_results/reposvul_v5/`**: `2026-10-03_135339` and `2026-10-03_135902` on 503 ReposVul Python pairs (101 dev / 402 test pairs).
- **Major statistical & engineering wins**: Replaced F1 calibration with **MCC** (`REALWORLD_CALIBRATE_METRIC=mcc`), added Youden's J = TPR - FPR, repo-cluster bootstrap CIs, and fixed Joern timeouts (`cpg_success_rate = 1.000`). `SAST board: dev-tuned threshold (0.900)` achieved **`MCC = 0.146`** (dMCC = [+0.012, +0.102] vs SAST `0.090`), **`Precision = 0.685`**, removing **53.4% of FPs** while keeping **71.8% of TPs**.
- **Why Phase 3 & Guard Check were cut after v5**: On ReposVul test, `LLM-spec taint alone` had **negative signal** (J = -0.042, MCC = -0.048). The new Judge `guard_check` (`dangerous_operation` / `required_check` / `check_in_code`) scored only J = +0.010 because the Judge conceded (`check_in_code = NONE`) on 754 of 884 debates and parroted prompt examples.

#### Test 6: Pooled Python v6 SAST-Gated Pipeline & Token Baselines (python_v6 · Oct 15, 2026)

2,506 functions · Clean MCC 0.192

- **Verified via `realworld_smoke` (10 samples, `2026-10-15_054127`) then full `python_v6` (`2026-10-15_141218`)**: 2,506 functions (500 CVEfixes + 503 ReposVul + 250 VUDENC pairs; 502 dev, 2,004 test, 0 LLM failures, 100% CPG success).
- **7 architectural upgrades**: (1) Same-file AST callers/callees passed to SAST board; (2) Judge receives automated sanitizer quote verification (`VERIFIED`/`NONE`/`FAILED` at 0.50 coverage); (3) Parallel independent Attacker || Defender (`92.6s` vs `190.0s`); (4) Widened gate with 10 Semgrep packs + `INFO->low` + Bandit `-l -i` + multi-tool dedup tags; (5) Multi-line Joern sink range + `method_line` parameter scoping; (6) Exact CWE/OWASP ID match in RAG before FAISS; (7) Pruned 8-feature Fusion model with L2 CV grid search (C=0.4).
- **Headline outcome**: `SAST board + fusion` is the only system with a strictly positive repo-cluster bootstrap dMCC CI over SAST across the combined test set (`MCC 0.133`, dMCC = [+0.027, +0.088]) and clean subset (`MCC 0.192`, dMCC = [+0.056, +0.174], `Precision 0.778`, `LR+ 3.50`).

---

## 3. v6 Results & Cost

### v6 Pooled Evaluation Results Explorer

Categories on every chart below, in order: SAST Gate, Board Vote, Board Calibrated, Board + Fusion, LLM Only, LLM + Context.

Chart notes, same on every slice:

- Discrimination Signal: MCC×100 and Youden's J×100 (Higher is Better). Source: `eval_results/python_v6/report_latest.md`. Held-out test split (scaled ×100 for readability; 0 = random guessing).
- Precision vs False Positive Rate on All Functions (%). Source: `eval_results/python_v6/report_latest.md`. End-to-end test split. SAST board + fusion cuts FPR down to 4.7%–9.5% while lifting precision to 68%–78%.

#### Combined Test Split (2,004 functions / 1,002 pairs · 442 SAST-flagged)

| System | MCC (×100) | Youden's J = TPR − FPR (×100) | Precision (%) | False Positive Rate (%) | Static FPs Removed (%) | Static TPs Kept (%) |
|---|---:|---:|---:|---:|---:|---:|
| SAST Gate | 7.5 | 6.2 | 57.0 | 19.0 | 0.0 | 100.0 |
| Board Vote | 9.7 | 6.9 | 61.5 | 11.5 | 39.5 | 73.0 |
| Board Calibrated | 9.8 | 6.9 | 62.0 | 10.9 | 42.6 | 70.6 |
| Board + Fusion | 13.3 | 8.3 | 69.0 | 6.8 | 64.2 | 59.9 |
| LLM Only | 7.6 | 6.8 | 56.1 | 24.3 | 45.3 | 67.9 |
| LLM + Context | 9.1 | 7.8 | 58.1 | 20.3 | 56.3 | 63.9 |

#### Clean Single-Function Fixes Subset (676 functions / 338 pairs · 170 SAST-flagged)

| System | MCC (×100) | Youden's J = TPR − FPR (×100) | Precision (%) | False Positive Rate (%) | Static FPs Removed (%) | Static TPs Kept (%) |
|---|---:|---:|---:|---:|---:|---:|
| SAST Gate | 7.5 | 6.5 | 56.5 | 21.9 | 0.0 | 100.0 |
| Board Vote | 11.0 | 8.0 | 62.9 | 11.5 | 47.3 | 68.8 |
| Board Calibrated | 10.8 | 7.7 | 63.0 | 11.0 | 50.0 | 65.6 |
| Board + Fusion | 19.2 | 11.8 | 77.8 | 4.7 | 78.4 | 58.3 |
| LLM Only | 8.2 | 7.4 | 56.6 | 24.3 | 52.7 | 66.7 |
| LLM + Context | 9.7 | 8.3 | 58.8 | 19.5 | 66.2 | 61.5 |

#### ReposVul Test Split (804 functions / 402 pairs · 179 SAST-flagged)

| System | MCC (×100) | Youden's J = TPR − FPR (×100) | Precision (%) | False Positive Rate (%) | Static FPs Removed (%) | Static TPs Kept (%) |
|---|---:|---:|---:|---:|---:|---:|
| SAST Gate | 8.1 | 6.7 | 57.5 | 18.9 | 0.0 | 100.0 |
| Board Vote | 12.0 | 8.5 | 64.7 | 10.2 | 46.1 | 72.8 |
| Board Calibrated | 12.4 | 8.5 | 65.7 | 9.2 | 51.3 | 68.9 |
| Board + Fusion | 13.8 | 8.5 | 70.2 | 6.2 | 67.1 | 57.3 |
| LLM Only | 8.0 | 7.2 | 56.3 | 24.9 | 48.7 | 66.0 |
| LLM + Context | 9.6 | 8.2 | 58.5 | 20.2 | 59.2 | 62.1 |

#### CVEfixes Test Split (800 functions / 400 pairs · 164 SAST-flagged)

| System | MCC (×100) | Youden's J = TPR − FPR (×100) | Precision (%) | False Positive Rate (%) | Static FPs Removed (%) | Static TPs Kept (%) |
|---|---:|---:|---:|---:|---:|---:|
| SAST Gate | 6.8 | 5.5 | 56.7 | 17.7 | 0.0 | 100.0 |
| Board Vote | 6.6 | 4.5 | 58.3 | 11.3 | 36.6 | 67.7 |
| Board Calibrated | 6.7 | 4.5 | 58.7 | 10.7 | 39.4 | 65.6 |
| Board + Fusion | 11.6 | 6.8 | 68.0 | 6.0 | 66.2 | 54.8 |
| LLM Only | 5.8 | 5.0 | 55.1 | 21.7 | 52.1 | 60.2 |
| LLM + Context | 6.5 | 5.2 | 56.3 | 18.2 | 66.2 | 54.8 |

#### VUDENC Test Split (400 functions / 200 pairs · 99 SAST-flagged)

| System | MCC (×100) | Youden's J = TPR − FPR (×100) | Precision (%) | False Positive Rate (%) | Static FPs Removed (%) | Static TPs Kept (%) |
|---|---:|---:|---:|---:|---:|---:|
| SAST Gate | 7.5 | 6.5 | 56.6 | 21.5 | 0.0 | 100.0 |
| Board Vote | 10.9 | 8.5 | 61.3 | 14.5 | 32.6 | 82.1 |
| Board Calibrated | 10.9 | 8.5 | 61.3 | 14.5 | 32.6 | 82.1 |
| Board + Fusion | 15.4 | 11.0 | 68.3 | 9.5 | 55.8 | 73.2 |
| LLM Only | 10.1 | 9.5 | 57.1 | 28.5 | 27.9 | 83.9 |
| LLM + Context | 13.0 | 12.0 | 59.8 | 24.5 | 34.9 | 82.1 |

### Token Cost & Efficiency Analysis (Combined Test: 2,004 Functions)

SAST Gate Filtering Efficiency (2,004 Test Functions): 442 sent to LLM (22.1%) · 1,562 skipped at 0 tokens (77.9%).

Usage-bar segments (of 2,004):

- Vulnerable functions the gate sent on: 252
- Fixed functions the gate sent on: 190
- Remainder, not sent: 1,562

| System | Functions Sent to LLM | LLM Calls / Reviewed Func | Mean Tokens / Function (All 2,004) | Mean Tokens / Reviewed Func | True Positives (Calibrated) | Tokens per True Positive |
|---|---:|---:|---:|---:|---:|---:|
| Semgrep + Bandit (Static Gate Only) | 0 / 2,004 (0.0%) | 0 | 0.0 | 0 | 252 | 0 |
| SAST Board (Attacker \|\| Defender -> Judge) | 442 / 2,004 (22.1%) | 3 | 1,312.0 | 5,948 | 178 (Board) / 151 (Fusion) | 14,771 |
| LLM Only, Whole Function (No SAST) | 2,004 / 2,004 (100.0%) | 1 | 1,052.2 | 1,052 | 312 | 6,758 |
| LLM Only + Same-File Context (No SAST) | 2,004 / 2,004 (100.0%) | 1 | 1,213.9 | 1,214 | 281 | 8,657 |

### Why SAST Board Currently Uses 1,312 Mean Tokens/Func vs 1,052 for LLM-Only

Although the SAST gate skips **77.9%** of functions for free, each of the **22.1%** flagged functions triggers **3 separate LLM calls** (Attacker, Defender, Judge), and each seat receives the full function code, AST context, and enriched findings packet (~5,948 tokens total per flagged function). Replacing the Attacker LLM call with the deterministic SAST+Joern brief (a 2-seat Defender → Judge board) will drop board cost to ~850 mean tokens/function, beating single-pass LLM-only on both token cost and accuracy.

### CWE Vulnerability Family Breakdown (v6 Combined Test)

| Vulnerability Family | Test Functions | Vuln Flagged by SAST (%) | SAST MCC / Recall | Board Calibrated MCC / Recall | LLM-Only Calibrated MCC / Recall | LLM+Context Calibrated MCC / Recall |
|---|---:|---:|---|---|---|---|
| sast_reachable (Pattern-Matchable) | 1,088 | 34.2% | 0.116 / 0.342 | 0.133 / 0.278 | 0.104 / 0.465 | 0.134 / 0.426 |
| logic_semantic (Auth, DoS, State, Info) | 916 | 14.4% | 0.016 / 0.144 | 0.045 / 0.059 | 0.041 / 0.129 | 0.029 / 0.107 |
| injection (SQLi, Cmd, XSS, Code) | 600 | 40.7% | 0.130 / 0.407 | 0.147 / 0.333 | 0.090 / 0.507 | 0.142 / 0.477 |
| access_control (Logic) | 306 | 15.7% | 0.028 / 0.157 | 0.051 / 0.085 | 0.010 / 0.131 | -0.020 / 0.111 |
| path_traversal (CWE-22) | 190 | 17.9% | 0.073 / 0.179 | 0.123 / 0.137 | 0.183 / 0.390 | 0.212 / 0.368 |
| ssrf_redirect (CWE-918 / CWE-601) | 152 | 25.0% | 0.047 / 0.250 | 0.070 / 0.197 | 0.083 / 0.395 | 0.044 / 0.303 |
| deserialization (Pickle / YAML) | 36 | 94.4% | 0.543 / 0.944 | 0.543 / 0.944 | 0.298 / 0.944 | 0.298 / 0.944 |
| xml (XXE) | 28 | 35.7% | 0.247 / 0.357 | 0.408 / 0.286 | 0.143 / 0.571 | 0.072 / 0.500 |

---

## 4. Fusion Model & Next Steps

### Inside the v6 Fusion Classifier (eval_results/python_v6/fusion_model.json)

Fitted on 79 SAST-flagged dev functions via 5-fold Stratified CV (C = 0.4, intercept = 0.0468, decision threshold = 0.5973). Every feature is z-score standardized (`(x - mean) / scale`) before multiplying by its learned weight.

### Standardized Logistic Regression Coefficients (×100)

Source: `eval_results/python_v6/fusion_model.json`. Magnitude of standardized coefficients (×100). Positive weights increase P(vulnerable); negative weights decrease P(vulnerable).

| Feature (signed weight ×100) | Absolute Magnitude of Weight (\|coef\| × 100) |
|---|---:|
| p_vulnerable (+20.8) | 20.8 |
| max_severity (+19.5) | 19.5 |
| both_tools (+6.0) | 6.0 |
| log_findings (−14.2) | 14.2 |
| any_taint (−15.4) | 15.4 |
| attacker_conf (−17.0) | 17.0 |
| evidence_grounded (−19.0) | 19.0 |
| defender_safety (−83.5) | 83.5 |

| Feature | Dev Mean | Dev Scale | Learned Weight (coef) | Direction & Physical Meaning |
|---|---:|---:|---:|---|
| p_vulnerable | 0.662 | 0.402 | +0.2078 | Higher Judge probability pushes prediction toward VULNERABLE |
| max_severity | 0.525 | 0.184 | +0.1948 | High/Critical static rules are much more likely to be real bugs |
| both_tools_flagged | 0.291 | 0.454 | +0.0595 | Semgrep + Bandit agreement increases vulnerability confidence |
| log_findings | 0.930 | 0.351 | −0.1419 | Many noisy low-severity alerts in one function slightly lower precision |
| any_taint | 0.646 | 0.478 | −0.1537 | Joern taint is sanitizer-blind (fires on fixed functions too) |
| attacker_confidence | 0.871 | 0.119 | −0.1704 | Attacker is chronically overconfident (mean 0.871, tiny variance) |
| evidence_grounded | 0.203 | 0.402 | −0.1903 | Verified verbatim sanitizer quote in code lowers P(vulnerable) |
| defender_safety | 0.533 | 0.330 | −0.8351 | Strongest discriminator: high Defender safety score suppresses FPs |

### 4 High-Impact Improvements for Next Iteration (v7 Roadmap)

#### 1. 2-Seat Board: SAST+Joern as Attacker Brief → Defender → Judge

Tag: −38% Tokens & Stronger Rebuttal.

In v6, `attacker_confidence` had a dev mean of `0.871` (`std = 0.119`) and a negative fusion weight (`-0.170`) because the Attacker LLM seat argues every SAST alert is exploitable. Meanwhile, making the Defender blind (`attacker=None`) slightly hurt the raw Judge threshold on ReposVul (`0.146 → 0.124`). Using the enriched SAST + Joern flow directly as the concrete attack claim lets the Defender rebut the exact sink/flow, restores sequential rebuttal quality, and cuts LLM calls per flagged function from **3 to 2** (~850 mean tokens/func, beating `LLM-only`).

#### 2. Sanitizer-Aware Joern Taint (Unfiltered vs Guarded Flows)

Tag: Fix −0.154 Taint Weight.

`any_taint` fired on **67.2%** of flagged functions and received a negative weight (`-0.154`) because Joern's `sink.reachableByFlows(source)` treats every function parameter as a taint source and does not stop when the patch adds `shlex.quote`, `os.path.realpath`, `int()`, or a dominating `if` check. Splitting taint into `unfiltered_taint` vs `guarded_taint` (checking whether flow nodes pass through validation/escaping calls or branch guards) will turn Joern into a positive discriminator between vulnerable and fixed pairs.

#### 3. Zero-Token Python AST Sink Gate for Path Traversal & SSRF

Tag: Raise 25.2% Recall Ceiling.

On `path_traversal` (190 functions), SAST flagged only **17.9%** of vulnerable functions (`MCC = 0.073`), whereas `LLM + context` reached **36.8% recall** (`MCC = 0.212`). Semgrep and Bandit miss dynamic path joins (`open(os.path.join(base, user_path))`), `shutil`/`tarfile`/`zipfile` extraction, and `requests`/`urllib` calls unless they match narrow literal patterns. A zero-token Python AST pre-filter that flags parameter-to-filesystem/network sinks will route those functions to the board without running an LLM on the whole dataset.

#### 4. Sync Celery Worker & Dashboard Headline with v6 Fusion

Tag: Unify Production & Eval.

1) In `hackersec/evaluation/realworld/report.py`, `HEADLINE_ORDER` still lists `board_calibrated` before `fusion`, so the top-level JSON summary key `hackersec_system` reports `board_calibrated` (`MCC 0.098`) instead of `fusion` (`MCC 0.133`). 2) In `hackersec/worker/tasks.py`, the live API worker still runs per-finding `board.deliberate()` and the legacy synthetic `FusionClassifier`. Wiring `deliberate_function()` + `fusion_model.json` into the worker aligns production scans with the benchmarked pipeline.
