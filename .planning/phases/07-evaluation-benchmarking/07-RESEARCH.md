# Phase 7 Research: Evaluation & Benchmarking

## RESEARCH COMPLETE

**Phase:** 7 — Evaluation & Benchmarking
**Goal:** Compute standard academic metrics (Precision, Recall, F1, FPR) validating HackerSec's performance improvements relative to raw SAST execution (Semgrep-only baseline) across Big-Vul and Juliet models.

---

## 1. Datasets Integration

Running massive suites gigabytes large offline typically halts development environments. Instead of blocking pipelines:
- **Test Generation Simulation:** The codebase mandates a `.py` generator mocking known vulnerable scripts matching Juliet semantics and Semgrep rules (e.g. `eval(user_input)` or `md5()`).
- Data directories (`data/juliet_subset`, `data/big_vul_subset`) will receive small scripted samples covering baseline configurations limiting the matrix arrays securely protecting bounds identically limiting CPU cycles natively.

## 2. Evaluation Metrics Mappings

For each job, the system evaluates:
- **Baseline (Semgrep Only):** If Semgrep detects it => `Positive`. (High False Positive Rate).
- **HackerSec:** If Semgrep + LLM + CPG -> Fusion -> output equals `"true_positive"` => `Positive`.
- **True Label:** Loaded directly from the test suite JSON metadata.
- **Formula:** 
    - Precision: TP / (TP + FP)
    - Recall: TP / (TP + FN)
    - F1: 2 * (Precision * Recall) / (Precision + Recall)

## 3. Results Aggregator Limits

- Export results strictly inside `eval_results/YYYY-MM-DD_run.json`.
- The structures enforce arrays partitioned per `CWE-ID` securely summarizing the accuracy differences per vulnerability category effectively validating ML improvements natively.

## Validation Strategy
1. **Runner Loops:** Execute mock arrays against baseline tools natively returning formatted metrics preventing JSON dump errors. 
2. **Deterministic Arrays:** Check formulas explicitly asserting basic tests `Precision=1.0` if `TP=1, FP=0`.
