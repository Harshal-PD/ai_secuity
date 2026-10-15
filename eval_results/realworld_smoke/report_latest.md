# HackerSec real-world evaluation (2026-10-15T05:41:27)

Status: **complete** — 10/10 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v6-sast-gate`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| reposvul | 1 (1) | 4 (4) | 5 |

- Dev functions evaluated: 2
- Fusion: only 0 flagged dev functions (need 20)
- LLM-only threshold on P(vulnerable): **0.000** (max mcc on dev)
- LLM-only + context threshold on P(vulnerable): **0.000** (max mcc on dev)

Each pair contributes one vulnerable and one fixed function, so flagging every function scores F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise columns show whether a system actually separates vulnerable from fixed code.

## Test split (primary)

### reposvul — 8 functions, 4 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.000 [0.000, 0.000] | — | 1.000 | 0.500 | 1.000 | — | — | — / — |
| Semgrep alone | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| Bandit alone | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| SAST board: Judge vote | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.500 | 1.000 | 1.000 | — | — / — |
| SAST board + evidence override (ablation) | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| LLM only, whole function, no SAST | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | — | — / — |
| LLM only, dev-tuned threshold | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | 1.00 | 0.050 / 0.010 |
| LLM only + same-file context, no SAST | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | — | — / — |
| LLM only + context, dev-tuned threshold | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | 1.00 | 0.050 / 0.010 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.667 [0.667, 0.667] | 1.000 |
| Semgrep + Bandit | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | — | 0.000 [0.000, 0.000] | — |
| Semgrep alone | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| Bandit alone | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| SAST board: Judge vote | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| SAST board + evidence override (ablation) | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| LLM only, whole function, no SAST | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| LLM only, dev-tuned threshold | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.667 [0.667, 0.667] | 1.000 |
| LLM only + same-file context, no SAST | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| LLM only + context, dev-tuned threshold | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.667 [0.667, 0.667] | 1.000 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Semgrep + Bandit (no LLM) | 0 | 0.0 | 0 | — |
| SAST board (LLM only where static analysis flagged) | 0 | 0.0 | 0 | — |
| LLM only, whole function, no SAST | 8 | 1,057.4 | 4 | 2,115 |
| LLM only + same-file context, no SAST | 8 | 1,150.1 | 4 | 2,300 |


**On functions static analysis flagged** (0: 0 vulnerable, 0 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| Semgrep + Bandit | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| Semgrep alone | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| Bandit alone | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| SAST board: Judge vote | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| SAST board + evidence override (ablation) | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only, whole function, no SAST | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only, dev-tuned threshold | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only + same-file context, no SAST | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only + context, dev-tuned threshold | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 4 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| Semgrep alone | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| Bandit alone | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| SAST board: Judge vote | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| SAST board + evidence override (ablation) | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| LLM only, whole function, no SAST | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| LLM only, dev-tuned threshold | 4 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| LLM only + same-file context, no SAST | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| LLM only + context, dev-tuned threshold | 4 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| LLM only, whole function, no SAST | 1.000 | 1.000 |
| LLM only, dev-tuned threshold | 1.000 | 1.000 |
| LLM only + same-file context, no SAST | 1.000 | 1.000 |
| LLM only + context, dev-tuned threshold | 1.000 | 1.000 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | sast MCC / R | semgrep MCC / R | bandit MCC / R | llm_only_calibrated MCC / R | llm_context_calibrated MCC / R |
|---|---|---|---|---|---|---|---|
| **logic_semantic** | 6 | 0.0% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| **sast_reachable** | 2 | 0.0% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| access_control (logic) | 4 | 0.0% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| injection | 2 | 0.0% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 1.000 | 0.000 / 1.000 |
| memory_numeric (logic) | 2 | 0.0% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 1.000 | 0.000 / 1.000 |

### Pipeline telemetry (test)

- flagged_functions: 0
- findings: 0
- findings_per_flagged_function: None
- by_tool: {}
- cpg_success_rate: None
- cpg_taint_found_rate: None
- rag_context_rate: None
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **llm_baselines**: llm_only_parse_failed_rate 0.0, llm_only_vulnerable_rate 0.0, llm_context_parse_failed_rate 0.0, llm_context_vulnerable_rate 0.0

## Test, clean subset (single-function fixes)

### clean — 8 functions, 4 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.000 [0.000, 0.000] | — | 1.000 | 0.500 | 1.000 | — | — | — / — |
| Semgrep alone | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| Bandit alone | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| SAST board: Judge vote | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.500 | 1.000 | 1.000 | — | — / — |
| SAST board + evidence override (ablation) | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| LLM only, whole function, no SAST | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | — | — / — |
| LLM only, dev-tuned threshold | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | 1.00 | 0.050 / 0.010 |
| LLM only + same-file context, no SAST | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | — | — / — |
| LLM only + context, dev-tuned threshold | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | 1.00 | 0.050 / 0.010 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.667 [0.667, 0.667] | 1.000 |
| Semgrep + Bandit | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | — | 0.000 [0.000, 0.000] | — |
| Semgrep alone | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| Bandit alone | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| SAST board: Judge vote | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| SAST board + evidence override (ablation) | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| LLM only, whole function, no SAST | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| LLM only, dev-tuned threshold | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.667 [0.667, 0.667] | 1.000 |
| LLM only + same-file context, no SAST | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.000 [0.000, 0.000] | 1.000 |
| LLM only + context, dev-tuned threshold | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [0.000, 0.000] | 0.667 [0.667, 0.667] | 1.000 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Semgrep + Bandit (no LLM) | 0 | 0.0 | 0 | — |
| SAST board (LLM only where static analysis flagged) | 0 | 0.0 | 0 | — |
| LLM only, whole function, no SAST | 8 | 1,057.4 | 4 | 2,115 |
| LLM only + same-file context, no SAST | 8 | 1,150.1 | 4 | 2,300 |


**On functions static analysis flagged** (0: 0 vulnerable, 0 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| Semgrep + Bandit | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| Semgrep alone | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| Bandit alone | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| SAST board: Judge vote | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| SAST board + evidence override (ablation) | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only, whole function, no SAST | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only, dev-tuned threshold | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only + same-file context, no SAST | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |
| LLM only + context, dev-tuned threshold | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | — | — |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 4 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| Semgrep alone | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| Bandit alone | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| SAST board: Judge vote | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| SAST board + evidence override (ablation) | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| LLM only, whole function, no SAST | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| LLM only, dev-tuned threshold | 4 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| LLM only + same-file context, no SAST | 4 | 0.000 [0.000, 0.000] | 0.000 | 1.000 | 0.000 | 0.000 | — |
| LLM only + context, dev-tuned threshold | 4 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| LLM only, whole function, no SAST | 1.000 | 1.000 |
| LLM only, dev-tuned threshold | 1.000 | 1.000 |
| LLM only + same-file context, no SAST | 1.000 | 1.000 |
| LLM only + context, dev-tuned threshold | 1.000 | 1.000 |

## Test, split by ReposVul's own static check

ReposVul's strict label requires Semgrep or RATS to flag the pre-fix file at the changed lines. SAST is favoured by construction where that check matched; the other stratum shows how each system does on fixes that pattern rules did not see.

### ReposVul static check did not match — 8 functions, 4 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.000 [0.000, 0.000] | — | 1.000 | 0.500 | 1.000 | — | — | — / — |
| Semgrep alone | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| Bandit alone | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| SAST board: Judge vote | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.500 | 1.000 | 1.000 | — | — / — |
| SAST board + evidence override (ablation) | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | — | — | 1.000 | — | — / — |
| LLM only, whole function, no SAST | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | — | — / — |
| LLM only, dev-tuned threshold | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | 1.00 | 0.050 / 0.010 |
| LLM only + same-file context, no SAST | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | — | — / — |
| LLM only + context, dev-tuned threshold | +0.000 [0.000, 0.000] | [0.000, 0.000] | 1.000 | 0.375 | 1.000 | 1.000 | 1.00 | 0.050 / 0.010 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | FPR | Accuracy | MCC | F1 |
|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| Semgrep + Bandit | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0.000 |
| Semgrep alone | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0.000 |
| Bandit alone | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0.000 |
| SAST board: Judge vote | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0.000 |
| SAST board + evidence override (ablation) | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0.000 |
| LLM only, whole function, no SAST | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0.000 |
| LLM only, dev-tuned threshold | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| LLM only + same-file context, no SAST | 0.000 | 0.000 | 0.000 | 0.500 | 0.000 | 0.000 |
| LLM only + context, dev-tuned threshold | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |

## Caveats

- Labels follow the fix-commit convention (CVEfixes, PrimeVul): a function changed by a security-fix commit is vulnerable before the fix and fixed after it. Tangled commits (> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded; the clean subset further keeps only commits that changed a single function.
- The SAST board only reasons about Semgrep and Bandit findings, so its recall cannot exceed theirs. The sast_flagged view isolates what the board adds on the functions it is asked to review.
- The LLM-only rows ask the same model once, with no static findings: the function alone, and the function plus same-file callers and callees. They are comparison baselines, not part of the shipped pipeline. They never see the dataset label or CWE. Context is limited to the same file.
- Token counts are Ollama's prompt_eval_count plus eval_count. Tokens per true positive divides the tokens spent on that system by the true positives of its dev-tuned threshold.
- Board thresholds and fusion models are fitted on the dev split only (maximising mcc); test repositories never appear in dev. Dev numbers are in-sample and are shown for reference.
- Test and dev are balanced by construction (one vulnerable and one fixed function per pair), so F1 rewards flagging everything: compare every row with the trivial reference, and read MCC, accuracy and the pairwise columns for discrimination. 'Right way round' is the share of pairs with differing verdicts where the vulnerable version is the flagged one; 0.5 means no signal.
- Confidence intervals resample whole repositories (1,000 draws), since pairs from one project are not independent. McNemar compares per-function correctness against SAST. Sign-test and McNemar p values in the signal tables are Holm-corrected across the systems compared.
- Precision at a given prevalence is TPR·π / (TPR·π + FPR·(1 − π)): what a user would see if that share of functions were vulnerable, instead of the 50% this test set has by construction.
- ReposVul files are kept by its 'llm' label policy (llm = its LLM untangling check marks the file as vulnerability-fixing; strict = its LLM and static checks both do), and patches it marks as outdated are skipped. Its static check is Semgrep/RATS, so the 'static check matched' stratum favours SAST by construction, and its LLM check may favour fixes an LLM recognises.
