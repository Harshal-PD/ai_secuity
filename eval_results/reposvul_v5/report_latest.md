# HackerSec real-world evaluation (2026-10-03T13:59:02)

Status: **complete** — 1006/1006 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v5-guard-check`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| reposvul | 101 (49) | 402 (151) | 218 |

- Dev functions evaluated: 202
- Board threshold on mean P(vulnerable) across Judge votes: **0.900** (max mcc on dev)
- Fusion: trained on 35 flagged dev functions (5-fold CV threshold, max mcc), threshold 0.337, dev CV F1 0.264, dev CV MCC 0.086
- Candidates board threshold on mean P(vulnerable): **0.900** (max mcc on dev)
- Candidates fusion: trained on 180 flagged dev functions (5-fold CV threshold, max mcc), threshold 0.576, dev CV F1 0.462, dev CV MCC 0.105

Each pair contributes one vulnerable and one fixed function, so flagging every function scores F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise columns show whether a system actually separates vulnerable from fixed code.

## Test split (primary)

### reposvul — 804 functions, 402 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.111, -0.041] | 1.000 | — | — | 0.247 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit (baseline) | +0.075 [0.041, 0.111] | — | 0 | 0.537 | 0 | — | 1.41 | 0.069 / 0.014 |
| SAST board: Judge majority vote | +0.095 [0.052, 0.144] | [-0.010, 0.055] | 0 | 0.552 | 0 | 1.000 | 1.95 | 0.093 / 0.019 |
| SAST board + evidence override (ablation) | +0.095 [0.059, 0.135] | [0.003, 0.042] | 0 | — | — | 1.000 | 1.63 | 0.079 / 0.016 |
| SAST board: vote score, dev-tuned threshold | +0.100 [0.060, 0.147] | [-0.007, 0.061] | 0 | 0.556 | 0 | 1.000 | 2.18 | 0.103 / 0.021 |
| SAST board + fusion (trained on dev) | +0.090 [0.050, 0.136] | [-0.007, 0.042] | 0 | 0.542 | 0.005 | 1.000 | 1.60 | 0.078 / 0.016 |
| LLM auditor alone (no critic) | +0.045 [-0.006, 0.103] | [-0.083, 0.029] | 0.412 | 0.500 | 1.000 | 1.000 | 1.13 | 0.056 / 0.011 |
| LLM-spec taint alone (no critic) | -0.042 [-0.077, -0.009] | [-0.163, -0.068] | 0.130 | — | — | 0.430 | 0.94 | 0.047 / 0.009 |
| Any candidate: SAST, taint or auditor (no critic) | -0.017 [-0.046, 0.012] | [-0.135, -0.050] | 0.827 | — | — | 1.000 | 0.98 | 0.049 / 0.010 |
| Candidates board: Judge majority vote | +0.052 [0.000, 0.109] | [-0.086, 0.041] | 0.412 | 0.525 | 0.316 | 1.000 | 1.10 | 0.055 / 0.011 |
| Candidates board + evidence override (ablation) | +0.030 [-0.015, 0.074] | [-0.101, 0.007] | 0.827 | — | — | 1.000 | 1.04 | 0.052 / 0.010 |
| Candidates board: vote score, dev-tuned threshold | +0.035 [-0.018, 0.096] | [-0.095, 0.024] | 0.827 | 0.520 | 0.615 | 1.000 | 1.08 | 0.054 / 0.011 |
| Candidates board + fusion (trained on dev) | +0.085 [0.033, 0.140] | [-0.044, 0.066] | 0.005 | 0.570 | 0.011 | 1.000 | 1.41 | 0.069 / 0.014 |
| Candidates board: flagged unless the Judge's quoted check is in the code | +0.010 [-0.030, 0.050] | [-0.118, -0.013] | 0.827 | — | — | 1.000 | 1.01 | 0.051 / 0.010 |

**End-to-end** (every function; SAST-board recall is capped by SAST, candidates-board recall by the any-candidate row)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.134, -0.049] | 0.667 [0.667, 0.667] | 0.2472 |
| Semgrep + Bandit (baseline) | 0.585 | 0.256 | 0.182 | 0.537 | 0.090 [0.049, 0.134] | — | 0.356 [0.310, 0.405] | — |
| SAST board: Judge majority vote | 0.661 | 0.194 | 0.100 | 0.547 | 0.134 [0.075, 0.193] | [0.000, 0.091] | 0.300 [0.238, 0.366] | 0.3581 |
| SAST board + evidence override (ablation) | 0.620 | 0.244 | 0.149 | 0.547 | 0.119 [0.074, 0.167] | [0.008, 0.056] | 0.350 [0.298, 0.403] | 0.0963 |
| SAST board: vote score, dev-tuned threshold | 0.685 | 0.184 | 0.085 | 0.550 | 0.146 [0.093, 0.205] | [0.012, 0.102] | 0.290 [0.230, 0.356] | 0.2750 |
| SAST board + fusion (trained on dev) | 0.615 | 0.239 | 0.149 | 0.545 | 0.113 [0.064, 0.174] | [-0.006, 0.059] | 0.344 [0.292, 0.398] | 0.2632 |
| LLM auditor alone (no critic) | 0.530 | 0.401 | 0.356 | 0.522 | 0.046 [-0.007, 0.106] | [-0.101, 0.017] | 0.456 [0.407, 0.508] | 0.5017 |
| LLM-spec taint alone (no critic) | 0.486 | 0.719 | 0.761 | 0.479 | -0.048 [-0.090, -0.011] | [-0.191, -0.082] | 0.580 [0.560, 0.598] | 0.0358 |
| Any candidate: SAST, taint or auditor (no critic) | 0.495 | 0.811 | 0.828 | 0.491 | -0.023 [-0.062, 0.016] | [-0.166, -0.060] | 0.615 [0.598, 0.631] | 0.1013 |
| Candidates board: Judge majority vote | 0.523 | 0.595 | 0.542 | 0.526 | 0.053 [0.000, 0.111] | [-0.105, 0.029] | 0.556 [0.525, 0.589] | 0.6755 |
| Candidates board + evidence override (ablation) | 0.510 | 0.756 | 0.726 | 0.515 | 0.034 [-0.018, 0.084] | [-0.121, 0.005] | 0.609 [0.589, 0.630] | 0.4219 |
| Candidates board: vote score, dev-tuned threshold | 0.519 | 0.465 | 0.430 | 0.517 | 0.035 [-0.018, 0.097] | [-0.115, 0.011] | 0.491 [0.448, 0.535] | 0.3865 |
| Candidates board + fusion (trained on dev) | 0.585 | 0.291 | 0.206 | 0.542 | 0.098 [0.038, 0.162] | [-0.054, 0.070] | 0.389 [0.330, 0.447] | 0.8191 |
| Candidates board: flagged unless the Judge's quoted check is in the code | 0.503 | 0.771 | 0.761 | 0.505 | 0.012 [-0.037, 0.058] | [-0.144, -0.017] | 0.609 [0.590, 0.627] | 0.2478 |

**On functions static analysis flagged** (176: 103 vulnerable, 73 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.585 | 1.000 | 1.000 | 0.000 | 0.738 | 0.0% | 100.0% |
| Semgrep + Bandit (baseline) | 0.585 | 1.000 | 1.000 | 0.000 | 0.738 | — | — |
| SAST board: Judge majority vote | 0.661 | 0.757 | 0.548 | 0.219 | 0.706 | 45.2% | 75.7% |
| SAST board + evidence override (ablation) | 0.620 | 0.952 | 0.822 | 0.211 | 0.751 | 17.8% | 95.2% |
| SAST board: vote score, dev-tuned threshold | 0.685 | 0.718 | 0.466 | 0.256 | 0.701 | 53.4% | 71.8% |
| SAST board + fusion (trained on dev) | 0.615 | 0.932 | 0.822 | 0.171 | 0.741 | 17.8% | 93.2% |
| LLM auditor alone (no critic) | 0.623 | 0.641 | 0.548 | 0.093 | 0.632 | 45.2% | 64.1% |
| LLM-spec taint alone (no critic) | 0.572 | 0.806 | 0.849 | -0.056 | 0.669 | 15.1% | 80.6% |
| Any candidate: SAST, taint or auditor (no critic) | 0.585 | 1.000 | 1.000 | 0.000 | 0.738 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.642 | 0.835 | 0.657 | 0.205 | 0.726 | 34.2% | 83.5% |
| Candidates board + evidence override (ablation) | 0.611 | 0.961 | 0.863 | 0.179 | 0.747 | 13.7% | 96.1% |
| Candidates board: vote score, dev-tuned threshold | 0.644 | 0.738 | 0.575 | 0.170 | 0.688 | 42.5% | 73.8% |
| Candidates board + fusion (trained on dev) | 0.637 | 0.631 | 0.507 | 0.124 | 0.634 | 49.3% | 63.1% |
| Candidates board: flagged unless the Judge's quoted check is in the code | 0.605 | 0.952 | 0.877 | 0.136 | 0.740 | 12.3% | 95.2% |

**On functions any candidate source flagged (SAST, LLM-spec taint or auditor)** (659: 326 vulnerable, 333 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.495 | 1.000 | 1.000 | 0.000 | 0.662 | 0.0% | 100.0% |
| Semgrep + Bandit (baseline) | 0.585 | 0.316 | 0.219 | 0.109 | 0.410 | — | — |
| SAST board: Judge majority vote | 0.661 | 0.239 | 0.120 | 0.155 | 0.351 | 88.0% | 23.9% |
| SAST board + evidence override (ablation) | 0.620 | 0.301 | 0.180 | 0.141 | 0.405 | 82.0% | 30.1% |
| SAST board: vote score, dev-tuned threshold | 0.685 | 0.227 | 0.102 | 0.169 | 0.341 | 89.8% | 22.7% |
| SAST board + fusion (trained on dev) | 0.615 | 0.294 | 0.180 | 0.134 | 0.398 | 82.0% | 29.4% |
| LLM auditor alone (no critic) | 0.530 | 0.494 | 0.429 | 0.065 | 0.511 | 57.1% | 49.4% |
| LLM-spec taint alone (no critic) | 0.486 | 0.886 | 0.919 | -0.055 | 0.628 | 8.1% | 88.6% |
| Any candidate: SAST, taint or auditor (no critic) | 0.495 | 1.000 | 1.000 | 0.000 | 0.662 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.523 | 0.733 | 0.655 | 0.085 | 0.611 | 34.5% | 73.3% |
| Candidates board + evidence override (ablation) | 0.510 | 0.932 | 0.877 | 0.095 | 0.659 | 12.3% | 93.2% |
| Candidates board: vote score, dev-tuned threshold | 0.519 | 0.574 | 0.519 | 0.054 | 0.545 | 48.0% | 57.4% |
| Candidates board + fusion (trained on dev) | 0.585 | 0.359 | 0.249 | 0.119 | 0.445 | 75.1% | 35.9% |
| Candidates board: flagged unless the Judge's quoted check is in the code | 0.503 | 0.951 | 0.919 | 0.065 | 0.658 | 8.1% | 95.1% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 402 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit (baseline) | 402 | 0.082 [0.050, 0.119] | 0.174 | 0.736 | 0.007 | 0.090 | 0.917 |
| SAST board: Judge majority vote | 402 | 0.112 [0.072, 0.159] | 0.082 | 0.789 | 0.017 | 0.129 | 0.865 |
| SAST board + evidence override (ablation) | 402 | 0.102 [0.067, 0.141] | 0.142 | 0.749 | 0.007 | 0.110 | 0.932 |
| SAST board: vote score, dev-tuned threshold | 402 | 0.110 [0.072, 0.155] | 0.075 | 0.806 | 0.010 | 0.119 | 0.917 |
| SAST board + fusion (trained on dev) | 402 | 0.102 [0.066, 0.146] | 0.137 | 0.749 | 0.012 | 0.114 | 0.891 |
| LLM auditor alone (no critic) | 402 | 0.142 [0.111, 0.181] | 0.259 | 0.502 | 0.097 | 0.239 | 0.594 |
| LLM-spec taint alone (no critic) | 402 | 0.037 [0.021, 0.056] | 0.682 | 0.202 | 0.080 | 0.117 | 0.319 |
| Any candidate: SAST, taint or auditor (no critic) | 402 | 0.042 [0.024, 0.064] | 0.769 | 0.129 | 0.060 | 0.102 | 0.415 |
| Candidates board: Judge majority vote | 402 | 0.177 [0.133, 0.221] | 0.418 | 0.281 | 0.124 | 0.301 | 0.587 |
| Candidates board + evidence override (ablation) | 402 | 0.110 [0.076, 0.142] | 0.647 | 0.164 | 0.080 | 0.189 | 0.579 |
| Candidates board: vote score, dev-tuned threshold | 402 | 0.179 [0.141, 0.222] | 0.286 | 0.391 | 0.144 | 0.323 | 0.554 |
| Candidates board + fusion (trained on dev) | 402 | 0.162 [0.124, 0.205] | 0.129 | 0.632 | 0.077 | 0.239 | 0.677 |
| Candidates board: flagged unless the Judge's quoted check is in the code | 402 | 0.090 [0.059, 0.120] | 0.682 | 0.149 | 0.080 | 0.169 | 0.529 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit (baseline) | 1.000 | 1.000 |
| SAST board: Judge majority vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.980 | 0.980 |
| SAST board + fusion (trained on dev) | 1.000 | 0.920 |
| LLM auditor alone (no critic) | 0.993 | 0.993 |
| Candidates board: Judge majority vote | 1.000 | 1.000 |
| Candidates board: vote score, dev-tuned threshold | 1.000 | 0.953 |
| Candidates board + fusion (trained on dev) | 0.988 | 0.888 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | Vulnerable with any candidate | sast MCC / R | board_calibrated MCC / R | hunter_raw MCC / R | union_raw MCC / R | full_board MCC / R | full_fusion MCC / R |
|---|---|---|---|---|---|---|---|---|---|
| **logic_semantic** | 422 | 16.6% | 74.9% | 0.033 / 0.166 | 0.064 / 0.090 | 0.005 / 0.270 | -0.028 / 0.749 | 0.005 / 0.488 | 0.055 / 0.204 |
| **sast_reachable** | 382 | 35.6% | 88.0% | 0.144 / 0.356 | 0.215 / 0.288 | 0.089 / 0.544 | -0.016 / 0.880 | 0.111 / 0.712 | 0.140 / 0.387 |
| injection | 230 | 41.7% | 89.6% | 0.156 / 0.417 | 0.249 / 0.330 | 0.035 / 0.548 | -0.062 / 0.896 | 0.148 / 0.739 | 0.126 / 0.435 |
| access_control (logic) | 108 | 14.8% | 72.2% | 0.000 / 0.148 | 0.031 / 0.111 | -0.066 / 0.204 | -0.021 / 0.722 | 0.000 / 0.463 | 0.085 / 0.148 |
| info_exposure (logic) | 104 | 17.3% | 73.1% | 0.026 / 0.173 | 0.038 / 0.077 | -0.064 / 0.250 | -0.068 / 0.731 | 0.000 / 0.558 | 0.066 / 0.288 |
| input_validation (logic) | 102 | 15.7% | 84.3% | 0.088 / 0.157 | 0.202 / 0.078 | 0.122 / 0.431 | -0.028 / 0.843 | -0.020 / 0.569 | 0.073 / 0.235 |
| path_traversal | 56 | 17.9% | 92.9% | 0.049 / 0.179 | 0.102 / 0.179 | 0.215 / 0.571 | 0.063 / 0.929 | 0.076 / 0.714 | 0.282 / 0.393 |
| other (logic) | 52 | 15.4% | 57.7% | 0.120 / 0.154 | 0.083 / 0.077 | 0.051 / 0.192 | -0.079 / 0.577 | -0.081 / 0.308 | -0.120 / 0.077 |
| ssrf_redirect | 42 | 19.1% | 90.5% | 0.064 / 0.191 | 0.073 / 0.143 | 0.048 / 0.524 | -0.092 / 0.905 | -0.101 / 0.619 | 0.192 / 0.238 |
| resource_dos (logic) | 30 | 0.0% | 73.3% | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.200 | 0.073 / 0.733 | -0.073 / 0.267 | 0.267 / 0.133 |
| crypto_secrets | 22 | 9.1% | 45.5% | 0.000 / 0.091 | -0.218 / 0.000 | -0.133 / 0.091 | 0.000 / 0.455 | 0.092 / 0.455 | -0.236 / 0.091 |
| memory_numeric (logic) | 16 | 50.0% | 87.5% | -0.126 / 0.500 | 0.160 / 0.250 | 0.000 / 0.125 | 0.160 / 0.875 | 0.405 / 0.500 | 0.000 / 0.125 |
| xml | 16 | 37.5% | 87.5% | 0.135 / 0.375 | 0.480 / 0.375 | 0.250 / 0.625 | 0.000 / 0.875 | 0.135 / 0.750 | 0.126 / 0.500 |
| deserialization | 16 | 87.5% | 100.0% | 0.630 / 0.875 | 0.500 / 0.750 | 0.674 / 1.000 | 0.378 / 1.000 | 0.289 / 0.875 | 0.289 / 0.375 |
| unknown (logic) | 10 | 40.0% | 100.0% | 0.000 / 0.400 | -0.218 / 0.200 | 0.000 / 0.400 | 0.000 / 1.000 | 0.408 / 0.800 | 0.000 / 0.600 |

### Pipeline telemetry (test)

- flagged_functions: 176
- findings: 298
- findings_per_flagged_function: 1.69
- by_tool: {'bandit': 206, 'semgrep': 92}
- cpg_success_rate: 1.0
- cpg_taint_found_rate: 0.7248
- rag_context_rate: 1.0
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **function_board**: functions 176, mean_valid_votes 0.99, unanimous_rate 0.9886, split_vote_rate 0.0, no_valid_vote_rate 0.0114, majority_not_vulnerable_rate 0.3295, evidence_grounded_rate 0.1477, evidence_reasons {'conceded': 136, 'no_span_match': 14, 'span_match': 26}, guard_grounded_rate 0.0966, override_flip_rate 0.2273, code_truncated_rate 0.0, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0114, defender_parse_failed_rate 0.0057, mean_seconds_per_function 190.0
- **candidates**: functions 804, any_candidate_rate 0.8197, sast_rate 0.2189, llm_taint_rate 0.74, auditor_rate 0.3781, only_llm_rate 0.6007, auditor_parse_failed_rate 0.0, auditor_vulnerable_verdict_rate 0.3781, spec_parse_failed_rate 0.0597, mean_spec_sinks 3.72, mean_spec_sites_checked 3.56, mean_context_chars 535.8, mean_seconds_per_function 114.1
- **candidates_board**: functions 659, mean_valid_votes 0.99, unanimous_rate 0.9939, split_vote_rate 0.0, no_valid_vote_rate 0.0061, majority_not_vulnerable_rate 0.3065, evidence_grounded_rate 0.1351, evidence_reasons {'conceded': 512, 'no_span_match': 58, 'span_match': 89}, guard_grounded_rate 0.0653, override_flip_rate 0.2109, code_truncated_rate 0.0, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0152, defender_parse_failed_rate 0.0015, mean_seconds_per_function 131.3

## Test, clean subset (single-function fixes)

### clean — 342 functions, 171 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.123, -0.024] | 1.000 | — | — | 0.493 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit (baseline) | +0.070 [0.024, 0.123] | — | 0.050 | 0.535 | 0.033 | — | 1.33 | 0.066 / 0.013 |
| SAST board: Judge majority vote | +0.064 [0.015, 0.122] | [-0.049, 0.041] | 0.239 | 0.541 | 0.066 | 1.000 | 1.52 | 0.074 / 0.015 |
| SAST board + evidence override (ablation) | +0.076 [0.031, 0.124] | [-0.028, 0.041] | 0.031 | — | — | 1.000 | 1.41 | 0.069 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.064 [0.015, 0.121] | [-0.051, 0.043] | 0.211 | 0.541 | 0.120 | 1.000 | 1.58 | 0.077 / 0.016 |
| SAST board + fusion (trained on dev) | +0.064 [0.017, 0.118] | [-0.039, 0.031] | 0.211 | 0.517 | 1.000 | 1.000 | 1.35 | 0.067 / 0.013 |
| LLM auditor alone (no critic) | +0.035 [-0.038, 0.120] | [-0.117, 0.052] | 1.000 | 0.485 | 1.000 | 1.000 | 1.10 | 0.055 / 0.011 |
| LLM-spec taint alone (no critic) | -0.035 [-0.093, 0.023] | [-0.184, -0.024] | 1.000 | — | — | 1.000 | 0.96 | 0.048 / 0.010 |
| Any candidate: SAST, taint or auditor (no critic) | -0.018 [-0.063, 0.029] | [-0.153, -0.018] | 1.000 | — | — | 1.000 | 0.98 | 0.049 / 0.010 |
| Candidates board: Judge majority vote | +0.053 [-0.036, 0.143] | [-0.127, 0.083] | 1.000 | 0.523 | 1.000 | 1.000 | 1.09 | 0.054 / 0.011 |
| Candidates board + evidence override (ablation) | +0.018 [-0.040, 0.079] | [-0.129, 0.024] | 1.000 | — | — | 1.000 | 1.02 | 0.051 / 0.010 |
| Candidates board: vote score, dev-tuned threshold | +0.076 [-0.014, 0.165] | [-0.091, 0.101] | 0.822 | 0.541 | 0.773 | 1.000 | 1.18 | 0.059 / 0.012 |
| Candidates board + fusion (trained on dev) | +0.088 [0.000, 0.174] | [-0.081, 0.111] | 0.286 | 0.585 | 0.120 | 1.000 | 1.42 | 0.069 / 0.014 |
| Candidates board: flagged unless the Judge's quoted check is in the code | +0.023 [-0.041, 0.088] | [-0.130, 0.039] | 1.000 | — | — | 1.000 | 1.03 | 0.051 / 0.010 |

**End-to-end** (every function; SAST-board recall is capped by SAST, candidates-board recall by the any-candidate row)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.144, -0.029] | 0.667 [0.667, 0.667] | 0.4935 |
| Semgrep + Bandit (baseline) | 0.571 | 0.281 | 0.210 | 0.535 | 0.082 [0.029, 0.144] | — | 0.377 [0.312, 0.433] | — |
| SAST board: Judge majority vote | 0.604 | 0.187 | 0.123 | 0.532 | 0.089 [0.021, 0.167] | [-0.048, 0.069] | 0.286 [0.206, 0.360] | 1.0000 |
| SAST board + evidence override (ablation) | 0.584 | 0.263 | 0.187 | 0.538 | 0.091 [0.038, 0.151] | [-0.030, 0.049] | 0.363 [0.290, 0.426] | 1.0000 |
| SAST board: vote score, dev-tuned threshold | 0.612 | 0.175 | 0.111 | 0.532 | 0.092 [0.022, 0.171] | [-0.049, 0.076] | 0.273 [0.192, 0.350] | 1.0000 |
| SAST board + fusion (trained on dev) | 0.575 | 0.246 | 0.181 | 0.532 | 0.079 [0.020, 0.145] | [-0.043, 0.042] | 0.344 [0.271, 0.411] | 1.0000 |
| LLM auditor alone (no critic) | 0.524 | 0.386 | 0.351 | 0.517 | 0.036 [-0.040, 0.124] | [-0.136, 0.047] | 0.444 [0.375, 0.513] | 0.6338 |
| LLM-spec taint alone (no critic) | 0.489 | 0.766 | 0.801 | 0.482 | -0.043 [-0.114, 0.027] | [-0.223, -0.030] | 0.597 [0.571, 0.622] | 0.2473 |
| Any candidate: SAST, taint or auditor (no critic) | 0.495 | 0.854 | 0.871 | 0.491 | -0.025 [-0.099, 0.042] | [-0.197, -0.019] | 0.627 [0.606, 0.645] | 0.3352 |
| Candidates board: Judge majority vote | 0.522 | 0.626 | 0.573 | 0.526 | 0.054 [-0.037, 0.144] | [-0.146, 0.080] | 0.569 [0.522, 0.616] | 0.8740 |
| Candidates board + evidence override (ablation) | 0.505 | 0.801 | 0.784 | 0.509 | 0.022 [-0.050, 0.098] | [-0.155, 0.033] | 0.620 [0.593, 0.644] | 0.5688 |
| Candidates board: vote score, dev-tuned threshold | 0.541 | 0.497 | 0.421 | 0.538 | 0.076 [-0.014, 0.165] | [-0.110, 0.092] | 0.518 [0.462, 0.580] | 1.0000 |
| Candidates board + fusion (trained on dev) | 0.586 | 0.298 | 0.210 | 0.544 | 0.101 [0.000, 0.196] | [-0.098, 0.127] | 0.395 [0.314, 0.471] | 0.8151 |
| Candidates board: flagged unless the Judge's quoted check is in the code | 0.507 | 0.813 | 0.789 | 0.512 | 0.029 [-0.052, 0.111] | [-0.154, 0.052] | 0.625 [0.600, 0.649] | 0.6225 |

**On functions static analysis flagged** (84: 48 vulnerable, 36 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.571 | 1.000 | 1.000 | 0.000 | 0.727 | 0.0% | 100.0% |
| Semgrep + Bandit (baseline) | 0.571 | 1.000 | 1.000 | 0.000 | 0.727 | — | — |
| SAST board: Judge majority vote | 0.604 | 0.667 | 0.583 | 0.086 | 0.634 | 41.7% | 66.7% |
| SAST board + evidence override (ablation) | 0.584 | 0.938 | 0.889 | 0.087 | 0.720 | 11.1% | 93.8% |
| SAST board: vote score, dev-tuned threshold | 0.612 | 0.625 | 0.528 | 0.098 | 0.619 | 47.2% | 62.5% |
| SAST board + fusion (trained on dev) | 0.575 | 0.875 | 0.861 | 0.020 | 0.694 | 13.9% | 87.5% |
| LLM auditor alone (no critic) | 0.600 | 0.625 | 0.556 | 0.070 | 0.612 | 44.4% | 62.5% |
| LLM-spec taint alone (no critic) | 0.559 | 0.792 | 0.833 | -0.052 | 0.655 | 16.7% | 79.2% |
| Any candidate: SAST, taint or auditor (no critic) | 0.571 | 1.000 | 1.000 | 0.000 | 0.727 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.631 | 0.854 | 0.667 | 0.222 | 0.726 | 33.3% | 85.4% |
| Candidates board + evidence override (ablation) | 0.570 | 0.938 | 0.944 | -0.015 | 0.709 | 5.6% | 93.8% |
| Candidates board: vote score, dev-tuned threshold | 0.643 | 0.750 | 0.556 | 0.204 | 0.692 | 44.4% | 75.0% |
| Candidates board + fusion (trained on dev) | 0.612 | 0.625 | 0.528 | 0.098 | 0.619 | 47.2% | 62.5% |
| Candidates board: flagged unless the Judge's quoted check is in the code | 0.577 | 0.938 | 0.917 | 0.040 | 0.714 | 8.3% | 93.8% |

**On functions any candidate source flagged (SAST, LLM-spec taint or auditor)** (295: 146 vulnerable, 149 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.495 | 1.000 | 1.000 | 0.000 | 0.662 | 0.0% | 100.0% |
| Semgrep + Bandit (baseline) | 0.571 | 0.329 | 0.242 | 0.097 | 0.417 | — | — |
| SAST board: Judge majority vote | 0.604 | 0.219 | 0.141 | 0.102 | 0.322 | 85.9% | 21.9% |
| SAST board + evidence override (ablation) | 0.584 | 0.308 | 0.215 | 0.106 | 0.404 | 78.5% | 30.8% |
| SAST board: vote score, dev-tuned threshold | 0.612 | 0.205 | 0.128 | 0.105 | 0.308 | 87.2% | 20.5% |
| SAST board + fusion (trained on dev) | 0.575 | 0.288 | 0.208 | 0.092 | 0.384 | 79.2% | 28.8% |
| LLM auditor alone (no critic) | 0.524 | 0.452 | 0.403 | 0.050 | 0.485 | 59.7% | 45.2% |
| LLM-spec taint alone (no critic) | 0.489 | 0.897 | 0.919 | -0.038 | 0.633 | 8.1% | 89.7% |
| Any candidate: SAST, taint or auditor (no critic) | 0.495 | 1.000 | 1.000 | 0.000 | 0.662 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.522 | 0.733 | 0.658 | 0.082 | 0.610 | 34.2% | 73.3% |
| Candidates board + evidence override (ablation) | 0.505 | 0.938 | 0.899 | 0.071 | 0.657 | 10.1% | 93.8% |
| Candidates board: vote score, dev-tuned threshold | 0.541 | 0.582 | 0.483 | 0.099 | 0.561 | 51.7% | 58.2% |
| Candidates board + fusion (trained on dev) | 0.586 | 0.349 | 0.242 | 0.118 | 0.438 | 75.8% | 34.9% |
| Candidates board: flagged unless the Judge's quoted check is in the code | 0.507 | 0.952 | 0.906 | 0.089 | 0.662 | 9.4% | 95.2% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 171 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit (baseline) | 171 | 0.082 [0.040, 0.130] | 0.199 | 0.708 | 0.012 | 0.094 | 0.875 |
| SAST board: Judge majority vote | 171 | 0.094 [0.051, 0.143] | 0.094 | 0.784 | 0.029 | 0.123 | 0.762 |
| SAST board + evidence override (ablation) | 171 | 0.088 [0.049, 0.132] | 0.175 | 0.725 | 0.012 | 0.099 | 0.882 |
| SAST board: vote score, dev-tuned threshold | 171 | 0.088 [0.046, 0.135] | 0.088 | 0.801 | 0.023 | 0.111 | 0.789 |
| SAST board + fusion (trained on dev) | 171 | 0.088 [0.046, 0.139] | 0.158 | 0.731 | 0.023 | 0.111 | 0.789 |
| LLM auditor alone (no critic) | 171 | 0.129 [0.083, 0.187] | 0.257 | 0.520 | 0.094 | 0.222 | 0.579 |
| LLM-spec taint alone (no critic) | 171 | 0.059 [0.029, 0.094] | 0.708 | 0.140 | 0.094 | 0.152 | 0.385 |
| Any candidate: SAST, taint or auditor (no critic) | 171 | 0.047 [0.018, 0.081] | 0.807 | 0.082 | 0.064 | 0.111 | 0.421 |
| Candidates board: Judge majority vote | 171 | 0.205 [0.142, 0.270] | 0.421 | 0.222 | 0.152 | 0.357 | 0.574 |
| Candidates board + evidence override (ablation) | 171 | 0.099 [0.058, 0.150] | 0.702 | 0.117 | 0.082 | 0.181 | 0.548 |
| Candidates board: vote score, dev-tuned threshold | 171 | 0.210 [0.150, 0.278] | 0.286 | 0.368 | 0.135 | 0.345 | 0.610 |
| Candidates board + fusion (trained on dev) | 171 | 0.175 [0.118, 0.241] | 0.123 | 0.614 | 0.088 | 0.263 | 0.667 |
| Candidates board: flagged unless the Judge's quoted check is in the code | 171 | 0.105 [0.060, 0.155] | 0.708 | 0.105 | 0.082 | 0.187 | 0.562 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit (baseline) | 1.000 | 1.000 |
| SAST board: Judge majority vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 1.000 | 0.977 |
| SAST board + fusion (trained on dev) | 1.000 | 0.959 |
| LLM auditor alone (no critic) | 0.994 | 0.994 |
| Candidates board: Judge majority vote | 1.000 | 1.000 |
| Candidates board: vote score, dev-tuned threshold | 1.000 | 0.947 |
| Candidates board + fusion (trained on dev) | 0.994 | 0.883 |

## Test, split by ReposVul's own static check

ReposVul's strict label requires Semgrep or RATS to flag the pre-fix file at the changed lines. SAST is favoured by construction where that check matched; the other stratum shows how each system does on fixes that pattern rules did not see.

### ReposVul static check matched — 152 functions, 76 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.425, -0.164] | 1.000 | — | — | 0.010 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit (baseline) | +0.289 [0.164, 0.425] | — | 0 | 0.645 | 0 | — | 1.71 | 0.083 / 0.017 |
| SAST board: Judge majority vote | +0.368 [0.242, 0.520] | [-0.040, 0.192] | 0 | 0.717 | 0 | 1.000 | 2.75 | 0.126 / 0.027 |
| SAST board + evidence override (ablation) | +0.355 [0.224, 0.494] | [-0.014, 0.167] | 0 | — | — | 1.000 | 2.23 | 0.105 / 0.022 |
| SAST board: vote score, dev-tuned threshold | +0.342 [0.224, 0.488] | [-0.077, 0.179] | 0 | 0.730 | 0 | 1.000 | 2.86 | 0.131 / 0.028 |
| SAST board + fusion (trained on dev) | +0.316 [0.186, 0.456] | [-0.065, 0.125] | 0 | 0.658 | 0.005 | 1.000 | 2.04 | 0.097 / 0.020 |
| LLM auditor alone (no critic) | +0.158 [0.014, 0.306] | [-0.305, 0.051] | 0.159 | 0.572 | 0.240 | 1.000 | 1.32 | 0.065 / 0.013 |
| LLM-spec taint alone (no critic) | -0.092 [-0.190, -0.013] | [-0.529, -0.239] | 0.234 | — | — | 0.005 | 0.90 | 0.045 / 0.009 |
| Any candidate: SAST, taint or auditor (no critic) | +0.013 [-0.028, 0.062] | [-0.410, -0.145] | 1.000 | — | — | 0.095 | 1.01 | 0.051 / 0.010 |
| Candidates board: Judge majority vote | +0.053 [-0.064, 0.191] | [-0.408, -0.064] | 1.000 | 0.539 | 0.573 | 0.198 | 1.07 | 0.053 / 0.011 |
| Candidates board + evidence override (ablation) | +0.066 [-0.013, 0.161] | [-0.371, -0.066] | 0.906 | — | — | 0.320 | 1.08 | 0.054 / 0.011 |
| Candidates board: vote score, dev-tuned threshold | +0.132 [0.000, 0.268] | [-0.314, 0.014] | 0.436 | 0.539 | 0.573 | 0.884 | 1.24 | 0.061 / 0.012 |
| Candidates board + fusion (trained on dev) | +0.237 [0.108, 0.367] | [-0.212, 0.105] | 0.002 | 0.691 | 0.004 | 1.000 | 1.75 | 0.084 / 0.017 |
| Candidates board: flagged unless the Judge's quoted check is in the code | +0.053 [-0.029, 0.147] | [-0.400, -0.071] | 1.000 | — | — | 0.320 | 1.06 | 0.053 / 0.011 |

### ReposVul static check did not match — 652 functions, 326 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.052, -0.003] | 1.000 | — | — | 0.767 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit (baseline) | +0.025 [0.003, 0.052] | — | 0.574 | 0.512 | 0.459 | — | 1.19 | 0.059 / 0.012 |
| SAST board: Judge majority vote | +0.031 [0.000, 0.066] | [-0.015, 0.030] | 0.575 | 0.514 | 0.754 | 1.000 | 1.42 | 0.069 / 0.014 |
| SAST board + evidence override (ablation) | +0.034 [0.012, 0.060] | [0.000, 0.020] | 0.142 | — | — | 1.000 | 1.29 | 0.064 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.043 [0.016, 0.074] | [-0.003, 0.044] | 0.057 | 0.515 | 0.754 | 1.000 | 1.70 | 0.082 / 0.017 |
| SAST board + fusion (trained on dev) | +0.037 [0.009, 0.070] | [-0.003, 0.034] | 0.142 | 0.515 | 0.811 | 1.000 | 1.32 | 0.065 / 0.013 |
| LLM auditor alone (no critic) | +0.018 [-0.032, 0.078] | [-0.059, 0.050] | 1.000 | 0.483 | 0.811 | 1.000 | 1.06 | 0.053 / 0.011 |
| LLM-spec taint alone (no critic) | -0.031 [-0.066, 0.009] | [-0.097, -0.013] | 0.860 | — | — | 1.000 | 0.96 | 0.048 / 0.010 |
| Any candidate: SAST, taint or auditor (no critic) | -0.025 [-0.060, 0.013] | [-0.094, -0.011] | 1.000 | — | — | 1.000 | 0.97 | 0.049 / 0.010 |
| Candidates board: Judge majority vote | +0.052 [-0.006, 0.115] | [-0.035, 0.093] | 0.776 | 0.521 | 0.811 | 1.000 | 1.10 | 0.055 / 0.011 |
| Candidates board + evidence override (ablation) | +0.021 [-0.032, 0.074] | [-0.063, 0.057] | 1.000 | — | — | 1.000 | 1.03 | 0.051 / 0.010 |
| Candidates board: vote score, dev-tuned threshold | +0.012 [-0.040, 0.071] | [-0.071, 0.049] | 1.000 | 0.515 | 0.811 | 1.000 | 1.03 | 0.051 / 0.010 |
| Candidates board + fusion (trained on dev) | +0.049 [-0.006, 0.104] | [-0.033, 0.079] | 0.611 | 0.541 | 0.754 | 1.000 | 1.27 | 0.063 / 0.013 |
| Candidates board: flagged unless the Judge's quoted check is in the code | +0.000 [-0.046, 0.048] | [-0.080, 0.024] | 1.000 | — | — | 1.000 | 1.00 | 0.050 / 0.010 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | FPR | Accuracy | MCC | F1 |
|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| Semgrep + Bandit (baseline) | 0.571 | 0.198 | 0.148 | 0.525 | 0.065 | 0.294 |
| SAST board: Judge majority vote | 0.591 | 0.129 | 0.089 | 0.520 | 0.064 | 0.211 |
| SAST board + evidence override (ablation) | 0.621 | 0.178 | 0.109 | 0.535 | 0.099 | 0.277 |
| SAST board: vote score, dev-tuned threshold | 0.600 | 0.119 | 0.079 | 0.520 | 0.066 | 0.198 |
| SAST board + fusion (trained on dev) | 0.633 | 0.188 | 0.109 | 0.540 | 0.111 | 0.290 |
| LLM auditor alone (no critic) | 0.543 | 0.505 | 0.426 | 0.540 | 0.079 | 0.523 |
| LLM-spec taint alone (no critic) | 0.500 | 0.782 | 0.782 | 0.500 | 0.000 | 0.610 |
| Any candidate: SAST, taint or auditor (no critic) | 0.506 | 0.901 | 0.881 | 0.510 | 0.032 | 0.648 |
| Candidates board: Judge majority vote | 0.536 | 0.733 | 0.634 | 0.549 | 0.106 | 0.619 |
| Candidates board + evidence override (ablation) | 0.506 | 0.871 | 0.852 | 0.510 | 0.029 | 0.640 |
| Candidates board: vote score, dev-tuned threshold | 0.578 | 0.624 | 0.455 | 0.584 | 0.169 | 0.600 |
| Candidates board + fusion (trained on dev) | 0.609 | 0.386 | 0.247 | 0.569 | 0.149 | 0.473 |
| Candidates board: flagged unless the Judge's quoted check is in the code | 0.508 | 0.891 | 0.861 | 0.515 | 0.045 | 0.647 |

## Caveats

- Labels follow the fix-commit convention (CVEfixes, PrimeVul): a function changed by a security-fix commit is vulnerable before the fix and fixed after it. Tangled commits (> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded; the clean subset further keeps only commits that changed a single function.
- The SAST board only reasons about Semgrep/Bandit findings, so its recall cannot exceed theirs. The candidates board also sees LLM-spec taint flows (IRIS-style: the LLM labels the function's calls as sources/sinks and Joern checks the flows) and LLM auditor candidates (GPTLens-style), so its ceiling is the 'any candidate' recall. The *_flagged views isolate what each board adds over its candidates.
- The auditor and the spec labelling see only the code and same-file callers/callees, never the dataset's label or CWE. Context is limited to the same file; cross-file callers are not shown.
- The auditor-alone and taint-alone rows have no critic; they measure how much each candidate source finds, and how noisy it is, before the board filters it.
- Board thresholds and fusion models are fitted on the dev split only (maximising mcc); test repositories never appear in dev. Dev numbers are in-sample and are shown for reference.
- Test and dev are balanced by construction (one vulnerable and one fixed function per pair), so F1 rewards flagging everything: compare every row with the trivial reference, and read MCC, accuracy and the pairwise columns for discrimination. 'Right way round' is the share of pairs with differing verdicts where the vulnerable version is the flagged one; 0.5 means no signal.
- Confidence intervals resample whole repositories (1,000 draws), since pairs from one project are not independent. McNemar compares per-function correctness against SAST. Sign-test and McNemar p values in the signal tables are Holm-corrected across the systems compared.
- Precision at a given prevalence is TPR·π / (TPR·π + FPR·(1 − π)): what a user would see if that share of functions were vulnerable, instead of the 50% this test set has by construction.
- ReposVul files are kept by its 'llm' label policy (llm = its LLM untangling check marks the file as vulnerability-fixing; strict = its LLM and static checks both do), and patches it marks as outdated are skipped. Its static check is Semgrep/RATS, so the 'static check matched' stratum favours SAST by construction, and its LLM check may favour fixes an LLM recognises.
