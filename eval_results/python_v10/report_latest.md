# HackerSec real-world evaluation (2026-10-30T22:19:43)

Status: **complete** — 2506/2506 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v10-soft-llm-screen`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| cvefixes | 100 (52) | 400 (133) | 154 |
| reposvul | 101 (44) | 402 (156) | 218 |
| vudenc | 50 (27) | 200 (103) | 90 |

- Dev functions evaluated: 502
- Board threshold on mean P(vulnerable) across Judge votes: **0.200** (max mcc on dev)
- Fusion: trained on 286 flagged dev functions (5-fold CV C=0.05, max mcc), threshold 0.568, dev CV F1 0.378, dev CV MCC 0.210
- LLM-only threshold on P(vulnerable): **0.200** (max mcc on dev)
- LLM-only + context threshold on P(vulnerable): **0.800** (max mcc on dev)
- Soft LLM Screen: every function the context baseline flags as VULNERABLE goes to the Board (no score threshold)

Each pair contributes one vulnerable and one fixed function, so flagging every function scores F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise columns show whether a system actually separates vulnerable from fixed code.

## Test split (primary)

### cvefixes — 800 functions, 400 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.020, 0.025] | 1.000 | — | — | 1.000 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | -0.003 [-0.025, 0.020] | — | 1.000 | 0.499 | 1.000 | — | 1.00 | 0.050 / 0.010 |
| Semgrep alone | +0.040 [0.019, 0.065] | [0.013, 0.077] | 0.001 | — | — | 1.000 | 1.64 | 0.080 / 0.016 |
| Bandit alone | +0.045 [0.018, 0.076] | [0.015, 0.083] | 0.005 | — | — | 1.000 | 1.28 | 0.063 / 0.013 |
| AST sink gate alone | -0.010 [-0.033, 0.012] | [-0.023, 0.010] | 1.000 | — | — | 1.000 | 0.98 | 0.049 / 0.010 |
| CodeQL alone | +0.040 [0.017, 0.071] | [0.013, 0.079] | 0.0004 | — | — | 1.000 | 3.00 | 0.136 / 0.029 |
| SAST board: Judge vote | +0.035 [-0.003, 0.070] | [0.005, 0.072] | 0.456 | 0.520 | 0.412 | 1.000 | 1.09 | 0.054 / 0.011 |
| SAST board + evidence override (ablation) | +0.030 [-0.005, 0.066] | [0.005, 0.068] | 0.456 | — | — | 0.947 | 1.06 | 0.053 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.037 [-0.005, 0.080] | [-0.000, 0.085] | 0.456 | 0.532 | 0.231 | 1.000 | 1.08 | 0.054 / 0.011 |
| SAST board + fusion (ablation, trained on dev) | +0.068 [0.032, 0.108] | [0.033, 0.117] | 0.005 | 0.540 | 0.231 | 1.000 | 1.38 | 0.068 / 0.014 |
| LLM only, whole function, no SAST | +0.055 [0.019, 0.094] | [0.016, 0.104] | 0.005 | 0.526 | 0.412 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only, dev-tuned threshold | +0.055 [0.019, 0.094] | [0.016, 0.104] | 0.005 | 0.526 | 0.412 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only + same-file context, no SAST | +0.062 [0.028, 0.102] | [0.023, 0.112] | 0.001 | 0.522 | 0.412 | 1.000 | 1.32 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.062 [0.028, 0.102] | [0.023, 0.112] | 0.001 | 0.522 | 0.412 | 1.000 | 1.32 | 0.065 / 0.013 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.020, 0.025] | 0.667 [0.667, 0.667] | 1.000 |
| Semgrep + Bandit + AST Gate | 0.499 | 0.552 | 0.555 | 0.499 | -0.003 [-0.025, 0.020] | — | 0.524 [0.497, 0.551] | — |
| Semgrep alone | 0.621 | 0.102 | 0.062 | 0.520 | 0.073 [0.036, 0.116] | [0.033, 0.126] | 0.176 [0.124, 0.240] | 0.410 |
| Bandit alone | 0.562 | 0.205 | 0.160 | 0.522 | 0.058 [0.023, 0.097] | [0.022, 0.101] | 0.300 [0.238, 0.356] | 0.296 |
| AST sink gate alone | 0.495 | 0.500 | 0.510 | 0.495 | -0.010 [-0.033, 0.012] | [-0.023, 0.010] | 0.497 [0.464, 0.533] | 0.749 |
| CodeQL alone | 0.750 | 0.060 | 0.020 | 0.520 | 0.102 [0.052, 0.159] | [0.054, 0.164] | 0.111 [0.064, 0.173] | 0.430 |
| SAST board: Judge vote | 0.522 | 0.422 | 0.388 | 0.517 | 0.036 [-0.003, 0.072] | [0.005, 0.074] | 0.467 [0.431, 0.504] | 0.210 |
| SAST board + evidence override (ablation) | 0.514 | 0.568 | 0.537 | 0.515 | 0.030 [-0.005, 0.067] | [0.005, 0.068] | 0.539 [0.510, 0.568] | 0.079 |
| SAST board: vote score, dev-tuned threshold | 0.520 | 0.480 | 0.443 | 0.519 | 0.038 [-0.005, 0.081] | [-0.000, 0.086] | 0.499 [0.462, 0.538] | 0.174 |
| SAST board + fusion (ablation, trained on dev) | 0.580 | 0.245 | 0.177 | 0.534 | 0.083 [0.040, 0.130] | [0.043, 0.136] | 0.344 [0.290, 0.401] | 0.103 |
| LLM only, whole function, no SAST | 0.557 | 0.268 | 0.212 | 0.527 | 0.064 [0.023, 0.108] | [0.020, 0.121] | 0.361 [0.302, 0.421] | 0.219 |
| LLM only, dev-tuned threshold | 0.557 | 0.268 | 0.212 | 0.527 | 0.064 [0.023, 0.108] | [0.020, 0.121] | 0.361 [0.302, 0.421] | 0.219 |
| LLM only + same-file context, no SAST | 0.570 | 0.255 | 0.193 | 0.531 | 0.075 [0.034, 0.121] | [0.031, 0.129] | 0.352 [0.293, 0.414] | 0.158 |
| LLM only + context, dev-tuned threshold | 0.570 | 0.255 | 0.193 | 0.531 | 0.075 [0.034, 0.121] | [0.031, 0.129] | 0.352 [0.293, 0.414] | 0.158 |

**SAST board: Judge vote vs the LLM baselines** (paired, same functions). Δ = board − baseline; CIs resample whole repositories. McNemar counts functions, or whole pairs, that one system gets right and the other does not; p values are Holm-corrected across the baselines.

| Baseline | ΔMCC [95% CI] | ΔJ [95% CI] | Functions: only board right / only baseline right | McNemar p | Pairs: only board correct / only baseline correct | Pair McNemar p |
|---|---|---|---|---|---|---|
| LLM only, whole function, no SAST | [-0.079, 0.019] | [-0.066, 0.022] | 114 / 122 | 1.000 | 27 / 21 | 1.000 |
| LLM only, dev-tuned threshold | [-0.079, 0.019] | [-0.066, 0.022] | 114 / 122 | 1.000 | 27 / 21 | 1.000 |
| LLM only + same-file context, no SAST | [-0.094, 0.013] | [-0.077, 0.018] | 110 / 121 | 1.000 | 28 / 24 | 1.000 |
| LLM only + context, dev-tuned threshold | [-0.094, 0.013] | [-0.077, 0.018] | 110 / 121 | 1.000 | 28 / 24 | 1.000 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 221 | 0 |
| Board (SAST ∪ Soft LLM Screen when enabled) | 468 | 3,429.1 | 192 | 14,288 |
| LLM only, whole function, no SAST | 800 | 973.1 | 107 | 7,276 |
| LLM only + same-file context, no SAST | 800 | 1,174.7 | 102 | 9,213 |


**On functions static analysis flagged** (443: 221 vulnerable, 222 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.499 | 1.000 | 1.000 | 0.000 | 0.666 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.499 | 1.000 | 1.000 | 0.000 | 0.666 | — | — |
| Semgrep alone | 0.621 | 0.185 | 0.113 | 0.102 | 0.286 | 88.7% | 18.6% |
| Bandit alone | 0.562 | 0.371 | 0.288 | 0.088 | 0.447 | 71.2% | 37.1% |
| AST sink gate alone | 0.495 | 0.905 | 0.919 | -0.025 | 0.640 | 8.1% | 90.5% |
| CodeQL alone | 0.750 | 0.109 | 0.036 | 0.140 | 0.190 | 96.4% | 10.9% |
| SAST board: Judge vote | 0.520 | 0.756 | 0.694 | 0.069 | 0.616 | 30.6% | 75.6% |
| SAST board + evidence override (ablation) | 0.511 | 0.968 | 0.923 | 0.099 | 0.669 | 7.7% | 96.8% |
| SAST board: vote score, dev-tuned threshold | 0.516 | 0.805 | 0.752 | 0.064 | 0.629 | 24.8% | 80.5% |
| SAST board + fusion (ablation, trained on dev) | 0.580 | 0.443 | 0.320 | 0.127 | 0.503 | 68.0% | 44.3% |
| LLM only, whole function, no SAST | 0.560 | 0.398 | 0.311 | 0.091 | 0.466 | 68.9% | 39.8% |
| LLM only, dev-tuned threshold | 0.560 | 0.398 | 0.311 | 0.091 | 0.466 | 68.9% | 39.8% |
| LLM only + same-file context, no SAST | 0.571 | 0.398 | 0.297 | 0.106 | 0.469 | 70.3% | 39.8% |
| LLM only + context, dev-tuned threshold | 0.571 | 0.398 | 0.297 | 0.106 | 0.469 | 70.3% | 39.8% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 400 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 400 | 0.033 [0.016, 0.048] | 0.520 | 0.412 | 0.035 | 0.068 | 0.481 |
| Semgrep alone | 400 | 0.043 [0.020, 0.067] | 0.060 | 0.895 | 0.003 | 0.045 | 0.944 |
| Bandit alone | 400 | 0.055 [0.031, 0.083] | 0.150 | 0.785 | 0.010 | 0.065 | 0.846 |
| AST sink gate alone | 400 | 0.022 [0.009, 0.038] | 0.477 | 0.468 | 0.033 | 0.055 | 0.409 |
| CodeQL alone | 400 | 0.040 [0.017, 0.071] | 0.020 | 0.940 | 0.000 | 0.040 | 1.000 |
| SAST board: Judge vote | 400 | 0.092 [0.065, 0.124] | 0.330 | 0.520 | 0.058 | 0.150 | 0.617 |
| SAST board + evidence override (ablation) | 400 | 0.077 [0.051, 0.110] | 0.490 | 0.385 | 0.048 | 0.125 | 0.620 |
| SAST board: vote score, dev-tuned threshold | 400 | 0.105 [0.077, 0.137] | 0.375 | 0.453 | 0.068 | 0.172 | 0.609 |
| SAST board + fusion (ablation, trained on dev) | 400 | 0.107 [0.075, 0.147] | 0.138 | 0.715 | 0.040 | 0.147 | 0.729 |
| LLM only, whole function, no SAST | 400 | 0.077 [0.048, 0.112] | 0.190 | 0.710 | 0.022 | 0.100 | 0.775 |
| LLM only, dev-tuned threshold | 400 | 0.077 [0.048, 0.112] | 0.190 | 0.710 | 0.022 | 0.100 | 0.775 |
| LLM only + same-file context, no SAST | 400 | 0.083 [0.051, 0.121] | 0.172 | 0.725 | 0.020 | 0.102 | 0.805 |
| LLM only + context, dev-tuned threshold | 400 | 0.083 [0.051, 0.121] | 0.172 | 0.725 | 0.020 | 0.102 | 0.805 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.998 | 0.998 |
| SAST board + fusion (ablation, trained on dev) | 0.978 | 0.905 |
| LLM only, whole function, no SAST | 1.000 | 0.988 |
| LLM only, dev-tuned threshold | 1.000 | 0.988 |
| LLM only + same-file context, no SAST | 1.000 | 0.990 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.990 |

### reposvul — 804 functions, 402 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.042, 0.005] | 1.000 | — | — | 0.738 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.017 [-0.005, 0.042] | — | 0.378 | 0.509 | 0.946 | — | 1.03 | 0.051 / 0.010 |
| Semgrep alone | +0.060 [0.030, 0.093] | [0.005, 0.083] | 9.7e-06 | — | — | 1.000 | 1.89 | 0.090 / 0.019 |
| Bandit alone | +0.065 [0.035, 0.098] | [0.014, 0.085] | 6.2e-05 | — | — | 1.000 | 1.41 | 0.069 / 0.014 |
| AST sink gate alone | +0.012 [-0.013, 0.036] | [-0.027, 0.013] | 0.378 | — | — | 1.000 | 1.02 | 0.051 / 0.010 |
| CodeQL alone | +0.052 [0.028, 0.081] | [0.005, 0.068] | 1e-05 | — | — | 1.000 | 2.05 | 0.097 / 0.020 |
| SAST board: Judge vote | +0.087 [0.045, 0.131] | [0.030, 0.115] | 0.00046 | 0.535 | 0.018 | 0.254 | 1.21 | 0.060 / 0.012 |
| SAST board + evidence override (ablation) | +0.057 [0.016, 0.101] | [0.002, 0.082] | 0.009 | — | — | 0.764 | 1.10 | 0.055 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.057 [0.009, 0.113] | [-0.007, 0.093] | 0.042 | 0.535 | 0.169 | 1.000 | 1.12 | 0.056 / 0.011 |
| SAST board + fusion (ablation, trained on dev) | +0.110 [0.065, 0.157] | [0.047, 0.141] | 3.3e-06 | 0.565 | 0.004 | 0.374 | 1.59 | 0.077 / 0.016 |
| LLM only, whole function, no SAST | +0.060 [0.019, 0.096] | [-0.003, 0.084] | 0.003 | 0.515 | 1.000 | 1.000 | 1.24 | 0.061 / 0.012 |
| LLM only, dev-tuned threshold | +0.062 [0.022, 0.099] | [0.000, 0.086] | 0.003 | 0.515 | 1.000 | 1.000 | 1.25 | 0.062 / 0.012 |
| LLM only + same-file context, no SAST | +0.062 [0.022, 0.104] | [0.000, 0.091] | 0.003 | 0.509 | 1.000 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.062 [0.022, 0.104] | [0.000, 0.091] | 0.003 | 0.509 | 1.000 | 1.000 | 1.26 | 0.062 / 0.013 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.043, 0.006] | 0.667 [0.667, 0.667] | 0.738 |
| Semgrep + Bandit + AST Gate | 0.507 | 0.610 | 0.592 | 0.509 | 0.018 [-0.006, 0.043] | — | 0.554 [0.529, 0.577] | — |
| Semgrep alone | 0.654 | 0.127 | 0.067 | 0.530 | 0.101 [0.054, 0.151] | [0.032, 0.141] | 0.212 [0.160, 0.267] | 0.427 |
| Bandit alone | 0.584 | 0.224 | 0.159 | 0.532 | 0.082 [0.044, 0.122] | [0.025, 0.109] | 0.324 [0.275, 0.369] | 0.321 |
| AST sink gate alone | 0.506 | 0.552 | 0.540 | 0.506 | 0.013 [-0.013, 0.036] | [-0.028, 0.013] | 0.528 [0.495, 0.555] | 0.880 |
| CodeQL alone | 0.672 | 0.102 | 0.050 | 0.526 | 0.099 [0.054, 0.144] | [0.039, 0.128] | 0.177 [0.120, 0.240] | 0.527 |
| SAST board: Judge vote | 0.548 | 0.500 | 0.413 | 0.543 | 0.087 [0.046, 0.132] | [0.030, 0.116] | 0.523 [0.481, 0.563] | 0.021 |
| SAST board + evidence override (ablation) | 0.523 | 0.639 | 0.582 | 0.529 | 0.059 [0.016, 0.104] | [0.003, 0.085] | 0.576 [0.545, 0.604] | 0.076 |
| SAST board: vote score, dev-tuned threshold | 0.528 | 0.547 | 0.490 | 0.529 | 0.057 [0.009, 0.113] | [-0.008, 0.092] | 0.537 [0.500, 0.571] | 0.205 |
| SAST board + fusion (ablation, trained on dev) | 0.613 | 0.296 | 0.187 | 0.555 | 0.128 [0.077, 0.181] | [0.060, 0.164] | 0.399 [0.342, 0.455] | 0.034 |
| LLM only, whole function, no SAST | 0.553 | 0.311 | 0.251 | 0.530 | 0.066 [0.021, 0.107] | [-0.001, 0.093] | 0.398 [0.344, 0.447] | 0.379 |
| LLM only, dev-tuned threshold | 0.555 | 0.313 | 0.251 | 0.531 | 0.069 [0.025, 0.112] | [0.002, 0.097] | 0.401 [0.347, 0.450] | 0.351 |
| LLM only + same-file context, no SAST | 0.557 | 0.306 | 0.244 | 0.531 | 0.070 [0.025, 0.116] | [0.004, 0.101] | 0.395 [0.338, 0.447] | 0.361 |
| LLM only + context, dev-tuned threshold | 0.557 | 0.306 | 0.244 | 0.531 | 0.070 [0.025, 0.116] | [0.004, 0.101] | 0.395 [0.338, 0.447] | 0.361 |

**SAST board: Judge vote vs the LLM baselines** (paired, same functions). Δ = board − baseline; CIs resample whole repositories. McNemar counts functions, or whole pairs, that one system gets right and the other does not; p values are Holm-corrected across the baselines.

| Baseline | ΔMCC [95% CI] | ΔJ [95% CI] | Functions: only board right / only baseline right | McNemar p | Pairs: only board correct / only baseline correct | Pair McNemar p |
|---|---|---|---|---|---|---|
| LLM only, whole function, no SAST | [-0.027, 0.069] | [-0.015, 0.071] | 130 / 119 | 1.000 | 40 / 21 | 0.082 |
| LLM only, dev-tuned threshold | [-0.028, 0.067] | [-0.018, 0.069] | 130 / 120 | 1.000 | 40 / 22 | 0.090 |
| LLM only + same-file context, no SAST | [-0.030, 0.066] | [-0.018, 0.070] | 129 / 119 | 1.000 | 37 / 20 | 0.090 |
| LLM only + context, dev-tuned threshold | [-0.030, 0.066] | [-0.018, 0.070] | 129 / 119 | 1.000 | 37 / 20 | 0.090 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 245 | 0 |
| Board (SAST ∪ Soft LLM Screen when enabled) | 525 | 3,953.5 | 220 | 14,448 |
| LLM only, whole function, no SAST | 804 | 1,036.5 | 126 | 6,614 |
| LLM only + same-file context, no SAST | 804 | 1,246.6 | 123 | 8,149 |


**On functions static analysis flagged** (483: 245 vulnerable, 238 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.507 | 1.000 | 1.000 | 0.000 | 0.673 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.507 | 1.000 | 1.000 | 0.000 | 0.673 | — | — |
| Semgrep alone | 0.654 | 0.208 | 0.113 | 0.129 | 0.316 | 88.7% | 20.8% |
| Bandit alone | 0.584 | 0.367 | 0.269 | 0.106 | 0.451 | 73.1% | 36.7% |
| AST sink gate alone | 0.506 | 0.906 | 0.912 | -0.010 | 0.649 | 8.8% | 90.6% |
| CodeQL alone | 0.672 | 0.167 | 0.084 | 0.125 | 0.268 | 91.6% | 16.7% |
| SAST board: Judge vote | 0.545 | 0.792 | 0.681 | 0.126 | 0.646 | 31.9% | 79.2% |
| SAST board + evidence override (ablation) | 0.528 | 0.971 | 0.895 | 0.154 | 0.684 | 10.5% | 97.1% |
| SAST board: vote score, dev-tuned threshold | 0.534 | 0.829 | 0.744 | 0.104 | 0.650 | 25.6% | 82.9% |
| SAST board + fusion (ablation, trained on dev) | 0.613 | 0.486 | 0.315 | 0.174 | 0.542 | 68.5% | 48.6% |
| LLM only, whole function, no SAST | 0.571 | 0.441 | 0.340 | 0.103 | 0.498 | 66.0% | 44.1% |
| LLM only, dev-tuned threshold | 0.571 | 0.441 | 0.340 | 0.103 | 0.498 | 66.0% | 44.1% |
| LLM only + same-file context, no SAST | 0.581 | 0.424 | 0.315 | 0.113 | 0.491 | 68.5% | 42.4% |
| LLM only + context, dev-tuned threshold | 0.581 | 0.424 | 0.315 | 0.113 | 0.491 | 68.5% | 42.4% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 402 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 402 | 0.035 [0.017, 0.056] | 0.575 | 0.373 | 0.017 | 0.052 | 0.667 |
| Semgrep alone | 402 | 0.062 [0.035, 0.096] | 0.065 | 0.871 | 0.003 | 0.065 | 0.962 |
| Bandit alone | 402 | 0.075 [0.047, 0.107] | 0.149 | 0.766 | 0.010 | 0.085 | 0.882 |
| AST sink gate alone | 402 | 0.027 [0.010, 0.048] | 0.525 | 0.433 | 0.015 | 0.042 | 0.647 |
| CodeQL alone | 402 | 0.052 [0.028, 0.081] | 0.050 | 0.898 | 0.000 | 0.052 | 1.000 |
| SAST board: Judge vote | 402 | 0.134 [0.100, 0.172] | 0.366 | 0.453 | 0.047 | 0.182 | 0.740 |
| SAST board + evidence override (ablation) | 402 | 0.095 [0.064, 0.131] | 0.545 | 0.323 | 0.037 | 0.132 | 0.717 |
| SAST board: vote score, dev-tuned threshold | 402 | 0.129 [0.095, 0.169] | 0.418 | 0.381 | 0.072 | 0.202 | 0.642 |
| SAST board + fusion (ablation, trained on dev) | 402 | 0.147 [0.106, 0.188] | 0.149 | 0.667 | 0.037 | 0.184 | 0.797 |
| LLM only, whole function, no SAST | 402 | 0.087 [0.056, 0.118] | 0.224 | 0.662 | 0.027 | 0.114 | 0.761 |
| LLM only, dev-tuned threshold | 402 | 0.090 [0.059, 0.122] | 0.224 | 0.659 | 0.027 | 0.117 | 0.766 |
| LLM only + same-file context, no SAST | 402 | 0.092 [0.061, 0.126] | 0.214 | 0.664 | 0.030 | 0.122 | 0.755 |
| LLM only + context, dev-tuned threshold | 402 | 0.092 [0.061, 0.126] | 0.214 | 0.664 | 0.030 | 0.122 | 0.755 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.998 | 0.998 |
| SAST board + fusion (ablation, trained on dev) | 0.973 | 0.890 |
| LLM only, whole function, no SAST | 1.000 | 0.985 |
| LLM only, dev-tuned threshold | 1.000 | 0.985 |
| LLM only + same-file context, no SAST | 0.988 | 0.988 |
| LLM only + context, dev-tuned threshold | 0.988 | 0.988 |

### vudenc — 400 functions, 200 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.046, 0.015] | 1.000 | — | — | 0.884 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.015 [-0.015, 0.046] | — | 1.000 | 0.507 | 0.581 | — | 1.03 | 0.051 / 0.010 |
| Semgrep alone | +0.025 [-0.010, 0.064] | [-0.033, 0.053] | 0.906 | — | — | 1.000 | 1.42 | 0.069 / 0.014 |
| Bandit alone | +0.060 [0.006, 0.126] | [-0.015, 0.114] | 0.025 | — | — | 1.000 | 1.32 | 0.065 / 0.013 |
| AST sink gate alone | +0.010 [-0.017, 0.041] | [-0.022, 0.011] | 1.000 | — | — | 1.000 | 1.02 | 0.051 / 0.010 |
| CodeQL alone | +0.010 [-0.006, 0.031] | [-0.041, 0.030] | 1.000 | — | — | 1.000 | 1.20 | 0.059 / 0.012 |
| SAST board: Judge vote | +0.105 [0.046, 0.175] | [0.027, 0.159] | 0.001 | 0.560 | 0.001 | 0.488 | 1.34 | 0.066 / 0.013 |
| SAST board + evidence override (ablation) | +0.050 [0.010, 0.095] | [0.000, 0.076] | 0.207 | — | — | 1.000 | 1.10 | 0.055 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.105 [0.037, 0.181] | [0.019, 0.166] | 0.005 | 0.557 | 0.034 | 0.462 | 1.29 | 0.064 / 0.013 |
| SAST board + fusion (ablation, trained on dev) | +0.125 [0.057, 0.201] | [0.036, 0.192] | 0.00045 | 0.590 | 0.004 | 0.507 | 1.69 | 0.082 / 0.017 |
| LLM only, whole function, no SAST | +0.095 [0.034, 0.168] | [0.019, 0.151] | 0.011 | 0.540 | 0.144 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only, dev-tuned threshold | +0.095 [0.034, 0.168] | [0.019, 0.151] | 0.011 | 0.540 | 0.144 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.110 [0.054, 0.174] | [0.037, 0.165] | 0.00014 | 0.552 | 0.033 | 0.835 | 1.43 | 0.070 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.110 [0.054, 0.174] | [0.037, 0.165] | 0.00014 | 0.552 | 0.033 | 0.835 | 1.43 | 0.070 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.046, 0.015] | 0.667 [0.667, 0.667] | 0.884 |
| Semgrep + Bandit + AST Gate | 0.507 | 0.540 | 0.525 | 0.507 | 0.015 [-0.015, 0.046] | — | 0.523 [0.477, 0.566] | — |
| Semgrep alone | 0.586 | 0.085 | 0.060 | 0.512 | 0.048 [-0.020, 0.125] | [-0.038, 0.115] | 0.148 [0.077, 0.226] | 0.941 |
| Bandit alone | 0.568 | 0.250 | 0.190 | 0.530 | 0.072 [0.007, 0.147] | [-0.014, 0.136] | 0.347 [0.260, 0.429] | 0.474 |
| AST sink gate alone | 0.505 | 0.505 | 0.495 | 0.505 | 0.010 [-0.017, 0.042] | [-0.022, 0.011] | 0.505 [0.459, 0.550] | 1.000 |
| CodeQL alone | 0.545 | 0.060 | 0.050 | 0.505 | 0.022 [-0.019, 0.068] | [-0.044, 0.059] | 0.108 [0.039, 0.186] | 1.000 |
| SAST board: Judge vote | 0.572 | 0.415 | 0.310 | 0.552 | 0.109 [0.048, 0.182] | [0.029, 0.167] | 0.481 [0.419, 0.543] | 0.044 |
| SAST board + evidence override (ablation) | 0.523 | 0.565 | 0.515 | 0.525 | 0.050 [0.010, 0.095] | [0.000, 0.077] | 0.543 [0.496, 0.588] | 0.189 |
| SAST board: vote score, dev-tuned threshold | 0.564 | 0.465 | 0.360 | 0.552 | 0.107 [0.038, 0.184] | [0.020, 0.169] | 0.510 [0.449, 0.567] | 0.038 |
| SAST board + fusion (ablation, trained on dev) | 0.629 | 0.305 | 0.180 | 0.562 | 0.146 [0.067, 0.233] | [0.051, 0.218] | 0.411 [0.325, 0.493] | 0.051 |
| LLM only, whole function, no SAST | 0.571 | 0.380 | 0.285 | 0.547 | 0.101 [0.035, 0.176] | [0.021, 0.156] | 0.457 [0.381, 0.528] | 0.174 |
| LLM only, dev-tuned threshold | 0.571 | 0.380 | 0.285 | 0.547 | 0.101 [0.035, 0.176] | [0.021, 0.156] | 0.457 [0.381, 0.528] | 0.174 |
| LLM only + same-file context, no SAST | 0.589 | 0.365 | 0.255 | 0.555 | 0.119 [0.058, 0.187] | [0.043, 0.176] | 0.451 [0.377, 0.525] | 0.093 |
| LLM only + context, dev-tuned threshold | 0.589 | 0.365 | 0.255 | 0.555 | 0.119 [0.058, 0.187] | [0.043, 0.176] | 0.451 [0.377, 0.525] | 0.093 |

**SAST board: Judge vote vs the LLM baselines** (paired, same functions). Δ = board − baseline; CIs resample whole repositories. McNemar counts functions, or whole pairs, that one system gets right and the other does not; p values are Holm-corrected across the baselines.

| Baseline | ΔMCC [95% CI] | ΔJ [95% CI] | Functions: only board right / only baseline right | McNemar p | Pairs: only board correct / only baseline correct | Pair McNemar p |
|---|---|---|---|---|---|---|
| LLM only, whole function, no SAST | [-0.051, 0.065] | [-0.044, 0.065] | 36 / 34 | 1.000 | 8 / 9 | 1.000 |
| LLM only, dev-tuned threshold | [-0.051, 0.065] | [-0.044, 0.065] | 36 / 34 | 1.000 | 8 / 9 | 1.000 |
| LLM only + same-file context, no SAST | [-0.060, 0.040] | [-0.051, 0.040] | 32 / 33 | 1.000 | 8 / 7 | 1.000 |
| LLM only + context, dev-tuned threshold | [-0.060, 0.040] | [-0.051, 0.040] | 32 / 33 | 1.000 | 8 / 7 | 1.000 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 108 | 0 |
| Board (SAST ∪ Soft LLM Screen when enabled) | 226 | 3,108.8 | 93 | 13,371 |
| LLM only, whole function, no SAST | 400 | 859.1 | 76 | 4,522 |
| LLM only + same-file context, no SAST | 400 | 1,039.4 | 73 | 5,696 |


**On functions static analysis flagged** (213: 108 vulnerable, 105 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.507 | 1.000 | 1.000 | 0.000 | 0.673 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.507 | 1.000 | 1.000 | 0.000 | 0.673 | — | — |
| Semgrep alone | 0.586 | 0.157 | 0.114 | 0.063 | 0.248 | 88.6% | 15.7% |
| Bandit alone | 0.568 | 0.463 | 0.362 | 0.103 | 0.510 | 63.8% | 46.3% |
| AST sink gate alone | 0.505 | 0.935 | 0.943 | -0.016 | 0.656 | 5.7% | 93.5% |
| CodeQL alone | 0.545 | 0.111 | 0.095 | 0.026 | 0.185 | 90.5% | 11.1% |
| SAST board: Judge vote | 0.573 | 0.759 | 0.581 | 0.190 | 0.653 | 41.9% | 75.9% |
| SAST board + evidence override (ablation) | 0.520 | 0.982 | 0.933 | 0.120 | 0.679 | 6.7% | 98.2% |
| SAST board: vote score, dev-tuned threshold | 0.561 | 0.806 | 0.648 | 0.177 | 0.662 | 35.2% | 80.6% |
| SAST board + fusion (ablation, trained on dev) | 0.629 | 0.565 | 0.343 | 0.223 | 0.595 | 65.7% | 56.5% |
| LLM only, whole function, no SAST | 0.580 | 0.602 | 0.448 | 0.154 | 0.591 | 55.2% | 60.2% |
| LLM only, dev-tuned threshold | 0.580 | 0.602 | 0.448 | 0.154 | 0.591 | 55.2% | 60.2% |
| LLM only + same-file context, no SAST | 0.586 | 0.602 | 0.438 | 0.164 | 0.594 | 56.2% | 60.2% |
| LLM only + context, dev-tuned threshold | 0.586 | 0.602 | 0.438 | 0.164 | 0.594 | 56.2% | 60.2% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 200 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 200 | 0.040 [0.011, 0.070] | 0.500 | 0.435 | 0.025 | 0.065 | 0.615 |
| Semgrep alone | 200 | 0.040 [0.015, 0.072] | 0.045 | 0.900 | 0.015 | 0.055 | 0.727 |
| Bandit alone | 200 | 0.070 [0.019, 0.133] | 0.180 | 0.740 | 0.010 | 0.080 | 0.875 |
| AST sink gate alone | 200 | 0.035 [0.010, 0.062] | 0.470 | 0.470 | 0.025 | 0.060 | 0.583 |
| CodeQL alone | 200 | 0.015 [0.000, 0.035] | 0.045 | 0.935 | 0.005 | 0.020 | 0.750 |
| SAST board: Judge vote | 200 | 0.125 [0.070, 0.191] | 0.290 | 0.565 | 0.020 | 0.145 | 0.862 |
| SAST board + evidence override (ablation) | 200 | 0.075 [0.036, 0.119] | 0.490 | 0.410 | 0.025 | 0.100 | 0.750 |
| SAST board: vote score, dev-tuned threshold | 200 | 0.140 [0.081, 0.209] | 0.325 | 0.500 | 0.035 | 0.175 | 0.800 |
| SAST board + fusion (ablation, trained on dev) | 200 | 0.155 [0.095, 0.226] | 0.150 | 0.665 | 0.030 | 0.185 | 0.838 |
| LLM only, whole function, no SAST | 200 | 0.130 [0.075, 0.194] | 0.250 | 0.585 | 0.035 | 0.165 | 0.788 |
| LLM only, dev-tuned threshold | 200 | 0.130 [0.075, 0.194] | 0.250 | 0.585 | 0.035 | 0.165 | 0.788 |
| LLM only + same-file context, no SAST | 200 | 0.120 [0.066, 0.184] | 0.245 | 0.625 | 0.010 | 0.130 | 0.923 |
| LLM only + context, dev-tuned threshold | 200 | 0.120 [0.066, 0.184] | 0.245 | 0.625 | 0.010 | 0.130 | 0.923 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.995 | 0.995 |
| SAST board + fusion (ablation, trained on dev) | 0.935 | 0.830 |
| LLM only, whole function, no SAST | 1.000 | 1.000 |
| LLM only, dev-tuned threshold | 1.000 | 1.000 |
| LLM only + same-file context, no SAST | 1.000 | 0.980 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.980 |

### combined — 2004 functions, 1002 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.022, 0.005] | 1.000 | — | — | 0.786 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.009 [-0.005, 0.022] | — | 0.611 | 0.504 | 0.306 | — | 1.02 | 0.051 / 0.010 |
| Semgrep alone | +0.045 [0.028, 0.065] | [0.015, 0.058] | 1.7e-09 | — | — | 0.780 | 1.70 | 0.082 / 0.017 |
| Bandit alone | +0.056 [0.035, 0.079] | [0.024, 0.072] | 3e-10 | — | — | 0.373 | 1.34 | 0.066 / 0.013 |
| AST sink gate alone | +0.003 [-0.011, 0.018] | [-0.017, 0.005] | 0.780 | — | — | 0.780 | 1.01 | 0.050 / 0.010 |
| CodeQL alone | +0.039 [0.024, 0.056] | [0.011, 0.050] | 3.4e-10 | — | — | 0.780 | 2.03 | 0.096 / 0.020 |
| SAST board: Judge vote | +0.070 [0.044, 0.096] | [0.036, 0.086] | 1.8e-07 | 0.534 | 9.4e-06 | 0.011 | 1.18 | 0.059 / 0.012 |
| SAST board + evidence override (ablation) | +0.045 [0.022, 0.068] | [0.016, 0.057] | 0.00018 | — | — | 0.030 | 1.08 | 0.054 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.059 [0.030, 0.089] | [0.022, 0.081] | 6.9e-05 | 0.538 | 0.00034 | 0.062 | 1.13 | 0.056 / 0.011 |
| SAST board + fusion (ablation, trained on dev) | +0.096 [0.070, 0.125] | [0.059, 0.117] | 8.5e-13 | 0.560 | 1.4e-06 | 0.011 | 1.53 | 0.074 / 0.015 |
| LLM only, whole function, no SAST | +0.065 [0.041, 0.091] | [0.031, 0.082] | 1e-08 | 0.524 | 0.032 | 0.265 | 1.27 | 0.062 / 0.013 |
| LLM only, dev-tuned threshold | +0.066 [0.043, 0.091] | [0.032, 0.084] | 7.8e-09 | 0.524 | 0.032 | 0.265 | 1.27 | 0.063 / 0.013 |
| LLM only + same-file context, no SAST | +0.072 [0.046, 0.096] | [0.037, 0.091] | 1e-10 | 0.523 | 0.035 | 0.207 | 1.32 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.072 [0.046, 0.096] | [0.037, 0.091] | 1e-10 | 0.523 | 0.035 | 0.207 | 1.32 | 0.065 / 0.013 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.022, 0.005] | 0.667 [0.667, 0.667] | 0.786 |
| Semgrep + Bandit + AST Gate | 0.504 | 0.573 | 0.564 | 0.504 | 0.009 [-0.005, 0.022] | — | 0.536 [0.519, 0.552] | — |
| Semgrep alone | 0.630 | 0.109 | 0.064 | 0.522 | 0.080 [0.051, 0.112] | [0.039, 0.105] | 0.185 [0.149, 0.224] | 0.260 |
| Bandit alone | 0.572 | 0.222 | 0.166 | 0.528 | 0.071 [0.045, 0.101] | [0.035, 0.091] | 0.319 [0.285, 0.353] | 0.093 |
| AST sink gate alone | 0.501 | 0.522 | 0.519 | 0.501 | 0.003 [-0.011, 0.018] | [-0.017, 0.005] | 0.511 [0.491, 0.530] | 0.610 |
| CodeQL alone | 0.670 | 0.077 | 0.038 | 0.519 | 0.084 [0.054, 0.116] | [0.044, 0.108] | 0.138 [0.104, 0.176] | 0.365 |
| SAST board: Judge vote | 0.542 | 0.452 | 0.382 | 0.535 | 0.071 [0.045, 0.097] | [0.037, 0.087] | 0.493 [0.468, 0.515] | 0.001 |
| SAST board + evidence override (ablation) | 0.520 | 0.596 | 0.551 | 0.522 | 0.045 [0.022, 0.068] | [0.017, 0.057] | 0.555 [0.537, 0.573] | 0.003 |
| SAST board: vote score, dev-tuned threshold | 0.531 | 0.504 | 0.445 | 0.529 | 0.059 [0.031, 0.089] | [0.022, 0.081] | 0.517 [0.494, 0.540] | 0.007 |
| SAST board + fusion (ablation, trained on dev) | 0.604 | 0.277 | 0.182 | 0.548 | 0.114 [0.084, 0.148] | [0.073, 0.139] | 0.380 [0.347, 0.413] | 0.00095 |
| LLM only, whole function, no SAST | 0.559 | 0.307 | 0.242 | 0.532 | 0.073 [0.047, 0.103] | [0.037, 0.092] | 0.397 [0.363, 0.428] | 0.048 |
| LLM only, dev-tuned threshold | 0.560 | 0.308 | 0.242 | 0.533 | 0.074 [0.048, 0.103] | [0.038, 0.094] | 0.398 [0.364, 0.428] | 0.044 |
| LLM only + same-file context, no SAST | 0.569 | 0.297 | 0.226 | 0.536 | 0.082 [0.052, 0.110] | [0.044, 0.104] | 0.391 [0.353, 0.422] | 0.026 |
| LLM only + context, dev-tuned threshold | 0.569 | 0.297 | 0.226 | 0.536 | 0.082 [0.052, 0.110] | [0.044, 0.104] | 0.391 [0.353, 0.422] | 0.026 |

**SAST board: Judge vote vs the LLM baselines** (paired, same functions). Δ = board − baseline; CIs resample whole repositories. McNemar counts functions, or whole pairs, that one system gets right and the other does not; p values are Holm-corrected across the baselines.

| Baseline | ΔMCC [95% CI] | ΔJ [95% CI] | Functions: only board right / only baseline right | McNemar p | Pairs: only board correct / only baseline correct | Pair McNemar p |
|---|---|---|---|---|---|---|
| LLM only, whole function, no SAST | [-0.031, 0.029] | [-0.022, 0.033] | 280 / 275 | 1.000 | 75 / 51 | 0.160 |
| LLM only, dev-tuned threshold | [-0.032, 0.028] | [-0.023, 0.032] | 280 / 276 | 1.000 | 75 / 52 | 0.160 |
| LLM only + same-file context, no SAST | [-0.040, 0.019] | [-0.028, 0.026] | 271 / 273 | 1.000 | 73 / 51 | 0.160 |
| LLM only + context, dev-tuned threshold | [-0.040, 0.019] | [-0.028, 0.026] | 271 / 273 | 1.000 | 73 / 51 | 0.160 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 574 | 0 |
| Board (SAST ∪ Soft LLM Screen when enabled) | 1219 | 3,575.6 | 505 | 14,189 |
| LLM only, whole function, no SAST | 2004 | 975.8 | 309 | 6,328 |
| LLM only + same-file context, no SAST | 2004 | 1,176.5 | 298 | 7,912 |


**On functions static analysis flagged** (1139: 574 vulnerable, 565 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.504 | 1.000 | 1.000 | 0.000 | 0.670 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.504 | 1.000 | 1.000 | 0.000 | 0.670 | — | — |
| Semgrep alone | 0.630 | 0.190 | 0.113 | 0.107 | 0.292 | 88.7% | 19.0% |
| Bandit alone | 0.572 | 0.387 | 0.294 | 0.098 | 0.462 | 70.6% | 38.7% |
| AST sink gate alone | 0.501 | 0.911 | 0.920 | -0.017 | 0.647 | 8.0% | 91.1% |
| CodeQL alone | 0.670 | 0.134 | 0.067 | 0.111 | 0.224 | 93.3% | 13.4% |
| SAST board: Judge vote | 0.540 | 0.772 | 0.667 | 0.116 | 0.636 | 33.3% | 77.2% |
| SAST board + evidence override (ablation) | 0.520 | 0.972 | 0.913 | 0.127 | 0.677 | 8.7% | 97.2% |
| SAST board: vote score, dev-tuned threshold | 0.532 | 0.815 | 0.729 | 0.103 | 0.644 | 27.1% | 81.5% |
| SAST board + fusion (ablation, trained on dev) | 0.604 | 0.484 | 0.322 | 0.165 | 0.538 | 67.8% | 48.4% |
| LLM only, whole function, no SAST | 0.570 | 0.455 | 0.349 | 0.108 | 0.506 | 65.1% | 45.5% |
| LLM only, dev-tuned threshold | 0.570 | 0.455 | 0.349 | 0.108 | 0.506 | 65.1% | 45.5% |
| LLM only + same-file context, no SAST | 0.579 | 0.448 | 0.331 | 0.120 | 0.505 | 66.9% | 44.8% |
| LLM only + context, dev-tuned threshold | 0.579 | 0.448 | 0.331 | 0.120 | 0.505 | 66.9% | 44.8% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 1002 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 1002 | 0.035 [0.023, 0.046] | 0.538 | 0.401 | 0.026 | 0.061 | 0.574 |
| Semgrep alone | 1002 | 0.050 [0.033, 0.069] | 0.059 | 0.886 | 0.005 | 0.055 | 0.909 |
| Bandit alone | 1002 | 0.066 [0.047, 0.087] | 0.156 | 0.768 | 0.010 | 0.076 | 0.868 |
| AST sink gate alone | 1002 | 0.027 [0.016, 0.039] | 0.495 | 0.454 | 0.024 | 0.051 | 0.529 |
| CodeQL alone | 1002 | 0.040 [0.025, 0.057] | 0.037 | 0.922 | 0.001 | 0.041 | 0.976 |
| SAST board: Judge vote | 1002 | 0.116 [0.094, 0.138] | 0.336 | 0.502 | 0.046 | 0.162 | 0.716 |
| SAST board + evidence override (ablation) | 1002 | 0.084 [0.066, 0.103] | 0.512 | 0.365 | 0.039 | 0.123 | 0.683 |
| SAST board: vote score, dev-tuned threshold | 1002 | 0.122 [0.099, 0.147] | 0.382 | 0.433 | 0.063 | 0.185 | 0.659 |
| SAST board + fusion (ablation, trained on dev) | 1002 | 0.133 [0.108, 0.160] | 0.145 | 0.686 | 0.037 | 0.170 | 0.782 |
| LLM only, whole function, no SAST | 1002 | 0.092 [0.072, 0.115] | 0.216 | 0.666 | 0.027 | 0.119 | 0.773 |
| LLM only, dev-tuned threshold | 1002 | 0.093 [0.073, 0.116] | 0.216 | 0.665 | 0.027 | 0.120 | 0.775 |
| LLM only + same-file context, no SAST | 1002 | 0.094 [0.072, 0.116] | 0.204 | 0.681 | 0.022 | 0.116 | 0.810 |
| LLM only + context, dev-tuned threshold | 1002 | 0.094 [0.072, 0.116] | 0.204 | 0.681 | 0.022 | 0.116 | 0.810 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.997 | 0.997 |
| SAST board + fusion (ablation, trained on dev) | 0.969 | 0.885 |
| LLM only, whole function, no SAST | 1.000 | 0.985 |
| LLM only, dev-tuned threshold | 1.000 | 0.985 |
| LLM only + same-file context, no SAST | 1.000 | 0.987 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.987 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | sast MCC / R | semgrep MCC / R | bandit MCC / R | board MCC / R | board_calibrated MCC / R | fusion MCC / R | llm_only_calibrated MCC / R | llm_context_calibrated MCC / R |
|---|---|---|---|---|---|---|---|---|---|---|
| **logic_semantic** | 916 | 51.3% | 0.004 / 0.513 | 0.018 / 0.037 | 0.017 / 0.129 | 0.009 / 0.349 | -0.004 / 0.402 | 0.030 / 0.166 | 0.031 / 0.124 | 0.021 / 0.116 |
| **sast_reachable** | 1088 | 62.3% | 0.013 / 0.623 | 0.115 / 0.169 | 0.108 / 0.300 | 0.121 / 0.539 | 0.112 / 0.590 | 0.174 / 0.371 | 0.106 / 0.463 | 0.124 / 0.450 |
| injection | 600 | 62.3% | -0.007 / 0.623 | 0.124 / 0.200 | 0.132 / 0.383 | 0.127 / 0.570 | 0.111 / 0.603 | 0.199 / 0.420 | 0.090 / 0.507 | 0.094 / 0.483 |
| access_control (logic) | 306 | 47.7% | -0.006 / 0.477 | 0.018 / 0.039 | 0.019 / 0.137 | 0.049 / 0.340 | -0.007 / 0.379 | 0.057 / 0.157 | 0.000 / 0.131 | 0.029 / 0.137 |
| path_traversal | 190 | 60.0% | 0.043 / 0.600 | 0.074 / 0.063 | 0.078 / 0.158 | 0.144 / 0.410 | 0.172 / 0.484 | 0.199 / 0.274 | 0.206 / 0.400 | 0.249 / 0.379 |
| info_exposure (logic) | 168 | 57.1% | 0.012 / 0.571 | 0.000 / 0.059 | 0.038 / 0.119 | -0.025 / 0.369 | 0.024 / 0.452 | 0.016 / 0.167 | 0.067 / 0.095 | 0.000 / 0.048 |
| ssrf_redirect | 152 | 67.1% | 0.014 / 0.671 | 0.072 / 0.184 | -0.022 / 0.092 | 0.105 / 0.553 | 0.120 / 0.645 | 0.088 / 0.316 | 0.083 / 0.382 | 0.135 / 0.447 |
| other (logic) | 142 | 46.5% | 0.000 / 0.465 | 0.049 / 0.028 | 0.023 / 0.113 | -0.016 / 0.268 | 0.000 / 0.310 | 0.000 / 0.141 | 0.000 / 0.099 | -0.026 / 0.070 |
| input_validation (logic) | 140 | 55.7% | 0.014 / 0.557 | 0.000 / 0.043 | 0.051 / 0.100 | 0.015 / 0.400 | -0.014 / 0.486 | 0.038 / 0.186 | 0.079 / 0.186 | 0.073 / 0.214 |
| resource_dos (logic) | 106 | 50.9% | 0.038 / 0.509 | 0.000 / 0.000 | -0.044 / 0.038 | -0.019 / 0.377 | 0.019 / 0.415 | 0.023 / 0.226 | 0.082 / 0.075 | 0.038 / 0.075 |
| crypto_secrets | 82 | 39.0% | -0.025 / 0.390 | 0.000 / 0.000 | 0.000 / 0.146 | 0.052 / 0.342 | -0.025 / 0.439 | 0.039 / 0.122 | 0.032 / 0.195 | 0.033 / 0.171 |
| deserialization | 36 | 100.0% | 0.354 / 1.000 | 0.447 / 0.667 | 0.405 / 0.833 | 0.241 / 0.944 | 0.241 / 0.944 | 0.543 / 0.944 | 0.298 / 0.944 | 0.401 / 0.944 |
| memory_numeric (logic) | 28 | 57.1% | -0.073 / 0.571 | 0.000 / 0.000 | -0.073 / 0.571 | -0.076 / 0.286 | -0.149 / 0.286 | 0.000 / 0.143 | 0.000 / 0.000 | 0.000 / 0.000 |
| xml | 28 | 71.4% | 0.076 / 0.714 | 0.000 / 0.000 | 0.247 / 0.357 | 0.149 / 0.714 | 0.076 / 0.714 | -0.076 / 0.286 | 0.072 / 0.571 | 0.000 / 0.429 |
| unknown (logic) | 26 | 53.8% | 0.000 / 0.538 | 0.200 / 0.077 | 0.000 / 0.231 | 0.078 / 0.462 | -0.077 / 0.462 | 0.000 / 0.077 | 0.000 / 0.385 | -0.081 / 0.308 |

### Pipeline telemetry (test)

- flagged_functions: 1139
- findings: 2402
- findings_per_flagged_function: 2.11
- by_tool: {'ast_sink': 1566, 'bandit': 473, 'codeql': 125, 'semgrep': 238}
- cpg_success_rate: 0.9938
- cpg_taint_found_rate: 0.6682
- cpg_unfiltered_taint_rate: 0.6249
- cpg_sanitized_taint_rate: 0.0987
- rag_context_rate: 1.0
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **function_board**: functions 1139, mean_valid_votes 1.0, unanimous_rate 0.9991, split_vote_rate 0.0, no_valid_vote_rate 0.0009, majority_not_vulnerable_rate 0.2801, evidence_grounded_rate 0.0869, evidence_reasons {'conceded': 930, 'no_span_match': 110, 'span_match': 99}, evidence_in_context_rate 0.0026, guard_grounded_rate 0.0, override_flip_rate 0.223, code_truncated_rate 0.0544, context_overflow_rate 0.0026, attacker_parse_failed_rate 0.0, defender_parse_failed_rate 0.0009, mean_seconds_per_function 49.7
- **repo_context**: functions 2004, available_rate 0.999, cross_file_callers_rate 0.2525, entry_point_rate 0.1018, flagged_cross_file_callers_rate 0.2669, flagged_entry_point_rate 0.1352, mean_context_chars 639.3
- **llm_baselines**: llm_only_parse_failed_rate 0.001, llm_only_vulnerable_rate 0.275, llm_context_parse_failed_rate 0.0, llm_context_vulnerable_rate 0.2615

## Test, clean subset (single-function fixes)

### clean — 676 functions, 338 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.033, 0.023] | 1.000 | — | — | 0.953 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.006 [-0.023, 0.033] | — | 1.000 | 0.503 | 0.839 | — | 1.01 | 0.051 / 0.010 |
| Semgrep alone | +0.062 [0.038, 0.091] | [0.022, 0.093] | 5.7e-05 | — | — | 1.000 | 2.00 | 0.095 / 0.020 |
| Bandit alone | +0.059 [0.029, 0.093] | [0.019, 0.091] | 0.004 | — | — | 1.000 | 1.31 | 0.064 / 0.013 |
| AST sink gate alone | +0.003 [-0.021, 0.029] | [-0.022, 0.017] | 1.000 | — | — | 1.000 | 1.01 | 0.050 / 0.010 |
| CodeQL alone | +0.027 [0.009, 0.047] | [-0.011, 0.054] | 0.070 | — | — | 1.000 | 1.69 | 0.082 / 0.017 |
| SAST board: Judge vote | +0.038 [-0.003, 0.082] | [-0.006, 0.073] | 0.524 | 0.519 | 0.392 | 1.000 | 1.10 | 0.055 / 0.011 |
| SAST board + evidence override (ablation) | +0.033 [-0.003, 0.066] | [-0.003, 0.052] | 0.524 | — | — | 1.000 | 1.06 | 0.053 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.021 [-0.024, 0.068] | [-0.028, 0.060] | 1.000 | 0.527 | 0.392 | 1.000 | 1.05 | 0.052 / 0.010 |
| SAST board + fusion (ablation, trained on dev) | +0.115 [0.074, 0.161] | [0.064, 0.159] | 8.2e-06 | 0.553 | 0.074 | 0.249 | 1.70 | 0.082 / 0.017 |
| LLM only, whole function, no SAST | +0.068 [0.034, 0.103] | [0.020, 0.103] | 0.002 | 0.537 | 0.139 | 1.000 | 1.28 | 0.063 / 0.013 |
| LLM only, dev-tuned threshold | +0.071 [0.037, 0.108] | [0.022, 0.109] | 0.001 | 0.537 | 0.139 | 1.000 | 1.30 | 0.064 / 0.013 |
| LLM only + same-file context, no SAST | +0.092 [0.058, 0.128] | [0.046, 0.129] | 4.4e-06 | 0.528 | 0.392 | 1.000 | 1.48 | 0.072 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.092 [0.058, 0.128] | [0.046, 0.129] | 4.4e-06 | 0.528 | 0.392 | 1.000 | 1.48 | 0.072 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.034, 0.023] | 0.667 [0.667, 0.667] | 0.953 |
| Semgrep + Bandit + AST Gate | 0.502 | 0.586 | 0.580 | 0.503 | 0.006 [-0.023, 0.034] | — | 0.541 [0.514, 0.567] | — |
| Semgrep alone | 0.667 | 0.124 | 0.062 | 0.531 | 0.107 [0.069, 0.153] | [0.056, 0.152] | 0.209 [0.162, 0.258] | 0.322 |
| Bandit alone | 0.567 | 0.252 | 0.192 | 0.530 | 0.071 [0.035, 0.111] | [0.026, 0.108] | 0.348 [0.299, 0.390] | 0.276 |
| AST sink gate alone | 0.501 | 0.530 | 0.527 | 0.501 | 0.003 [-0.021, 0.029] | [-0.023, 0.017] | 0.515 [0.483, 0.545] | 1.000 |
| CodeQL alone | 0.629 | 0.065 | 0.038 | 0.513 | 0.060 [0.021, 0.100] | [0.008, 0.103] | 0.118 [0.076, 0.162] | 0.752 |
| SAST board: Judge vote | 0.523 | 0.435 | 0.396 | 0.519 | 0.039 [-0.003, 0.084] | [-0.006, 0.074] | 0.475 [0.438, 0.515] | 0.371 |
| SAST board + evidence override (ablation) | 0.514 | 0.604 | 0.571 | 0.516 | 0.033 [-0.003, 0.067] | [-0.003, 0.053] | 0.555 [0.523, 0.582] | 0.222 |
| SAST board: vote score, dev-tuned threshold | 0.511 | 0.476 | 0.456 | 0.510 | 0.021 [-0.024, 0.069] | [-0.028, 0.060] | 0.493 [0.454, 0.531] | 0.714 |
| SAST board + fusion (ablation, trained on dev) | 0.629 | 0.281 | 0.166 | 0.558 | 0.139 [0.089, 0.191] | [0.081, 0.189] | 0.389 [0.335, 0.442] | 0.021 |
| LLM only, whole function, no SAST | 0.562 | 0.308 | 0.240 | 0.534 | 0.076 [0.038, 0.117] | [0.026, 0.115] | 0.398 [0.352, 0.445] | 0.224 |
| LLM only, dev-tuned threshold | 0.565 | 0.311 | 0.240 | 0.535 | 0.080 [0.041, 0.121] | [0.028, 0.121] | 0.401 [0.355, 0.448] | 0.203 |
| LLM only + same-file context, no SAST | 0.596 | 0.284 | 0.192 | 0.546 | 0.108 [0.069, 0.147] | [0.058, 0.149] | 0.385 [0.335, 0.434] | 0.096 |
| LLM only + context, dev-tuned threshold | 0.596 | 0.284 | 0.192 | 0.546 | 0.108 [0.069, 0.147] | [0.058, 0.149] | 0.385 [0.335, 0.434] | 0.096 |

**SAST board: Judge vote vs the LLM baselines** (paired, same functions). Δ = board − baseline; CIs resample whole repositories. McNemar counts functions, or whole pairs, that one system gets right and the other does not; p values are Holm-corrected across the baselines.

| Baseline | ΔMCC [95% CI] | ΔJ [95% CI] | Functions: only board right / only baseline right | McNemar p | Pairs: only board correct / only baseline correct | Pair McNemar p |
|---|---|---|---|---|---|---|
| LLM only, whole function, no SAST | [-0.093, 0.014] | [-0.080, 0.018] | 92 / 102 | 0.948 | 22 / 18 | 1.000 |
| LLM only, dev-tuned threshold | [-0.095, 0.011] | [-0.083, 0.016] | 92 / 103 | 0.948 | 22 / 19 | 1.000 |
| LLM only + same-file context, no SAST | [-0.118, -0.019] | [-0.098, -0.009] | 88 / 106 | 0.889 | 19 / 20 | 1.000 |
| LLM only + context, dev-tuned threshold | [-0.118, -0.019] | [-0.098, -0.009] | 88 / 106 | 0.889 | 19 / 20 | 1.000 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 198 | 0 |
| Board (SAST ∪ Soft LLM Screen when enabled) | 419 | 3,666.7 | 161 | 15,396 |
| LLM only, whole function, no SAST | 676 | 1,008.8 | 105 | 6,495 |
| LLM only + same-file context, no SAST | 676 | 1,195.7 | 96 | 8,420 |


**On functions static analysis flagged** (394: 198 vulnerable, 196 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.502 | 1.000 | 1.000 | 0.000 | 0.669 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.502 | 1.000 | 1.000 | 0.000 | 0.669 | — | — |
| Semgrep alone | 0.667 | 0.212 | 0.107 | 0.143 | 0.322 | 89.3% | 21.2% |
| Bandit alone | 0.567 | 0.429 | 0.332 | 0.101 | 0.488 | 66.8% | 42.9% |
| AST sink gate alone | 0.501 | 0.904 | 0.908 | -0.007 | 0.645 | 9.2% | 90.4% |
| CodeQL alone | 0.629 | 0.111 | 0.066 | 0.079 | 0.189 | 93.4% | 11.1% |
| SAST board: Judge vote | 0.520 | 0.722 | 0.673 | 0.053 | 0.605 | 32.6% | 72.2% |
| SAST board + evidence override (ablation) | 0.511 | 0.965 | 0.934 | 0.070 | 0.668 | 6.6% | 96.5% |
| SAST board: vote score, dev-tuned threshold | 0.512 | 0.763 | 0.735 | 0.032 | 0.613 | 26.5% | 76.3% |
| SAST board + fusion (ablation, trained on dev) | 0.629 | 0.480 | 0.286 | 0.200 | 0.544 | 71.4% | 48.0% |
| LLM only, whole function, no SAST | 0.578 | 0.450 | 0.332 | 0.121 | 0.506 | 66.8% | 45.0% |
| LLM only, dev-tuned threshold | 0.578 | 0.450 | 0.332 | 0.121 | 0.506 | 66.8% | 45.0% |
| LLM only + same-file context, no SAST | 0.610 | 0.419 | 0.270 | 0.157 | 0.497 | 73.0% | 41.9% |
| LLM only + context, dev-tuned threshold | 0.610 | 0.419 | 0.270 | 0.157 | 0.497 | 73.0% | 41.9% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 338 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 338 | 0.038 [0.018, 0.061] | 0.547 | 0.382 | 0.033 | 0.071 | 0.542 |
| Semgrep alone | 338 | 0.065 [0.042, 0.094] | 0.059 | 0.873 | 0.003 | 0.068 | 0.957 |
| Bandit alone | 338 | 0.077 [0.051, 0.107] | 0.175 | 0.731 | 0.018 | 0.095 | 0.812 |
| AST sink gate alone | 338 | 0.033 [0.015, 0.052] | 0.497 | 0.441 | 0.030 | 0.062 | 0.524 |
| CodeQL alone | 338 | 0.030 [0.012, 0.050] | 0.035 | 0.932 | 0.003 | 0.033 | 0.909 |
| SAST board: Judge vote | 338 | 0.101 [0.068, 0.134] | 0.334 | 0.503 | 0.062 | 0.163 | 0.618 |
| SAST board + evidence override (ablation) | 338 | 0.074 [0.049, 0.099] | 0.530 | 0.355 | 0.041 | 0.115 | 0.641 |
| SAST board: vote score, dev-tuned threshold | 338 | 0.106 [0.075, 0.142] | 0.370 | 0.438 | 0.086 | 0.192 | 0.554 |
| SAST board + fusion (ablation, trained on dev) | 338 | 0.151 [0.112, 0.191] | 0.130 | 0.683 | 0.035 | 0.186 | 0.809 |
| LLM only, whole function, no SAST | 338 | 0.089 [0.059, 0.123] | 0.219 | 0.672 | 0.021 | 0.110 | 0.811 |
| LLM only, dev-tuned threshold | 338 | 0.092 [0.061, 0.126] | 0.219 | 0.669 | 0.021 | 0.112 | 0.816 |
| LLM only + same-file context, no SAST | 338 | 0.104 [0.073, 0.138] | 0.180 | 0.704 | 0.012 | 0.115 | 0.897 |
| LLM only + context, dev-tuned threshold | 338 | 0.104 [0.073, 0.138] | 0.180 | 0.704 | 0.012 | 0.115 | 0.897 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.994 | 0.994 |
| SAST board + fusion (ablation, trained on dev) | 0.950 | 0.882 |
| LLM only, whole function, no SAST | 1.000 | 0.991 |
| LLM only, dev-tuned threshold | 1.000 | 0.991 |
| LLM only + same-file context, no SAST | 1.000 | 0.991 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.991 |

## Test, split by ReposVul's own static check

ReposVul's strict label requires Semgrep or RATS to flag the pre-fix file at the changed lines. SAST is favoured by construction where that check matched; the other stratum shows how each system does on fixes that pattern rules did not see.

### ReposVul static check matched — 158 functions, 79 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.099, 0.026] | 1.000 | — | — | 0.629 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.038 [-0.026, 0.099] | — | 0.906 | 0.519 | 0.453 | — | 1.04 | 0.052 / 0.010 |
| Semgrep alone | +0.317 [0.193, 0.460] | [0.152, 0.422] | 7.7e-07 | — | — | 0.230 | 2.47 | 0.115 / 0.024 |
| Bandit alone | +0.240 [0.129, 0.366] | [0.077, 0.322] | 4.6e-05 | — | — | 0.687 | 1.76 | 0.085 / 0.018 |
| AST sink gate alone | +0.038 [-0.038, 0.122] | [-0.053, 0.053] | 0.906 | — | — | 1.000 | 1.05 | 0.052 / 0.011 |
| CodeQL alone | +0.139 [0.055, 0.232] | [-0.000, 0.207] | 0.005 | — | — | 1.000 | 3.20 | 0.144 / 0.031 |
| SAST board: Judge vote | +0.203 [0.113, 0.309] | [0.067, 0.281] | 0.003 | 0.589 | 0.009 | 0.230 | 1.32 | 0.065 / 0.013 |
| SAST board + evidence override (ablation) | +0.127 [0.051, 0.207] | [0.012, 0.182] | 0.039 | — | — | 0.829 | 1.16 | 0.058 / 0.012 |
| SAST board: vote score, dev-tuned threshold | +0.165 [0.059, 0.279] | [0.013, 0.256] | 0.029 | 0.671 | 0.0002 | 0.697 | 1.25 | 0.061 / 0.012 |
| SAST board + fusion (ablation, trained on dev) | +0.253 [0.133, 0.381] | [0.096, 0.325] | 0.003 | 0.677 | 0.005 | 0.533 | 1.77 | 0.085 / 0.018 |
| LLM only, whole function, no SAST | +0.177 [0.077, 0.284] | [0.024, 0.250] | 0.004 | 0.614 | 0.008 | 1.000 | 1.37 | 0.067 / 0.014 |
| LLM only, dev-tuned threshold | +0.177 [0.077, 0.284] | [0.024, 0.250] | 0.004 | 0.614 | 0.008 | 1.000 | 1.37 | 0.067 / 0.014 |
| LLM only + same-file context, no SAST | +0.190 [0.088, 0.308] | [0.046, 0.267] | 0.003 | 0.633 | 0.005 | 1.000 | 1.45 | 0.071 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.190 [0.088, 0.308] | [0.046, 0.267] | 0.003 | 0.633 | 0.005 | 1.000 | 1.45 | 0.071 / 0.015 |

### ReposVul static check did not match — 646 functions, 323 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.037, 0.011] | 1.000 | — | — | 0.863 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.012 [-0.011, 0.037] | — | 1.000 | 0.506 | 1.000 | — | 1.02 | 0.051 / 0.010 |
| Semgrep alone | -0.003 [-0.011, 0.000] | [-0.040, 0.009] | 1.000 | — | — | 1.000 | 0.90 | 0.045 / 0.009 |
| Bandit alone | +0.022 [0.000, 0.050] | [-0.019, 0.043] | 0.790 | — | — | 1.000 | 1.18 | 0.058 / 0.012 |
| AST sink gate alone | +0.006 [-0.016, 0.028] | [-0.029, 0.013] | 1.000 | — | — | 1.000 | 1.01 | 0.051 / 0.010 |
| CodeQL alone | +0.031 [0.012, 0.052] | [-0.006, 0.044] | 0.023 | — | — | 1.000 | 1.67 | 0.081 / 0.017 |
| SAST board: Judge vote | +0.059 [0.012, 0.109] | [0.003, 0.092] | 0.139 | 0.522 | 0.647 | 1.000 | 1.16 | 0.058 / 0.012 |
| SAST board + evidence override (ablation) | +0.040 [-0.007, 0.088] | [-0.013, 0.072] | 0.533 | — | — | 1.000 | 1.08 | 0.054 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.031 [-0.027, 0.086] | [-0.035, 0.068] | 0.980 | 0.501 | 1.000 | 1.000 | 1.07 | 0.053 / 0.011 |
| SAST board + fusion (ablation, trained on dev) | +0.074 [0.030, 0.123] | [0.014, 0.113] | 0.005 | 0.537 | 0.480 | 1.000 | 1.49 | 0.073 / 0.015 |
| LLM only, whole function, no SAST | +0.031 [-0.011, 0.070] | [-0.031, 0.062] | 0.790 | 0.491 | 1.000 | 1.000 | 1.16 | 0.058 / 0.012 |
| LLM only, dev-tuned threshold | +0.034 [-0.007, 0.072] | [-0.027, 0.065] | 0.637 | 0.491 | 1.000 | 1.000 | 1.17 | 0.058 / 0.012 |
| LLM only + same-file context, no SAST | +0.031 [-0.007, 0.071] | [-0.026, 0.065] | 0.790 | 0.478 | 1.000 | 1.000 | 1.15 | 0.057 / 0.011 |
| LLM only + context, dev-tuned threshold | +0.031 [-0.007, 0.071] | [-0.026, 0.065] | 0.790 | 0.478 | 1.000 | 1.000 | 1.15 | 0.057 / 0.011 |

## Test, split by what the repository shows about callers

Pairs are grouped by the vulnerable version: callers of the function found in other files, a web-framework entry point with no such callers, or neither. This shows where cross-file context can matter.

### Callers found in other files — 504 functions, 252 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.046, -0.004] | 1.000 | — | — | 0.724 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.024 [0.004, 0.046] | — | 0.219 | 0.512 | 0.328 | — | 1.04 | 0.052 / 0.010 |
| Semgrep alone | +0.056 [0.023, 0.093] | [-0.004, 0.070] | 0.001 | — | — | 1.000 | 2.56 | 0.119 / 0.025 |
| Bandit alone | +0.095 [0.051, 0.144] | [0.026, 0.121] | 3.9e-05 | — | — | 1.000 | 1.69 | 0.082 / 0.017 |
| AST sink gate alone | +0.008 [-0.012, 0.028] | [-0.035, 0.000] | 0.688 | — | — | 1.000 | 1.01 | 0.051 / 0.010 |
| CodeQL alone | +0.024 [0.008, 0.044] | [-0.023, 0.025] | 0.094 | — | — | 1.000 | 1.75 | 0.084 / 0.017 |
| SAST board: Judge vote | +0.071 [0.013, 0.134] | [-0.011, 0.108] | 0.070 | 0.542 | 0.039 | 1.000 | 1.18 | 0.059 / 0.012 |
| SAST board + evidence override (ablation) | +0.064 [0.022, 0.108] | [0.004, 0.079] | 0.045 | — | — | 1.000 | 1.11 | 0.055 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.087 [0.029, 0.151] | [0.008, 0.120] | 0.023 | 0.559 | 0.018 | 1.000 | 1.20 | 0.059 / 0.012 |
| SAST board + fusion (ablation, trained on dev) | +0.075 [0.021, 0.140] | [-0.004, 0.114] | 0.036 | 0.575 | 0.012 | 1.000 | 1.44 | 0.070 / 0.014 |
| LLM only, whole function, no SAST | +0.079 [0.025, 0.136] | [0.000, 0.110] | 0.022 | 0.548 | 0.069 | 1.000 | 1.33 | 0.065 / 0.013 |
| LLM only, dev-tuned threshold | +0.083 [0.029, 0.140] | [0.004, 0.114] | 0.016 | 0.548 | 0.069 | 1.000 | 1.34 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.068 [0.020, 0.122] | [-0.009, 0.097] | 0.036 | 0.520 | 0.686 | 1.000 | 1.28 | 0.063 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.068 [0.020, 0.122] | [-0.009, 0.097] | 0.036 | 0.520 | 0.686 | 1.000 | 1.28 | 0.063 / 0.013 |

### Framework entry point, no cross-file callers — 182 functions, 91 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.116, 0.024] | 1.000 | — | — | 0.665 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.044 [-0.024, 0.116] | — | 0.875 | 0.522 | 0.488 | — | 1.06 | 0.053 / 0.011 |
| Semgrep alone | +0.044 [0.000, 0.104] | [-0.076, 0.083] | 0.875 | — | — | 1.000 | 1.29 | 0.063 / 0.013 |
| Bandit alone | +0.000 [-0.044, 0.044] | [-0.108, 0.022] | 1.000 | — | — | 1.000 | 1.00 | 0.050 / 0.010 |
| AST sink gate alone | -0.011 [-0.072, 0.045] | [-0.122, 0.011] | 1.000 | — | — | 1.000 | 0.98 | 0.049 / 0.010 |
| CodeQL alone | +0.165 [0.083, 0.258] | [0.036, 0.214] | 0.00079 | — | — | 1.000 | 1.83 | 0.088 / 0.018 |
| SAST board: Judge vote | +0.154 [0.046, 0.259] | [0.021, 0.223] | 0.013 | 0.582 | 0.012 | 1.000 | 1.35 | 0.066 / 0.013 |
| SAST board + evidence override (ablation) | +0.132 [0.022, 0.245] | [-0.012, 0.204] | 0.045 | — | — | 1.000 | 1.20 | 0.059 / 0.012 |
| SAST board: vote score, dev-tuned threshold | +0.121 [0.000, 0.250] | [-0.044, 0.216] | 0.216 | 0.571 | 0.363 | 1.000 | 1.22 | 0.060 / 0.012 |
| SAST board + fusion (ablation, trained on dev) | +0.165 [0.057, 0.293] | [-0.010, 0.269] | 0.023 | 0.588 | 0.363 | 1.000 | 1.79 | 0.086 / 0.018 |
| LLM only, whole function, no SAST | +0.132 [0.055, 0.235] | [-0.020, 0.209] | 0.006 | 0.549 | 0.488 | 1.000 | 1.41 | 0.069 / 0.014 |
| LLM only, dev-tuned threshold | +0.132 [0.055, 0.235] | [-0.020, 0.209] | 0.006 | 0.549 | 0.488 | 1.000 | 1.41 | 0.069 / 0.014 |
| LLM only + same-file context, no SAST | +0.121 [0.032, 0.231] | [-0.034, 0.196] | 0.027 | 0.560 | 0.448 | 1.000 | 1.42 | 0.070 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.121 [0.032, 0.231] | [-0.034, 0.196] | 0.027 | 0.560 | 0.448 | 1.000 | 1.42 | 0.070 / 0.014 |

### Neither — 1318 functions, 659 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.017, 0.020] | 1.000 | — | — | 1.000 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | -0.002 [-0.020, 0.017] | — | 1.000 | 0.499 | 1.000 | — | 1.00 | 0.050 / 0.010 |
| Semgrep alone | +0.041 [0.020, 0.063] | [0.017, 0.071] | 3.1e-05 | — | — | 0.801 | 1.66 | 0.080 / 0.017 |
| Bandit alone | +0.049 [0.024, 0.075] | [0.021, 0.081] | 9.4e-06 | — | — | 0.718 | 1.26 | 0.062 / 0.013 |
| AST sink gate alone | +0.003 [-0.015, 0.023] | [-0.006, 0.016] | 1.000 | — | — | 0.966 | 1.01 | 0.050 / 0.010 |
| CodeQL alone | +0.027 [0.013, 0.044] | [0.006, 0.053] | 0.00032 | — | — | 0.966 | 2.50 | 0.116 / 0.025 |
| SAST board: Judge vote | +0.058 [0.029, 0.087] | [0.030, 0.090] | 0.00047 | 0.524 | 0.031 | 0.067 | 1.16 | 0.057 / 0.011 |
| SAST board + evidence override (ablation) | +0.026 [-0.002, 0.051] | [0.003, 0.050] | 0.170 | — | — | 0.443 | 1.05 | 0.052 / 0.011 |
| SAST board: vote score, dev-tuned threshold | +0.040 [0.006, 0.074] | [0.009, 0.076] | 0.067 | 0.526 | 0.163 | 0.443 | 1.09 | 0.054 / 0.011 |
| SAST board + fusion (ablation, trained on dev) | +0.094 [0.063, 0.125] | [0.060, 0.129] | 8.7e-09 | 0.550 | 0.002 | 0.022 | 1.52 | 0.074 / 0.015 |
| LLM only, whole function, no SAST | +0.050 [0.022, 0.080] | [0.019, 0.087] | 0.00047 | 0.512 | 0.829 | 0.718 | 1.22 | 0.060 / 0.012 |
| LLM only, dev-tuned threshold | +0.050 [0.022, 0.080] | [0.019, 0.087] | 0.00047 | 0.512 | 0.829 | 0.718 | 1.22 | 0.060 / 0.012 |
| LLM only + same-file context, no SAST | +0.067 [0.038, 0.098] | [0.035, 0.103] | 1.2e-06 | 0.519 | 0.427 | 0.443 | 1.32 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.067 [0.038, 0.098] | [0.035, 0.103] | 1.2e-06 | 0.519 | 0.427 | 0.443 | 1.32 | 0.065 / 0.013 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | FPR | Accuracy | MCC | F1 |
|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| Semgrep + Bandit + AST Gate | 0.496 | 0.566 | 0.574 | 0.496 | -0.008 | 0.529 |
| Semgrep alone | 0.611 | 0.088 | 0.056 | 0.516 | 0.062 | 0.153 |
| Bandit alone | 0.621 | 0.163 | 0.100 | 0.532 | 0.094 | 0.259 |
| AST sink gate alone | 0.485 | 0.530 | 0.562 | 0.484 | -0.032 | 0.507 |
| CodeQL alone | 0.556 | 0.040 | 0.032 | 0.504 | 0.021 | 0.074 |
| SAST board: Judge vote | 0.562 | 0.430 | 0.335 | 0.548 | 0.098 | 0.488 |
| SAST board + evidence override (ablation) | 0.525 | 0.574 | 0.518 | 0.528 | 0.056 | 0.549 |
| SAST board: vote score, dev-tuned threshold | 0.563 | 0.482 | 0.374 | 0.554 | 0.109 | 0.519 |
| SAST board + fusion (ablation, trained on dev) | 0.727 | 0.255 | 0.096 | 0.580 | 0.210 | 0.378 |
| LLM only, whole function, no SAST | 0.639 | 0.275 | 0.155 | 0.560 | 0.145 | 0.384 |
| LLM only, dev-tuned threshold | 0.642 | 0.279 | 0.155 | 0.562 | 0.150 | 0.389 |
| LLM only + same-file context, no SAST | 0.612 | 0.239 | 0.151 | 0.544 | 0.111 | 0.344 |
| LLM only + context, dev-tuned threshold | 0.612 | 0.239 | 0.151 | 0.544 | 0.111 | 0.344 |

## Caveats

- Labels follow the fix-commit convention (CVEfixes, PrimeVul): a function changed by a security-fix commit is vulnerable before the fix and fixed after it. Tangled commits (> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded; the clean subset further keeps only commits that changed a single function.
- The SAST board only reasons about Semgrep and Bandit findings, so its recall cannot exceed theirs. The sast_flagged view isolates what the board adds on the functions it is asked to review.
- The LLM-only rows ask the same model once, with no static findings: the function alone, and the function plus the context the board sees. They are comparison baselines, not part of the shipped pipeline. They never see the dataset label or CWE. Context is same-file callers and callees, callers in other files of the repository at the same commit (resolved by name and imports, test files excluded), and the web-framework entry point when there is one.
- Token counts are Ollama's prompt_eval_count plus eval_count. Tokens per true positive divides the tokens spent on that system by the true positives of its dev-tuned threshold.
- Board thresholds and fusion models are fitted on the dev split only (maximising mcc); test repositories never appear in dev. Dev numbers are in-sample and are shown for reference.
- Test and dev are balanced by construction (one vulnerable and one fixed function per pair), so F1 rewards flagging everything: compare every row with the trivial reference, and read MCC, accuracy and the pairwise columns for discrimination. 'Right way round' is the share of pairs with differing verdicts where the vulnerable version is the flagged one; 0.5 means no signal.
- Confidence intervals resample whole repositories (1,000 draws), since pairs from one project are not independent. McNemar compares per-function correctness against SAST. Sign-test and McNemar p values in the signal tables are Holm-corrected across the systems compared.
- Precision at a given prevalence is TPR·π / (TPR·π + FPR·(1 − π)): what a user would see if that share of functions were vulnerable, instead of the 50% this test set has by construction.
- VUDENC commits are keyword-mined and noisier than CVE-linked CVEfixes commits; compare within, not across, datasets.
- ReposVul files are kept by its 'llm' label policy (llm = its LLM untangling check marks the file as vulnerability-fixing; strict = its LLM and static checks both do), and patches it marks as outdated are skipped. Its static check is Semgrep/RATS, so the 'static check matched' stratum favours SAST by construction, and its LLM check may favour fixes an LLM recognises.
