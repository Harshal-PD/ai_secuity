# HackerSec real-world evaluation (2026-10-23T23:26:08)

Status: **complete** — 2506/2506 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v9-judge-repo-callers`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| cvefixes | 100 (52) | 400 (133) | 154 |
| reposvul | 101 (44) | 402 (156) | 218 |
| vudenc | 50 (27) | 200 (103) | 90 |

- Dev functions evaluated: 502
- Board threshold on mean P(vulnerable) across Judge votes: **0.700** (max mcc on dev)
- Fusion: trained on 107 flagged dev functions (5-fold CV C=0.4, max mcc), threshold 0.619, dev CV F1 0.227, dev CV MCC 0.191
- LLM-only threshold on P(vulnerable): **0.200** (max mcc on dev)
- LLM-only + context threshold on P(vulnerable): **0.900** (max mcc on dev)

Each pair contributes one vulnerable and one fixed function, so flagging every function scores F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise columns show whether a system actually separates vulnerable from fixed code.

## Test split (primary)

### cvefixes — 800 functions, 400 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.094, -0.033] | 1.000 | — | — | 0.323 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.062 [0.033, 0.094] | — | 0.00056 | 0.531 | 0.00035 | — | 1.27 | 0.063 / 0.013 |
| Semgrep alone | +0.040 [0.019, 0.065] | [-0.053, 0.008] | 0.00087 | — | — | 1.000 | 1.64 | 0.080 / 0.016 |
| Bandit alone | +0.045 [0.018, 0.076] | [-0.045, 0.009] | 0.003 | — | — | 1.000 | 1.28 | 0.063 / 0.013 |
| AST sink gate alone | +0.022 [0.000, 0.048] | [-0.070, -0.009] | 0.064 | — | — | 1.000 | 1.24 | 0.061 / 0.012 |
| CodeQL alone | +0.040 [0.017, 0.071] | [-0.056, 0.010] | 0.00027 | — | — | 1.000 | 3.00 | 0.136 / 0.029 |
| SAST board: Judge vote | +0.085 [0.053, 0.122] | [-0.000, 0.048] | 3.7e-06 | 0.547 | 1.1e-06 | 1.000 | 1.63 | 0.079 / 0.016 |
| SAST board + evidence override (ablation) | +0.077 [0.046, 0.113] | [-0.003, 0.038] | 5.5e-05 | — | — | 1.000 | 1.40 | 0.069 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.083 [0.050, 0.121] | [-0.003, 0.047] | 1.2e-05 | 0.554 | 7.6e-06 | 1.000 | 1.61 | 0.078 / 0.016 |
| SAST board + fusion (ablation, trained on dev) | +0.095 [0.054, 0.141] | [-0.005, 0.075] | 1.8e-07 | 0.569 | 2e-06 | 1.000 | 2.23 | 0.105 / 0.022 |
| LLM only, whole function, no SAST | +0.055 [0.020, 0.094] | [-0.050, 0.038] | 0.003 | 0.526 | 0.284 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only, dev-tuned threshold | +0.055 [0.020, 0.094] | [-0.050, 0.038] | 0.003 | 0.526 | 0.284 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only + same-file context, no SAST | +0.062 [0.029, 0.102] | [-0.041, 0.046] | 0.00056 | 0.520 | 0.376 | 1.000 | 1.33 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.058 [0.016, 0.099] | [-0.048, 0.041] | 0.003 | 0.520 | 0.376 | 1.000 | 1.37 | 0.067 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.106, -0.038] | 0.667 [0.667, 0.667] | 0.323 |
| Semgrep + Bandit + AST Gate | 0.559 | 0.295 | 0.233 | 0.531 | 0.071 [0.038, 0.106] | — | 0.386 [0.337, 0.432] | — |
| Semgrep alone | 0.621 | 0.102 | 0.062 | 0.520 | 0.073 [0.036, 0.116] | [-0.041, 0.046] | 0.176 [0.124, 0.240] | 0.507 |
| Bandit alone | 0.562 | 0.205 | 0.160 | 0.522 | 0.058 [0.023, 0.097] | [-0.045, 0.019] | 0.300 [0.238, 0.356] | 0.457 |
| AST sink gate alone | 0.553 | 0.117 | 0.095 | 0.511 | 0.036 [0.000, 0.076] | [-0.073, 0.005] | 0.194 [0.137, 0.254] | 0.181 |
| CodeQL alone | 0.750 | 0.060 | 0.020 | 0.520 | 0.102 [0.052, 0.159] | [-0.020, 0.087] | 0.111 [0.064, 0.173] | 0.550 |
| SAST board: Judge vote | 0.620 | 0.220 | 0.135 | 0.542 | 0.111 [0.070, 0.159] | [0.009, 0.074] | 0.325 [0.266, 0.388] | 0.336 |
| SAST board + evidence override (ablation) | 0.583 | 0.273 | 0.195 | 0.539 | 0.092 [0.057, 0.131] | [-0.001, 0.048] | 0.371 [0.320, 0.422] | 0.307 |
| SAST board: vote score, dev-tuned threshold | 0.617 | 0.217 | 0.135 | 0.541 | 0.108 [0.066, 0.157] | [0.006, 0.071] | 0.322 [0.263, 0.384] | 0.403 |
| SAST board + fusion (ablation, trained on dev) | 0.690 | 0.172 | 0.077 | 0.547 | 0.144 [0.089, 0.200] | [0.021, 0.127] | 0.276 [0.202, 0.347] | 0.255 |
| LLM only, whole function, no SAST | 0.557 | 0.268 | 0.212 | 0.527 | 0.064 [0.024, 0.108] | [-0.057, 0.046] | 0.361 [0.302, 0.419] | 0.884 |
| LLM only, dev-tuned threshold | 0.557 | 0.268 | 0.212 | 0.527 | 0.064 [0.024, 0.108] | [-0.057, 0.046] | 0.361 [0.302, 0.419] | 0.884 |
| LLM only + same-file context, no SAST | 0.571 | 0.253 | 0.190 | 0.531 | 0.075 [0.036, 0.122] | [-0.045, 0.057] | 0.350 [0.291, 0.412] | 1.000 |
| LLM only + context, dev-tuned threshold | 0.577 | 0.215 | 0.158 | 0.529 | 0.074 [0.021, 0.124] | [-0.049, 0.057] | 0.313 [0.250, 0.378] | 0.942 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 118 | 0 |
| SAST board (LLM only where static analysis flagged) | 211 | 962.7 | 87 | 8,853 |
| LLM only, whole function, no SAST | 800 | 972.9 | 107 | 7,274 |
| LLM only + same-file context, no SAST | 800 | 1,175.1 | 86 | 10,931 |


**On functions static analysis flagged** (211: 118 vulnerable, 93 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.559 | 1.000 | 1.000 | 0.000 | 0.717 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.559 | 1.000 | 1.000 | 0.000 | 0.717 | — | — |
| Semgrep alone | 0.621 | 0.347 | 0.269 | 0.084 | 0.446 | 73.1% | 34.8% |
| Bandit alone | 0.562 | 0.695 | 0.688 | 0.007 | 0.621 | 31.2% | 69.5% |
| AST sink gate alone | 0.553 | 0.398 | 0.409 | -0.010 | 0.463 | 59.1% | 39.8% |
| CodeQL alone | 0.750 | 0.203 | 0.086 | 0.163 | 0.320 | 91.4% | 20.3% |
| SAST board: Judge vote | 0.620 | 0.746 | 0.581 | 0.175 | 0.677 | 41.9% | 74.6% |
| SAST board + evidence override (ablation) | 0.583 | 0.924 | 0.839 | 0.133 | 0.715 | 16.1% | 92.4% |
| SAST board: vote score, dev-tuned threshold | 0.617 | 0.737 | 0.581 | 0.165 | 0.672 | 41.9% | 73.7% |
| SAST board + fusion (ablation, trained on dev) | 0.690 | 0.585 | 0.333 | 0.250 | 0.633 | 66.7% | 58.5% |
| LLM only, whole function, no SAST | 0.611 | 0.559 | 0.452 | 0.107 | 0.584 | 54.8% | 55.9% |
| LLM only, dev-tuned threshold | 0.611 | 0.559 | 0.452 | 0.107 | 0.584 | 54.8% | 55.9% |
| LLM only + same-file context, no SAST | 0.631 | 0.551 | 0.409 | 0.141 | 0.588 | 59.1% | 55.1% |
| LLM only + context, dev-tuned threshold | 0.663 | 0.483 | 0.312 | 0.173 | 0.559 | 68.8% | 48.3% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 400 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 400 | 0.080 [0.053, 0.111] | 0.215 | 0.688 | 0.018 | 0.098 | 0.821 |
| Semgrep alone | 400 | 0.043 [0.020, 0.067] | 0.060 | 0.895 | 0.003 | 0.045 | 0.944 |
| Bandit alone | 400 | 0.055 [0.031, 0.083] | 0.150 | 0.785 | 0.010 | 0.065 | 0.846 |
| AST sink gate alone | 400 | 0.035 [0.018, 0.055] | 0.083 | 0.870 | 0.013 | 0.048 | 0.737 |
| CodeQL alone | 400 | 0.040 [0.017, 0.071] | 0.020 | 0.940 | 0.000 | 0.040 | 1.000 |
| SAST board: Judge vote | 400 | 0.100 [0.069, 0.136] | 0.120 | 0.765 | 0.015 | 0.115 | 0.870 |
| SAST board + evidence override (ablation) | 400 | 0.098 [0.069, 0.130] | 0.175 | 0.708 | 0.020 | 0.117 | 0.830 |
| SAST board: vote score, dev-tuned threshold | 400 | 0.100 [0.069, 0.136] | 0.117 | 0.765 | 0.018 | 0.117 | 0.851 |
| SAST board + fusion (ablation, trained on dev) | 400 | 0.107 [0.070, 0.151] | 0.065 | 0.815 | 0.013 | 0.120 | 0.896 |
| LLM only, whole function, no SAST | 400 | 0.077 [0.048, 0.110] | 0.190 | 0.710 | 0.022 | 0.100 | 0.775 |
| LLM only, dev-tuned threshold | 400 | 0.077 [0.048, 0.110] | 0.190 | 0.710 | 0.022 | 0.100 | 0.775 |
| LLM only + same-file context, no SAST | 400 | 0.080 [0.049, 0.118] | 0.172 | 0.730 | 0.018 | 0.098 | 0.821 |
| LLM only + context, dev-tuned threshold | 400 | 0.085 [0.056, 0.120] | 0.130 | 0.757 | 0.028 | 0.113 | 0.756 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.998 | 0.998 |
| SAST board + fusion (ablation, trained on dev) | 0.983 | 0.882 |
| LLM only, whole function, no SAST | 1.000 | 0.988 |
| LLM only, dev-tuned threshold | 1.000 | 0.988 |
| LLM only + same-file context, no SAST | 1.000 | 0.990 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.990 |

### reposvul — 804 functions, 402 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.120, -0.050] | 1.000 | — | — | 0.160 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.085 [0.050, 0.120] | — | 5.1e-07 | 0.542 | 3.4e-07 | — | 1.31 | 0.065 / 0.013 |
| Semgrep alone | +0.060 [0.030, 0.093] | [-0.062, 0.011] | 6.4e-06 | — | — | 1.000 | 1.89 | 0.090 / 0.019 |
| Bandit alone | +0.065 [0.035, 0.098] | [-0.044, 0.003] | 3.7e-05 | — | — | 1.000 | 1.41 | 0.069 / 0.014 |
| AST sink gate alone | +0.055 [0.028, 0.083] | [-0.068, 0.008] | 5.2e-05 | — | — | 1.000 | 1.49 | 0.073 / 0.015 |
| CodeQL alone | +0.052 [0.028, 0.081] | [-0.069, 0.006] | 6.7e-06 | — | — | 1.000 | 2.05 | 0.097 / 0.020 |
| SAST board: Judge vote | +0.124 [0.080, 0.175] | [0.005, 0.079] | 4.3e-09 | 0.565 | 4.3e-09 | 0.970 | 1.83 | 0.088 / 0.018 |
| SAST board + evidence override (ablation) | +0.114 [0.076, 0.160] | [0.005, 0.059] | 3.8e-09 | — | — | 0.348 | 1.51 | 0.074 / 0.015 |
| SAST board: vote score, dev-tuned threshold | +0.127 [0.082, 0.177] | [0.007, 0.080] | 1.3e-09 | 0.565 | 3.4e-07 | 0.863 | 1.86 | 0.089 / 0.018 |
| SAST board + fusion (ablation, trained on dev) | +0.110 [0.065, 0.159] | [-0.013, 0.063] | 2.4e-08 | 0.587 | 7.3e-09 | 1.000 | 2.10 | 0.100 / 0.021 |
| LLM only, whole function, no SAST | +0.055 [0.016, 0.090] | [-0.081, 0.011] | 0.001 | 0.516 | 1.000 | 1.000 | 1.22 | 0.060 / 0.012 |
| LLM only, dev-tuned threshold | +0.057 [0.018, 0.094] | [-0.079, 0.015] | 0.001 | 0.516 | 1.000 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only + same-file context, no SAST | +0.065 [0.026, 0.105] | [-0.066, 0.025] | 0.00092 | 0.509 | 1.000 | 1.000 | 1.27 | 0.062 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.080 [0.041, 0.121] | [-0.047, 0.038] | 0.00017 | 0.509 | 1.000 | 1.000 | 1.41 | 0.069 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.131, -0.053] | 0.667 [0.667, 0.667] | 0.160 |
| Semgrep + Bandit + AST Gate | 0.568 | 0.356 | 0.271 | 0.542 | 0.091 [0.053, 0.131] | — | 0.437 [0.393, 0.478] | — |
| Semgrep alone | 0.654 | 0.127 | 0.067 | 0.530 | 0.101 [0.054, 0.151] | [-0.040, 0.060] | 0.212 [0.160, 0.267] | 0.495 |
| Bandit alone | 0.584 | 0.224 | 0.159 | 0.532 | 0.082 [0.044, 0.122] | [-0.035, 0.018] | 0.324 [0.275, 0.369] | 0.480 |
| AST sink gate alone | 0.598 | 0.167 | 0.112 | 0.527 | 0.079 [0.042, 0.116] | [-0.056, 0.032] | 0.261 [0.204, 0.318] | 0.353 |
| CodeQL alone | 0.672 | 0.102 | 0.050 | 0.526 | 0.099 [0.054, 0.144] | [-0.039, 0.058] | 0.177 [0.120, 0.240] | 0.385 |
| SAST board: Judge vote | 0.647 | 0.274 | 0.149 | 0.562 | 0.152 [0.098, 0.206] | [0.021, 0.105] | 0.385 [0.325, 0.444] | 0.097 |
| SAST board + evidence override (ablation) | 0.602 | 0.338 | 0.224 | 0.557 | 0.127 [0.086, 0.175] | [0.009, 0.069] | 0.433 [0.385, 0.482] | 0.029 |
| SAST board: vote score, dev-tuned threshold | 0.651 | 0.274 | 0.147 | 0.563 | 0.156 [0.102, 0.209] | [0.024, 0.107] | 0.385 [0.326, 0.444] | 0.078 |
| SAST board + fusion (ablation, trained on dev) | 0.677 | 0.209 | 0.100 | 0.555 | 0.151 [0.095, 0.211] | [0.012, 0.108] | 0.319 [0.254, 0.387] | 0.426 |
| LLM only, whole function, no SAST | 0.549 | 0.308 | 0.254 | 0.527 | 0.061 [0.018, 0.102] | [-0.087, 0.016] | 0.395 [0.339, 0.445] | 0.437 |
| LLM only, dev-tuned threshold | 0.551 | 0.311 | 0.254 | 0.529 | 0.064 [0.020, 0.105] | [-0.085, 0.020] | 0.398 [0.341, 0.448] | 0.481 |
| LLM only + same-file context, no SAST | 0.559 | 0.308 | 0.244 | 0.532 | 0.072 [0.029, 0.118] | [-0.072, 0.030] | 0.397 [0.343, 0.450] | 0.629 |
| LLM only + context, dev-tuned threshold | 0.584 | 0.276 | 0.197 | 0.540 | 0.094 [0.048, 0.140] | [-0.046, 0.051] | 0.375 [0.317, 0.430] | 0.946 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 143 | 0 |
| SAST board (LLM only where static analysis flagged) | 252 | 1,172.5 | 110 | 8,570 |
| LLM only, whole function, no SAST | 804 | 1,037.0 | 125 | 6,670 |
| LLM only + same-file context, no SAST | 804 | 1,246.3 | 111 | 9,027 |


**On functions static analysis flagged** (252: 143 vulnerable, 109 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.568 | 1.000 | 1.000 | 0.000 | 0.724 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.568 | 1.000 | 1.000 | 0.000 | 0.724 | — | — |
| Semgrep alone | 0.654 | 0.357 | 0.248 | 0.117 | 0.462 | 75.2% | 35.7% |
| Bandit alone | 0.584 | 0.629 | 0.587 | 0.043 | 0.606 | 41.3% | 62.9% |
| AST sink gate alone | 0.598 | 0.469 | 0.413 | 0.056 | 0.525 | 58.7% | 46.9% |
| CodeQL alone | 0.672 | 0.287 | 0.183 | 0.119 | 0.402 | 81.7% | 28.7% |
| SAST board: Judge vote | 0.647 | 0.769 | 0.550 | 0.231 | 0.703 | 45.0% | 76.9% |
| SAST board + evidence override (ablation) | 0.602 | 0.951 | 0.826 | 0.204 | 0.737 | 17.4% | 95.1% |
| SAST board: vote score, dev-tuned threshold | 0.651 | 0.769 | 0.541 | 0.240 | 0.705 | 45.9% | 76.9% |
| SAST board + fusion (ablation, trained on dev) | 0.677 | 0.587 | 0.367 | 0.218 | 0.629 | 63.3% | 58.7% |
| LLM only, whole function, no SAST | 0.626 | 0.608 | 0.477 | 0.131 | 0.617 | 52.3% | 60.8% |
| LLM only, dev-tuned threshold | 0.626 | 0.608 | 0.477 | 0.131 | 0.617 | 52.3% | 60.8% |
| LLM only + same-file context, no SAST | 0.644 | 0.594 | 0.431 | 0.162 | 0.618 | 56.9% | 59.4% |
| LLM only + context, dev-tuned threshold | 0.684 | 0.545 | 0.330 | 0.214 | 0.607 | 67.0% | 54.5% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 402 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 402 | 0.095 [0.062, 0.130] | 0.261 | 0.634 | 0.010 | 0.104 | 0.905 |
| Semgrep alone | 402 | 0.062 [0.035, 0.096] | 0.065 | 0.871 | 0.003 | 0.065 | 0.962 |
| Bandit alone | 402 | 0.075 [0.047, 0.107] | 0.149 | 0.766 | 0.010 | 0.085 | 0.882 |
| AST sink gate alone | 402 | 0.060 [0.035, 0.087] | 0.107 | 0.828 | 0.005 | 0.065 | 0.923 |
| CodeQL alone | 402 | 0.052 [0.028, 0.081] | 0.050 | 0.898 | 0.000 | 0.052 | 1.000 |
| SAST board: Judge vote | 402 | 0.147 [0.106, 0.193] | 0.127 | 0.704 | 0.022 | 0.169 | 0.868 |
| SAST board + evidence override (ablation) | 402 | 0.129 [0.092, 0.173] | 0.209 | 0.647 | 0.015 | 0.144 | 0.897 |
| SAST board: vote score, dev-tuned threshold | 402 | 0.147 [0.106, 0.193] | 0.127 | 0.707 | 0.020 | 0.167 | 0.881 |
| SAST board + fusion (ablation, trained on dev) | 402 | 0.127 [0.087, 0.172] | 0.082 | 0.774 | 0.017 | 0.144 | 0.879 |
| LLM only, whole function, no SAST | 402 | 0.080 [0.050, 0.110] | 0.229 | 0.667 | 0.025 | 0.104 | 0.762 |
| LLM only, dev-tuned threshold | 402 | 0.082 [0.052, 0.113] | 0.229 | 0.664 | 0.025 | 0.107 | 0.767 |
| LLM only + same-file context, no SAST | 402 | 0.095 [0.064, 0.127] | 0.214 | 0.662 | 0.030 | 0.124 | 0.760 |
| LLM only + context, dev-tuned threshold | 402 | 0.114 [0.084, 0.150] | 0.162 | 0.689 | 0.035 | 0.149 | 0.767 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.998 | 0.998 |
| SAST board + fusion (ablation, trained on dev) | 0.965 | 0.871 |
| LLM only, whole function, no SAST | 1.000 | 0.985 |
| LLM only, dev-tuned threshold | 1.000 | 0.985 |
| LLM only + same-file context, no SAST | 0.985 | 0.985 |
| LLM only + context, dev-tuned threshold | 0.985 | 0.985 |

### vudenc — 400 functions, 200 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.131, -0.011] | 1.000 | — | — | 0.479 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.065 [0.011, 0.131] | — | 0.009 | 0.532 | 0.014 | — | 1.26 | 0.062 / 0.013 |
| Semgrep alone | +0.025 [-0.010, 0.064] | [-0.107, 0.021] | 0.453 | — | — | 1.000 | 1.42 | 0.069 / 0.014 |
| Bandit alone | +0.060 [0.006, 0.126] | [-0.023, 0.011] | 0.013 | — | — | 1.000 | 1.32 | 0.065 / 0.013 |
| AST sink gate alone | +0.055 [0.015, 0.104] | [-0.063, 0.034] | 0.005 | — | — | 1.000 | 1.48 | 0.072 / 0.015 |
| CodeQL alone | +0.010 [-0.006, 0.031] | [-0.117, -0.000] | 0.625 | — | — | 1.000 | 1.20 | 0.059 / 0.012 |
| SAST board: Judge vote | +0.100 [0.043, 0.171] | [0.005, 0.065] | 0.002 | 0.547 | 0.004 | 1.000 | 1.59 | 0.077 / 0.016 |
| SAST board + evidence override (ablation) | +0.090 [0.034, 0.157] | [0.000, 0.049] | 0.002 | — | — | 1.000 | 1.41 | 0.069 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.100 [0.043, 0.172] | [0.005, 0.067] | 0.002 | 0.547 | 0.022 | 1.000 | 1.61 | 0.078 / 0.016 |
| SAST board + fusion (ablation, trained on dev) | +0.125 [0.059, 0.201] | [0.015, 0.107] | 6e-05 | 0.573 | 0.002 | 0.783 | 1.96 | 0.094 / 0.019 |
| LLM only, whole function, no SAST | +0.105 [0.041, 0.176] | [-0.009, 0.089] | 0.002 | 0.547 | 0.070 | 1.000 | 1.38 | 0.068 / 0.014 |
| LLM only, dev-tuned threshold | +0.105 [0.041, 0.176] | [-0.009, 0.089] | 0.002 | 0.547 | 0.070 | 1.000 | 1.38 | 0.068 / 0.014 |
| LLM only + same-file context, no SAST | +0.100 [0.045, 0.165] | [0.000, 0.070] | 0.00039 | 0.545 | 0.070 | 1.000 | 1.38 | 0.068 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.110 [0.053, 0.174] | [0.005, 0.084] | 0.00013 | 0.545 | 0.070 | 1.000 | 1.45 | 0.071 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.143, -0.013] | 0.667 [0.667, 0.667] | 0.479 |
| Semgrep + Bandit + AST Gate | 0.557 | 0.315 | 0.250 | 0.532 | 0.072 [0.013, 0.143] | — | 0.403 [0.328, 0.476] | — |
| Semgrep alone | 0.586 | 0.085 | 0.060 | 0.512 | 0.048 [-0.020, 0.125] | [-0.115, 0.067] | 0.148 [0.077, 0.226] | 0.445 |
| Bandit alone | 0.568 | 0.250 | 0.190 | 0.530 | 0.072 [0.007, 0.147] | [-0.021, 0.021] | 0.347 [0.260, 0.429] | 1.000 |
| AST sink gate alone | 0.597 | 0.170 | 0.115 | 0.527 | 0.079 [0.023, 0.147] | [-0.052, 0.058] | 0.265 [0.172, 0.350] | 0.894 |
| CodeQL alone | 0.545 | 0.060 | 0.050 | 0.505 | 0.022 [-0.019, 0.068] | [-0.126, 0.017] | 0.108 [0.039, 0.186] | 0.294 |
| SAST board: Judge vote | 0.614 | 0.270 | 0.170 | 0.550 | 0.121 [0.054, 0.201] | [0.012, 0.085] | 0.375 [0.285, 0.461] | 0.230 |
| SAST board + evidence override (ablation) | 0.585 | 0.310 | 0.220 | 0.545 | 0.102 [0.038, 0.176] | [0.002, 0.056] | 0.405 [0.328, 0.483] | 0.125 |
| SAST board: vote score, dev-tuned threshold | 0.616 | 0.265 | 0.165 | 0.550 | 0.122 [0.054, 0.202] | [0.012, 0.088] | 0.371 [0.281, 0.458] | 0.248 |
| SAST board + fusion (ablation, trained on dev) | 0.662 | 0.255 | 0.130 | 0.562 | 0.159 [0.077, 0.243] | [0.031, 0.141] | 0.368 [0.270, 0.462] | 0.065 |
| LLM only, whole function, no SAST | 0.579 | 0.385 | 0.280 | 0.552 | 0.111 [0.044, 0.186] | [-0.014, 0.092] | 0.463 [0.386, 0.534] | 0.403 |
| LLM only, dev-tuned threshold | 0.579 | 0.385 | 0.280 | 0.552 | 0.111 [0.044, 0.186] | [-0.014, 0.092] | 0.463 [0.386, 0.534] | 0.403 |
| LLM only + same-file context, no SAST | 0.579 | 0.365 | 0.265 | 0.550 | 0.108 [0.049, 0.174] | [-0.005, 0.074] | 0.448 [0.378, 0.521] | 0.477 |
| LLM only + context, dev-tuned threshold | 0.592 | 0.355 | 0.245 | 0.555 | 0.120 [0.059, 0.186] | [0.004, 0.091] | 0.444 [0.372, 0.522] | 0.356 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 63 | 0 |
| SAST board (LLM only where static analysis flagged) | 113 | 984.1 | 53 | 7,427 |
| LLM only, whole function, no SAST | 400 | 859.0 | 77 | 4,463 |
| LLM only + same-file context, no SAST | 400 | 1,040.1 | 71 | 5,860 |


**On functions static analysis flagged** (113: 63 vulnerable, 50 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.557 | 1.000 | 1.000 | 0.000 | 0.716 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.557 | 1.000 | 1.000 | 0.000 | 0.716 | — | — |
| Semgrep alone | 0.586 | 0.270 | 0.240 | 0.034 | 0.370 | 76.0% | 27.0% |
| Bandit alone | 0.568 | 0.794 | 0.760 | 0.040 | 0.662 | 24.0% | 79.4% |
| AST sink gate alone | 0.597 | 0.540 | 0.460 | 0.079 | 0.567 | 54.0% | 54.0% |
| CodeQL alone | 0.545 | 0.191 | 0.200 | -0.012 | 0.282 | 80.0% | 19.1% |
| SAST board: Judge vote | 0.614 | 0.857 | 0.680 | 0.212 | 0.715 | 32.0% | 85.7% |
| SAST board + evidence override (ablation) | 0.585 | 0.984 | 0.880 | 0.214 | 0.734 | 12.0% | 98.4% |
| SAST board: vote score, dev-tuned threshold | 0.616 | 0.841 | 0.660 | 0.211 | 0.711 | 34.0% | 84.1% |
| SAST board + fusion (ablation, trained on dev) | 0.662 | 0.809 | 0.520 | 0.309 | 0.729 | 48.0% | 81.0% |
| LLM only, whole function, no SAST | 0.591 | 0.825 | 0.720 | 0.126 | 0.689 | 28.0% | 82.5% |
| LLM only, dev-tuned threshold | 0.591 | 0.825 | 0.720 | 0.126 | 0.689 | 28.0% | 82.5% |
| LLM only + same-file context, no SAST | 0.583 | 0.778 | 0.700 | 0.088 | 0.667 | 30.0% | 77.8% |
| LLM only + context, dev-tuned threshold | 0.608 | 0.762 | 0.620 | 0.154 | 0.676 | 38.0% | 76.2% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 200 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 200 | 0.075 [0.025, 0.137] | 0.240 | 0.675 | 0.010 | 0.085 | 0.882 |
| Semgrep alone | 200 | 0.040 [0.015, 0.072] | 0.045 | 0.900 | 0.015 | 0.055 | 0.727 |
| Bandit alone | 200 | 0.070 [0.019, 0.133] | 0.180 | 0.740 | 0.010 | 0.080 | 0.875 |
| AST sink gate alone | 200 | 0.055 [0.015, 0.104] | 0.115 | 0.830 | 0.000 | 0.055 | 1.000 |
| CodeQL alone | 200 | 0.015 [0.000, 0.035] | 0.045 | 0.935 | 0.005 | 0.020 | 0.750 |
| SAST board: Judge vote | 200 | 0.120 [0.065, 0.190] | 0.150 | 0.710 | 0.020 | 0.140 | 0.857 |
| SAST board + evidence override (ablation) | 200 | 0.105 [0.051, 0.172] | 0.205 | 0.675 | 0.015 | 0.120 | 0.875 |
| SAST board: vote score, dev-tuned threshold | 200 | 0.120 [0.065, 0.190] | 0.145 | 0.715 | 0.020 | 0.140 | 0.857 |
| SAST board + fusion (ablation, trained on dev) | 200 | 0.140 [0.077, 0.216] | 0.115 | 0.730 | 0.015 | 0.155 | 0.903 |
| LLM only, whole function, no SAST | 200 | 0.135 [0.080, 0.200] | 0.250 | 0.585 | 0.030 | 0.165 | 0.818 |
| LLM only, dev-tuned threshold | 200 | 0.135 [0.080, 0.200] | 0.250 | 0.585 | 0.030 | 0.165 | 0.818 |
| LLM only + same-file context, no SAST | 200 | 0.110 [0.056, 0.174] | 0.255 | 0.625 | 0.010 | 0.120 | 0.917 |
| LLM only + context, dev-tuned threshold | 200 | 0.120 [0.066, 0.185] | 0.235 | 0.635 | 0.010 | 0.130 | 0.923 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.995 | 0.995 |
| SAST board + fusion (ablation, trained on dev) | 1.000 | 0.880 |
| LLM only, whole function, no SAST | 1.000 | 0.980 |
| LLM only, dev-tuned threshold | 1.000 | 0.980 |
| LLM only + same-file context, no SAST | 1.000 | 0.980 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.980 |

### combined — 2004 functions, 1002 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.096, -0.049] | 1.000 | — | — | 0.060 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.072 [0.049, 0.096] | — | 3.6e-13 | 0.536 | 2e-13 | — | 1.29 | 0.063 / 0.013 |
| Semgrep alone | +0.045 [0.028, 0.065] | [-0.050, -0.006] | 8.5e-10 | — | — | 1.000 | 1.70 | 0.082 / 0.017 |
| Bandit alone | +0.056 [0.035, 0.079] | [-0.030, -0.003] | 1.8e-10 | — | — | 1.000 | 1.34 | 0.066 / 0.013 |
| AST sink gate alone | +0.042 [0.025, 0.061] | [-0.052, -0.010] | 7.5e-09 | — | — | 0.847 | 1.40 | 0.069 / 0.014 |
| CodeQL alone | +0.039 [0.024, 0.056] | [-0.056, -0.011] | 1.9e-10 | — | — | 0.952 | 2.03 | 0.096 / 0.020 |
| SAST board: Judge vote | +0.104 [0.077, 0.131] | [0.014, 0.050] | 9.3e-19 | 0.554 | 1.4e-18 | 0.211 | 1.70 | 0.082 / 0.017 |
| SAST board + evidence override (ablation) | +0.095 [0.071, 0.120] | [0.010, 0.037] | 2.4e-17 | — | — | 0.038 | 1.45 | 0.071 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.104 [0.077, 0.131] | [0.014, 0.050] | 9.3e-19 | 0.557 | 1.4e-14 | 0.211 | 1.71 | 0.083 / 0.017 |
| SAST board + fusion (ablation, trained on dev) | +0.107 [0.079, 0.136] | [0.011, 0.058] | 6.6e-21 | 0.577 | 3.5e-18 | 0.361 | 2.10 | 0.100 / 0.021 |
| LLM only, whole function, no SAST | +0.065 [0.042, 0.091] | [-0.035, 0.021] | 1.7e-09 | 0.526 | 0.011 | 1.000 | 1.27 | 0.062 / 0.013 |
| LLM only, dev-tuned threshold | +0.066 [0.043, 0.091] | [-0.034, 0.021] | 1.6e-09 | 0.526 | 0.011 | 1.000 | 1.27 | 0.063 / 0.013 |
| LLM only + same-file context, no SAST | +0.071 [0.046, 0.095] | [-0.029, 0.024] | 6.1e-11 | 0.520 | 0.050 | 1.000 | 1.31 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.077 [0.052, 0.102] | [-0.021, 0.030] | 5.9e-11 | 0.520 | 0.050 | 1.000 | 1.40 | 0.069 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.107, -0.054] | 0.667 [0.667, 0.667] | 0.060 |
| Semgrep + Bandit + AST Gate | 0.562 | 0.323 | 0.252 | 0.536 | 0.079 [0.054, 0.107] | — | 0.411 [0.382, 0.439] | — |
| Semgrep alone | 0.630 | 0.109 | 0.064 | 0.522 | 0.080 [0.051, 0.112] | [-0.030, 0.033] | 0.185 [0.149, 0.224] | 0.195 |
| Bandit alone | 0.572 | 0.222 | 0.166 | 0.528 | 0.071 [0.045, 0.101] | [-0.025, 0.008] | 0.319 [0.285, 0.353] | 0.274 |
| AST sink gate alone | 0.583 | 0.148 | 0.106 | 0.521 | 0.063 [0.039, 0.091] | [-0.043, 0.010] | 0.236 [0.203, 0.269] | 0.106 |
| CodeQL alone | 0.670 | 0.077 | 0.038 | 0.519 | 0.084 [0.054, 0.116] | [-0.029, 0.035] | 0.138 [0.104, 0.176] | 0.136 |
| SAST board: Judge vote | 0.630 | 0.252 | 0.148 | 0.552 | 0.130 [0.097, 0.161] | [0.028, 0.073] | 0.359 [0.323, 0.393] | 0.019 |
| SAST board + evidence override (ablation) | 0.592 | 0.306 | 0.212 | 0.547 | 0.108 [0.082, 0.135] | [0.014, 0.044] | 0.404 [0.372, 0.434] | 0.003 |
| SAST board: vote score, dev-tuned threshold | 0.631 | 0.249 | 0.146 | 0.552 | 0.130 [0.098, 0.162] | [0.028, 0.073] | 0.358 [0.322, 0.393] | 0.021 |
| SAST board + fusion (ablation, trained on dev) | 0.678 | 0.204 | 0.097 | 0.553 | 0.149 [0.114, 0.186] | [0.040, 0.098] | 0.313 [0.271, 0.354] | 0.040 |
| LLM only, whole function, no SAST | 0.559 | 0.307 | 0.242 | 0.532 | 0.073 [0.048, 0.102] | [-0.039, 0.024] | 0.397 [0.363, 0.428] | 0.779 |
| LLM only, dev-tuned threshold | 0.560 | 0.308 | 0.242 | 0.533 | 0.074 [0.049, 0.102] | [-0.038, 0.024] | 0.398 [0.364, 0.428] | 0.815 |
| LLM only + same-file context, no SAST | 0.568 | 0.297 | 0.227 | 0.535 | 0.081 [0.053, 0.108] | [-0.030, 0.029] | 0.390 [0.354, 0.424] | 1.000 |
| LLM only + context, dev-tuned threshold | 0.584 | 0.268 | 0.191 | 0.538 | 0.091 [0.062, 0.120] | [-0.019, 0.041] | 0.367 [0.329, 0.403] | 0.855 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 324 | 0 |
| SAST board (LLM only where static analysis flagged) | 576 | 1,051.2 | 250 | 8,426 |
| LLM only, whole function, no SAST | 2004 | 975.9 | 309 | 6,329 |
| LLM only + same-file context, no SAST | 2004 | 1,176.7 | 268 | 8,799 |


**On functions static analysis flagged** (576: 324 vulnerable, 252 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.562 | 1.000 | 1.000 | 0.000 | 0.720 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.562 | 1.000 | 1.000 | 0.000 | 0.720 | — | — |
| Semgrep alone | 0.630 | 0.336 | 0.254 | 0.089 | 0.439 | 74.6% | 33.6% |
| Bandit alone | 0.572 | 0.685 | 0.659 | 0.028 | 0.624 | 34.1% | 68.5% |
| AST sink gate alone | 0.583 | 0.457 | 0.421 | 0.036 | 0.512 | 57.9% | 45.7% |
| CodeQL alone | 0.670 | 0.238 | 0.151 | 0.108 | 0.351 | 84.9% | 23.8% |
| SAST board: Judge vote | 0.630 | 0.778 | 0.587 | 0.205 | 0.696 | 41.3% | 77.8% |
| SAST board + evidence override (ablation) | 0.592 | 0.948 | 0.841 | 0.176 | 0.728 | 15.9% | 94.8% |
| SAST board: vote score, dev-tuned threshold | 0.631 | 0.772 | 0.579 | 0.206 | 0.694 | 42.1% | 77.2% |
| SAST board + fusion (ablation, trained on dev) | 0.678 | 0.630 | 0.385 | 0.243 | 0.653 | 61.5% | 63.0% |
| LLM only, whole function, no SAST | 0.612 | 0.633 | 0.516 | 0.117 | 0.622 | 48.4% | 63.3% |
| LLM only, dev-tuned threshold | 0.612 | 0.633 | 0.516 | 0.117 | 0.622 | 48.4% | 63.3% |
| LLM only + same-file context, no SAST | 0.624 | 0.614 | 0.476 | 0.138 | 0.619 | 52.4% | 61.4% |
| LLM only + context, dev-tuned threshold | 0.656 | 0.565 | 0.381 | 0.182 | 0.607 | 61.9% | 56.5% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 1002 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 1002 | 0.085 [0.064, 0.108] | 0.238 | 0.664 | 0.013 | 0.098 | 0.867 |
| Semgrep alone | 1002 | 0.050 [0.033, 0.069] | 0.059 | 0.886 | 0.005 | 0.055 | 0.909 |
| Bandit alone | 1002 | 0.066 [0.047, 0.087] | 0.156 | 0.768 | 0.010 | 0.076 | 0.868 |
| AST sink gate alone | 1002 | 0.049 [0.034, 0.067] | 0.099 | 0.845 | 0.007 | 0.056 | 0.875 |
| CodeQL alone | 1002 | 0.040 [0.025, 0.057] | 0.037 | 0.922 | 0.001 | 0.041 | 0.976 |
| SAST board: Judge vote | 1002 | 0.123 [0.098, 0.147] | 0.129 | 0.730 | 0.019 | 0.142 | 0.866 |
| SAST board + evidence override (ablation) | 1002 | 0.112 [0.090, 0.135] | 0.195 | 0.677 | 0.017 | 0.129 | 0.868 |
| SAST board: vote score, dev-tuned threshold | 1002 | 0.123 [0.098, 0.147] | 0.127 | 0.732 | 0.019 | 0.142 | 0.866 |
| SAST board + fusion (ablation, trained on dev) | 1002 | 0.122 [0.097, 0.150] | 0.082 | 0.781 | 0.015 | 0.137 | 0.890 |
| LLM only, whole function, no SAST | 1002 | 0.090 [0.070, 0.113] | 0.218 | 0.668 | 0.025 | 0.115 | 0.783 |
| LLM only, dev-tuned threshold | 1002 | 0.091 [0.071, 0.113] | 0.218 | 0.667 | 0.025 | 0.116 | 0.784 |
| LLM only + same-file context, no SAST | 1002 | 0.092 [0.072, 0.114] | 0.206 | 0.682 | 0.021 | 0.113 | 0.814 |
| LLM only + context, dev-tuned threshold | 1002 | 0.104 [0.084, 0.125] | 0.164 | 0.706 | 0.027 | 0.131 | 0.794 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.997 | 0.997 |
| SAST board + fusion (ablation, trained on dev) | 0.984 | 0.878 |
| LLM only, whole function, no SAST | 1.000 | 0.985 |
| LLM only, dev-tuned threshold | 1.000 | 0.985 |
| LLM only + same-file context, no SAST | 1.000 | 0.986 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.986 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | sast MCC / R | semgrep MCC / R | bandit MCC / R | board MCC / R | board_calibrated MCC / R | fusion MCC / R | llm_only_calibrated MCC / R | llm_context_calibrated MCC / R |
|---|---|---|---|---|---|---|---|---|---|---|
| **logic_semantic** | 916 | 18.3% | 0.020 / 0.183 | 0.018 / 0.037 | 0.017 / 0.129 | 0.035 / 0.096 | 0.031 / 0.094 | 0.046 / 0.070 | 0.031 / 0.124 | 0.027 / 0.096 |
| **sast_reachable** | 1088 | 44.1% | 0.123 / 0.441 | 0.115 / 0.169 | 0.108 / 0.300 | 0.192 / 0.382 | 0.194 / 0.381 | 0.213 / 0.316 | 0.106 / 0.463 | 0.135 / 0.412 |
| injection | 600 | 46.7% | 0.147 / 0.467 | 0.124 / 0.200 | 0.132 / 0.383 | 0.211 / 0.417 | 0.216 / 0.413 | 0.221 / 0.353 | 0.087 / 0.507 | 0.133 / 0.460 |
| access_control (logic) | 306 | 18.9% | 0.017 / 0.190 | 0.018 / 0.039 | 0.019 / 0.137 | 0.032 / 0.118 | 0.032 / 0.118 | 0.062 / 0.091 | 0.000 / 0.131 | -0.021 / 0.105 |
| path_traversal | 190 | 36.8% | 0.078 / 0.368 | 0.074 / 0.063 | 0.078 / 0.158 | 0.203 / 0.305 | 0.203 / 0.305 | 0.242 / 0.253 | 0.218 / 0.400 | 0.189 / 0.305 |
| info_exposure (logic) | 168 | 20.2% | 0.046 / 0.202 | 0.000 / 0.059 | 0.038 / 0.119 | -0.037 / 0.107 | -0.056 / 0.095 | -0.022 / 0.071 | 0.067 / 0.095 | 0.105 / 0.048 |
| ssrf_redirect | 152 | 36.8% | 0.084 / 0.368 | 0.072 / 0.184 | -0.022 / 0.092 | 0.136 / 0.316 | 0.136 / 0.316 | 0.105 / 0.210 | 0.083 / 0.382 | 0.157 / 0.382 |
| other (logic) | 142 | 14.1% | 0.000 / 0.141 | 0.049 / 0.028 | 0.023 / 0.113 | 0.055 / 0.085 | 0.055 / 0.085 | 0.122 / 0.085 | 0.023 / 0.113 | 0.029 / 0.070 |
| input_validation (logic) | 140 | 14.3% | 0.043 / 0.143 | 0.000 / 0.043 | 0.051 / 0.100 | 0.098 / 0.071 | 0.098 / 0.071 | 0.038 / 0.043 | 0.079 / 0.186 | 0.063 / 0.157 |
| resource_dos (logic) | 106 | 13.2% | 0.029 / 0.132 | 0.000 / 0.000 | -0.044 / 0.038 | 0.044 / 0.057 | 0.044 / 0.057 | 0.057 / 0.038 | 0.044 / 0.057 | 0.134 / 0.075 |
| crypto_secrets | 82 | 31.7% | 0.054 / 0.317 | 0.000 / 0.000 | 0.000 / 0.146 | 0.061 / 0.220 | 0.061 / 0.220 | 0.000 / 0.098 | 0.000 / 0.171 | 0.033 / 0.171 |
| deserialization | 36 | 94.4% | 0.298 / 0.944 | 0.447 / 0.667 | 0.405 / 0.833 | 0.321 / 0.889 | 0.321 / 0.889 | 0.684 / 0.944 | 0.298 / 0.944 | 0.248 / 0.833 |
| memory_numeric (logic) | 28 | 57.1% | -0.073 / 0.571 | 0.000 / 0.000 | -0.073 / 0.571 | 0.277 / 0.143 | 0.277 / 0.143 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| xml | 28 | 50.0% | 0.219 / 0.500 | 0.000 / 0.000 | 0.247 / 0.357 | 0.348 / 0.357 | 0.348 / 0.357 | 0.348 / 0.357 | 0.144 / 0.643 | 0.000 / 0.429 |
| unknown (logic) | 26 | 23.1% | 0.000 / 0.231 | 0.200 / 0.077 | 0.000 / 0.231 | 0.000 / 0.077 | 0.000 / 0.077 | 0.000 / 0.077 | 0.000 / 0.385 | -0.081 / 0.308 |

### Pipeline telemetry (test)

- flagged_functions: 576
- findings: 1133
- findings_per_flagged_function: 1.97
- by_tool: {'ast_sink': 291, 'bandit': 474, 'codeql': 130, 'semgrep': 238}
- cpg_success_rate: 1.0
- cpg_taint_found_rate: 0.7167
- cpg_unfiltered_taint_rate: 0.6752
- cpg_sanitized_taint_rate: 0.105
- rag_context_rate: 1.0
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **function_board**: functions 576, mean_valid_votes 1.0, unanimous_rate 0.9965, split_vote_rate 0.0, no_valid_vote_rate 0.0035, majority_not_vulnerable_rate 0.3056, evidence_grounded_rate 0.125, evidence_reasons {'conceded': 417, 'no_span_match': 87, 'span_match': 72}, evidence_in_context_rate 0.0052, guard_grounded_rate 0.0, override_flip_rate 0.2066, code_truncated_rate 0.0677, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0, defender_parse_failed_rate 0.0, mean_seconds_per_function 25.2
- **repo_context**: functions 2004, available_rate 0.999, cross_file_callers_rate 0.2525, entry_point_rate 0.1018, flagged_cross_file_callers_rate 0.2326, flagged_entry_point_rate 0.1615, mean_context_chars 639.3
- **llm_baselines**: llm_only_parse_failed_rate 0.001, llm_only_vulnerable_rate 0.275, llm_context_parse_failed_rate 0.0, llm_context_vulnerable_rate 0.262

## Test, clean subset (single-function fixes)

### clean — 676 functions, 338 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.099, -0.032] | 1.000 | — | — | 0.332 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.065 [0.032, 0.099] | — | 0.00094 | 0.532 | 0.002 | — | 1.24 | 0.061 / 0.012 |
| Semgrep alone | +0.062 [0.038, 0.091] | [-0.037, 0.029] | 4.6e-05 | — | — | 1.000 | 2.00 | 0.095 / 0.020 |
| Bandit alone | +0.059 [0.029, 0.093] | [-0.027, 0.015] | 0.001 | — | — | 1.000 | 1.31 | 0.064 / 0.013 |
| AST sink gate alone | +0.059 [0.032, 0.090] | [-0.040, 0.031] | 0.00035 | — | — | 1.000 | 1.74 | 0.084 / 0.017 |
| CodeQL alone | +0.027 [0.009, 0.047] | [-0.069, -0.009] | 0.012 | — | — | 1.000 | 1.69 | 0.082 / 0.017 |
| SAST board: Judge vote | +0.098 [0.061, 0.136] | [0.006, 0.060] | 3e-06 | 0.549 | 2.7e-05 | 1.000 | 1.62 | 0.079 / 0.016 |
| SAST board + evidence override (ablation) | +0.083 [0.049, 0.117] | [0.000, 0.037] | 5.9e-05 | — | — | 1.000 | 1.33 | 0.066 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.098 [0.064, 0.135] | [0.006, 0.061] | 3e-06 | 0.552 | 0.00049 | 1.000 | 1.63 | 0.079 / 0.016 |
| SAST board + fusion (ablation, trained on dev) | +0.106 [0.069, 0.143] | [0.006, 0.075] | 7.3e-08 | 0.570 | 6.6e-05 | 1.000 | 2.12 | 0.101 / 0.021 |
| LLM only, whole function, no SAST | +0.074 [0.043, 0.108] | [-0.032, 0.050] | 0.00011 | 0.541 | 0.031 | 1.000 | 1.31 | 0.065 / 0.013 |
| LLM only, dev-tuned threshold | +0.077 [0.045, 0.112] | [-0.029, 0.053] | 7.7e-05 | 0.541 | 0.031 | 1.000 | 1.32 | 0.065 / 0.013 |
| LLM only + same-file context, no SAST | +0.092 [0.058, 0.128] | [-0.015, 0.068] | 3.4e-06 | 0.528 | 0.163 | 1.000 | 1.48 | 0.072 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.095 [0.058, 0.135] | [-0.015, 0.079] | 4e-06 | 0.528 | 0.163 | 1.000 | 1.56 | 0.076 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.107, -0.036] | 0.667 [0.667, 0.667] | 0.332 |
| Semgrep + Bandit + AST Gate | 0.553 | 0.340 | 0.275 | 0.532 | 0.070 [0.036, 0.107] | — | 0.421 [0.379, 0.459] | — |
| Semgrep alone | 0.667 | 0.124 | 0.062 | 0.531 | 0.107 [0.069, 0.153] | [-0.007, 0.084] | 0.209 [0.162, 0.258] | 1.000 |
| Bandit alone | 0.567 | 0.252 | 0.192 | 0.530 | 0.071 [0.035, 0.111] | [-0.022, 0.025] | 0.348 [0.299, 0.390] | 0.896 |
| AST sink gate alone | 0.635 | 0.139 | 0.080 | 0.530 | 0.095 [0.051, 0.142] | [-0.020, 0.074] | 0.228 [0.177, 0.284] | 0.931 |
| CodeQL alone | 0.629 | 0.065 | 0.038 | 0.513 | 0.060 [0.021, 0.100] | [-0.051, 0.033] | 0.118 [0.076, 0.162] | 0.362 |
| SAST board: Judge vote | 0.619 | 0.254 | 0.157 | 0.549 | 0.121 [0.078, 0.167] | [0.018, 0.086] | 0.361 [0.315, 0.408] | 0.228 |
| SAST board + evidence override (ablation) | 0.571 | 0.331 | 0.248 | 0.541 | 0.091 [0.054, 0.129] | [0.002, 0.043] | 0.419 [0.376, 0.461] | 0.146 |
| SAST board: vote score, dev-tuned threshold | 0.620 | 0.252 | 0.154 | 0.549 | 0.121 [0.079, 0.167] | [0.018, 0.086] | 0.358 [0.312, 0.406] | 0.235 |
| SAST board + fusion (ablation, trained on dev) | 0.680 | 0.201 | 0.095 | 0.553 | 0.150 [0.103, 0.200] | [0.034, 0.121] | 0.310 [0.255, 0.366] | 0.211 |
| LLM only, whole function, no SAST | 0.568 | 0.311 | 0.237 | 0.537 | 0.083 [0.048, 0.120] | [-0.033, 0.057] | 0.402 [0.354, 0.447] | 0.879 |
| LLM only, dev-tuned threshold | 0.570 | 0.314 | 0.237 | 0.538 | 0.086 [0.051, 0.124] | [-0.031, 0.062] | 0.405 [0.356, 0.449] | 0.819 |
| LLM only + same-file context, no SAST | 0.596 | 0.284 | 0.192 | 0.546 | 0.108 [0.070, 0.148] | [-0.009, 0.083] | 0.385 [0.335, 0.434] | 0.545 |
| LLM only + context, dev-tuned threshold | 0.610 | 0.263 | 0.169 | 0.547 | 0.115 [0.074, 0.160] | [-0.006, 0.098] | 0.368 [0.315, 0.420] | 0.507 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 115 | 0 |
| SAST board (LLM only where static analysis flagged) | 208 | 1,110.1 | 85 | 8,828 |
| LLM only, whole function, no SAST | 676 | 1,009.2 | 106 | 6,436 |
| LLM only + same-file context, no SAST | 676 | 1,195.3 | 89 | 9,079 |


**On functions static analysis flagged** (208: 115 vulnerable, 93 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.553 | 1.000 | 1.000 | 0.000 | 0.712 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.553 | 1.000 | 1.000 | 0.000 | 0.712 | — | — |
| Semgrep alone | 0.667 | 0.365 | 0.226 | 0.151 | 0.472 | 77.4% | 36.5% |
| Bandit alone | 0.567 | 0.739 | 0.699 | 0.045 | 0.641 | 30.1% | 73.9% |
| AST sink gate alone | 0.635 | 0.409 | 0.290 | 0.123 | 0.497 | 71.0% | 40.9% |
| CodeQL alone | 0.629 | 0.191 | 0.140 | 0.069 | 0.293 | 86.0% | 19.1% |
| SAST board: Judge vote | 0.619 | 0.748 | 0.570 | 0.188 | 0.677 | 43.0% | 74.8% |
| SAST board + evidence override (ablation) | 0.571 | 0.974 | 0.903 | 0.151 | 0.720 | 9.7% | 97.4% |
| SAST board: vote score, dev-tuned threshold | 0.620 | 0.739 | 0.559 | 0.189 | 0.675 | 44.1% | 73.9% |
| SAST board + fusion (ablation, trained on dev) | 0.680 | 0.591 | 0.344 | 0.246 | 0.633 | 65.6% | 59.1% |
| LLM only, whole function, no SAST | 0.631 | 0.609 | 0.441 | 0.167 | 0.620 | 55.9% | 60.9% |
| LLM only, dev-tuned threshold | 0.631 | 0.609 | 0.441 | 0.167 | 0.620 | 55.9% | 60.9% |
| LLM only + same-file context, no SAST | 0.660 | 0.556 | 0.355 | 0.201 | 0.604 | 64.5% | 55.6% |
| LLM only + context, dev-tuned threshold | 0.706 | 0.522 | 0.269 | 0.256 | 0.600 | 73.1% | 52.2% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 338 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 338 | 0.086 [0.060, 0.117] | 0.254 | 0.639 | 0.021 | 0.106 | 0.806 |
| Semgrep alone | 338 | 0.065 [0.042, 0.094] | 0.059 | 0.873 | 0.003 | 0.068 | 0.957 |
| Bandit alone | 338 | 0.077 [0.051, 0.107] | 0.175 | 0.731 | 0.018 | 0.095 | 0.812 |
| AST sink gate alone | 338 | 0.068 [0.043, 0.098] | 0.071 | 0.852 | 0.009 | 0.077 | 0.885 |
| CodeQL alone | 338 | 0.030 [0.012, 0.050] | 0.035 | 0.932 | 0.003 | 0.033 | 0.909 |
| SAST board: Judge vote | 338 | 0.112 [0.081, 0.149] | 0.142 | 0.731 | 0.015 | 0.127 | 0.884 |
| SAST board + evidence override (ablation) | 338 | 0.101 [0.071, 0.135] | 0.231 | 0.651 | 0.018 | 0.118 | 0.850 |
| SAST board: vote score, dev-tuned threshold | 338 | 0.112 [0.081, 0.149] | 0.139 | 0.734 | 0.015 | 0.127 | 0.884 |
| SAST board + fusion (ablation, trained on dev) | 338 | 0.115 [0.081, 0.150] | 0.086 | 0.790 | 0.009 | 0.124 | 0.929 |
| LLM only, whole function, no SAST | 338 | 0.089 [0.061, 0.123] | 0.222 | 0.675 | 0.015 | 0.104 | 0.857 |
| LLM only, dev-tuned threshold | 338 | 0.092 [0.064, 0.125] | 0.222 | 0.672 | 0.015 | 0.106 | 0.861 |
| LLM only + same-file context, no SAST | 338 | 0.104 [0.073, 0.137] | 0.180 | 0.704 | 0.012 | 0.115 | 0.897 |
| LLM only + context, dev-tuned threshold | 338 | 0.110 [0.075, 0.147] | 0.154 | 0.722 | 0.015 | 0.124 | 0.881 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.997 | 0.997 |
| SAST board + fusion (ablation, trained on dev) | 0.959 | 0.882 |
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
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.398, -0.169] | 1.000 | — | — | 0.007 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.279 [0.169, 0.398] | — | 3.8e-06 | 0.639 | 2.4e-06 | — | 1.59 | 0.077 / 0.016 |
| Semgrep alone | +0.317 [0.193, 0.460] | [-0.072, 0.157] | 6e-07 | — | — | 1.000 | 2.47 | 0.115 / 0.024 |
| Bandit alone | +0.240 [0.129, 0.366] | [-0.110, 0.033] | 2.7e-05 | — | — | 1.000 | 1.76 | 0.085 / 0.018 |
| AST sink gate alone | +0.165 [0.071, 0.263] | [-0.239, 0.000] | 0.004 | — | — | 1.000 | 1.81 | 0.087 / 0.018 |
| CodeQL alone | +0.139 [0.055, 0.232] | [-0.289, 0.014] | 0.004 | — | — | 1.000 | 3.20 | 0.144 / 0.031 |
| SAST board: Judge vote | +0.342 [0.216, 0.461] | [-0.023, 0.149] | 1.8e-07 | 0.690 | 1.1e-08 | 1.000 | 2.12 | 0.101 / 0.021 |
| SAST board + evidence override (ablation) | +0.317 [0.197, 0.432] | [-0.014, 0.107] | 6e-07 | — | — | 1.000 | 1.78 | 0.086 / 0.018 |
| SAST board: vote score, dev-tuned threshold | +0.342 [0.216, 0.461] | [-0.023, 0.149] | 1.8e-07 | 0.728 | 2e-09 | 1.000 | 2.12 | 0.101 / 0.021 |
| SAST board + fusion (ablation, trained on dev) | +0.354 [0.220, 0.500] | [-0.027, 0.188] | 9.7e-08 | 0.797 | 5.1e-10 | 1.000 | 2.87 | 0.131 / 0.028 |
| LLM only, whole function, no SAST | +0.165 [0.064, 0.274] | [-0.258, 0.015] | 0.004 | 0.601 | 0.010 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only, dev-tuned threshold | +0.165 [0.064, 0.274] | [-0.258, 0.015] | 0.004 | 0.601 | 0.010 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.177 [0.077, 0.289] | [-0.247, 0.041] | 0.003 | 0.627 | 0.003 | 1.000 | 1.41 | 0.069 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.228 [0.125, 0.347] | [-0.190, 0.095] | 0.00024 | 0.627 | 0.003 | 1.000 | 1.75 | 0.084 / 0.017 |

### ReposVul static check did not match — 646 functions, 323 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.071, -0.007] | 1.000 | — | — | 0.619 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.037 [0.007, 0.071] | — | 0.094 | 0.519 | 0.082 | — | 1.17 | 0.058 / 0.012 |
| Semgrep alone | -0.003 [-0.011, 0.000] | [-0.075, -0.011] | 1.000 | — | — | 1.000 | 0.90 | 0.045 / 0.009 |
| Bandit alone | +0.022 [0.000, 0.050] | [-0.039, 0.006] | 0.355 | — | — | 1.000 | 1.18 | 0.058 / 0.012 |
| AST sink gate alone | +0.028 [0.008, 0.053] | [-0.038, 0.021] | 0.094 | — | — | 1.000 | 1.31 | 0.065 / 0.013 |
| CodeQL alone | +0.031 [0.012, 0.052] | [-0.035, 0.022] | 0.020 | — | — | 1.000 | 1.67 | 0.081 / 0.017 |
| SAST board: Judge vote | +0.071 [0.029, 0.121] | [-0.003, 0.076] | 0.005 | 0.534 | 0.010 | 1.000 | 1.64 | 0.079 / 0.016 |
| SAST board + evidence override (ablation) | +0.065 [0.029, 0.109] | [0.000, 0.060] | 0.004 | — | — | 0.763 | 1.36 | 0.067 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.074 [0.035, 0.123] | [0.003, 0.078] | 0.002 | 0.525 | 0.220 | 1.000 | 1.69 | 0.082 / 0.017 |
| SAST board + fusion (ablation, trained on dev) | +0.050 [0.015, 0.091] | [-0.023, 0.049] | 0.047 | 0.536 | 0.082 | 1.000 | 1.64 | 0.080 / 0.016 |
| LLM only, whole function, no SAST | +0.028 [-0.010, 0.064] | [-0.055, 0.032] | 0.355 | 0.495 | 1.000 | 1.000 | 1.14 | 0.057 / 0.011 |
| LLM only, dev-tuned threshold | +0.031 [-0.007, 0.069] | [-0.054, 0.036] | 0.349 | 0.495 | 1.000 | 1.000 | 1.16 | 0.058 / 0.012 |
| LLM only + same-file context, no SAST | +0.037 [-0.004, 0.079] | [-0.046, 0.044] | 0.288 | 0.480 | 0.948 | 1.000 | 1.19 | 0.059 / 0.012 |
| LLM only + context, dev-tuned threshold | +0.043 [0.003, 0.086] | [-0.041, 0.052] | 0.231 | 0.480 | 0.948 | 1.000 | 1.25 | 0.062 / 0.013 |

## Test, split by what the repository shows about callers

Pairs are grouped by the vulnerable version: callers of the function found in other files, a web-framework entry point with no such callers, or neither. This shows where cross-file context can matter.

### Callers found in other files — 504 functions, 252 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.138, -0.039] | 1.000 | — | — | 0.275 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.087 [0.039, 0.138] | — | 0.001 | 0.544 | 0.00079 | — | 1.39 | 0.068 / 0.014 |
| Semgrep alone | +0.056 [0.023, 0.093] | [-0.083, 0.017] | 0.001 | — | — | 1.000 | 2.56 | 0.119 / 0.025 |
| Bandit alone | +0.095 [0.051, 0.144] | [-0.012, 0.033] | 3.3e-05 | — | — | 1.000 | 1.69 | 0.082 / 0.017 |
| AST sink gate alone | +0.032 [-0.004, 0.075] | [-0.092, -0.022] | 0.063 | — | — | 1.000 | 1.27 | 0.062 / 0.013 |
| CodeQL alone | +0.024 [0.008, 0.044] | [-0.111, -0.017] | 0.063 | — | — | 1.000 | 1.75 | 0.084 / 0.017 |
| SAST board: Judge vote | +0.091 [0.038, 0.147] | [-0.031, 0.038] | 0.002 | 0.554 | 0.00053 | 1.000 | 1.66 | 0.080 / 0.017 |
| SAST board + evidence override (ablation) | +0.115 [0.066, 0.169] | [0.004, 0.054] | 1.3e-05 | — | — | 1.000 | 1.66 | 0.080 / 0.017 |
| SAST board: vote score, dev-tuned threshold | +0.091 [0.038, 0.147] | [-0.031, 0.038] | 0.002 | 0.550 | 0.005 | 1.000 | 1.66 | 0.080 / 0.017 |
| SAST board + fusion (ablation, trained on dev) | +0.103 [0.055, 0.155] | [-0.025, 0.062] | 1.1e-05 | 0.564 | 0.003 | 1.000 | 2.37 | 0.111 / 0.023 |
| LLM only, whole function, no SAST | +0.071 [0.021, 0.124] | [-0.079, 0.040] | 0.020 | 0.546 | 0.066 | 1.000 | 1.29 | 0.064 / 0.013 |
| LLM only, dev-tuned threshold | +0.075 [0.023, 0.130] | [-0.074, 0.044] | 0.020 | 0.546 | 0.066 | 1.000 | 1.31 | 0.064 / 0.013 |
| LLM only + same-file context, no SAST | +0.064 [0.017, 0.118] | [-0.077, 0.030] | 0.021 | 0.514 | 1.000 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.071 [0.021, 0.126] | [-0.064, 0.040] | 0.020 | 0.514 | 1.000 | 1.000 | 1.33 | 0.066 / 0.013 |

### Framework entry point, no cross-file callers — 182 functions, 91 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.261, -0.072] | 1.000 | — | — | 0.167 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.165 [0.072, 0.261] | — | 0.002 | 0.582 | 0.001 | — | 1.47 | 0.072 / 0.015 |
| Semgrep alone | +0.044 [0.000, 0.104] | [-0.209, -0.026] | 0.438 | — | — | 1.000 | 1.29 | 0.063 / 0.013 |
| Bandit alone | +0.000 [-0.044, 0.044] | [-0.255, -0.085] | 1.000 | — | — | 0.923 | 1.00 | 0.050 / 0.010 |
| AST sink gate alone | +0.121 [0.048, 0.209] | [-0.138, 0.056] | 0.014 | — | — | 1.000 | 2.10 | 0.100 / 0.021 |
| CodeQL alone | +0.165 [0.083, 0.258] | [-0.083, 0.089] | 0.00061 | — | — | 1.000 | 1.83 | 0.088 / 0.018 |
| SAST board: Judge vote | +0.253 [0.144, 0.370] | [-0.010, 0.204] | 7.3e-05 | 0.637 | 1.1e-05 | 1.000 | 2.35 | 0.110 / 0.023 |
| SAST board + evidence override (ablation) | +0.231 [0.122, 0.333] | [-0.021, 0.165] | 0.00021 | — | — | 1.000 | 1.88 | 0.090 / 0.019 |
| SAST board: vote score, dev-tuned threshold | +0.253 [0.144, 0.370] | [-0.010, 0.204] | 7.3e-05 | 0.659 | 3.3e-06 | 1.000 | 2.35 | 0.110 / 0.023 |
| SAST board + fusion (ablation, trained on dev) | +0.132 [0.036, 0.239] | [-0.151, 0.096] | 0.014 | 0.654 | 0.00015 | 1.000 | 1.92 | 0.092 / 0.019 |
| LLM only, whole function, no SAST | +0.132 [0.055, 0.235] | [-0.143, 0.087] | 0.004 | 0.549 | 0.326 | 1.000 | 1.41 | 0.069 / 0.014 |
| LLM only, dev-tuned threshold | +0.132 [0.055, 0.235] | [-0.143, 0.087] | 0.004 | 0.549 | 0.326 | 1.000 | 1.41 | 0.069 / 0.014 |
| LLM only + same-file context, no SAST | +0.132 [0.042, 0.242] | [-0.155, 0.095] | 0.011 | 0.566 | 0.230 | 1.000 | 1.48 | 0.072 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.143 [0.052, 0.253] | [-0.147, 0.107] | 0.012 | 0.566 | 0.230 | 1.000 | 1.65 | 0.080 / 0.016 |

### Neither — 1318 functions, 659 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.078, -0.031] | 1.000 | — | — | 0.271 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.053 [0.031, 0.078] | — | 2.5e-06 | 0.527 | 1.8e-06 | — | 1.21 | 0.060 / 0.012 |
| Semgrep alone | +0.041 [0.020, 0.063] | [-0.036, 0.011] | 1.7e-05 | — | — | 1.000 | 1.66 | 0.080 / 0.017 |
| Bandit alone | +0.049 [0.024, 0.075] | [-0.019, 0.010] | 5.7e-06 | — | — | 1.000 | 1.26 | 0.062 / 0.013 |
| AST sink gate alone | +0.035 [0.020, 0.052] | [-0.044, 0.006] | 6.1e-05 | — | — | 1.000 | 1.35 | 0.066 / 0.013 |
| CodeQL alone | +0.027 [0.013, 0.044] | [-0.051, -0.000] | 6.1e-05 | — | — | 1.000 | 2.50 | 0.116 / 0.025 |
| SAST board: Judge vote | +0.088 [0.061, 0.117] | [0.018, 0.054] | 1.2e-10 | 0.543 | 9.3e-10 | 0.418 | 1.60 | 0.078 / 0.016 |
| SAST board + evidence override (ablation) | +0.068 [0.043, 0.095] | [0.003, 0.029] | 2.1e-07 | — | — | 0.889 | 1.31 | 0.065 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.088 [0.061, 0.116] | [0.017, 0.054] | 1.2e-10 | 0.545 | 3.9e-07 | 0.418 | 1.62 | 0.078 / 0.016 |
| SAST board + fusion (ablation, trained on dev) | +0.105 [0.071, 0.138] | [0.027, 0.073] | 5.7e-13 | 0.571 | 1.9e-11 | 0.117 | 2.06 | 0.098 / 0.020 |
| LLM only, whole function, no SAST | +0.053 [0.026, 0.081] | [-0.030, 0.032] | 6.1e-05 | 0.516 | 0.518 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only, dev-tuned threshold | +0.053 [0.026, 0.081] | [-0.030, 0.032] | 6.1e-05 | 0.516 | 0.518 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only + same-file context, no SAST | +0.065 [0.037, 0.095] | [-0.017, 0.043] | 9.2e-07 | 0.517 | 0.518 | 1.000 | 1.31 | 0.064 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.070 [0.041, 0.100] | [-0.012, 0.045] | 1.2e-06 | 0.517 | 0.518 | 1.000 | 1.39 | 0.068 / 0.014 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | FPR | Accuracy | MCC | F1 |
|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| Semgrep + Bandit + AST Gate | 0.570 | 0.243 | 0.183 | 0.530 | 0.073 | 0.341 |
| Semgrep alone | 0.611 | 0.088 | 0.056 | 0.516 | 0.062 | 0.153 |
| Bandit alone | 0.621 | 0.163 | 0.100 | 0.532 | 0.094 | 0.259 |
| AST sink gate alone | 0.622 | 0.092 | 0.056 | 0.518 | 0.069 | 0.160 |
| CodeQL alone | 0.556 | 0.040 | 0.032 | 0.504 | 0.021 | 0.074 |
| SAST board: Judge vote | 0.710 | 0.175 | 0.072 | 0.552 | 0.157 | 0.281 |
| SAST board + evidence override (ablation) | 0.655 | 0.219 | 0.116 | 0.552 | 0.139 | 0.328 |
| SAST board: vote score, dev-tuned threshold | 0.721 | 0.175 | 0.068 | 0.554 | 0.165 | 0.282 |
| SAST board + fusion (ablation, trained on dev) | 0.825 | 0.132 | 0.028 | 0.552 | 0.191 | 0.227 |
| LLM only, whole function, no SAST | 0.639 | 0.275 | 0.155 | 0.560 | 0.145 | 0.384 |
| LLM only, dev-tuned threshold | 0.642 | 0.279 | 0.155 | 0.562 | 0.150 | 0.389 |
| LLM only + same-file context, no SAST | 0.615 | 0.235 | 0.147 | 0.544 | 0.111 | 0.340 |
| LLM only + context, dev-tuned threshold | 0.624 | 0.211 | 0.128 | 0.542 | 0.112 | 0.316 |

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
