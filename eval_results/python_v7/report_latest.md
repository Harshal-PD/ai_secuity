# HackerSec real-world evaluation (2026-10-21T05:37:13)

Status: **complete** — 2506/2506 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v7-hybrid-2seat`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| cvefixes | 100 (52) | 400 (133) | 154 |
| reposvul | 101 (44) | 402 (156) | 218 |
| vudenc | 50 (27) | 200 (103) | 90 |

- Dev functions evaluated: 502
- Board threshold on mean P(vulnerable) across Judge votes: **0.800** (max mcc on dev)
- Fusion: trained on 104 flagged dev functions (5-fold CV C=0.15, max mcc), threshold 0.588, dev CV F1 0.228, dev CV MCC 0.201
- LLM-only threshold on P(vulnerable): **0.200** (max mcc on dev)
- LLM-only + context threshold on P(vulnerable): **0.900** (max mcc on dev)
- Cascade unflagged context threshold on P(vulnerable): **1.000** (max mcc on dev)

Each pair contributes one vulnerable and one fixed function, so flagging every function scores F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise columns show whether a system actually separates vulnerable from fixed code.

## Test split (primary)

### cvefixes — 800 functions, 400 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.073, -0.017] | 1.000 | — | — | 0.488 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.045 [0.017, 0.073] | — | 0.012 | 0.522 | 0.018 | — | 1.20 | 0.059 / 0.012 |
| Semgrep alone | +0.040 [0.019, 0.065] | [-0.032, 0.024] | 0.002 | — | — | 1.000 | 1.64 | 0.080 / 0.016 |
| Bandit alone | +0.045 [0.018, 0.076] | [-0.022, 0.022] | 0.006 | — | — | 1.000 | 1.28 | 0.063 / 0.013 |
| AST sink gate alone | +0.022 [0.000, 0.048] | [-0.049, 0.003] | 0.064 | — | — | 1.000 | 1.24 | 0.061 / 0.012 |
| SAST board: Judge vote | +0.050 [0.020, 0.080] | [-0.009, 0.019] | 0.008 | 0.525 | 0.016 | 1.000 | 1.27 | 0.063 / 0.013 |
| SAST board + evidence override (ablation) | +0.052 [0.023, 0.082] | [-0.003, 0.018] | 0.007 | — | — | 1.000 | 1.25 | 0.062 / 0.012 |
| SAST board: vote score, dev-tuned threshold | +0.040 [0.011, 0.071] | [-0.025, 0.017] | 0.028 | 0.536 | 0.004 | 1.000 | 1.24 | 0.061 / 0.012 |
| SAST board + fusion (trained on dev) | +0.060 [0.029, 0.093] | [-0.018, 0.048] | 0.0005 | 0.549 | 0.002 | 1.000 | 1.69 | 0.082 / 0.017 |
| SAST board + fusion + context cascade (trained on dev) | +0.052 [0.020, 0.085] | [-0.025, 0.042] | 0.006 | 0.530 | 0.413 | 1.000 | 1.55 | 0.075 / 0.015 |
| LLM only, whole function, no SAST | +0.050 [0.014, 0.088] | [-0.034, 0.046] | 0.010 | 0.524 | 0.413 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only, dev-tuned threshold | +0.050 [0.014, 0.088] | [-0.034, 0.046] | 0.010 | 0.524 | 0.413 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only + same-file context, no SAST | +0.048 [0.015, 0.083] | [-0.037, 0.044] | 0.012 | 0.505 | 1.000 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only + context, dev-tuned threshold | +0.058 [0.020, 0.093] | [-0.025, 0.052] | 0.007 | 0.505 | 1.000 | 1.000 | 1.33 | 0.065 / 0.013 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.084, -0.020] | 0.667 [0.667, 0.667] | 0.488 |
| Semgrep + Bandit + AST Gate | 0.545 | 0.273 | 0.228 | 0.522 | 0.052 [0.020, 0.084] | — | 0.363 [0.314, 0.409] | — |
| Semgrep alone | 0.621 | 0.102 | 0.062 | 0.520 | 0.073 [0.036, 0.116] | [-0.019, 0.065] | 0.176 [0.124, 0.240] | 0.931 |
| Bandit alone | 0.562 | 0.205 | 0.160 | 0.522 | 0.058 [0.023, 0.097] | [-0.021, 0.036] | 0.300 [0.238, 0.356] | 1.000 |
| AST sink gate alone | 0.553 | 0.117 | 0.095 | 0.511 | 0.036 [0.000, 0.076] | [-0.051, 0.018] | 0.194 [0.137, 0.254] | 0.456 |
| SAST board: Judge vote | 0.560 | 0.233 | 0.182 | 0.525 | 0.062 [0.024, 0.098] | [-0.007, 0.028] | 0.329 [0.275, 0.382] | 0.864 |
| SAST board + evidence override (ablation) | 0.555 | 0.265 | 0.212 | 0.526 | 0.062 [0.028, 0.096] | [-0.003, 0.022] | 0.359 [0.309, 0.407] | 0.508 |
| SAST board: vote score, dev-tuned threshold | 0.554 | 0.205 | 0.165 | 0.520 | 0.051 [0.014, 0.091] | [-0.025, 0.028] | 0.299 [0.243, 0.352] | 0.890 |
| SAST board + fusion (trained on dev) | 0.628 | 0.147 | 0.087 | 0.530 | 0.093 [0.046, 0.140] | [-0.006, 0.088] | 0.239 [0.177, 0.301] | 0.627 |
| SAST board + fusion + context cascade (trained on dev) | 0.608 | 0.147 | 0.095 | 0.526 | 0.080 [0.032, 0.126] | [-0.018, 0.075] | 0.237 [0.175, 0.300] | 0.848 |
| LLM only, whole function, no SAST | 0.552 | 0.265 | 0.215 | 0.525 | 0.059 [0.017, 0.101] | [-0.040, 0.055] | 0.358 [0.297, 0.416] | 0.940 |
| LLM only, dev-tuned threshold | 0.552 | 0.265 | 0.215 | 0.525 | 0.059 [0.017, 0.101] | [-0.040, 0.055] | 0.358 [0.297, 0.416] | 0.940 |
| LLM only + same-file context, no SAST | 0.551 | 0.258 | 0.210 | 0.524 | 0.056 [0.018, 0.097] | [-0.041, 0.053] | 0.351 [0.287, 0.411] | 1.000 |
| LLM only + context, dev-tuned threshold | 0.571 | 0.233 | 0.175 | 0.529 | 0.071 [0.025, 0.114] | [-0.028, 0.068] | 0.330 [0.265, 0.392] | 0.770 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 109 | 0 |
| SAST board (LLM only where static analysis flagged) | 200 | 891.5 | 82 | 8,698 |
| LLM only, whole function, no SAST | 800 | 1,032.2 | 106 | 7,790 |
| LLM only + same-file context, no SAST | 800 | 1,185.9 | 93 | 10,201 |


**On functions static analysis flagged** (200: 109 vulnerable, 91 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.545 | 1.000 | 1.000 | 0.000 | 0.706 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.545 | 1.000 | 1.000 | 0.000 | 0.706 | — | — |
| Semgrep alone | 0.621 | 0.376 | 0.275 | 0.107 | 0.469 | 72.5% | 37.6% |
| Bandit alone | 0.562 | 0.752 | 0.703 | 0.055 | 0.643 | 29.7% | 75.2% |
| AST sink gate alone | 0.553 | 0.431 | 0.418 | 0.014 | 0.484 | 58.2% | 43.1% |
| SAST board: Judge vote | 0.560 | 0.853 | 0.802 | 0.068 | 0.676 | 19.8% | 85.3% |
| SAST board + evidence override (ablation) | 0.555 | 0.973 | 0.934 | 0.092 | 0.707 | 6.6% | 97.2% |
| SAST board: vote score, dev-tuned threshold | 0.554 | 0.752 | 0.725 | 0.031 | 0.638 | 27.5% | 75.2% |
| SAST board + fusion (trained on dev) | 0.628 | 0.541 | 0.385 | 0.156 | 0.581 | 61.5% | 54.1% |
| SAST board + fusion + context cascade (trained on dev) | 0.628 | 0.541 | 0.385 | 0.156 | 0.581 | 61.5% | 54.1% |
| LLM only, whole function, no SAST | 0.598 | 0.587 | 0.472 | 0.114 | 0.593 | 52.8% | 58.7% |
| LLM only, dev-tuned threshold | 0.598 | 0.587 | 0.472 | 0.114 | 0.593 | 52.8% | 58.7% |
| LLM only + same-file context, no SAST | 0.612 | 0.578 | 0.440 | 0.138 | 0.594 | 56.0% | 57.8% |
| LLM only + context, dev-tuned threshold | 0.659 | 0.532 | 0.330 | 0.203 | 0.589 | 67.0% | 53.2% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 400 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 400 | 0.065 [0.041, 0.092] | 0.207 | 0.708 | 0.020 | 0.085 | 0.765 |
| Semgrep alone | 400 | 0.043 [0.020, 0.067] | 0.060 | 0.895 | 0.003 | 0.045 | 0.944 |
| Bandit alone | 400 | 0.055 [0.031, 0.083] | 0.150 | 0.785 | 0.010 | 0.065 | 0.846 |
| AST sink gate alone | 400 | 0.035 [0.018, 0.055] | 0.083 | 0.870 | 0.013 | 0.048 | 0.737 |
| SAST board: Judge vote | 400 | 0.070 [0.045, 0.098] | 0.163 | 0.748 | 0.020 | 0.090 | 0.778 |
| SAST board + evidence override (ablation) | 400 | 0.072 [0.048, 0.101] | 0.193 | 0.715 | 0.020 | 0.092 | 0.784 |
| SAST board: vote score, dev-tuned threshold | 400 | 0.068 [0.040, 0.099] | 0.138 | 0.767 | 0.028 | 0.095 | 0.711 |
| SAST board + fusion (trained on dev) | 400 | 0.072 [0.045, 0.102] | 0.075 | 0.840 | 0.013 | 0.085 | 0.853 |
| SAST board + fusion + context cascade (trained on dev) | 400 | 0.070 [0.043, 0.099] | 0.077 | 0.835 | 0.018 | 0.087 | 0.800 |
| LLM only, whole function, no SAST | 400 | 0.072 [0.045, 0.105] | 0.193 | 0.713 | 0.022 | 0.095 | 0.763 |
| LLM only, dev-tuned threshold | 400 | 0.072 [0.045, 0.105] | 0.193 | 0.713 | 0.022 | 0.095 | 0.763 |
| LLM only + same-file context, no SAST | 400 | 0.072 [0.043, 0.109] | 0.185 | 0.718 | 0.025 | 0.098 | 0.744 |
| LLM only + context, dev-tuned threshold | 400 | 0.085 [0.055, 0.121] | 0.147 | 0.740 | 0.028 | 0.113 | 0.756 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.993 | 0.993 |
| SAST board + fusion (trained on dev) | 0.993 | 0.895 |
| SAST board + fusion + context cascade (trained on dev) | 0.993 | 0.895 |
| LLM only, whole function, no SAST | 1.000 | 0.990 |
| LLM only, dev-tuned threshold | 1.000 | 0.990 |
| LLM only + same-file context, no SAST | 1.000 | 0.990 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.990 |

### reposvul — 804 functions, 402 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.108, -0.040] | 1.000 | — | — | 0.228 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.075 [0.040, 0.108] | — | 9.7e-06 | 0.537 | 9.7e-06 | — | 1.31 | 0.064 / 0.013 |
| Semgrep alone | +0.060 [0.030, 0.093] | [-0.048, 0.020] | 6.4e-06 | — | — | 1.000 | 1.89 | 0.090 / 0.019 |
| Bandit alone | +0.065 [0.035, 0.098] | [-0.030, 0.013] | 2.5e-05 | — | — | 1.000 | 1.41 | 0.069 / 0.014 |
| AST sink gate alone | +0.055 [0.028, 0.083] | [-0.050, 0.013] | 3.1e-05 | — | — | 1.000 | 1.49 | 0.073 / 0.015 |
| SAST board: Judge vote | +0.095 [0.058, 0.129] | [0.005, 0.035] | 6.6e-08 | 0.545 | 8.1e-07 | 1.000 | 1.51 | 0.074 / 0.015 |
| SAST board + evidence override (ablation) | +0.082 [0.046, 0.117] | [-0.003, 0.019] | 4.9e-06 | — | — | 1.000 | 1.35 | 0.067 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.097 [0.057, 0.135] | [0.003, 0.042] | 9.1e-08 | 0.557 | 5.6e-07 | 1.000 | 1.61 | 0.078 / 0.016 |
| SAST board + fusion (trained on dev) | +0.085 [0.051, 0.121] | [-0.018, 0.039] | 3.1e-06 | 0.563 | 1.3e-05 | 1.000 | 1.79 | 0.086 / 0.018 |
| SAST board + fusion + context cascade (trained on dev) | +0.087 [0.053, 0.125] | [-0.016, 0.040] | 1.9e-06 | 0.536 | 0.240 | 1.000 | 1.81 | 0.087 / 0.018 |
| LLM only, whole function, no SAST | +0.062 [0.024, 0.097] | [-0.057, 0.028] | 0.00021 | 0.516 | 1.000 | 1.000 | 1.24 | 0.061 / 0.012 |
| LLM only, dev-tuned threshold | +0.065 [0.027, 0.101] | [-0.056, 0.031] | 0.00021 | 0.516 | 1.000 | 1.000 | 1.25 | 0.062 / 0.013 |
| LLM only + same-file context, no SAST | +0.080 [0.042, 0.118] | [-0.041, 0.049] | 1.1e-05 | 0.514 | 1.000 | 1.000 | 1.34 | 0.066 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.087 [0.046, 0.131] | [-0.033, 0.057] | 1.7e-05 | 0.514 | 1.000 | 1.000 | 1.44 | 0.070 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.121, -0.045] | 0.667 [0.667, 0.667] | 0.228 |
| Semgrep + Bandit + AST Gate | 0.566 | 0.318 | 0.244 | 0.537 | 0.083 [0.045, 0.121] | — | 0.408 [0.364, 0.451] | — |
| Semgrep alone | 0.654 | 0.127 | 0.067 | 0.530 | 0.101 [0.054, 0.151] | [-0.029, 0.070] | 0.212 [0.160, 0.267] | 0.681 |
| Bandit alone | 0.584 | 0.224 | 0.159 | 0.532 | 0.082 [0.044, 0.122] | [-0.025, 0.026] | 0.324 [0.275, 0.369] | 0.724 |
| AST sink gate alone | 0.598 | 0.167 | 0.112 | 0.527 | 0.079 [0.042, 0.116] | [-0.040, 0.034] | 0.261 [0.204, 0.318] | 0.512 |
| SAST board: Judge vote | 0.602 | 0.279 | 0.184 | 0.547 | 0.112 [0.069, 0.154] | [0.011, 0.049] | 0.381 [0.333, 0.432] | 0.268 |
| SAST board + evidence override (ablation) | 0.575 | 0.313 | 0.231 | 0.541 | 0.092 [0.053, 0.130] | [-0.003, 0.022] | 0.406 [0.363, 0.450] | 0.453 |
| SAST board: vote score, dev-tuned threshold | 0.617 | 0.256 | 0.159 | 0.548 | 0.120 [0.073, 0.163] | [0.011, 0.063] | 0.362 [0.309, 0.414] | 0.298 |
| SAST board + fusion (trained on dev) | 0.642 | 0.192 | 0.107 | 0.542 | 0.119 [0.073, 0.168] | [-0.001, 0.073] | 0.295 [0.241, 0.353] | 0.771 |
| SAST board + fusion + context cascade (trained on dev) | 0.645 | 0.194 | 0.107 | 0.543 | 0.122 [0.075, 0.170] | [0.001, 0.076] | 0.298 [0.243, 0.357] | 0.699 |
| LLM only, whole function, no SAST | 0.554 | 0.318 | 0.256 | 0.531 | 0.069 [0.026, 0.109] | [-0.066, 0.032] | 0.404 [0.351, 0.454] | 0.773 |
| LLM only, dev-tuned threshold | 0.556 | 0.321 | 0.256 | 0.532 | 0.071 [0.029, 0.113] | [-0.062, 0.035] | 0.407 [0.353, 0.456] | 0.830 |
| LLM only + same-file context, no SAST | 0.573 | 0.313 | 0.234 | 0.540 | 0.089 [0.048, 0.132] | [-0.044, 0.056] | 0.405 [0.347, 0.459] | 0.944 |
| LLM only + context, dev-tuned threshold | 0.590 | 0.286 | 0.199 | 0.543 | 0.102 [0.054, 0.151] | [-0.036, 0.070] | 0.385 [0.326, 0.445] | 0.778 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 128 | 0 |
| SAST board (LLM only where static analysis flagged) | 226 | 1,047.9 | 103 | 8,179 |
| LLM only, whole function, no SAST | 804 | 1,144.9 | 129 | 7,135 |
| LLM only + same-file context, no SAST | 804 | 1,326.7 | 115 | 9,275 |


**On functions static analysis flagged** (226: 128 vulnerable, 98 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.566 | 1.000 | 1.000 | 0.000 | 0.723 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.566 | 1.000 | 1.000 | 0.000 | 0.723 | — | — |
| Semgrep alone | 0.654 | 0.398 | 0.276 | 0.128 | 0.495 | 72.5% | 39.8% |
| Bandit alone | 0.584 | 0.703 | 0.653 | 0.053 | 0.638 | 34.7% | 70.3% |
| AST sink gate alone | 0.598 | 0.523 | 0.459 | 0.064 | 0.558 | 54.1% | 52.3% |
| SAST board: Judge vote | 0.602 | 0.875 | 0.755 | 0.156 | 0.713 | 24.5% | 87.5% |
| SAST board + evidence override (ablation) | 0.575 | 0.984 | 0.949 | 0.101 | 0.726 | 5.1% | 98.4% |
| SAST board: vote score, dev-tuned threshold | 0.617 | 0.805 | 0.653 | 0.171 | 0.698 | 34.7% | 80.5% |
| SAST board + fusion (trained on dev) | 0.642 | 0.602 | 0.439 | 0.162 | 0.621 | 56.1% | 60.2% |
| SAST board + fusion + context cascade (trained on dev) | 0.642 | 0.602 | 0.439 | 0.162 | 0.621 | 56.1% | 60.2% |
| LLM only, whole function, no SAST | 0.621 | 0.641 | 0.510 | 0.131 | 0.631 | 49.0% | 64.1% |
| LLM only, dev-tuned threshold | 0.621 | 0.641 | 0.510 | 0.131 | 0.631 | 49.0% | 64.1% |
| LLM only + same-file context, no SAST | 0.650 | 0.625 | 0.439 | 0.185 | 0.637 | 56.1% | 62.5% |
| LLM only + context, dev-tuned threshold | 0.682 | 0.586 | 0.357 | 0.227 | 0.630 | 64.3% | 58.6% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 402 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 402 | 0.087 [0.057, 0.121] | 0.231 | 0.669 | 0.012 | 0.100 | 0.875 |
| Semgrep alone | 402 | 0.062 [0.035, 0.096] | 0.065 | 0.871 | 0.003 | 0.065 | 0.962 |
| Bandit alone | 402 | 0.075 [0.047, 0.107] | 0.149 | 0.766 | 0.010 | 0.085 | 0.882 |
| AST sink gate alone | 402 | 0.060 [0.035, 0.087] | 0.107 | 0.828 | 0.005 | 0.065 | 0.923 |
| SAST board: Judge vote | 402 | 0.104 [0.071, 0.139] | 0.174 | 0.711 | 0.010 | 0.114 | 0.913 |
| SAST board + evidence override (ablation) | 402 | 0.097 [0.066, 0.131] | 0.216 | 0.672 | 0.015 | 0.112 | 0.867 |
| SAST board: vote score, dev-tuned threshold | 402 | 0.110 [0.074, 0.144] | 0.147 | 0.731 | 0.012 | 0.122 | 0.898 |
| SAST board + fusion (trained on dev) | 402 | 0.100 [0.066, 0.136] | 0.092 | 0.793 | 0.015 | 0.114 | 0.870 |
| SAST board + fusion + context cascade (trained on dev) | 402 | 0.102 [0.068, 0.139] | 0.092 | 0.791 | 0.015 | 0.117 | 0.872 |
| LLM only, whole function, no SAST | 402 | 0.085 [0.055, 0.117] | 0.234 | 0.659 | 0.022 | 0.107 | 0.791 |
| LLM only, dev-tuned threshold | 402 | 0.087 [0.058, 0.119] | 0.234 | 0.657 | 0.022 | 0.110 | 0.795 |
| LLM only + same-file context, no SAST | 402 | 0.097 [0.064, 0.132] | 0.216 | 0.669 | 0.017 | 0.114 | 0.848 |
| LLM only + context, dev-tuned threshold | 402 | 0.114 [0.080, 0.154] | 0.172 | 0.687 | 0.027 | 0.142 | 0.807 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.995 | 0.995 |
| SAST board + fusion (trained on dev) | 0.983 | 0.878 |
| SAST board + fusion + context cascade (trained on dev) | 0.983 | 0.881 |
| LLM only, whole function, no SAST | 1.000 | 0.988 |
| LLM only, dev-tuned threshold | 1.000 | 0.988 |
| LLM only + same-file context, no SAST | 0.988 | 0.988 |
| LLM only + context, dev-tuned threshold | 0.988 | 0.988 |

### vudenc — 400 functions, 200 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.135, -0.019] | 1.000 | — | — | 0.445 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.070 [0.019, 0.135] | — | 0.004 | 0.535 | 0.004 | — | 1.29 | 0.064 / 0.013 |
| Semgrep alone | +0.025 [-0.010, 0.064] | [-0.114, 0.016] | 0.227 | — | — | 1.000 | 1.42 | 0.069 / 0.014 |
| Bandit alone | +0.060 [0.006, 0.126] | [-0.025, 0.000] | 0.013 | — | — | 1.000 | 1.32 | 0.065 / 0.013 |
| AST sink gate alone | +0.055 [0.015, 0.104] | [-0.067, 0.027] | 0.004 | — | — | 1.000 | 1.48 | 0.072 / 0.015 |
| SAST board: Judge vote | +0.090 [0.033, 0.161] | [-0.005, 0.048] | 0.003 | 0.545 | 0.002 | 1.000 | 1.43 | 0.070 / 0.014 |
| SAST board + evidence override (ablation) | +0.080 [0.026, 0.150] | [-0.009, 0.032] | 0.004 | — | — | 1.000 | 1.36 | 0.067 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.105 [0.046, 0.175] | [0.000, 0.071] | 0.00054 | 0.557 | 0.0006 | 0.785 | 1.54 | 0.075 / 0.015 |
| SAST board + fusion (trained on dev) | +0.080 [0.030, 0.141] | [-0.048, 0.061] | 0.004 | 0.547 | 0.110 | 1.000 | 1.64 | 0.080 / 0.016 |
| SAST board + fusion + context cascade (trained on dev) | +0.070 [0.015, 0.138] | [-0.063, 0.061] | 0.019 | 0.555 | 0.123 | 1.000 | 1.50 | 0.073 / 0.015 |
| LLM only, whole function, no SAST | +0.100 [0.037, 0.175] | [-0.016, 0.079] | 0.004 | 0.540 | 0.176 | 1.000 | 1.35 | 0.066 / 0.013 |
| LLM only, dev-tuned threshold | +0.100 [0.037, 0.175] | [-0.016, 0.079] | 0.004 | 0.540 | 0.176 | 1.000 | 1.35 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.115 [0.058, 0.183] | [0.000, 0.089] | 0.00041 | 0.540 | 0.176 | 1.000 | 1.44 | 0.071 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.125 [0.070, 0.190] | [0.009, 0.101] | 0.00014 | 0.540 | 0.176 | 1.000 | 1.52 | 0.074 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.147, -0.021] | 0.667 [0.667, 0.667] | 0.445 |
| Semgrep + Bandit + AST Gate | 0.564 | 0.310 | 0.240 | 0.535 | 0.078 [0.021, 0.147] | — | 0.400 [0.325, 0.476] | — |
| Semgrep alone | 0.586 | 0.085 | 0.060 | 0.512 | 0.048 [-0.020, 0.125] | [-0.118, 0.062] | 0.148 [0.077, 0.226] | 0.374 |
| Bandit alone | 0.568 | 0.250 | 0.190 | 0.530 | 0.072 [0.007, 0.147] | [-0.025, 0.009] | 0.347 [0.260, 0.429] | 0.832 |
| AST sink gate alone | 0.597 | 0.170 | 0.115 | 0.527 | 0.079 [0.023, 0.147] | [-0.057, 0.052] | 0.265 [0.172, 0.350] | 0.784 |
| SAST board: Judge vote | 0.588 | 0.300 | 0.210 | 0.545 | 0.103 [0.038, 0.180] | [-0.005, 0.058] | 0.397 [0.316, 0.481] | 0.289 |
| SAST board + evidence override (ablation) | 0.576 | 0.305 | 0.225 | 0.540 | 0.091 [0.029, 0.168] | [-0.009, 0.037] | 0.399 [0.320, 0.477] | 0.625 |
| SAST board: vote score, dev-tuned threshold | 0.606 | 0.300 | 0.195 | 0.552 | 0.122 [0.053, 0.200] | [0.002, 0.086] | 0.401 [0.319, 0.486] | 0.065 |
| SAST board + fusion (trained on dev) | 0.621 | 0.205 | 0.125 | 0.540 | 0.108 [0.042, 0.182] | [-0.041, 0.090] | 0.308 [0.218, 0.394] | 0.880 |
| SAST board + fusion + context cascade (trained on dev) | 0.600 | 0.210 | 0.140 | 0.535 | 0.092 [0.020, 0.173] | [-0.060, 0.089] | 0.311 [0.223, 0.399] | 1.000 |
| LLM only, whole function, no SAST | 0.575 | 0.385 | 0.285 | 0.550 | 0.106 [0.040, 0.184] | [-0.025, 0.082] | 0.461 [0.385, 0.533] | 0.561 |
| LLM only, dev-tuned threshold | 0.575 | 0.385 | 0.285 | 0.550 | 0.106 [0.040, 0.184] | [-0.025, 0.082] | 0.461 [0.385, 0.533] | 0.561 |
| LLM only + same-file context, no SAST | 0.591 | 0.375 | 0.260 | 0.557 | 0.123 [0.062, 0.193] | [-0.003, 0.092] | 0.459 [0.389, 0.529] | 0.336 |
| LLM only + context, dev-tuned threshold | 0.603 | 0.365 | 0.240 | 0.562 | 0.136 [0.075, 0.206] | [0.003, 0.108] | 0.455 [0.385, 0.529] | 0.242 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 62 | 0 |
| SAST board (LLM only where static analysis flagged) | 110 | 910.2 | 60 | 6,068 |
| LLM only, whole function, no SAST | 400 | 906.3 | 77 | 4,708 |
| LLM only + same-file context, no SAST | 400 | 1,042.3 | 73 | 5,711 |


**On functions static analysis flagged** (110: 62 vulnerable, 48 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.564 | 1.000 | 1.000 | 0.000 | 0.721 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.564 | 1.000 | 1.000 | 0.000 | 0.721 | — | — |
| Semgrep alone | 0.586 | 0.274 | 0.250 | 0.027 | 0.374 | 75.0% | 27.4% |
| Bandit alone | 0.568 | 0.806 | 0.792 | 0.018 | 0.667 | 20.8% | 80.7% |
| AST sink gate alone | 0.597 | 0.548 | 0.479 | 0.069 | 0.571 | 52.1% | 54.8% |
| SAST board: Judge vote | 0.588 | 0.968 | 0.875 | 0.177 | 0.732 | 12.5% | 96.8% |
| SAST board + evidence override (ablation) | 0.576 | 0.984 | 0.938 | 0.123 | 0.726 | 6.2% | 98.4% |
| SAST board: vote score, dev-tuned threshold | 0.606 | 0.968 | 0.812 | 0.257 | 0.745 | 18.8% | 96.8% |
| SAST board + fusion (trained on dev) | 0.621 | 0.661 | 0.521 | 0.142 | 0.641 | 47.9% | 66.1% |
| SAST board + fusion + context cascade (trained on dev) | 0.621 | 0.661 | 0.521 | 0.142 | 0.641 | 47.9% | 66.1% |
| LLM only, whole function, no SAST | 0.600 | 0.823 | 0.708 | 0.135 | 0.694 | 29.2% | 82.3% |
| LLM only, dev-tuned threshold | 0.600 | 0.823 | 0.708 | 0.135 | 0.694 | 29.2% | 82.3% |
| LLM only + same-file context, no SAST | 0.595 | 0.806 | 0.708 | 0.115 | 0.685 | 29.2% | 80.7% |
| LLM only + context, dev-tuned threshold | 0.620 | 0.790 | 0.625 | 0.182 | 0.695 | 37.5% | 79.0% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 200 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 200 | 0.075 [0.025, 0.137] | 0.235 | 0.685 | 0.005 | 0.080 | 0.938 |
| Semgrep alone | 200 | 0.040 [0.015, 0.072] | 0.045 | 0.900 | 0.015 | 0.055 | 0.727 |
| Bandit alone | 200 | 0.070 [0.019, 0.133] | 0.180 | 0.740 | 0.010 | 0.080 | 0.875 |
| AST sink gate alone | 200 | 0.055 [0.015, 0.104] | 0.115 | 0.830 | 0.000 | 0.055 | 1.000 |
| SAST board: Judge vote | 200 | 0.105 [0.052, 0.174] | 0.195 | 0.685 | 0.015 | 0.120 | 0.875 |
| SAST board + evidence override (ablation) | 200 | 0.090 [0.037, 0.157] | 0.215 | 0.685 | 0.010 | 0.100 | 0.900 |
| SAST board: vote score, dev-tuned threshold | 200 | 0.120 [0.061, 0.191] | 0.180 | 0.685 | 0.015 | 0.135 | 0.889 |
| SAST board + fusion (trained on dev) | 200 | 0.095 [0.049, 0.153] | 0.110 | 0.780 | 0.015 | 0.110 | 0.864 |
| SAST board + fusion + context cascade (trained on dev) | 200 | 0.100 [0.052, 0.164] | 0.110 | 0.760 | 0.030 | 0.130 | 0.769 |
| LLM only, whole function, no SAST | 200 | 0.130 [0.074, 0.195] | 0.255 | 0.585 | 0.030 | 0.160 | 0.812 |
| LLM only, dev-tuned threshold | 200 | 0.130 [0.074, 0.195] | 0.255 | 0.585 | 0.030 | 0.160 | 0.812 |
| LLM only + same-file context, no SAST | 200 | 0.135 [0.083, 0.196] | 0.240 | 0.605 | 0.020 | 0.155 | 0.871 |
| LLM only + context, dev-tuned threshold | 200 | 0.145 [0.091, 0.208] | 0.220 | 0.615 | 0.020 | 0.165 | 0.879 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.990 | 0.990 |
| SAST board + fusion (trained on dev) | 0.960 | 0.920 |
| SAST board + fusion + context cascade (trained on dev) | 0.960 | 0.920 |
| LLM only, whole function, no SAST | 1.000 | 1.000 |
| LLM only, dev-tuned threshold | 1.000 | 1.000 |
| LLM only + same-file context, no SAST | 1.000 | 1.000 |
| LLM only + context, dev-tuned threshold | 1.000 | 1.000 |

### combined — 2004 functions, 1002 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.086, -0.040] | 1.000 | — | — | 0.111 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.062 [0.040, 0.086] | — | 1.1e-10 | 0.531 | 1.2e-10 | — | 1.26 | 0.062 / 0.013 |
| Semgrep alone | +0.045 [0.028, 0.065] | [-0.040, 0.004] | 8.5e-10 | — | — | 1.000 | 1.70 | 0.082 / 0.017 |
| Bandit alone | +0.056 [0.035, 0.079] | [-0.019, 0.006] | 1.5e-10 | — | — | 1.000 | 1.34 | 0.066 / 0.013 |
| AST sink gate alone | +0.042 [0.025, 0.061] | [-0.040, -0.002] | 7.5e-09 | — | — | 1.000 | 1.40 | 0.069 / 0.014 |
| SAST board: Judge vote | +0.076 [0.054, 0.101] | [0.004, 0.024] | 2.5e-13 | 0.537 | 5.4e-12 | 1.000 | 1.40 | 0.069 / 0.014 |
| SAST board + evidence override (ablation) | +0.070 [0.048, 0.094] | [0.001, 0.015] | 8.2e-12 | — | — | 1.000 | 1.31 | 0.065 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.076 [0.053, 0.102] | [0.001, 0.029] | 2.7e-12 | 0.549 | 3.5e-13 | 1.000 | 1.45 | 0.071 / 0.014 |
| SAST board + fusion (trained on dev) | +0.074 [0.052, 0.098] | [-0.009, 0.030] | 3.3e-13 | 0.554 | 3.5e-10 | 1.000 | 1.72 | 0.083 / 0.017 |
| SAST board + fusion + context cascade (trained on dev) | +0.070 [0.047, 0.094] | [-0.013, 0.029] | 3.6e-11 | 0.537 | 0.003 | 1.000 | 1.64 | 0.080 / 0.016 |
| LLM only, whole function, no SAST | +0.065 [0.042, 0.090] | [-0.024, 0.028] | 1.1e-09 | 0.524 | 0.028 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only, dev-tuned threshold | +0.066 [0.044, 0.092] | [-0.023, 0.028] | 1.1e-09 | 0.524 | 0.028 | 1.000 | 1.27 | 0.063 / 0.013 |
| LLM only + same-file context, no SAST | +0.074 [0.050, 0.100] | [-0.014, 0.040] | 1.6e-11 | 0.515 | 0.169 | 1.000 | 1.32 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.083 [0.058, 0.111] | [-0.005, 0.048] | 2.8e-12 | 0.515 | 0.169 | 1.000 | 1.42 | 0.070 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.096, -0.045] | 0.667 [0.667, 0.667] | 0.111 |
| Semgrep + Bandit + AST Gate | 0.558 | 0.298 | 0.236 | 0.531 | 0.070 [0.045, 0.096] | — | 0.389 [0.359, 0.417] | — |
| Semgrep alone | 0.630 | 0.109 | 0.064 | 0.522 | 0.080 [0.051, 0.112] | [-0.022, 0.041] | 0.185 [0.149, 0.224] | 0.401 |
| Bandit alone | 0.572 | 0.222 | 0.166 | 0.528 | 0.071 [0.045, 0.101] | [-0.014, 0.016] | 0.319 [0.285, 0.353] | 0.681 |
| AST sink gate alone | 0.583 | 0.148 | 0.106 | 0.521 | 0.063 [0.039, 0.091] | [-0.030, 0.016] | 0.236 [0.203, 0.269] | 0.258 |
| SAST board: Judge vote | 0.584 | 0.265 | 0.189 | 0.538 | 0.091 [0.065, 0.120] | [0.009, 0.033] | 0.364 [0.331, 0.397] | 0.151 |
| SAST board + evidence override (ablation) | 0.568 | 0.292 | 0.223 | 0.535 | 0.080 [0.056, 0.108] | [0.002, 0.018] | 0.386 [0.356, 0.416] | 0.115 |
| SAST board: vote score, dev-tuned threshold | 0.592 | 0.244 | 0.169 | 0.538 | 0.094 [0.066, 0.125] | [0.008, 0.042] | 0.346 [0.314, 0.381] | 0.239 |
| SAST board + fusion (trained on dev) | 0.632 | 0.177 | 0.103 | 0.537 | 0.106 [0.076, 0.138] | [0.009, 0.061] | 0.276 [0.236, 0.316] | 0.492 |
| SAST board + fusion + context cascade (trained on dev) | 0.622 | 0.179 | 0.109 | 0.535 | 0.100 [0.069, 0.132] | [0.001, 0.057] | 0.278 [0.236, 0.317] | 0.667 |
| LLM only, whole function, no SAST | 0.558 | 0.310 | 0.245 | 0.532 | 0.072 [0.047, 0.102] | [-0.029, 0.030] | 0.399 [0.367, 0.431] | 0.924 |
| LLM only, dev-tuned threshold | 0.559 | 0.311 | 0.245 | 0.533 | 0.073 [0.049, 0.103] | [-0.027, 0.031] | 0.400 [0.367, 0.432] | 0.887 |
| LLM only + same-file context, no SAST | 0.569 | 0.303 | 0.230 | 0.537 | 0.084 [0.058, 0.112] | [-0.017, 0.045] | 0.396 [0.360, 0.430] | 0.604 |
| LLM only + context, dev-tuned threshold | 0.587 | 0.280 | 0.198 | 0.541 | 0.097 [0.069, 0.130] | [-0.003, 0.058] | 0.380 [0.343, 0.417] | 0.352 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 299 | 0 |
| SAST board (LLM only where static analysis flagged) | 536 | 958.0 | 245 | 7,836 |
| LLM only, whole function, no SAST | 2004 | 1,052.3 | 312 | 6,759 |
| LLM only + same-file context, no SAST | 2004 | 1,213.7 | 281 | 8,656 |


**On functions static analysis flagged** (536: 299 vulnerable, 237 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.558 | 1.000 | 1.000 | 0.000 | 0.716 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.558 | 1.000 | 1.000 | 0.000 | 0.716 | — | — |
| Semgrep alone | 0.630 | 0.364 | 0.270 | 0.100 | 0.462 | 73.0% | 36.4% |
| Bandit alone | 0.572 | 0.743 | 0.700 | 0.047 | 0.646 | 30.0% | 74.2% |
| AST sink gate alone | 0.583 | 0.495 | 0.447 | 0.048 | 0.535 | 55.3% | 49.5% |
| SAST board: Judge vote | 0.584 | 0.886 | 0.797 | 0.122 | 0.704 | 20.2% | 88.6% |
| SAST board + evidence override (ablation) | 0.568 | 0.980 | 0.941 | 0.102 | 0.719 | 5.9% | 98.0% |
| SAST board: vote score, dev-tuned threshold | 0.592 | 0.819 | 0.713 | 0.126 | 0.687 | 28.7% | 81.9% |
| SAST board + fusion (trained on dev) | 0.632 | 0.592 | 0.435 | 0.157 | 0.611 | 56.5% | 59.2% |
| SAST board + fusion + context cascade (trained on dev) | 0.632 | 0.592 | 0.435 | 0.157 | 0.611 | 56.5% | 59.2% |
| LLM only, whole function, no SAST | 0.608 | 0.659 | 0.536 | 0.125 | 0.632 | 46.4% | 65.9% |
| LLM only, dev-tuned threshold | 0.608 | 0.659 | 0.536 | 0.125 | 0.632 | 46.4% | 65.9% |
| LLM only + same-file context, no SAST | 0.623 | 0.645 | 0.494 | 0.153 | 0.634 | 50.6% | 64.5% |
| LLM only + context, dev-tuned threshold | 0.657 | 0.609 | 0.401 | 0.207 | 0.632 | 59.9% | 60.9% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 1002 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 1002 | 0.076 [0.056, 0.098] | 0.223 | 0.688 | 0.014 | 0.090 | 0.844 |
| Semgrep alone | 1002 | 0.050 [0.033, 0.069] | 0.059 | 0.886 | 0.005 | 0.055 | 0.909 |
| Bandit alone | 1002 | 0.066 [0.047, 0.087] | 0.156 | 0.768 | 0.010 | 0.076 | 0.868 |
| AST sink gate alone | 1002 | 0.049 [0.034, 0.067] | 0.099 | 0.845 | 0.007 | 0.056 | 0.875 |
| SAST board: Judge vote | 1002 | 0.091 [0.070, 0.114] | 0.174 | 0.721 | 0.015 | 0.106 | 0.859 |
| SAST board + evidence override (ablation) | 1002 | 0.086 [0.066, 0.108] | 0.207 | 0.692 | 0.016 | 0.102 | 0.843 |
| SAST board: vote score, dev-tuned threshold | 1002 | 0.095 [0.074, 0.118] | 0.150 | 0.737 | 0.019 | 0.114 | 0.833 |
| SAST board + fusion (trained on dev) | 1002 | 0.088 [0.068, 0.111] | 0.089 | 0.809 | 0.014 | 0.102 | 0.863 |
| SAST board + fusion + context cascade (trained on dev) | 1002 | 0.089 [0.068, 0.112] | 0.090 | 0.802 | 0.019 | 0.108 | 0.824 |
| LLM only, whole function, no SAST | 1002 | 0.089 [0.069, 0.112] | 0.222 | 0.666 | 0.024 | 0.113 | 0.788 |
| LLM only, dev-tuned threshold | 1002 | 0.090 [0.070, 0.112] | 0.222 | 0.665 | 0.024 | 0.114 | 0.789 |
| LLM only + same-file context, no SAST | 1002 | 0.095 [0.074, 0.117] | 0.209 | 0.676 | 0.021 | 0.116 | 0.819 |
| LLM only + context, dev-tuned threshold | 1002 | 0.109 [0.087, 0.132] | 0.172 | 0.694 | 0.026 | 0.135 | 0.807 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.993 | 0.993 |
| SAST board + fusion (trained on dev) | 0.989 | 0.890 |
| SAST board + fusion + context cascade (trained on dev) | 0.989 | 0.890 |
| LLM only, whole function, no SAST | 1.000 | 0.987 |
| LLM only, dev-tuned threshold | 1.000 | 0.987 |
| LLM only + same-file context, no SAST | 1.000 | 0.987 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.987 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | sast MCC / R | semgrep MCC / R | bandit MCC / R | board_calibrated MCC / R | fusion MCC / R | cascade MCC / R | llm_only_calibrated MCC / R | llm_context_calibrated MCC / R |
|---|---|---|---|---|---|---|---|---|---|---|
| **logic_semantic** | 916 | 16.2% | 0.006 / 0.162 | 0.018 / 0.037 | 0.017 / 0.129 | 0.018 / 0.107 | 0.034 / 0.061 | 0.034 / 0.061 | 0.031 / 0.124 | 0.041 / 0.109 |
| **sast_reachable** | 1088 | 41.4% | 0.115 / 0.414 | 0.115 / 0.169 | 0.108 / 0.300 | 0.143 / 0.360 | 0.151 / 0.274 | 0.140 / 0.278 | 0.106 / 0.469 | 0.138 / 0.425 |
| injection | 600 | 43.3% | 0.135 / 0.433 | 0.124 / 0.200 | 0.132 / 0.383 | 0.160 / 0.400 | 0.187 / 0.337 | 0.177 / 0.343 | 0.087 / 0.507 | 0.146 / 0.477 |
| access_control (logic) | 306 | 17.0% | 0.000 / 0.170 | 0.018 / 0.039 | 0.019 / 0.137 | -0.029 / 0.118 | 0.043 / 0.065 | 0.043 / 0.065 | 0.010 / 0.131 | 0.000 / 0.111 |
| path_traversal | 190 | 36.8% | 0.113 / 0.368 | 0.074 / 0.063 | 0.078 / 0.158 | 0.181 / 0.284 | 0.123 / 0.137 | 0.103 / 0.137 | 0.206 / 0.400 | 0.229 / 0.358 |
| info_exposure (logic) | 168 | 15.5% | 0.017 / 0.155 | 0.000 / 0.059 | 0.038 / 0.119 | 0.000 / 0.107 | -0.022 / 0.071 | -0.022 / 0.071 | 0.067 / 0.095 | 0.079 / 0.071 |
| ssrf_redirect | 152 | 34.2% | 0.057 / 0.342 | 0.072 / 0.184 | -0.022 / 0.092 | 0.074 / 0.303 | 0.052 / 0.197 | 0.052 / 0.197 | 0.083 / 0.395 | 0.044 / 0.303 |
| other (logic) | 142 | 14.1% | 0.000 / 0.141 | 0.049 / 0.028 | 0.023 / 0.113 | 0.055 / 0.085 | 0.087 / 0.085 | 0.087 / 0.085 | 0.023 / 0.113 | 0.055 / 0.085 |
| input_validation (logic) | 140 | 12.9% | 0.045 / 0.129 | 0.000 / 0.043 | 0.051 / 0.100 | 0.087 / 0.086 | 0.061 / 0.071 | 0.061 / 0.071 | 0.058 / 0.186 | 0.060 / 0.171 |
| resource_dos (logic) | 106 | 9.4% | 0.000 / 0.094 | 0.000 / 0.000 | -0.044 / 0.038 | 0.000 / 0.057 | 0.000 / 0.000 | 0.000 / 0.000 | 0.044 / 0.057 | 0.134 / 0.075 |
| crypto_secrets | 82 | 24.4% | 0.000 / 0.244 | 0.000 / 0.000 | 0.000 / 0.146 | 0.000 / 0.098 | 0.044 / 0.098 | 0.000 / 0.098 | 0.030 / 0.220 | 0.069 / 0.171 |
| deserialization | 36 | 94.4% | 0.298 / 0.944 | 0.447 / 0.667 | 0.405 / 0.833 | 0.134 / 0.833 | 0.471 / 0.889 | 0.471 / 0.889 | 0.298 / 0.944 | 0.298 / 0.944 |
| memory_numeric (logic) | 28 | 57.1% | -0.073 / 0.571 | 0.000 / 0.000 | -0.073 / 0.571 | 0.229 / 0.429 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| xml | 28 | 50.0% | 0.219 / 0.500 | 0.000 / 0.000 | 0.247 / 0.357 | 0.382 / 0.500 | -0.193 / 0.000 | -0.193 / 0.000 | 0.144 / 0.643 | 0.072 / 0.500 |
| unknown (logic) | 26 | 23.1% | 0.000 / 0.231 | 0.200 / 0.077 | 0.000 / 0.231 | 0.000 / 0.077 | 0.000 / 0.077 | 0.000 / 0.077 | 0.000 / 0.385 | 0.000 / 0.385 |

### Pipeline telemetry (test)

- flagged_functions: 536
- findings: 1029
- findings_per_flagged_function: 1.92
- by_tool: {'ast_sink': 308, 'bandit': 483, 'semgrep': 238}
- cpg_success_rate: 1.0
- cpg_taint_found_rate: 0.724
- cpg_unfiltered_taint_rate: 0.4383
- cpg_sanitized_taint_rate: 0.3547
- rag_context_rate: 1.0
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **function_board**: functions 536, mean_valid_votes 1.0, unanimous_rate 1.0, split_vote_rate 0.0, no_valid_vote_rate 0.0, majority_not_vulnerable_rate 0.153, evidence_grounded_rate 0.0616, evidence_reasons {'conceded': 461, 'no_span_match': 42, 'span_match': 33}, guard_grounded_rate 0.0, override_flip_rate 0.1157, code_truncated_rate 0.0, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0, defender_parse_failed_rate 0.0, mean_seconds_per_function 47.0
- **llm_baselines**: llm_only_parse_failed_rate 0.001, llm_only_vulnerable_rate 0.2779, llm_context_parse_failed_rate 0.0, llm_context_vulnerable_rate 0.2665

## Test, clean subset (single-function fixes)

### clean — 676 functions, 338 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.098, -0.031] | 1.000 | — | — | 0.363 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.062 [0.031, 0.098] | — | 0.001 | 0.531 | 0.005 | — | 1.24 | 0.061 / 0.012 |
| Semgrep alone | +0.062 [0.038, 0.091] | [-0.038, 0.033] | 4e-05 | — | — | 1.000 | 2.00 | 0.095 / 0.020 |
| Bandit alone | +0.059 [0.029, 0.093] | [-0.023, 0.017] | 0.001 | — | — | 1.000 | 1.31 | 0.064 / 0.013 |
| AST sink gate alone | +0.059 [0.032, 0.090] | [-0.035, 0.031] | 0.00035 | — | — | 1.000 | 1.74 | 0.084 / 0.017 |
| SAST board: Judge vote | +0.095 [0.062, 0.130] | [0.015, 0.051] | 1.9e-06 | 0.541 | 0.00018 | 1.000 | 1.54 | 0.075 / 0.015 |
| SAST board + evidence override (ablation) | +0.077 [0.042, 0.113] | [0.000, 0.030] | 0.00035 | — | — | 1.000 | 1.32 | 0.065 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.098 [0.066, 0.137] | [0.014, 0.060] | 2.2e-06 | 0.562 | 2.5e-06 | 1.000 | 1.63 | 0.079 / 0.016 |
| SAST board + fusion (trained on dev) | +0.106 [0.070, 0.147] | [0.010, 0.080] | 1.2e-06 | 0.567 | 0.00016 | 1.000 | 2.12 | 0.101 / 0.021 |
| SAST board + fusion + context cascade (trained on dev) | +0.101 [0.064, 0.138] | [0.003, 0.075] | 5e-06 | 0.555 | 0.021 | 1.000 | 2.00 | 0.095 / 0.020 |
| LLM only, whole function, no SAST | +0.074 [0.043, 0.106] | [-0.029, 0.051] | 5.5e-05 | 0.540 | 0.040 | 1.000 | 1.30 | 0.064 / 0.013 |
| LLM only, dev-tuned threshold | +0.077 [0.045, 0.110] | [-0.027, 0.054] | 4e-05 | 0.540 | 0.040 | 1.000 | 1.32 | 0.065 / 0.013 |
| LLM only + same-file context, no SAST | +0.089 [0.056, 0.123] | [-0.018, 0.068] | 2e-07 | 0.530 | 0.094 | 1.000 | 1.42 | 0.070 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.092 [0.056, 0.131] | [-0.016, 0.077] | 1.4e-06 | 0.530 | 0.094 | 1.000 | 1.48 | 0.072 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.107, -0.034] | 0.667 [0.667, 0.667] | 0.363 |
| Semgrep + Bandit + AST Gate | 0.554 | 0.317 | 0.254 | 0.531 | 0.069 [0.034, 0.107] | — | 0.403 [0.360, 0.443] | — |
| Semgrep alone | 0.667 | 0.124 | 0.062 | 0.531 | 0.107 [0.069, 0.153] | [-0.010, 0.085] | 0.209 [0.162, 0.258] | 1.000 |
| Bandit alone | 0.567 | 0.252 | 0.192 | 0.530 | 0.071 [0.035, 0.111] | [-0.020, 0.026] | 0.348 [0.299, 0.390] | 1.000 |
| AST sink gate alone | 0.635 | 0.139 | 0.080 | 0.530 | 0.095 [0.051, 0.142] | [-0.016, 0.073] | 0.228 [0.177, 0.284] | 1.000 |
| SAST board: Judge vote | 0.607 | 0.269 | 0.175 | 0.547 | 0.114 [0.075, 0.154] | [0.024, 0.067] | 0.373 [0.325, 0.421] | 0.126 |
| SAST board + evidence override (ablation) | 0.570 | 0.314 | 0.237 | 0.538 | 0.086 [0.047, 0.126] | [0.001, 0.035] | 0.405 [0.361, 0.446] | 0.125 |
| SAST board: vote score, dev-tuned threshold | 0.620 | 0.252 | 0.154 | 0.549 | 0.121 [0.081, 0.170] | [0.025, 0.083] | 0.358 [0.308, 0.406] | 0.141 |
| SAST board + fusion (trained on dev) | 0.680 | 0.201 | 0.095 | 0.553 | 0.150 [0.099, 0.207] | [0.037, 0.130] | 0.310 [0.261, 0.364] | 0.146 |
| SAST board + fusion + context cascade (trained on dev) | 0.667 | 0.201 | 0.101 | 0.550 | 0.141 [0.090, 0.196] | [0.026, 0.121] | 0.309 [0.260, 0.363] | 0.218 |
| LLM only, whole function, no SAST | 0.566 | 0.317 | 0.243 | 0.537 | 0.082 [0.049, 0.118] | [-0.032, 0.056] | 0.406 [0.359, 0.454] | 0.814 |
| LLM only, dev-tuned threshold | 0.568 | 0.320 | 0.243 | 0.538 | 0.086 [0.052, 0.123] | [-0.031, 0.059] | 0.409 [0.363, 0.456] | 0.754 |
| LLM only + same-file context, no SAST | 0.587 | 0.299 | 0.210 | 0.544 | 0.102 [0.065, 0.140] | [-0.018, 0.080] | 0.396 [0.346, 0.449] | 0.534 |
| LLM only + context, dev-tuned threshold | 0.598 | 0.281 | 0.189 | 0.546 | 0.108 [0.068, 0.153] | [-0.015, 0.093] | 0.382 [0.329, 0.437] | 0.493 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 107 | 0 |
| SAST board (LLM only where static analysis flagged) | 193 | 1,040.0 | 85 | 8,271 |
| LLM only, whole function, no SAST | 676 | 1,108.6 | 108 | 6,939 |
| LLM only + same-file context, no SAST | 676 | 1,265.9 | 95 | 9,008 |


**On functions static analysis flagged** (193: 107 vulnerable, 86 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.554 | 1.000 | 1.000 | 0.000 | 0.713 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.554 | 1.000 | 1.000 | 0.000 | 0.713 | — | — |
| Semgrep alone | 0.667 | 0.393 | 0.244 | 0.157 | 0.494 | 75.6% | 39.2% |
| Bandit alone | 0.567 | 0.794 | 0.756 | 0.046 | 0.661 | 24.4% | 79.4% |
| AST sink gate alone | 0.635 | 0.439 | 0.314 | 0.128 | 0.519 | 68.6% | 43.9% |
| SAST board: Judge vote | 0.607 | 0.851 | 0.686 | 0.196 | 0.708 | 31.4% | 85.0% |
| SAST board + evidence override (ablation) | 0.570 | 0.991 | 0.930 | 0.161 | 0.724 | 7.0% | 99.1% |
| SAST board: vote score, dev-tuned threshold | 0.620 | 0.794 | 0.605 | 0.208 | 0.697 | 39.5% | 79.4% |
| SAST board + fusion (trained on dev) | 0.680 | 0.635 | 0.372 | 0.262 | 0.657 | 62.8% | 63.5% |
| SAST board + fusion + context cascade (trained on dev) | 0.680 | 0.635 | 0.372 | 0.262 | 0.657 | 62.8% | 63.5% |
| LLM only, whole function, no SAST | 0.627 | 0.645 | 0.477 | 0.169 | 0.636 | 52.3% | 64.5% |
| LLM only, dev-tuned threshold | 0.627 | 0.645 | 0.477 | 0.169 | 0.636 | 52.3% | 64.5% |
| LLM only + same-file context, no SAST | 0.660 | 0.617 | 0.395 | 0.220 | 0.638 | 60.5% | 61.7% |
| LLM only + context, dev-tuned threshold | 0.700 | 0.589 | 0.314 | 0.274 | 0.640 | 68.6% | 58.9% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 338 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 338 | 0.086 [0.059, 0.117] | 0.231 | 0.660 | 0.024 | 0.110 | 0.784 |
| Semgrep alone | 338 | 0.065 [0.042, 0.094] | 0.059 | 0.873 | 0.003 | 0.068 | 0.957 |
| Bandit alone | 338 | 0.077 [0.051, 0.107] | 0.175 | 0.731 | 0.018 | 0.095 | 0.812 |
| AST sink gate alone | 338 | 0.068 [0.043, 0.098] | 0.071 | 0.852 | 0.009 | 0.077 | 0.885 |
| SAST board: Judge vote | 338 | 0.106 [0.076, 0.139] | 0.163 | 0.719 | 0.012 | 0.118 | 0.900 |
| SAST board + evidence override (ablation) | 338 | 0.104 [0.076, 0.137] | 0.210 | 0.660 | 0.027 | 0.130 | 0.795 |
| SAST board: vote score, dev-tuned threshold | 338 | 0.112 [0.082, 0.148] | 0.139 | 0.734 | 0.015 | 0.127 | 0.884 |
| SAST board + fusion (trained on dev) | 338 | 0.124 [0.091, 0.160] | 0.077 | 0.781 | 0.018 | 0.142 | 0.875 |
| SAST board + fusion + context cascade (trained on dev) | 338 | 0.121 [0.089, 0.157] | 0.080 | 0.778 | 0.021 | 0.142 | 0.854 |
| LLM only, whole function, no SAST | 338 | 0.086 [0.058, 0.119] | 0.231 | 0.672 | 0.012 | 0.098 | 0.879 |
| LLM only, dev-tuned threshold | 338 | 0.089 [0.061, 0.123] | 0.231 | 0.669 | 0.012 | 0.101 | 0.882 |
| LLM only + same-file context, no SAST | 338 | 0.092 [0.060, 0.126] | 0.207 | 0.698 | 0.003 | 0.095 | 0.969 |
| LLM only + context, dev-tuned threshold | 338 | 0.101 [0.068, 0.139] | 0.180 | 0.710 | 0.009 | 0.110 | 0.919 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.991 | 0.991 |
| SAST board + fusion (trained on dev) | 0.994 | 0.858 |
| SAST board + fusion + context cascade (trained on dev) | 0.994 | 0.858 |
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
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.383, -0.153] | 1.000 | — | — | 0.011 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.266 [0.153, 0.383] | — | 7.6e-06 | 0.633 | 4.8e-06 | — | 1.57 | 0.076 / 0.016 |
| Semgrep alone | +0.317 [0.193, 0.460] | [-0.053, 0.167] | 7.7e-07 | — | — | 1.000 | 2.47 | 0.115 / 0.024 |
| Bandit alone | +0.240 [0.129, 0.366] | [-0.090, 0.043] | 2.7e-05 | — | — | 1.000 | 1.76 | 0.085 / 0.018 |
| AST sink gate alone | +0.165 [0.071, 0.263] | [-0.220, 0.016] | 0.003 | — | — | 1.000 | 1.81 | 0.087 / 0.018 |
| SAST board: Judge vote | +0.304 [0.184, 0.423] | [-0.013, 0.099] | 7.2e-06 | 0.652 | 4.8e-06 | 1.000 | 1.80 | 0.086 / 0.018 |
| SAST board + evidence override (ablation) | +0.266 [0.143, 0.385] | [-0.038, 0.038] | 3.4e-05 | — | — | 1.000 | 1.58 | 0.077 / 0.016 |
| SAST board: vote score, dev-tuned threshold | +0.317 [0.198, 0.436] | [-0.000, 0.112] | 7.7e-07 | 0.703 | 5.3e-07 | 1.000 | 1.93 | 0.092 / 0.019 |
| SAST board + fusion (trained on dev) | +0.354 [0.229, 0.488] | [-0.000, 0.185] | 2.5e-06 | 0.753 | 2.1e-07 | 1.000 | 2.33 | 0.109 / 0.023 |
| SAST board + fusion + context cascade (trained on dev) | +0.367 [0.240, 0.506] | [0.011, 0.205] | 1.4e-06 | 0.753 | 3.2e-06 | 1.000 | 2.38 | 0.111 / 0.024 |
| LLM only, whole function, no SAST | +0.165 [0.064, 0.274] | [-0.243, 0.029] | 0.003 | 0.601 | 0.010 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only, dev-tuned threshold | +0.165 [0.064, 0.274] | [-0.243, 0.029] | 0.003 | 0.601 | 0.010 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.215 [0.108, 0.330] | [-0.193, 0.096] | 0.00033 | 0.639 | 0.001 | 1.000 | 1.53 | 0.075 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.240 [0.130, 0.382] | [-0.172, 0.141] | 0.00033 | 0.639 | 0.001 | 1.000 | 1.76 | 0.085 / 0.018 |

### ReposVul static check did not match — 646 functions, 323 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.062, 0.000] | 1.000 | — | — | 0.724 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.028 [0.000, 0.062] | — | 0.318 | 0.514 | 0.445 | — | 1.15 | 0.057 / 0.011 |
| Semgrep alone | -0.003 [-0.011, 0.000] | [-0.065, -0.003] | 1.000 | — | — | 1.000 | 0.90 | 0.045 / 0.009 |
| Bandit alone | +0.022 [0.000, 0.050] | [-0.027, 0.013] | 0.474 | — | — | 1.000 | 1.18 | 0.058 / 0.012 |
| AST sink gate alone | +0.028 [0.008, 0.053] | [-0.020, 0.019] | 0.105 | — | — | 1.000 | 1.31 | 0.065 / 0.013 |
| SAST board: Judge vote | +0.043 [0.015, 0.076] | [0.004, 0.029] | 0.033 | 0.519 | 0.152 | 1.000 | 1.32 | 0.065 / 0.013 |
| SAST board + evidence override (ablation) | +0.037 [0.008, 0.073] | [0.000, 0.022] | 0.135 | — | — | 1.000 | 1.21 | 0.060 / 0.012 |
| SAST board: vote score, dev-tuned threshold | +0.043 [0.013, 0.078] | [-0.003, 0.035] | 0.073 | 0.522 | 0.231 | 1.000 | 1.38 | 0.068 / 0.014 |
| SAST board + fusion (trained on dev) | +0.019 [-0.003, 0.044] | [-0.036, 0.015] | 0.539 | 0.517 | 1.000 | 1.000 | 1.27 | 0.063 / 0.013 |
| SAST board + fusion + context cascade (trained on dev) | +0.019 [-0.003, 0.044] | [-0.036, 0.015] | 0.539 | 0.483 | 1.000 | 1.000 | 1.27 | 0.063 / 0.013 |
| LLM only, whole function, no SAST | +0.037 [0.000, 0.074] | [-0.033, 0.048] | 0.214 | 0.495 | 1.000 | 1.000 | 1.19 | 0.059 / 0.012 |
| LLM only, dev-tuned threshold | +0.040 [0.000, 0.077] | [-0.030, 0.050] | 0.169 | 0.495 | 1.000 | 1.000 | 1.20 | 0.060 / 0.012 |
| LLM only + same-file context, no SAST | +0.046 [0.009, 0.089] | [-0.019, 0.057] | 0.071 | 0.483 | 1.000 | 1.000 | 1.24 | 0.061 / 0.012 |
| LLM only + context, dev-tuned threshold | +0.050 [0.012, 0.089] | [-0.017, 0.059] | 0.090 | 0.483 | 1.000 | 1.000 | 1.29 | 0.064 / 0.013 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | FPR | Accuracy | MCC | F1 |
|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| Semgrep + Bandit + AST Gate | 0.577 | 0.239 | 0.175 | 0.532 | 0.079 | 0.338 |
| Semgrep alone | 0.611 | 0.088 | 0.056 | 0.516 | 0.062 | 0.153 |
| Bandit alone | 0.621 | 0.163 | 0.100 | 0.532 | 0.094 | 0.259 |
| AST sink gate alone | 0.622 | 0.092 | 0.056 | 0.518 | 0.069 | 0.160 |
| SAST board: Judge vote | 0.667 | 0.199 | 0.100 | 0.550 | 0.140 | 0.307 |
| SAST board + evidence override (ablation) | 0.620 | 0.227 | 0.139 | 0.544 | 0.113 | 0.332 |
| SAST board: vote score, dev-tuned threshold | 0.692 | 0.179 | 0.080 | 0.550 | 0.148 | 0.285 |
| SAST board + fusion (trained on dev) | 0.838 | 0.123 | 0.024 | 0.550 | 0.191 | 0.215 |
| SAST board + fusion + context cascade (trained on dev) | 0.850 | 0.136 | 0.024 | 0.556 | 0.206 | 0.234 |
| LLM only, whole function, no SAST | 0.639 | 0.275 | 0.155 | 0.560 | 0.145 | 0.384 |
| LLM only, dev-tuned threshold | 0.642 | 0.279 | 0.155 | 0.562 | 0.150 | 0.389 |
| LLM only + same-file context, no SAST | 0.639 | 0.247 | 0.139 | 0.554 | 0.136 | 0.356 |
| LLM only + context, dev-tuned threshold | 0.655 | 0.227 | 0.119 | 0.554 | 0.142 | 0.337 |

## Caveats

- Labels follow the fix-commit convention (CVEfixes, PrimeVul): a function changed by a security-fix commit is vulnerable before the fix and fixed after it. Tangled commits (> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded; the clean subset further keeps only commits that changed a single function.
- The SAST board only reasons about Semgrep and Bandit findings, so its recall cannot exceed theirs. The sast_flagged view isolates what the board adds on the functions it is asked to review.
- The LLM-only rows ask the same model once, with no static findings: the function alone, and the function plus same-file callers and callees. They are comparison baselines, not part of the shipped pipeline. They never see the dataset label or CWE. Context is limited to the same file.
- Token counts are Ollama's prompt_eval_count plus eval_count. Tokens per true positive divides the tokens spent on that system by the true positives of its dev-tuned threshold.
- Board thresholds and fusion models are fitted on the dev split only (maximising mcc); test repositories never appear in dev. Dev numbers are in-sample and are shown for reference.
- Test and dev are balanced by construction (one vulnerable and one fixed function per pair), so F1 rewards flagging everything: compare every row with the trivial reference, and read MCC, accuracy and the pairwise columns for discrimination. 'Right way round' is the share of pairs with differing verdicts where the vulnerable version is the flagged one; 0.5 means no signal.
- Confidence intervals resample whole repositories (1,000 draws), since pairs from one project are not independent. McNemar compares per-function correctness against SAST. Sign-test and McNemar p values in the signal tables are Holm-corrected across the systems compared.
- Precision at a given prevalence is TPR·π / (TPR·π + FPR·(1 − π)): what a user would see if that share of functions were vulnerable, instead of the 50% this test set has by construction.
- VUDENC commits are keyword-mined and noisier than CVE-linked CVEfixes commits; compare within, not across, datasets.
- ReposVul files are kept by its 'llm' label policy (llm = its LLM untangling check marks the file as vulnerability-fixing; strict = its LLM and static checks both do), and patches it marks as outdated are skipped. Its static check is Semgrep/RATS, so the 'static check matched' stratum favours SAST by construction, and its LLM check may favour fixes an LLM recognises.
