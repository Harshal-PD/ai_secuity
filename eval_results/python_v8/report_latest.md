# HackerSec real-world evaluation (2026-10-23T20:01:50)

Status: **complete** — 2506/2506 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v8-precision-codeql`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| cvefixes | 100 (52) | 400 (133) | 154 |
| reposvul | 101 (44) | 402 (156) | 218 |
| vudenc | 50 (27) | 200 (103) | 90 |

- Dev functions evaluated: 502
- Board threshold on mean P(vulnerable) across Judge votes: **0.800** (max mcc on dev)
- Fusion: trained on 107 flagged dev functions (5-fold CV C=1.0, max mcc), threshold 0.616, dev CV F1 0.250, dev CV MCC 0.202
- LLM-only threshold on P(vulnerable): **0.200** (max mcc on dev)
- LLM-only + context threshold on P(vulnerable): **0.900** (max mcc on dev)
- Cascade unflagged context threshold on P(vulnerable): **1.000** (max mcc on dev)

Each pair contributes one vulnerable and one fixed function, so flagging every function scores F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise columns show whether a system actually separates vulnerable from fixed code.

## Test split (primary)

### cvefixes — 800 functions, 400 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.094, -0.033] | 1.000 | — | — | 0.323 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.062 [0.033, 0.094] | — | 0.00077 | 0.531 | 0.00052 | — | 1.27 | 0.063 / 0.013 |
| Semgrep alone | +0.040 [0.019, 0.065] | [-0.053, 0.008] | 0.001 | — | — | 1.000 | 1.64 | 0.080 / 0.016 |
| Bandit alone | +0.045 [0.018, 0.076] | [-0.045, 0.009] | 0.002 | — | — | 1.000 | 1.28 | 0.063 / 0.013 |
| AST sink gate alone | +0.022 [0.000, 0.048] | [-0.070, -0.009] | 0.064 | — | — | 1.000 | 1.24 | 0.061 / 0.012 |
| CodeQL alone | +0.040 [0.017, 0.071] | [-0.056, 0.010] | 0.00037 | — | — | 1.000 | 3.00 | 0.136 / 0.029 |
| SAST board: Judge vote | +0.065 [0.034, 0.101] | [-0.019, 0.030] | 0.001 | 0.542 | 4.8e-05 | 1.000 | 1.46 | 0.071 / 0.015 |
| SAST board + evidence override (ablation) | +0.075 [0.044, 0.109] | [-0.006, 0.033] | 7.4e-05 | — | — | 1.000 | 1.38 | 0.068 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.060 [0.027, 0.100] | [-0.032, 0.033] | 0.002 | 0.544 | 0.00076 | 1.000 | 1.50 | 0.073 / 0.015 |
| SAST board + fusion (trained on dev) | +0.072 [0.039, 0.113] | [-0.022, 0.046] | 0.00012 | 0.554 | 0.00052 | 1.000 | 1.66 | 0.080 / 0.017 |
| SAST board + fusion + context cascade (trained on dev) | +0.065 [0.032, 0.104] | [-0.030, 0.039] | 0.001 | 0.536 | 0.191 | 1.000 | 1.55 | 0.076 / 0.015 |
| LLM only, whole function, no SAST | +0.058 [0.022, 0.096] | [-0.049, 0.041] | 0.002 | 0.529 | 0.191 | 1.000 | 1.27 | 0.063 / 0.013 |
| LLM only, dev-tuned threshold | +0.058 [0.022, 0.096] | [-0.049, 0.041] | 0.002 | 0.529 | 0.191 | 1.000 | 1.27 | 0.063 / 0.013 |
| LLM only + same-file context, no SAST | +0.052 [0.021, 0.087] | [-0.053, 0.033] | 0.004 | 0.510 | 1.000 | 1.000 | 1.25 | 0.062 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.060 [0.023, 0.096] | [-0.048, 0.039] | 0.002 | 0.510 | 1.000 | 1.000 | 1.34 | 0.066 / 0.013 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.106, -0.038] | 0.667 [0.667, 0.667] | 0.323 |
| Semgrep + Bandit + AST Gate | 0.559 | 0.295 | 0.233 | 0.531 | 0.071 [0.038, 0.106] | — | 0.386 [0.337, 0.432] | — |
| Semgrep alone | 0.621 | 0.102 | 0.062 | 0.520 | 0.073 [0.036, 0.116] | [-0.041, 0.046] | 0.176 [0.124, 0.240] | 0.507 |
| Bandit alone | 0.562 | 0.205 | 0.160 | 0.522 | 0.058 [0.023, 0.097] | [-0.045, 0.019] | 0.300 [0.238, 0.356] | 0.457 |
| AST sink gate alone | 0.553 | 0.117 | 0.095 | 0.511 | 0.036 [0.000, 0.076] | [-0.073, 0.005] | 0.194 [0.137, 0.254] | 0.181 |
| CodeQL alone | 0.750 | 0.060 | 0.020 | 0.520 | 0.102 [0.052, 0.159] | [-0.020, 0.087] | 0.111 [0.064, 0.173] | 0.550 |
| SAST board: Judge vote | 0.593 | 0.207 | 0.142 | 0.532 | 0.086 [0.045, 0.130] | [-0.014, 0.048] | 0.307 [0.249, 0.365] | 1.000 |
| SAST board + evidence override (ablation) | 0.580 | 0.273 | 0.198 | 0.537 | 0.088 [0.053, 0.126] | [-0.004, 0.041] | 0.371 [0.317, 0.422] | 0.405 |
| SAST board: vote score, dev-tuned threshold | 0.600 | 0.180 | 0.120 | 0.530 | 0.084 [0.038, 0.134] | [-0.025, 0.058] | 0.277 [0.217, 0.339] | 1.000 |
| SAST board + fusion (trained on dev) | 0.624 | 0.182 | 0.110 | 0.536 | 0.103 [0.059, 0.153] | [-0.009, 0.075] | 0.282 [0.219, 0.348] | 0.757 |
| SAST board + fusion + context cascade (trained on dev) | 0.608 | 0.182 | 0.117 | 0.532 | 0.091 [0.047, 0.141] | [-0.021, 0.066] | 0.281 [0.218, 0.346] | 1.000 |
| LLM only, whole function, no SAST | 0.560 | 0.268 | 0.210 | 0.529 | 0.067 [0.026, 0.111] | [-0.054, 0.050] | 0.362 [0.303, 0.420] | 0.942 |
| LLM only, dev-tuned threshold | 0.560 | 0.268 | 0.210 | 0.529 | 0.067 [0.026, 0.111] | [-0.054, 0.050] | 0.362 [0.303, 0.420] | 0.942 |
| LLM only + same-file context, no SAST | 0.556 | 0.260 | 0.207 | 0.526 | 0.062 [0.024, 0.102] | [-0.060, 0.040] | 0.354 [0.291, 0.414] | 0.828 |
| LLM only + context, dev-tuned threshold | 0.573 | 0.235 | 0.175 | 0.530 | 0.074 [0.028, 0.119] | [-0.052, 0.055] | 0.333 [0.269, 0.395] | 1.000 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 118 | 0 |
| SAST board (LLM only where static analysis flagged) | 211 | 942.0 | 72 | 10,467 |
| LLM only, whole function, no SAST | 800 | 983.1 | 107 | 7,351 |
| LLM only + same-file context, no SAST | 800 | 1,125.4 | 94 | 9,578 |


**On functions static analysis flagged** (211: 118 vulnerable, 93 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.559 | 1.000 | 1.000 | 0.000 | 0.717 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.559 | 1.000 | 1.000 | 0.000 | 0.717 | — | — |
| Semgrep alone | 0.621 | 0.347 | 0.269 | 0.084 | 0.446 | 73.1% | 34.8% |
| Bandit alone | 0.562 | 0.695 | 0.688 | 0.007 | 0.621 | 31.2% | 69.5% |
| AST sink gate alone | 0.553 | 0.398 | 0.409 | -0.010 | 0.463 | 59.1% | 39.8% |
| CodeQL alone | 0.750 | 0.203 | 0.086 | 0.163 | 0.320 | 91.4% | 20.3% |
| SAST board: Judge vote | 0.593 | 0.703 | 0.613 | 0.095 | 0.643 | 38.7% | 70.3% |
| SAST board + evidence override (ablation) | 0.580 | 0.924 | 0.850 | 0.118 | 0.712 | 15.0% | 92.4% |
| SAST board: vote score, dev-tuned threshold | 0.600 | 0.610 | 0.516 | 0.094 | 0.605 | 48.4% | 61.0% |
| SAST board + fusion (trained on dev) | 0.624 | 0.619 | 0.473 | 0.145 | 0.621 | 52.7% | 61.9% |
| SAST board + fusion + context cascade (trained on dev) | 0.624 | 0.619 | 0.473 | 0.145 | 0.621 | 52.7% | 61.9% |
| LLM only, whole function, no SAST | 0.617 | 0.559 | 0.441 | 0.118 | 0.587 | 55.9% | 55.9% |
| LLM only, dev-tuned threshold | 0.617 | 0.559 | 0.441 | 0.118 | 0.587 | 55.9% | 55.9% |
| LLM only + same-file context, no SAST | 0.635 | 0.559 | 0.409 | 0.150 | 0.595 | 59.1% | 55.9% |
| LLM only + context, dev-tuned threshold | 0.678 | 0.517 | 0.312 | 0.206 | 0.587 | 68.8% | 51.7% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 400 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 400 | 0.080 [0.053, 0.111] | 0.215 | 0.688 | 0.018 | 0.098 | 0.821 |
| Semgrep alone | 400 | 0.043 [0.020, 0.067] | 0.060 | 0.895 | 0.003 | 0.045 | 0.944 |
| Bandit alone | 400 | 0.055 [0.031, 0.083] | 0.150 | 0.785 | 0.010 | 0.065 | 0.846 |
| AST sink gate alone | 400 | 0.035 [0.018, 0.055] | 0.083 | 0.870 | 0.013 | 0.048 | 0.737 |
| CodeQL alone | 400 | 0.040 [0.017, 0.071] | 0.020 | 0.940 | 0.000 | 0.040 | 1.000 |
| SAST board: Judge vote | 400 | 0.087 [0.059, 0.120] | 0.120 | 0.770 | 0.022 | 0.110 | 0.795 |
| SAST board + evidence override (ablation) | 400 | 0.092 [0.064, 0.124] | 0.180 | 0.710 | 0.018 | 0.110 | 0.841 |
| SAST board: vote score, dev-tuned threshold | 400 | 0.085 [0.054, 0.119] | 0.095 | 0.795 | 0.025 | 0.110 | 0.773 |
| SAST board + fusion (trained on dev) | 400 | 0.090 [0.059, 0.127] | 0.092 | 0.800 | 0.018 | 0.107 | 0.837 |
| SAST board + fusion + context cascade (trained on dev) | 400 | 0.087 [0.055, 0.123] | 0.095 | 0.795 | 0.022 | 0.110 | 0.795 |
| LLM only, whole function, no SAST | 400 | 0.077 [0.048, 0.110] | 0.190 | 0.713 | 0.020 | 0.098 | 0.795 |
| LLM only, dev-tuned threshold | 400 | 0.077 [0.048, 0.110] | 0.190 | 0.713 | 0.020 | 0.098 | 0.795 |
| LLM only + same-file context, no SAST | 400 | 0.080 [0.052, 0.116] | 0.180 | 0.713 | 0.028 | 0.107 | 0.744 |
| LLM only + context, dev-tuned threshold | 400 | 0.090 [0.061, 0.124] | 0.145 | 0.735 | 0.030 | 0.120 | 0.750 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.998 | 0.998 |
| SAST board + fusion (trained on dev) | 0.968 | 0.887 |
| SAST board + fusion + context cascade (trained on dev) | 0.968 | 0.887 |
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
| Semgrep alone | +0.060 [0.030, 0.093] | [-0.062, 0.011] | 5.8e-06 | — | — | 1.000 | 1.89 | 0.090 / 0.019 |
| Bandit alone | +0.065 [0.035, 0.098] | [-0.044, 0.003] | 2.5e-05 | — | — | 1.000 | 1.41 | 0.069 / 0.014 |
| AST sink gate alone | +0.055 [0.028, 0.083] | [-0.068, 0.008] | 3.1e-05 | — | — | 1.000 | 1.49 | 0.073 / 0.015 |
| CodeQL alone | +0.052 [0.028, 0.081] | [-0.069, 0.006] | 5.8e-06 | — | — | 1.000 | 2.05 | 0.097 / 0.020 |
| SAST board: Judge vote | +0.129 [0.088, 0.170] | [0.020, 0.071] | 3.3e-10 | 0.566 | 2.9e-10 | 0.643 | 1.85 | 0.089 / 0.018 |
| SAST board + evidence override (ablation) | +0.114 [0.076, 0.156] | [0.008, 0.053] | 4.9e-10 | — | — | 0.295 | 1.51 | 0.073 / 0.015 |
| SAST board: vote score, dev-tuned threshold | +0.122 [0.079, 0.164] | [0.009, 0.068] | 3.8e-09 | 0.573 | 2.1e-09 | 1.000 | 1.86 | 0.089 / 0.018 |
| SAST board + fusion (trained on dev) | +0.119 [0.073, 0.171] | [0.004, 0.073] | 4.5e-08 | 0.585 | 9e-09 | 1.000 | 2.07 | 0.098 / 0.020 |
| SAST board + fusion + context cascade (trained on dev) | +0.124 [0.077, 0.174] | [0.007, 0.077] | 1.7e-08 | 0.562 | 0.003 | 1.000 | 2.11 | 0.100 / 0.021 |
| LLM only, whole function, no SAST | +0.057 [0.019, 0.093] | [-0.078, 0.015] | 0.00036 | 0.517 | 0.987 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only, dev-tuned threshold | +0.060 [0.022, 0.096] | [-0.075, 0.018] | 0.00036 | 0.517 | 0.987 | 1.000 | 1.24 | 0.061 / 0.012 |
| LLM only + same-file context, no SAST | +0.082 [0.044, 0.121] | [-0.052, 0.044] | 5.8e-06 | 0.514 | 0.987 | 1.000 | 1.35 | 0.067 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.090 [0.050, 0.129] | [-0.041, 0.051] | 5.8e-06 | 0.514 | 0.987 | 1.000 | 1.46 | 0.071 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.131, -0.053] | 0.667 [0.667, 0.667] | 0.160 |
| Semgrep + Bandit + AST Gate | 0.568 | 0.356 | 0.271 | 0.542 | 0.091 [0.053, 0.131] | — | 0.437 [0.393, 0.478] | — |
| Semgrep alone | 0.654 | 0.127 | 0.067 | 0.530 | 0.101 [0.054, 0.151] | [-0.040, 0.060] | 0.212 [0.160, 0.267] | 0.495 |
| Bandit alone | 0.584 | 0.224 | 0.159 | 0.532 | 0.082 [0.044, 0.122] | [-0.035, 0.018] | 0.324 [0.275, 0.369] | 0.480 |
| AST sink gate alone | 0.598 | 0.167 | 0.112 | 0.527 | 0.079 [0.042, 0.116] | [-0.056, 0.032] | 0.261 [0.204, 0.318] | 0.353 |
| CodeQL alone | 0.672 | 0.102 | 0.050 | 0.526 | 0.099 [0.054, 0.144] | [-0.039, 0.058] | 0.177 [0.120, 0.240] | 0.385 |
| SAST board: Judge vote | 0.649 | 0.281 | 0.152 | 0.565 | 0.157 [0.108, 0.203] | [0.035, 0.098] | 0.392 [0.343, 0.442] | 0.054 |
| SAST board + evidence override (ablation) | 0.601 | 0.341 | 0.226 | 0.557 | 0.127 [0.084, 0.172] | [0.011, 0.063] | 0.435 [0.388, 0.481] | 0.023 |
| SAST board: vote score, dev-tuned threshold | 0.650 | 0.264 | 0.142 | 0.561 | 0.152 [0.100, 0.200] | [0.027, 0.098] | 0.375 [0.323, 0.427] | 0.137 |
| SAST board + fusion (trained on dev) | 0.674 | 0.231 | 0.112 | 0.560 | 0.158 [0.101, 0.218] | [0.027, 0.113] | 0.344 [0.285, 0.408] | 0.223 |
| SAST board + fusion + context cascade (trained on dev) | 0.679 | 0.236 | 0.112 | 0.562 | 0.164 [0.106, 0.222] | [0.029, 0.118] | 0.351 [0.291, 0.413] | 0.163 |
| LLM only, whole function, no SAST | 0.551 | 0.311 | 0.254 | 0.529 | 0.064 [0.022, 0.104] | [-0.083, 0.019] | 0.398 [0.341, 0.448] | 0.481 |
| LLM only, dev-tuned threshold | 0.553 | 0.313 | 0.254 | 0.530 | 0.066 [0.025, 0.107] | [-0.080, 0.022] | 0.400 [0.344, 0.452] | 0.527 |
| LLM only + same-file context, no SAST | 0.575 | 0.313 | 0.231 | 0.541 | 0.092 [0.049, 0.135] | [-0.054, 0.052] | 0.406 [0.348, 0.459] | 1.000 |
| LLM only + context, dev-tuned threshold | 0.594 | 0.284 | 0.194 | 0.545 | 0.105 [0.058, 0.152] | [-0.038, 0.065] | 0.384 [0.327, 0.441] | 0.945 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 143 | 0 |
| SAST board (LLM only where static analysis flagged) | 252 | 1,136.5 | 106 | 8,620 |
| LLM only, whole function, no SAST | 804 | 1,054.8 | 126 | 6,730 |
| LLM only + same-file context, no SAST | 804 | 1,217.7 | 114 | 8,588 |


**On functions static analysis flagged** (252: 143 vulnerable, 109 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.568 | 1.000 | 1.000 | 0.000 | 0.724 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.568 | 1.000 | 1.000 | 0.000 | 0.724 | — | — |
| Semgrep alone | 0.654 | 0.357 | 0.248 | 0.117 | 0.462 | 75.2% | 35.7% |
| Bandit alone | 0.584 | 0.629 | 0.587 | 0.043 | 0.606 | 41.3% | 62.9% |
| AST sink gate alone | 0.598 | 0.469 | 0.413 | 0.056 | 0.525 | 58.7% | 46.9% |
| CodeQL alone | 0.672 | 0.287 | 0.183 | 0.119 | 0.402 | 81.7% | 28.7% |
| SAST board: Judge vote | 0.649 | 0.790 | 0.560 | 0.247 | 0.713 | 44.0% | 79.0% |
| SAST board + evidence override (ablation) | 0.601 | 0.958 | 0.835 | 0.208 | 0.739 | 16.5% | 95.8% |
| SAST board: vote score, dev-tuned threshold | 0.650 | 0.741 | 0.523 | 0.226 | 0.693 | 47.7% | 74.1% |
| SAST board + fusion (trained on dev) | 0.674 | 0.650 | 0.413 | 0.236 | 0.662 | 58.7% | 65.0% |
| SAST board + fusion + context cascade (trained on dev) | 0.674 | 0.650 | 0.413 | 0.236 | 0.662 | 58.7% | 65.0% |
| LLM only, whole function, no SAST | 0.626 | 0.608 | 0.477 | 0.131 | 0.617 | 52.3% | 60.8% |
| LLM only, dev-tuned threshold | 0.626 | 0.608 | 0.477 | 0.131 | 0.617 | 52.3% | 60.8% |
| LLM only + same-file context, no SAST | 0.644 | 0.608 | 0.440 | 0.167 | 0.626 | 56.0% | 60.8% |
| LLM only + context, dev-tuned threshold | 0.678 | 0.559 | 0.349 | 0.209 | 0.613 | 65.1% | 55.9% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 402 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 402 | 0.095 [0.062, 0.130] | 0.261 | 0.634 | 0.010 | 0.104 | 0.905 |
| Semgrep alone | 402 | 0.062 [0.035, 0.096] | 0.065 | 0.871 | 0.003 | 0.065 | 0.962 |
| Bandit alone | 402 | 0.075 [0.047, 0.107] | 0.149 | 0.766 | 0.010 | 0.085 | 0.882 |
| AST sink gate alone | 402 | 0.060 [0.035, 0.087] | 0.107 | 0.828 | 0.005 | 0.065 | 0.923 |
| CodeQL alone | 402 | 0.052 [0.028, 0.081] | 0.050 | 0.898 | 0.000 | 0.052 | 1.000 |
| SAST board: Judge vote | 402 | 0.147 [0.110, 0.185] | 0.134 | 0.702 | 0.017 | 0.164 | 0.894 |
| SAST board + evidence override (ablation) | 402 | 0.124 [0.089, 0.164] | 0.216 | 0.649 | 0.010 | 0.134 | 0.926 |
| SAST board: vote score, dev-tuned threshold | 402 | 0.142 [0.105, 0.179] | 0.122 | 0.716 | 0.020 | 0.162 | 0.877 |
| SAST board + fusion (trained on dev) | 402 | 0.147 [0.108, 0.192] | 0.085 | 0.741 | 0.027 | 0.174 | 0.843 |
| SAST board + fusion + context cascade (trained on dev) | 402 | 0.152 [0.113, 0.196] | 0.085 | 0.736 | 0.027 | 0.179 | 0.847 |
| LLM only, whole function, no SAST | 402 | 0.077 [0.049, 0.108] | 0.234 | 0.669 | 0.020 | 0.097 | 0.795 |
| LLM only, dev-tuned threshold | 402 | 0.080 [0.052, 0.112] | 0.234 | 0.667 | 0.020 | 0.100 | 0.800 |
| LLM only + same-file context, no SAST | 402 | 0.100 [0.068, 0.134] | 0.214 | 0.669 | 0.017 | 0.117 | 0.851 |
| LLM only + context, dev-tuned threshold | 402 | 0.112 [0.077, 0.149] | 0.172 | 0.694 | 0.022 | 0.134 | 0.833 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 1.000 | 1.000 |
| SAST board + fusion (trained on dev) | 0.975 | 0.866 |
| SAST board + fusion + context cascade (trained on dev) | 0.975 | 0.866 |
| LLM only, whole function, no SAST | 1.000 | 0.985 |
| LLM only, dev-tuned threshold | 1.000 | 0.985 |
| LLM only + same-file context, no SAST | 0.985 | 0.985 |
| LLM only + context, dev-tuned threshold | 0.985 | 0.985 |

### vudenc — 400 functions, 200 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.131, -0.011] | 1.000 | — | — | 0.479 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.065 [0.011, 0.131] | — | 0.013 | 0.532 | 0.012 | — | 1.26 | 0.062 / 0.013 |
| Semgrep alone | +0.025 [-0.010, 0.064] | [-0.107, 0.021] | 0.453 | — | — | 1.000 | 1.42 | 0.069 / 0.014 |
| Bandit alone | +0.060 [0.006, 0.126] | [-0.023, 0.011] | 0.013 | — | — | 1.000 | 1.32 | 0.065 / 0.013 |
| AST sink gate alone | +0.055 [0.015, 0.104] | [-0.063, 0.034] | 0.007 | — | — | 1.000 | 1.48 | 0.072 / 0.015 |
| CodeQL alone | +0.010 [-0.006, 0.031] | [-0.117, -0.000] | 0.625 | — | — | 1.000 | 1.20 | 0.059 / 0.012 |
| SAST board: Judge vote | +0.115 [0.053, 0.185] | [0.020, 0.086] | 0.0002 | 0.557 | 0.00013 | 0.577 | 1.68 | 0.081 / 0.017 |
| SAST board + evidence override (ablation) | +0.100 [0.043, 0.168] | [0.010, 0.066] | 0.00037 | — | — | 0.203 | 1.47 | 0.072 / 0.015 |
| SAST board: vote score, dev-tuned threshold | +0.115 [0.054, 0.189] | [0.015, 0.088] | 0.0002 | 0.568 | 0.00013 | 0.872 | 1.74 | 0.084 / 0.017 |
| SAST board + fusion (trained on dev) | +0.130 [0.062, 0.206] | [0.023, 0.115] | 3.6e-05 | 0.578 | 0.00046 | 0.421 | 1.96 | 0.094 / 0.019 |
| SAST board + fusion + context cascade (trained on dev) | +0.120 [0.048, 0.199] | [0.005, 0.115] | 0.00063 | 0.585 | 0.002 | 0.890 | 1.80 | 0.086 / 0.018 |
| LLM only, whole function, no SAST | +0.090 [0.029, 0.160] | [-0.022, 0.074] | 0.013 | 0.540 | 0.161 | 1.000 | 1.31 | 0.065 / 0.013 |
| LLM only, dev-tuned threshold | +0.090 [0.029, 0.160] | [-0.022, 0.074] | 0.013 | 0.540 | 0.161 | 1.000 | 1.31 | 0.065 / 0.013 |
| LLM only + same-file context, no SAST | +0.105 [0.049, 0.172] | [-0.000, 0.083] | 0.00083 | 0.540 | 0.161 | 1.000 | 1.40 | 0.069 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.115 [0.058, 0.180] | [0.005, 0.095] | 0.00037 | 0.540 | 0.161 | 1.000 | 1.47 | 0.072 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.143, -0.013] | 0.667 [0.667, 0.667] | 0.479 |
| Semgrep + Bandit + AST Gate | 0.557 | 0.315 | 0.250 | 0.532 | 0.072 [0.013, 0.143] | — | 0.403 [0.328, 0.476] | — |
| Semgrep alone | 0.586 | 0.085 | 0.060 | 0.512 | 0.048 [-0.020, 0.125] | [-0.115, 0.067] | 0.148 [0.077, 0.226] | 0.445 |
| Bandit alone | 0.568 | 0.250 | 0.190 | 0.530 | 0.072 [0.007, 0.147] | [-0.021, 0.021] | 0.347 [0.260, 0.429] | 1.000 |
| AST sink gate alone | 0.597 | 0.170 | 0.115 | 0.527 | 0.079 [0.023, 0.147] | [-0.052, 0.058] | 0.265 [0.172, 0.350] | 0.894 |
| CodeQL alone | 0.545 | 0.060 | 0.050 | 0.505 | 0.022 [-0.019, 0.068] | [-0.126, 0.017] | 0.108 [0.039, 0.186] | 0.294 |
| SAST board: Judge vote | 0.626 | 0.285 | 0.170 | 0.557 | 0.137 [0.064, 0.215] | [0.028, 0.106] | 0.392 [0.302, 0.478] | 0.052 |
| SAST board + evidence override (ablation) | 0.594 | 0.315 | 0.215 | 0.550 | 0.113 [0.048, 0.188] | [0.012, 0.076] | 0.412 [0.334, 0.489] | 0.016 |
| SAST board: vote score, dev-tuned threshold | 0.635 | 0.270 | 0.155 | 0.557 | 0.141 [0.067, 0.223] | [0.027, 0.118] | 0.379 [0.290, 0.470] | 0.087 |
| SAST board + fusion (trained on dev) | 0.662 | 0.265 | 0.135 | 0.565 | 0.163 [0.086, 0.247] | [0.037, 0.146] | 0.379 [0.282, 0.470] | 0.035 |
| SAST board + fusion + context cascade (trained on dev) | 0.643 | 0.270 | 0.150 | 0.560 | 0.147 [0.063, 0.233] | [0.014, 0.142] | 0.380 [0.290, 0.471] | 0.099 |
| LLM only, whole function, no SAST | 0.567 | 0.380 | 0.290 | 0.545 | 0.095 [0.031, 0.170] | [-0.027, 0.076] | 0.455 [0.379, 0.526] | 0.635 |
| LLM only, dev-tuned threshold | 0.567 | 0.380 | 0.290 | 0.545 | 0.095 [0.031, 0.170] | [-0.027, 0.076] | 0.455 [0.379, 0.526] | 0.635 |
| LLM only + same-file context, no SAST | 0.583 | 0.370 | 0.265 | 0.552 | 0.113 [0.052, 0.183] | [-0.007, 0.088] | 0.453 [0.382, 0.524] | 0.410 |
| LLM only + context, dev-tuned threshold | 0.595 | 0.360 | 0.245 | 0.557 | 0.125 [0.064, 0.194] | [0.002, 0.102] | 0.449 [0.377, 0.525] | 0.302 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 63 | 0 |
| SAST board (LLM only where static analysis flagged) | 113 | 951.5 | 54 | 7,048 |
| LLM only, whole function, no SAST | 400 | 871.8 | 76 | 4,588 |
| LLM only + same-file context, no SAST | 400 | 1,001.4 | 72 | 5,563 |


**On functions static analysis flagged** (113: 63 vulnerable, 50 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.557 | 1.000 | 1.000 | 0.000 | 0.716 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.557 | 1.000 | 1.000 | 0.000 | 0.716 | — | — |
| Semgrep alone | 0.586 | 0.270 | 0.240 | 0.034 | 0.370 | 76.0% | 27.0% |
| Bandit alone | 0.568 | 0.794 | 0.760 | 0.040 | 0.662 | 24.0% | 79.4% |
| AST sink gate alone | 0.597 | 0.540 | 0.460 | 0.079 | 0.567 | 54.0% | 54.0% |
| CodeQL alone | 0.545 | 0.191 | 0.200 | -0.012 | 0.282 | 80.0% | 19.1% |
| SAST board: Judge vote | 0.626 | 0.905 | 0.680 | 0.282 | 0.740 | 32.0% | 90.5% |
| SAST board + evidence override (ablation) | 0.594 | 1.000 | 0.860 | 0.288 | 0.746 | 14.0% | 100.0% |
| SAST board: vote score, dev-tuned threshold | 0.635 | 0.857 | 0.620 | 0.273 | 0.730 | 38.0% | 85.7% |
| SAST board + fusion (trained on dev) | 0.662 | 0.841 | 0.540 | 0.329 | 0.741 | 46.0% | 84.1% |
| SAST board + fusion + context cascade (trained on dev) | 0.662 | 0.841 | 0.540 | 0.329 | 0.741 | 46.0% | 84.1% |
| LLM only, whole function, no SAST | 0.591 | 0.825 | 0.720 | 0.126 | 0.689 | 28.0% | 82.5% |
| LLM only, dev-tuned threshold | 0.591 | 0.825 | 0.720 | 0.126 | 0.689 | 28.0% | 82.5% |
| LLM only + same-file context, no SAST | 0.595 | 0.794 | 0.680 | 0.129 | 0.680 | 32.0% | 79.4% |
| LLM only + context, dev-tuned threshold | 0.620 | 0.778 | 0.600 | 0.193 | 0.690 | 40.0% | 77.8% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 200 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 200 | 0.075 [0.025, 0.137] | 0.240 | 0.675 | 0.010 | 0.085 | 0.882 |
| Semgrep alone | 200 | 0.040 [0.015, 0.072] | 0.045 | 0.900 | 0.015 | 0.055 | 0.727 |
| Bandit alone | 200 | 0.070 [0.019, 0.133] | 0.180 | 0.740 | 0.010 | 0.080 | 0.875 |
| AST sink gate alone | 200 | 0.055 [0.015, 0.104] | 0.115 | 0.830 | 0.000 | 0.055 | 1.000 |
| CodeQL alone | 200 | 0.015 [0.000, 0.035] | 0.045 | 0.935 | 0.005 | 0.020 | 0.750 |
| SAST board: Judge vote | 200 | 0.130 [0.070, 0.204] | 0.155 | 0.700 | 0.015 | 0.145 | 0.897 |
| SAST board + evidence override (ablation) | 200 | 0.110 [0.055, 0.178] | 0.205 | 0.675 | 0.010 | 0.120 | 0.917 |
| SAST board: vote score, dev-tuned threshold | 200 | 0.130 [0.071, 0.201] | 0.140 | 0.715 | 0.015 | 0.145 | 0.897 |
| SAST board + fusion (trained on dev) | 200 | 0.145 [0.082, 0.216] | 0.120 | 0.720 | 0.015 | 0.160 | 0.906 |
| SAST board + fusion + context cascade (trained on dev) | 200 | 0.150 [0.085, 0.223] | 0.120 | 0.700 | 0.030 | 0.180 | 0.833 |
| LLM only, whole function, no SAST | 200 | 0.125 [0.070, 0.189] | 0.255 | 0.585 | 0.035 | 0.160 | 0.781 |
| LLM only, dev-tuned threshold | 200 | 0.125 [0.070, 0.189] | 0.255 | 0.585 | 0.035 | 0.160 | 0.781 |
| LLM only + same-file context, no SAST | 200 | 0.125 [0.073, 0.185] | 0.245 | 0.610 | 0.020 | 0.145 | 0.862 |
| LLM only + context, dev-tuned threshold | 200 | 0.135 [0.082, 0.196] | 0.225 | 0.620 | 0.020 | 0.155 | 0.871 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.995 | 0.995 |
| SAST board + fusion (trained on dev) | 1.000 | 0.935 |
| SAST board + fusion + context cascade (trained on dev) | 1.000 | 0.935 |
| LLM only, whole function, no SAST | 1.000 | 0.980 |
| LLM only, dev-tuned threshold | 1.000 | 0.980 |
| LLM only + same-file context, no SAST | 1.000 | 1.000 |
| LLM only + context, dev-tuned threshold | 1.000 | 1.000 |

### combined — 2004 functions, 1002 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.096, -0.049] | 1.000 | — | — | 0.060 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.072 [0.049, 0.096] | — | 3.6e-13 | 0.536 | 2.4e-13 | — | 1.29 | 0.063 / 0.013 |
| Semgrep alone | +0.045 [0.028, 0.065] | [-0.050, -0.006] | 8.5e-10 | — | — | 1.000 | 1.70 | 0.082 / 0.017 |
| Bandit alone | +0.056 [0.035, 0.079] | [-0.030, -0.003] | 1.8e-10 | — | — | 1.000 | 1.34 | 0.066 / 0.013 |
| AST sink gate alone | +0.042 [0.025, 0.061] | [-0.052, -0.010] | 7.5e-09 | — | — | 0.953 | 1.40 | 0.069 / 0.014 |
| CodeQL alone | +0.039 [0.024, 0.056] | [-0.056, -0.011] | 1.9e-10 | — | — | 0.953 | 2.03 | 0.096 / 0.020 |
| SAST board: Judge vote | +0.101 [0.075, 0.127] | [0.014, 0.044] | 5.2e-18 | 0.555 | 2.3e-19 | 0.383 | 1.66 | 0.081 / 0.017 |
| SAST board + evidence override (ablation) | +0.096 [0.072, 0.122] | [0.011, 0.037] | 6.5e-19 | — | — | 0.019 | 1.45 | 0.071 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.096 [0.070, 0.122] | [0.005, 0.043] | 2.6e-16 | 0.560 | 1.4e-16 | 0.953 | 1.71 | 0.082 / 0.017 |
| SAST board + fusion (trained on dev) | +0.103 [0.077, 0.132] | [0.010, 0.053] | 6.7e-18 | 0.571 | 7.2e-16 | 0.584 | 1.89 | 0.090 / 0.019 |
| SAST board + fusion + context cascade (trained on dev) | +0.100 [0.074, 0.128] | [0.006, 0.051] | 6e-16 | 0.556 | 1.4e-06 | 0.875 | 1.82 | 0.087 / 0.018 |
| LLM only, whole function, no SAST | +0.064 [0.042, 0.090] | [-0.035, 0.019] | 1.2e-09 | 0.526 | 0.011 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only, dev-tuned threshold | +0.065 [0.043, 0.091] | [-0.034, 0.020] | 1.1e-09 | 0.526 | 0.011 | 1.000 | 1.27 | 0.062 / 0.013 |
| LLM only + same-file context, no SAST | +0.075 [0.051, 0.100] | [-0.025, 0.030] | 1.4e-11 | 0.517 | 0.103 | 1.000 | 1.33 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.083 [0.059, 0.110] | [-0.015, 0.038] | 1.4e-12 | 0.517 | 0.103 | 1.000 | 1.42 | 0.070 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.107, -0.054] | 0.667 [0.667, 0.667] | 0.060 |
| Semgrep + Bandit + AST Gate | 0.562 | 0.323 | 0.252 | 0.536 | 0.079 [0.054, 0.107] | — | 0.411 [0.382, 0.439] | — |
| Semgrep alone | 0.630 | 0.109 | 0.064 | 0.522 | 0.080 [0.051, 0.112] | [-0.030, 0.033] | 0.185 [0.149, 0.224] | 0.195 |
| Bandit alone | 0.572 | 0.222 | 0.166 | 0.528 | 0.071 [0.045, 0.101] | [-0.025, 0.008] | 0.319 [0.285, 0.353] | 0.274 |
| AST sink gate alone | 0.583 | 0.148 | 0.106 | 0.521 | 0.063 [0.039, 0.091] | [-0.043, 0.010] | 0.236 [0.203, 0.269] | 0.106 |
| CodeQL alone | 0.670 | 0.077 | 0.038 | 0.519 | 0.084 [0.054, 0.116] | [-0.029, 0.035] | 0.138 [0.104, 0.176] | 0.136 |
| SAST board: Judge vote | 0.625 | 0.253 | 0.152 | 0.550 | 0.126 [0.096, 0.157] | [0.028, 0.065] | 0.360 [0.324, 0.394] | 0.032 |
| SAST board + evidence override (ablation) | 0.592 | 0.308 | 0.213 | 0.548 | 0.109 [0.083, 0.138] | [0.015, 0.045] | 0.406 [0.374, 0.435] | 0.001 |
| SAST board: vote score, dev-tuned threshold | 0.630 | 0.232 | 0.136 | 0.548 | 0.124 [0.092, 0.155] | [0.022, 0.068] | 0.339 [0.301, 0.374] | 0.111 |
| SAST board + fusion (trained on dev) | 0.654 | 0.219 | 0.116 | 0.551 | 0.138 [0.105, 0.172] | [0.032, 0.085] | 0.328 [0.291, 0.366] | 0.053 |
| SAST board + fusion + context cascade (trained on dev) | 0.645 | 0.222 | 0.122 | 0.550 | 0.132 [0.099, 0.168] | [0.025, 0.081] | 0.330 [0.293, 0.370] | 0.088 |
| LLM only, whole function, no SAST | 0.558 | 0.307 | 0.243 | 0.532 | 0.071 [0.047, 0.101] | [-0.039, 0.022] | 0.396 [0.363, 0.428] | 0.744 |
| LLM only, dev-tuned threshold | 0.559 | 0.308 | 0.243 | 0.532 | 0.073 [0.048, 0.102] | [-0.038, 0.024] | 0.397 [0.363, 0.429] | 0.780 |
| LLM only + same-file context, no SAST | 0.570 | 0.303 | 0.229 | 0.537 | 0.085 [0.058, 0.113] | [-0.027, 0.036] | 0.396 [0.360, 0.430] | 0.926 |
| LLM only + context, dev-tuned threshold | 0.587 | 0.279 | 0.197 | 0.541 | 0.097 [0.070, 0.127] | [-0.013, 0.049] | 0.379 [0.341, 0.415] | 0.648 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 324 | 0 |
| SAST board (LLM only where static analysis flagged) | 576 | 1,021.9 | 232 | 8,827 |
| LLM only, whole function, no SAST | 2004 | 989.6 | 309 | 6,418 |
| LLM only + same-file context, no SAST | 2004 | 1,137.7 | 280 | 8,142 |


**On functions static analysis flagged** (576: 324 vulnerable, 252 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.562 | 1.000 | 1.000 | 0.000 | 0.720 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.562 | 1.000 | 1.000 | 0.000 | 0.720 | — | — |
| Semgrep alone | 0.630 | 0.336 | 0.254 | 0.089 | 0.439 | 74.6% | 33.6% |
| Bandit alone | 0.572 | 0.685 | 0.659 | 0.028 | 0.624 | 34.1% | 68.5% |
| AST sink gate alone | 0.583 | 0.457 | 0.421 | 0.036 | 0.512 | 57.9% | 45.7% |
| CodeQL alone | 0.670 | 0.238 | 0.151 | 0.108 | 0.351 | 84.9% | 23.8% |
| SAST board: Judge vote | 0.625 | 0.781 | 0.603 | 0.193 | 0.694 | 39.7% | 78.1% |
| SAST board + evidence override (ablation) | 0.592 | 0.954 | 0.845 | 0.185 | 0.731 | 15.5% | 95.4% |
| SAST board: vote score, dev-tuned threshold | 0.630 | 0.716 | 0.540 | 0.182 | 0.670 | 46.0% | 71.6% |
| SAST board + fusion (trained on dev) | 0.654 | 0.676 | 0.460 | 0.217 | 0.665 | 54.0% | 67.6% |
| SAST board + fusion + context cascade (trained on dev) | 0.654 | 0.676 | 0.460 | 0.217 | 0.665 | 54.0% | 67.6% |
| LLM only, whole function, no SAST | 0.614 | 0.633 | 0.512 | 0.121 | 0.623 | 48.8% | 63.3% |
| LLM only, dev-tuned threshold | 0.614 | 0.633 | 0.512 | 0.121 | 0.623 | 48.8% | 63.3% |
| LLM only + same-file context, no SAST | 0.628 | 0.626 | 0.476 | 0.150 | 0.627 | 52.4% | 62.6% |
| LLM only + context, dev-tuned threshold | 0.662 | 0.586 | 0.385 | 0.200 | 0.622 | 61.5% | 58.6% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 1002 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 1002 | 0.085 [0.064, 0.108] | 0.238 | 0.664 | 0.013 | 0.098 | 0.867 |
| Semgrep alone | 1002 | 0.050 [0.033, 0.069] | 0.059 | 0.886 | 0.005 | 0.055 | 0.909 |
| Bandit alone | 1002 | 0.066 [0.047, 0.087] | 0.156 | 0.768 | 0.010 | 0.076 | 0.868 |
| AST sink gate alone | 1002 | 0.049 [0.034, 0.067] | 0.099 | 0.845 | 0.007 | 0.056 | 0.875 |
| CodeQL alone | 1002 | 0.040 [0.025, 0.057] | 0.037 | 0.922 | 0.001 | 0.041 | 0.976 |
| SAST board: Judge vote | 1002 | 0.120 [0.098, 0.144] | 0.133 | 0.729 | 0.019 | 0.139 | 0.863 |
| SAST board + evidence override (ablation) | 1002 | 0.109 [0.087, 0.133] | 0.200 | 0.679 | 0.013 | 0.122 | 0.893 |
| SAST board: vote score, dev-tuned threshold | 1002 | 0.117 [0.093, 0.141] | 0.115 | 0.748 | 0.021 | 0.138 | 0.848 |
| SAST board + fusion (trained on dev) | 1002 | 0.124 [0.099, 0.149] | 0.095 | 0.760 | 0.021 | 0.145 | 0.855 |
| SAST board + fusion + context cascade (trained on dev) | 1002 | 0.126 [0.101, 0.152] | 0.096 | 0.752 | 0.026 | 0.152 | 0.829 |
| LLM only, whole function, no SAST | 1002 | 0.087 [0.067, 0.109] | 0.221 | 0.670 | 0.023 | 0.110 | 0.791 |
| LLM only, dev-tuned threshold | 1002 | 0.088 [0.068, 0.110] | 0.221 | 0.669 | 0.023 | 0.111 | 0.793 |
| LLM only + same-file context, no SAST | 1002 | 0.097 [0.075, 0.119] | 0.207 | 0.675 | 0.022 | 0.119 | 0.815 |
| LLM only + context, dev-tuned threshold | 1002 | 0.108 [0.086, 0.130] | 0.172 | 0.696 | 0.025 | 0.133 | 0.812 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.998 | 0.998 |
| SAST board + fusion (trained on dev) | 0.966 | 0.887 |
| SAST board + fusion + context cascade (trained on dev) | 0.966 | 0.887 |
| LLM only, whole function, no SAST | 1.000 | 0.985 |
| LLM only, dev-tuned threshold | 1.000 | 0.985 |
| LLM only + same-file context, no SAST | 1.000 | 0.986 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.986 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | sast MCC / R | semgrep MCC / R | bandit MCC / R | board_calibrated MCC / R | fusion MCC / R | cascade MCC / R | llm_only_calibrated MCC / R | llm_context_calibrated MCC / R |
|---|---|---|---|---|---|---|---|---|---|---|
| **logic_semantic** | 916 | 18.3% | 0.020 / 0.183 | 0.018 / 0.037 | 0.017 / 0.129 | 0.031 / 0.096 | 0.033 / 0.083 | 0.037 / 0.085 | 0.034 / 0.124 | 0.044 / 0.109 |
| **sast_reachable** | 1088 | 44.1% | 0.123 / 0.441 | 0.115 / 0.169 | 0.108 / 0.300 | 0.183 / 0.346 | 0.203 / 0.333 | 0.193 / 0.336 | 0.103 / 0.463 | 0.136 / 0.423 |
| injection | 600 | 46.7% | 0.147 / 0.467 | 0.124 / 0.200 | 0.132 / 0.383 | 0.189 / 0.390 | 0.240 / 0.393 | 0.230 / 0.400 | 0.087 / 0.507 | 0.143 / 0.470 |
| access_control (logic) | 306 | 18.9% | 0.017 / 0.190 | 0.018 / 0.039 | 0.019 / 0.137 | 0.033 / 0.111 | 0.047 / 0.098 | 0.047 / 0.098 | 0.020 / 0.131 | 0.010 / 0.118 |
| path_traversal | 190 | 36.8% | 0.078 / 0.368 | 0.074 / 0.063 | 0.078 / 0.158 | 0.199 / 0.274 | 0.181 / 0.242 | 0.165 / 0.242 | 0.183 / 0.390 | 0.210 / 0.379 |
| info_exposure (logic) | 168 | 20.2% | 0.046 / 0.202 | 0.000 / 0.059 | 0.038 / 0.119 | 0.000 / 0.119 | 0.022 / 0.083 | 0.022 / 0.083 | 0.067 / 0.095 | 0.079 / 0.071 |
| ssrf_redirect | 152 | 36.8% | 0.084 / 0.368 | 0.072 / 0.184 | -0.022 / 0.092 | 0.132 / 0.250 | 0.120 / 0.224 | 0.120 / 0.224 | 0.097 / 0.395 | 0.059 / 0.303 |
| other (logic) | 142 | 14.1% | 0.000 / 0.141 | 0.049 / 0.028 | 0.023 / 0.113 | 0.079 / 0.099 | 0.029 / 0.070 | 0.029 / 0.070 | 0.023 / 0.113 | 0.061 / 0.070 |
| input_validation (logic) | 140 | 14.3% | 0.043 / 0.143 | 0.000 / 0.043 | 0.051 / 0.100 | 0.061 / 0.071 | 0.098 / 0.071 | 0.123 / 0.086 | 0.058 / 0.186 | 0.060 / 0.171 |
| resource_dos (logic) | 106 | 13.2% | 0.029 / 0.132 | 0.000 / 0.000 | -0.044 / 0.038 | 0.000 / 0.038 | -0.044 / 0.038 | -0.044 / 0.038 | 0.044 / 0.057 | 0.134 / 0.075 |
| crypto_secrets | 82 | 31.7% | 0.054 / 0.317 | 0.000 / 0.000 | 0.000 / 0.146 | 0.069 / 0.171 | 0.000 / 0.122 | -0.036 / 0.122 | 0.000 / 0.171 | 0.069 / 0.171 |
| deserialization | 36 | 94.4% | 0.298 / 0.944 | 0.447 / 0.667 | 0.405 / 0.833 | 0.507 / 0.833 | 0.570 / 0.889 | 0.570 / 0.889 | 0.298 / 0.944 | 0.211 / 0.889 |
| memory_numeric (logic) | 28 | 57.1% | -0.073 / 0.571 | 0.000 / 0.000 | -0.073 / 0.571 | 0.000 / 0.143 | 0.000 / 0.071 | 0.000 / 0.071 | 0.000 / 0.000 | 0.000 / 0.000 |
| xml | 28 | 50.0% | 0.219 / 0.500 | 0.000 / 0.000 | 0.247 / 0.357 | 0.174 / 0.286 | 0.000 / 0.143 | 0.000 / 0.143 | 0.144 / 0.643 | 0.144 / 0.500 |
| unknown (logic) | 26 | 23.1% | 0.000 / 0.231 | 0.200 / 0.077 | 0.000 / 0.231 | 0.000 / 0.077 | 0.000 / 0.231 | 0.000 / 0.231 | 0.000 / 0.385 | 0.000 / 0.385 |

### Pipeline telemetry (test)

- flagged_functions: 576
- findings: 1133
- findings_per_flagged_function: 1.97
- by_tool: {'ast_sink': 291, 'bandit': 474, 'codeql': 130, 'semgrep': 238}
- cpg_success_rate: 1.0
- cpg_taint_found_rate: 0.7167
- cpg_unfiltered_taint_rate: 0.6743
- cpg_sanitized_taint_rate: 0.1068
- rag_context_rate: 1.0
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **function_board**: functions 576, mean_valid_votes 1.0, unanimous_rate 1.0, split_vote_rate 0.0, no_valid_vote_rate 0.0, majority_not_vulnerable_rate 0.2969, evidence_grounded_rate 0.1198, evidence_reasons {'conceded': 424, 'no_span_match': 83, 'span_match': 69}, guard_grounded_rate 0.0, override_flip_rate 0.2031, code_truncated_rate 0.059, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0, defender_parse_failed_rate 0.0017, mean_seconds_per_function 53.9
- **llm_baselines**: llm_only_parse_failed_rate 0.001, llm_only_vulnerable_rate 0.2754, llm_context_parse_failed_rate 0.0, llm_context_vulnerable_rate 0.266

## Test, clean subset (single-function fixes)

### clean — 676 functions, 338 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.099, -0.032] | 1.000 | — | — | 0.332 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.065 [0.032, 0.099] | — | 0.001 | 0.532 | 0.002 | — | 1.24 | 0.061 / 0.012 |
| Semgrep alone | +0.062 [0.038, 0.091] | [-0.037, 0.029] | 5.7e-05 | — | — | 1.000 | 2.00 | 0.095 / 0.020 |
| Bandit alone | +0.059 [0.029, 0.093] | [-0.027, 0.015] | 0.001 | — | — | 1.000 | 1.31 | 0.064 / 0.013 |
| AST sink gate alone | +0.059 [0.032, 0.090] | [-0.040, 0.031] | 0.00062 | — | — | 1.000 | 1.74 | 0.084 / 0.017 |
| CodeQL alone | +0.027 [0.009, 0.047] | [-0.069, -0.009] | 0.012 | — | — | 1.000 | 1.69 | 0.082 / 0.017 |
| SAST board: Judge vote | +0.101 [0.065, 0.139] | [0.008, 0.063] | 3.7e-06 | 0.552 | 1.1e-05 | 1.000 | 1.63 | 0.079 / 0.016 |
| SAST board + evidence override (ablation) | +0.083 [0.050, 0.120] | [-0.000, 0.039] | 7.5e-05 | — | — | 1.000 | 1.34 | 0.066 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.095 [0.059, 0.134] | [-0.000, 0.062] | 2e-05 | 0.556 | 8.9e-05 | 1.000 | 1.64 | 0.080 / 0.016 |
| SAST board + fusion (trained on dev) | +0.089 [0.049, 0.130] | [-0.009, 0.058] | 0.00019 | 0.565 | 0.00016 | 1.000 | 1.71 | 0.083 / 0.017 |
| SAST board + fusion + context cascade (trained on dev) | +0.083 [0.043, 0.124] | [-0.017, 0.053] | 0.00062 | 0.556 | 0.015 | 1.000 | 1.64 | 0.079 / 0.016 |
| LLM only, whole function, no SAST | +0.062 [0.030, 0.096] | [-0.044, 0.037] | 0.001 | 0.540 | 0.040 | 1.000 | 1.25 | 0.062 / 0.013 |
| LLM only, dev-tuned threshold | +0.065 [0.032, 0.099] | [-0.042, 0.041] | 0.00098 | 0.540 | 0.040 | 1.000 | 1.27 | 0.062 / 0.013 |
| LLM only + same-file context, no SAST | +0.095 [0.061, 0.132] | [-0.014, 0.074] | 2.7e-07 | 0.535 | 0.040 | 1.000 | 1.46 | 0.071 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.095 [0.059, 0.135] | [-0.015, 0.080] | 8.7e-07 | 0.535 | 0.040 | 1.000 | 1.51 | 0.073 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.107, -0.036] | 0.667 [0.667, 0.667] | 0.332 |
| Semgrep + Bandit + AST Gate | 0.553 | 0.340 | 0.275 | 0.532 | 0.070 [0.036, 0.107] | — | 0.421 [0.379, 0.459] | — |
| Semgrep alone | 0.667 | 0.124 | 0.062 | 0.531 | 0.107 [0.069, 0.153] | [-0.007, 0.084] | 0.209 [0.162, 0.258] | 1.000 |
| Bandit alone | 0.567 | 0.252 | 0.192 | 0.530 | 0.071 [0.035, 0.111] | [-0.022, 0.025] | 0.348 [0.299, 0.390] | 0.896 |
| AST sink gate alone | 0.635 | 0.139 | 0.080 | 0.530 | 0.095 [0.051, 0.142] | [-0.020, 0.074] | 0.228 [0.177, 0.284] | 0.931 |
| CodeQL alone | 0.629 | 0.065 | 0.038 | 0.513 | 0.060 [0.021, 0.100] | [-0.051, 0.033] | 0.118 [0.076, 0.162] | 0.362 |
| SAST board: Judge vote | 0.620 | 0.260 | 0.160 | 0.550 | 0.123 [0.079, 0.169] | [0.021, 0.086] | 0.367 [0.317, 0.415] | 0.175 |
| SAST board + evidence override (ablation) | 0.572 | 0.328 | 0.246 | 0.541 | 0.092 [0.055, 0.131] | [0.001, 0.044] | 0.417 [0.373, 0.459] | 0.180 |
| SAST board: vote score, dev-tuned threshold | 0.621 | 0.243 | 0.148 | 0.547 | 0.119 [0.075, 0.168] | [0.011, 0.088] | 0.349 [0.298, 0.396] | 0.302 |
| SAST board + fusion (trained on dev) | 0.632 | 0.213 | 0.124 | 0.544 | 0.118 [0.066, 0.174] | [0.006, 0.093] | 0.319 [0.267, 0.371] | 0.470 |
| SAST board + fusion + context cascade (trained on dev) | 0.621 | 0.213 | 0.130 | 0.541 | 0.110 [0.057, 0.165] | [-0.007, 0.085] | 0.317 [0.266, 0.369] | 0.610 |
| LLM only, whole function, no SAST | 0.556 | 0.308 | 0.246 | 0.531 | 0.069 [0.033, 0.108] | [-0.047, 0.043] | 0.396 [0.350, 0.442] | 1.000 |
| LLM only, dev-tuned threshold | 0.558 | 0.311 | 0.246 | 0.532 | 0.073 [0.035, 0.110] | [-0.044, 0.047] | 0.399 [0.351, 0.445] | 1.000 |
| LLM only + same-file context, no SAST | 0.593 | 0.302 | 0.207 | 0.547 | 0.109 [0.070, 0.151] | [-0.011, 0.088] | 0.400 [0.350, 0.452] | 0.500 |
| LLM only + context, dev-tuned threshold | 0.601 | 0.281 | 0.186 | 0.547 | 0.112 [0.070, 0.157] | [-0.011, 0.096] | 0.383 [0.330, 0.436] | 0.509 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Static Gate (no LLM) | 0 | 0.0 | 115 | 0 |
| SAST board (LLM only where static analysis flagged) | 208 | 1,085.5 | 82 | 8,949 |
| LLM only, whole function, no SAST | 676 | 1,030.9 | 105 | 6,637 |
| LLM only + same-file context, no SAST | 676 | 1,167.9 | 95 | 8,310 |


**On functions static analysis flagged** (208: 115 vulnerable, 93 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.553 | 1.000 | 1.000 | 0.000 | 0.712 | 0.0% | 100.0% |
| Semgrep + Bandit + AST Gate | 0.553 | 1.000 | 1.000 | 0.000 | 0.712 | — | — |
| Semgrep alone | 0.667 | 0.365 | 0.226 | 0.151 | 0.472 | 77.4% | 36.5% |
| Bandit alone | 0.567 | 0.739 | 0.699 | 0.045 | 0.641 | 30.1% | 73.9% |
| AST sink gate alone | 0.635 | 0.409 | 0.290 | 0.123 | 0.497 | 71.0% | 40.9% |
| CodeQL alone | 0.629 | 0.191 | 0.140 | 0.069 | 0.293 | 86.0% | 19.1% |
| SAST board: Judge vote | 0.620 | 0.765 | 0.581 | 0.197 | 0.685 | 41.9% | 76.5% |
| SAST board + evidence override (ablation) | 0.572 | 0.965 | 0.892 | 0.144 | 0.718 | 10.8% | 96.5% |
| SAST board: vote score, dev-tuned threshold | 0.621 | 0.713 | 0.538 | 0.181 | 0.664 | 46.2% | 71.3% |
| SAST board + fusion (trained on dev) | 0.632 | 0.626 | 0.452 | 0.174 | 0.629 | 54.8% | 62.6% |
| SAST board + fusion + context cascade (trained on dev) | 0.632 | 0.626 | 0.452 | 0.174 | 0.629 | 54.8% | 62.6% |
| LLM only, whole function, no SAST | 0.625 | 0.609 | 0.452 | 0.157 | 0.617 | 54.8% | 60.9% |
| LLM only, dev-tuned threshold | 0.625 | 0.609 | 0.452 | 0.157 | 0.617 | 54.8% | 60.9% |
| LLM only + same-file context, no SAST | 0.673 | 0.591 | 0.355 | 0.235 | 0.630 | 64.5% | 59.1% |
| LLM only + context, dev-tuned threshold | 0.711 | 0.556 | 0.280 | 0.278 | 0.624 | 72.0% | 55.6% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 338 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit + AST Gate | 338 | 0.086 [0.060, 0.117] | 0.254 | 0.639 | 0.021 | 0.106 | 0.806 |
| Semgrep alone | 338 | 0.065 [0.042, 0.094] | 0.059 | 0.873 | 0.003 | 0.068 | 0.957 |
| Bandit alone | 338 | 0.077 [0.051, 0.107] | 0.175 | 0.731 | 0.018 | 0.095 | 0.812 |
| AST sink gate alone | 338 | 0.068 [0.043, 0.098] | 0.071 | 0.852 | 0.009 | 0.077 | 0.885 |
| CodeQL alone | 338 | 0.030 [0.012, 0.050] | 0.035 | 0.932 | 0.003 | 0.033 | 0.909 |
| SAST board: Judge vote | 338 | 0.118 [0.085, 0.155] | 0.142 | 0.722 | 0.018 | 0.136 | 0.870 |
| SAST board + evidence override (ablation) | 338 | 0.101 [0.072, 0.136] | 0.228 | 0.654 | 0.018 | 0.118 | 0.850 |
| SAST board: vote score, dev-tuned threshold | 338 | 0.115 [0.083, 0.152] | 0.127 | 0.737 | 0.021 | 0.136 | 0.848 |
| SAST board + fusion (trained on dev) | 338 | 0.118 [0.085, 0.157] | 0.095 | 0.757 | 0.030 | 0.148 | 0.800 |
| SAST board + fusion + context cascade (trained on dev) | 338 | 0.115 [0.082, 0.154] | 0.098 | 0.754 | 0.033 | 0.148 | 0.780 |
| LLM only, whole function, no SAST | 338 | 0.080 [0.053, 0.112] | 0.228 | 0.675 | 0.018 | 0.098 | 0.818 |
| LLM only, dev-tuned threshold | 338 | 0.083 [0.055, 0.115] | 0.228 | 0.672 | 0.018 | 0.101 | 0.824 |
| LLM only + same-file context, no SAST | 338 | 0.101 [0.069, 0.137] | 0.201 | 0.692 | 0.006 | 0.106 | 0.944 |
| LLM only + context, dev-tuned threshold | 338 | 0.104 [0.070, 0.142] | 0.177 | 0.710 | 0.009 | 0.112 | 0.921 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit + AST Gate | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.997 | 0.997 |
| SAST board + fusion (trained on dev) | 0.973 | 0.890 |
| SAST board + fusion + context cascade (trained on dev) | 0.973 | 0.890 |
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
| Semgrep + Bandit + AST Gate | +0.279 [0.169, 0.398] | — | 4.2e-06 | 0.639 | 2.4e-06 | — | 1.59 | 0.077 / 0.016 |
| Semgrep alone | +0.317 [0.193, 0.460] | [-0.072, 0.157] | 7.2e-07 | — | — | 1.000 | 2.47 | 0.115 / 0.024 |
| Bandit alone | +0.240 [0.129, 0.366] | [-0.110, 0.033] | 2.7e-05 | — | — | 1.000 | 1.76 | 0.085 / 0.018 |
| AST sink gate alone | +0.165 [0.071, 0.263] | [-0.239, 0.000] | 0.004 | — | — | 1.000 | 1.81 | 0.087 / 0.018 |
| CodeQL alone | +0.139 [0.055, 0.232] | [-0.289, 0.014] | 0.004 | — | — | 1.000 | 3.20 | 0.144 / 0.031 |
| SAST board: Judge vote | +0.380 [0.253, 0.500] | [0.024, 0.192] | 2.6e-08 | 0.703 | 3.7e-09 | 1.000 | 2.30 | 0.108 / 0.023 |
| SAST board + evidence override (ablation) | +0.317 [0.197, 0.432] | [-0.027, 0.114] | 7.2e-07 | — | — | 1.000 | 1.81 | 0.087 / 0.018 |
| SAST board: vote score, dev-tuned threshold | +0.342 [0.226, 0.462] | [-0.026, 0.167] | 1.9e-07 | 0.747 | 3.4e-10 | 1.000 | 2.23 | 0.105 / 0.022 |
| SAST board + fusion (trained on dev) | +0.342 [0.203, 0.481] | [-0.036, 0.159] | 4.2e-06 | 0.759 | 9.2e-08 | 1.000 | 2.59 | 0.120 / 0.025 |
| SAST board + fusion + context cascade (trained on dev) | +0.354 [0.212, 0.494] | [-0.026, 0.169] | 2.5e-06 | 0.766 | 6e-07 | 1.000 | 2.65 | 0.122 / 0.026 |
| LLM only, whole function, no SAST | +0.165 [0.064, 0.274] | [-0.258, 0.015] | 0.004 | 0.608 | 0.007 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only, dev-tuned threshold | +0.165 [0.064, 0.274] | [-0.258, 0.015] | 0.004 | 0.608 | 0.007 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.203 [0.103, 0.312] | [-0.212, 0.066] | 0.00072 | 0.639 | 0.00045 | 1.000 | 1.48 | 0.072 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.228 [0.128, 0.351] | [-0.190, 0.105] | 0.00024 | 0.639 | 0.00045 | 1.000 | 1.72 | 0.083 / 0.017 |

### ReposVul static check did not match — 646 functions, 323 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.071, -0.007] | 1.000 | — | — | 0.619 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit + AST Gate | +0.037 [0.007, 0.071] | — | 0.070 | 0.519 | 0.071 | — | 1.17 | 0.058 / 0.012 |
| Semgrep alone | -0.003 [-0.011, 0.000] | [-0.075, -0.011] | 1.000 | — | — | 1.000 | 0.90 | 0.045 / 0.009 |
| Bandit alone | +0.022 [0.000, 0.050] | [-0.039, 0.006] | 0.237 | — | — | 1.000 | 1.18 | 0.058 / 0.012 |
| AST sink gate alone | +0.028 [0.008, 0.053] | [-0.038, 0.021] | 0.070 | — | — | 1.000 | 1.31 | 0.065 / 0.013 |
| CodeQL alone | +0.031 [0.012, 0.052] | [-0.035, 0.022] | 0.018 | — | — | 1.000 | 1.67 | 0.081 / 0.017 |
| SAST board: Judge vote | +0.068 [0.031, 0.109] | [0.006, 0.058] | 0.004 | 0.532 | 0.007 | 1.000 | 1.58 | 0.077 / 0.016 |
| SAST board + evidence override (ablation) | +0.065 [0.030, 0.105] | [0.007, 0.052] | 0.001 | — | — | 0.457 | 1.35 | 0.066 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.068 [0.030, 0.113] | [0.003, 0.059] | 0.006 | 0.531 | 0.046 | 1.000 | 1.63 | 0.079 / 0.016 |
| SAST board + fusion (trained on dev) | +0.065 [0.025, 0.111] | [-0.006, 0.062] | 0.011 | 0.542 | 0.017 | 1.000 | 1.75 | 0.084 / 0.017 |
| SAST board + fusion + context cascade (trained on dev) | +0.068 [0.029, 0.114] | [-0.003, 0.064] | 0.007 | 0.512 | 1.000 | 1.000 | 1.79 | 0.086 / 0.018 |
| LLM only, whole function, no SAST | +0.031 [-0.004, 0.066] | [-0.050, 0.036] | 0.192 | 0.495 | 1.000 | 1.000 | 1.16 | 0.058 / 0.012 |
| LLM only, dev-tuned threshold | +0.034 [0.000, 0.071] | [-0.047, 0.040] | 0.173 | 0.495 | 1.000 | 1.000 | 1.17 | 0.058 / 0.012 |
| LLM only + same-file context, no SAST | +0.053 [0.015, 0.095] | [-0.029, 0.060] | 0.019 | 0.483 | 1.000 | 1.000 | 1.28 | 0.063 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.056 [0.018, 0.098] | [-0.030, 0.061] | 0.021 | 0.483 | 1.000 | 1.000 | 1.34 | 0.066 / 0.013 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | FPR | Accuracy | MCC | F1 |
|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| Semgrep + Bandit + AST Gate | 0.570 | 0.243 | 0.183 | 0.530 | 0.073 | 0.341 |
| Semgrep alone | 0.611 | 0.088 | 0.056 | 0.516 | 0.062 | 0.153 |
| Bandit alone | 0.621 | 0.163 | 0.100 | 0.532 | 0.094 | 0.259 |
| AST sink gate alone | 0.622 | 0.092 | 0.056 | 0.518 | 0.069 | 0.160 |
| CodeQL alone | 0.556 | 0.040 | 0.032 | 0.504 | 0.021 | 0.074 |
| SAST board: Judge vote | 0.721 | 0.175 | 0.068 | 0.554 | 0.165 | 0.282 |
| SAST board + evidence override (ablation) | 0.674 | 0.231 | 0.112 | 0.560 | 0.159 | 0.344 |
| SAST board: vote score, dev-tuned threshold | 0.746 | 0.163 | 0.056 | 0.554 | 0.172 | 0.268 |
| SAST board + fusion (trained on dev) | 0.822 | 0.147 | 0.032 | 0.558 | 0.202 | 0.250 |
| SAST board + fusion + context cascade (trained on dev) | 0.833 | 0.159 | 0.032 | 0.564 | 0.217 | 0.268 |
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
