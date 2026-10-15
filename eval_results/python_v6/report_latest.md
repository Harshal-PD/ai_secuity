# HackerSec real-world evaluation (2026-10-15T14:12:18)

Status: **complete** — 2506/2506 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v6-sast-gate`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| cvefixes | 100 (52) | 400 (133) | 154 |
| reposvul | 101 (44) | 402 (156) | 218 |
| vudenc | 50 (27) | 200 (103) | 90 |

- Dev functions evaluated: 502
- Board threshold on mean P(vulnerable) across Judge votes: **0.800** (max mcc on dev)
- Fusion: trained on 79 flagged dev functions (5-fold CV C=0.4, max mcc), threshold 0.597, dev CV F1 0.222, dev CV MCC 0.206
- LLM-only threshold on P(vulnerable): **0.200** (max mcc on dev)
- LLM-only + context threshold on P(vulnerable): **0.900** (max mcc on dev)

Each pair contributes one vulnerable and one fixed function, so flagging every function scores F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise columns show whether a system actually separates vulnerable from fixed code.

## Test split (primary)

### cvefixes — 800 functions, 400 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.084, -0.028] | 1.000 | — | — | 0.405 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.055 [0.028, 0.084] | — | 0.0006 | 0.527 | 0.0004 | — | 1.31 | 0.065 / 0.013 |
| Semgrep alone | +0.040 [0.019, 0.065] | [-0.042, 0.010] | 0.001 | — | — | 1.000 | 1.64 | 0.080 / 0.016 |
| Bandit alone | +0.045 [0.018, 0.076] | [-0.020, -0.002] | 0.004 | — | — | 1.000 | 1.28 | 0.063 / 0.013 |
| SAST board: Judge vote | +0.045 [0.013, 0.080] | [-0.037, 0.019] | 0.013 | 0.529 | 0.002 | 1.000 | 1.40 | 0.069 / 0.014 |
| SAST board + evidence override (ablation) | +0.058 [0.030, 0.091] | [-0.015, 0.022] | 0.0006 | — | — | 1.000 | 1.38 | 0.068 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.045 [0.014, 0.079] | [-0.034, 0.017] | 0.013 | 0.544 | 0.0001 | 1.000 | 1.42 | 0.070 / 0.014 |
| SAST board + fusion (trained on dev) | +0.068 [0.038, 0.105] | [-0.023, 0.048] | 0.0001 | 0.545 | 0.002 | 1.000 | 2.12 | 0.101 / 0.021 |
| LLM only, whole function, no SAST | +0.050 [0.016, 0.087] | [-0.046, 0.040] | 0.013 | 0.521 | 0.609 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only, dev-tuned threshold | +0.050 [0.016, 0.087] | [-0.046, 0.040] | 0.013 | 0.521 | 0.609 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only + same-file context, no SAST | +0.045 [0.010, 0.084] | [-0.057, 0.037] | 0.013 | 0.506 | 1.000 | 1.000 | 1.21 | 0.060 / 0.012 |
| LLM only + context, dev-tuned threshold | +0.052 [0.015, 0.092] | [-0.048, 0.046] | 0.013 | 0.506 | 1.000 | 1.000 | 1.29 | 0.064 / 0.013 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.103, -0.036] | 0.667 [0.667, 0.667] | 0.405 |
| Semgrep + Bandit | 0.567 | 0.233 | 0.177 | 0.527 | 0.068 [0.036, 0.103] | — | 0.330 [0.270, 0.382] | — |
| Semgrep alone | 0.621 | 0.102 | 0.062 | 0.520 | 0.073 [0.036, 0.116] | [-0.034, 0.047] | 0.176 [0.124, 0.240] | 0.614 |
| Bandit alone | 0.562 | 0.205 | 0.160 | 0.522 | 0.058 [0.023, 0.097] | [-0.022, 0.001] | 0.300 [0.238, 0.356] | 0.481 |
| SAST board: Judge vote | 0.583 | 0.158 | 0.113 | 0.522 | 0.066 [0.021, 0.116] | [-0.040, 0.039] | 0.248 [0.180, 0.318] | 0.689 |
| SAST board + evidence override (ablation) | 0.580 | 0.207 | 0.150 | 0.529 | 0.075 [0.039, 0.120] | [-0.015, 0.034] | 0.306 [0.241, 0.361] | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.587 | 0.152 | 0.107 | 0.522 | 0.067 [0.020, 0.115] | [-0.036, 0.039] | 0.242 [0.177, 0.309] | 0.699 |
| SAST board + fusion (trained on dev) | 0.680 | 0.128 | 0.060 | 0.534 | 0.116 [0.068, 0.167] | [-0.005, 0.099] | 0.215 [0.151, 0.291] | 0.672 |
| LLM only, whole function, no SAST | 0.551 | 0.268 | 0.217 | 0.525 | 0.058 [0.019, 0.101] | [-0.060, 0.045] | 0.360 [0.302, 0.418] | 0.940 |
| LLM only, dev-tuned threshold | 0.551 | 0.268 | 0.217 | 0.525 | 0.058 [0.019, 0.101] | [-0.060, 0.045] | 0.360 [0.302, 0.418] | 0.940 |
| LLM only + same-file context, no SAST | 0.547 | 0.260 | 0.215 | 0.522 | 0.053 [0.012, 0.098] | [-0.072, 0.040] | 0.352 [0.286, 0.416] | 0.820 |
| LLM only + context, dev-tuned threshold | 0.563 | 0.235 | 0.182 | 0.526 | 0.065 [0.018, 0.112] | [-0.062, 0.053] | 0.332 [0.267, 0.395] | 1.000 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Semgrep + Bandit (no LLM) | 0 | 0.0 | 93 | 0 |
| SAST board (LLM only where static analysis flagged) | 164 | 1,226.5 | 61 | 16,085 |
| LLM only, whole function, no SAST | 800 | 1,032.1 | 107 | 7,717 |
| LLM only + same-file context, no SAST | 800 | 1,185.9 | 94 | 10,093 |


**On functions static analysis flagged** (164: 93 vulnerable, 71 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.567 | 1.000 | 1.000 | 0.000 | 0.724 | 0.0% | 100.0% |
| Semgrep + Bandit | 0.567 | 1.000 | 1.000 | 0.000 | 0.724 | — | — |
| Semgrep alone | 0.621 | 0.441 | 0.352 | 0.090 | 0.516 | 64.8% | 44.1% |
| Bandit alone | 0.562 | 0.882 | 0.901 | -0.031 | 0.686 | 9.9% | 88.2% |
| SAST board: Judge vote | 0.583 | 0.677 | 0.634 | 0.046 | 0.627 | 36.6% | 67.7% |
| SAST board + evidence override (ablation) | 0.580 | 0.892 | 0.845 | 0.070 | 0.703 | 15.5% | 89.2% |
| SAST board: vote score, dev-tuned threshold | 0.587 | 0.656 | 0.606 | 0.052 | 0.619 | 39.4% | 65.6% |
| SAST board + fusion (trained on dev) | 0.680 | 0.548 | 0.338 | 0.209 | 0.607 | 66.2% | 54.8% |
| LLM only, whole function, no SAST | 0.622 | 0.602 | 0.479 | 0.123 | 0.612 | 52.1% | 60.2% |
| LLM only, dev-tuned threshold | 0.622 | 0.602 | 0.479 | 0.123 | 0.612 | 52.1% | 60.2% |
| LLM only + same-file context, no SAST | 0.622 | 0.602 | 0.479 | 0.123 | 0.612 | 52.1% | 60.2% |
| LLM only + context, dev-tuned threshold | 0.680 | 0.548 | 0.338 | 0.209 | 0.607 | 66.2% | 54.8% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 400 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit | 400 | 0.065 [0.040, 0.093] | 0.168 | 0.757 | 0.010 | 0.075 | 0.867 |
| Semgrep alone | 400 | 0.043 [0.020, 0.067] | 0.060 | 0.895 | 0.003 | 0.045 | 0.944 |
| Bandit alone | 400 | 0.055 [0.031, 0.083] | 0.150 | 0.785 | 0.010 | 0.065 | 0.846 |
| SAST board: Judge vote | 400 | 0.062 [0.036, 0.095] | 0.095 | 0.825 | 0.018 | 0.080 | 0.781 |
| SAST board + evidence override (ablation) | 400 | 0.070 [0.044, 0.101] | 0.138 | 0.780 | 0.013 | 0.083 | 0.849 |
| SAST board: vote score, dev-tuned threshold | 400 | 0.062 [0.035, 0.094] | 0.090 | 0.830 | 0.018 | 0.080 | 0.781 |
| SAST board + fusion (trained on dev) | 400 | 0.080 [0.051, 0.118] | 0.048 | 0.860 | 0.013 | 0.092 | 0.865 |
| LLM only, whole function, no SAST | 400 | 0.075 [0.046, 0.108] | 0.193 | 0.708 | 0.025 | 0.100 | 0.750 |
| LLM only, dev-tuned threshold | 400 | 0.075 [0.046, 0.108] | 0.193 | 0.708 | 0.025 | 0.100 | 0.750 |
| LLM only + same-file context, no SAST | 400 | 0.072 [0.043, 0.109] | 0.188 | 0.713 | 0.028 | 0.100 | 0.725 |
| LLM only + context, dev-tuned threshold | 400 | 0.085 [0.055, 0.121] | 0.150 | 0.733 | 0.033 | 0.117 | 0.723 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.990 | 0.897 |
| SAST board + fusion (trained on dev) | 0.970 | 0.875 |
| LLM only, whole function, no SAST | 1.000 | 0.990 |
| LLM only, dev-tuned threshold | 1.000 | 0.990 |
| LLM only + same-file context, no SAST | 1.000 | 0.990 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.990 |

### reposvul — 804 functions, 402 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.100, -0.036] | 1.000 | — | — | 0.298 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.067 [0.036, 0.100] | — | 0 | 0.534 | 0 | — | 1.36 | 0.067 / 0.013 |
| Semgrep alone | +0.060 [0.030, 0.093] | [-0.039, 0.022] | 0 | — | — | 1.000 | 1.89 | 0.090 / 0.019 |
| Bandit alone | +0.065 [0.035, 0.098] | [-0.011, 0.005] | 0 | — | — | 1.000 | 1.41 | 0.069 / 0.014 |
| SAST board: Judge vote | +0.085 [0.049, 0.124] | [-0.010, 0.045] | 0 | 0.547 | 0 | 1.000 | 1.83 | 0.088 / 0.018 |
| SAST board + evidence override (ablation) | +0.077 [0.046, 0.111] | [-0.007, 0.027] | 0 | — | — | 1.000 | 1.46 | 0.071 / 0.015 |
| SAST board: vote score, dev-tuned threshold | +0.085 [0.048, 0.128] | [-0.013, 0.046] | 0 | 0.567 | 0 | 1.000 | 1.92 | 0.092 / 0.019 |
| SAST board + fusion (trained on dev) | +0.085 [0.049, 0.127] | [-0.018, 0.053] | 0 | 0.580 | 0 | 1.000 | 2.36 | 0.111 / 0.023 |
| LLM only, whole function, no SAST | +0.070 [0.030, 0.105] | [-0.046, 0.044] | 0 | 0.522 | 0.530 | 1.000 | 1.28 | 0.063 / 0.013 |
| LLM only, dev-tuned threshold | +0.072 [0.033, 0.107] | [-0.044, 0.045] | 0 | 0.522 | 0.530 | 1.000 | 1.29 | 0.064 / 0.013 |
| LLM only + same-file context, no SAST | +0.075 [0.036, 0.112] | [-0.039, 0.055] | 0 | 0.515 | 0.677 | 1.000 | 1.32 | 0.065 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.082 [0.041, 0.125] | [-0.031, 0.058] | 0 | 0.515 | 0.677 | 1.000 | 1.41 | 0.069 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.121, -0.043] | 0.667 [0.667, 0.667] | 0.298 |
| Semgrep + Bandit | 0.575 | 0.256 | 0.189 | 0.534 | 0.081 [0.043, 0.121] | — | 0.355 [0.307, 0.399] | — |
| Semgrep alone | 0.654 | 0.127 | 0.067 | 0.530 | 0.101 [0.054, 0.151] | [-0.026, 0.062] | 0.212 [0.160, 0.267] | 0.842 |
| Bandit alone | 0.584 | 0.224 | 0.159 | 0.532 | 0.082 [0.044, 0.122] | [-0.010, 0.012] | 0.324 [0.275, 0.369] | 1.000 |
| SAST board: Judge vote | 0.647 | 0.187 | 0.102 | 0.542 | 0.120 [0.073, 0.170] | [0.004, 0.074] | 0.290 [0.232, 0.354] | 0.450 |
| SAST board + evidence override (ablation) | 0.594 | 0.244 | 0.167 | 0.539 | 0.096 [0.056, 0.138] | [-0.007, 0.037] | 0.346 [0.297, 0.395] | 0.424 |
| SAST board: vote score, dev-tuned threshold | 0.657 | 0.177 | 0.092 | 0.542 | 0.124 [0.073, 0.179] | [0.002, 0.082] | 0.278 [0.218, 0.344] | 0.477 |
| SAST board + fusion (trained on dev) | 0.702 | 0.147 | 0.062 | 0.542 | 0.138 [0.083, 0.192] | [0.009, 0.105] | 0.243 [0.182, 0.309] | 0.538 |
| LLM only, whole function, no SAST | 0.561 | 0.318 | 0.249 | 0.535 | 0.077 [0.033, 0.117] | [-0.062, 0.045] | 0.406 [0.353, 0.455] | 1.000 |
| LLM only, dev-tuned threshold | 0.563 | 0.321 | 0.249 | 0.536 | 0.080 [0.036, 0.121] | [-0.058, 0.048] | 0.409 [0.354, 0.458] | 0.943 |
| LLM only + same-file context, no SAST | 0.568 | 0.311 | 0.236 | 0.537 | 0.084 [0.040, 0.126] | [-0.050, 0.054] | 0.402 [0.345, 0.457] | 0.884 |
| LLM only + context, dev-tuned threshold | 0.585 | 0.284 | 0.202 | 0.541 | 0.096 [0.047, 0.142] | [-0.041, 0.067] | 0.382 [0.323, 0.441] | 0.713 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Semgrep + Bandit (no LLM) | 0 | 0.0 | 103 | 0 |
| SAST board (LLM only where static analysis flagged) | 179 | 1,409.4 | 71 | 15,960 |
| LLM only, whole function, no SAST | 804 | 1,144.6 | 129 | 7,134 |
| LLM only + same-file context, no SAST | 804 | 1,327.1 | 114 | 9,360 |


**On functions static analysis flagged** (179: 103 vulnerable, 76 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.575 | 1.000 | 1.000 | 0.000 | 0.731 | 0.0% | 100.0% |
| Semgrep + Bandit | 0.575 | 1.000 | 1.000 | 0.000 | 0.731 | — | — |
| Semgrep alone | 0.654 | 0.495 | 0.355 | 0.139 | 0.564 | 64.5% | 49.5% |
| Bandit alone | 0.584 | 0.874 | 0.842 | 0.045 | 0.700 | 15.8% | 87.4% |
| SAST board: Judge vote | 0.647 | 0.728 | 0.539 | 0.195 | 0.685 | 46.1% | 72.8% |
| SAST board + evidence override (ablation) | 0.594 | 0.952 | 0.882 | 0.129 | 0.731 | 11.8% | 95.2% |
| SAST board: vote score, dev-tuned threshold | 0.657 | 0.689 | 0.487 | 0.205 | 0.673 | 51.3% | 68.9% |
| SAST board + fusion (trained on dev) | 0.702 | 0.573 | 0.329 | 0.241 | 0.631 | 67.1% | 57.3% |
| LLM only, whole function, no SAST | 0.635 | 0.660 | 0.513 | 0.148 | 0.648 | 48.7% | 66.0% |
| LLM only, dev-tuned threshold | 0.635 | 0.660 | 0.513 | 0.148 | 0.648 | 48.7% | 66.0% |
| LLM only + same-file context, no SAST | 0.632 | 0.650 | 0.513 | 0.138 | 0.641 | 48.7% | 65.0% |
| LLM only + context, dev-tuned threshold | 0.674 | 0.621 | 0.408 | 0.211 | 0.646 | 59.2% | 62.1% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 402 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit | 402 | 0.077 [0.048, 0.109] | 0.179 | 0.734 | 0.010 | 0.087 | 0.886 |
| Semgrep alone | 402 | 0.062 [0.035, 0.096] | 0.065 | 0.871 | 0.003 | 0.065 | 0.962 |
| Bandit alone | 402 | 0.075 [0.047, 0.107] | 0.149 | 0.766 | 0.010 | 0.085 | 0.882 |
| SAST board: Judge vote | 402 | 0.102 [0.070, 0.140] | 0.085 | 0.796 | 0.017 | 0.119 | 0.854 |
| SAST board + evidence override (ablation) | 402 | 0.087 [0.058, 0.120] | 0.157 | 0.746 | 0.010 | 0.097 | 0.897 |
| SAST board: vote score, dev-tuned threshold | 402 | 0.102 [0.068, 0.141] | 0.075 | 0.806 | 0.017 | 0.119 | 0.854 |
| SAST board + fusion (trained on dev) | 402 | 0.097 [0.066, 0.137] | 0.050 | 0.841 | 0.012 | 0.110 | 0.886 |
| LLM only, whole function, no SAST | 402 | 0.090 [0.057, 0.122] | 0.229 | 0.662 | 0.020 | 0.110 | 0.818 |
| LLM only, dev-tuned threshold | 402 | 0.092 [0.060, 0.124] | 0.229 | 0.659 | 0.020 | 0.112 | 0.822 |
| LLM only + same-file context, no SAST | 402 | 0.095 [0.063, 0.130] | 0.216 | 0.669 | 0.020 | 0.114 | 0.826 |
| LLM only + context, dev-tuned threshold | 402 | 0.110 [0.076, 0.146] | 0.174 | 0.689 | 0.027 | 0.137 | 0.800 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.995 | 0.873 |
| SAST board + fusion (trained on dev) | 0.960 | 0.863 |
| LLM only, whole function, no SAST | 1.000 | 0.988 |
| LLM only, dev-tuned threshold | 1.000 | 0.988 |
| LLM only + same-file context, no SAST | 0.985 | 0.985 |
| LLM only + context, dev-tuned threshold | 0.985 | 0.985 |

### vudenc — 400 functions, 200 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.132, -0.010] | 1.000 | — | — | 0.489 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.065 [0.010, 0.132] | — | 0.009 | 0.532 | 0.012 | — | 1.30 | 0.064 / 0.013 |
| Semgrep alone | +0.025 [-0.010, 0.064] | [-0.110, 0.021] | 0.227 | — | — | 1.000 | 1.42 | 0.069 / 0.014 |
| Bandit alone | +0.060 [0.006, 0.126] | [-0.016, 0.000] | 0.012 | — | — | 1.000 | 1.32 | 0.065 / 0.013 |
| SAST board: Judge vote | +0.085 [0.024, 0.157] | [-0.015, 0.055] | 0.007 | 0.542 | 0.009 | 1.000 | 1.59 | 0.077 / 0.016 |
| SAST board + evidence override (ablation) | +0.075 [0.010, 0.146] | [-0.025, 0.045] | 0.012 | — | — | 1.000 | 1.43 | 0.070 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.085 [0.024, 0.157] | [-0.015, 0.055] | 0.007 | 0.573 | 0 | 1.000 | 1.59 | 0.077 / 0.016 |
| SAST board + fusion (trained on dev) | +0.110 [0.039, 0.186] | [-0.005, 0.097] | 0.002 | 0.562 | 0.009 | 1.000 | 2.16 | 0.102 / 0.021 |
| LLM only, whole function, no SAST | +0.095 [0.031, 0.168] | [-0.021, 0.082] | 0.007 | 0.537 | 0.176 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only, dev-tuned threshold | +0.095 [0.031, 0.168] | [-0.021, 0.082] | 0.007 | 0.537 | 0.176 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.105 [0.047, 0.171] | [-0.005, 0.081] | 0.001 | 0.540 | 0.176 | 1.000 | 1.39 | 0.068 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.120 [0.063, 0.185] | [0.005, 0.104] | 0.0002 | 0.540 | 0.176 | 1.000 | 1.49 | 0.073 / 0.015 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.146, -0.012] | 0.667 [0.667, 0.667] | 0.489 |
| Semgrep + Bandit | 0.566 | 0.280 | 0.215 | 0.532 | 0.075 [0.012, 0.146] | — | 0.375 [0.293, 0.453] | — |
| Semgrep alone | 0.586 | 0.085 | 0.060 | 0.512 | 0.048 [-0.020, 0.125] | [-0.114, 0.062] | 0.148 [0.077, 0.226] | 0.403 |
| Bandit alone | 0.568 | 0.250 | 0.190 | 0.530 | 0.072 [0.007, 0.147] | [-0.017, 0.007] | 0.347 [0.260, 0.429] | 1.000 |
| SAST board: Judge vote | 0.613 | 0.230 | 0.145 | 0.542 | 0.109 [0.032, 0.190] | [-0.012, 0.075] | 0.335 [0.241, 0.425] | 0.541 |
| SAST board + evidence override (ablation) | 0.588 | 0.250 | 0.175 | 0.537 | 0.092 [0.013, 0.172] | [-0.026, 0.059] | 0.351 [0.261, 0.437] | 0.791 |
| SAST board: vote score, dev-tuned threshold | 0.613 | 0.230 | 0.145 | 0.542 | 0.109 [0.032, 0.190] | [-0.012, 0.075] | 0.335 [0.241, 0.425] | 0.541 |
| SAST board + fusion (trained on dev) | 0.683 | 0.205 | 0.095 | 0.555 | 0.154 [0.060, 0.243] | [0.011, 0.142] | 0.315 [0.217, 0.411] | 0.200 |
| LLM only, whole function, no SAST | 0.571 | 0.380 | 0.285 | 0.547 | 0.101 [0.034, 0.175] | [-0.031, 0.083] | 0.457 [0.382, 0.530] | 0.567 |
| LLM only, dev-tuned threshold | 0.571 | 0.380 | 0.285 | 0.547 | 0.101 [0.034, 0.175] | [-0.031, 0.083] | 0.457 [0.382, 0.530] | 0.567 |
| LLM only + same-file context, no SAST | 0.581 | 0.375 | 0.270 | 0.552 | 0.112 [0.051, 0.182] | [-0.012, 0.083] | 0.456 [0.389, 0.526] | 0.396 |
| LLM only + context, dev-tuned threshold | 0.598 | 0.365 | 0.245 | 0.560 | 0.130 [0.069, 0.199] | [-0.002, 0.110] | 0.453 [0.384, 0.527] | 0.242 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Semgrep + Bandit (no LLM) | 0 | 0.0 | 56 | 0 |
| SAST board (LLM only where static analysis flagged) | 99 | 1,287.3 | 46 | 11,194 |
| LLM only, whole function, no SAST | 400 | 906.4 | 76 | 4,770 |
| LLM only + same-file context, no SAST | 400 | 1,042.0 | 73 | 5,710 |


**On functions static analysis flagged** (99: 56 vulnerable, 43 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.566 | 1.000 | 1.000 | 0.000 | 0.723 | 0.0% | 100.0% |
| Semgrep + Bandit | 0.566 | 1.000 | 1.000 | 0.000 | 0.723 | — | — |
| Semgrep alone | 0.586 | 0.304 | 0.279 | 0.027 | 0.400 | 72.1% | 30.4% |
| Bandit alone | 0.568 | 0.893 | 0.884 | 0.014 | 0.694 | 11.6% | 89.3% |
| SAST board: Judge vote | 0.613 | 0.821 | 0.674 | 0.170 | 0.702 | 32.6% | 82.1% |
| SAST board + evidence override (ablation) | 0.588 | 0.893 | 0.814 | 0.112 | 0.709 | 18.6% | 89.3% |
| SAST board: vote score, dev-tuned threshold | 0.613 | 0.821 | 0.674 | 0.170 | 0.702 | 32.6% | 82.1% |
| SAST board + fusion (trained on dev) | 0.683 | 0.732 | 0.442 | 0.294 | 0.707 | 55.8% | 73.2% |
| LLM only, whole function, no SAST | 0.603 | 0.839 | 0.721 | 0.143 | 0.702 | 27.9% | 83.9% |
| LLM only, dev-tuned threshold | 0.603 | 0.839 | 0.721 | 0.143 | 0.702 | 27.9% | 83.9% |
| LLM only + same-file context, no SAST | 0.588 | 0.839 | 0.767 | 0.090 | 0.691 | 23.3% | 83.9% |
| LLM only + context, dev-tuned threshold | 0.622 | 0.821 | 0.651 | 0.194 | 0.708 | 34.9% | 82.1% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 200 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit | 200 | 0.075 [0.025, 0.137] | 0.205 | 0.710 | 0.010 | 0.085 | 0.882 |
| Semgrep alone | 200 | 0.040 [0.015, 0.072] | 0.045 | 0.900 | 0.015 | 0.055 | 0.727 |
| Bandit alone | 200 | 0.070 [0.019, 0.133] | 0.180 | 0.740 | 0.010 | 0.080 | 0.875 |
| SAST board: Judge vote | 200 | 0.105 [0.047, 0.173] | 0.125 | 0.750 | 0.020 | 0.125 | 0.840 |
| SAST board + evidence override (ablation) | 200 | 0.100 [0.045, 0.168] | 0.150 | 0.725 | 0.025 | 0.125 | 0.800 |
| SAST board: vote score, dev-tuned threshold | 200 | 0.105 [0.047, 0.173] | 0.125 | 0.750 | 0.020 | 0.125 | 0.840 |
| SAST board + fusion (trained on dev) | 200 | 0.140 [0.076, 0.210] | 0.065 | 0.765 | 0.030 | 0.170 | 0.824 |
| LLM only, whole function, no SAST | 200 | 0.125 [0.071, 0.189] | 0.255 | 0.590 | 0.030 | 0.155 | 0.806 |
| LLM only, dev-tuned threshold | 200 | 0.125 [0.071, 0.189] | 0.255 | 0.590 | 0.030 | 0.155 | 0.806 |
| LLM only + same-file context, no SAST | 200 | 0.125 [0.072, 0.186] | 0.250 | 0.605 | 0.020 | 0.145 | 0.862 |
| LLM only + context, dev-tuned threshold | 200 | 0.140 [0.087, 0.203] | 0.225 | 0.615 | 0.020 | 0.160 | 0.875 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 1.000 | 0.985 |
| SAST board + fusion (trained on dev) | 0.990 | 0.835 |
| LLM only, whole function, no SAST | 1.000 | 0.980 |
| LLM only, dev-tuned threshold | 1.000 | 0.980 |
| LLM only + same-file context, no SAST | 1.000 | 1.000 |
| LLM only + context, dev-tuned threshold | 1.000 | 1.000 |

### combined — 2004 functions, 1002 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.084, -0.041] | 1.000 | — | — | 0.123 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.062 [0.041, 0.084] | — | 0 | 0.531 | 0 | — | 1.33 | 0.065 / 0.013 |
| Semgrep alone | +0.045 [0.028, 0.065] | [-0.037, 0.003] | 0 | — | — | 1.000 | 1.70 | 0.082 / 0.017 |
| Bandit alone | +0.056 [0.035, 0.079] | [-0.012, -0.001] | 0 | — | — | 1.000 | 1.34 | 0.066 / 0.013 |
| SAST board: Judge vote | +0.069 [0.045, 0.096] | [-0.011, 0.024] | 0 | 0.539 | 0 | 1.000 | 1.60 | 0.078 / 0.016 |
| SAST board + evidence override (ablation) | +0.069 [0.048, 0.093] | [-0.006, 0.019] | 0 | — | — | 1.000 | 1.43 | 0.070 / 0.014 |
| SAST board: vote score, dev-tuned threshold | +0.069 [0.044, 0.096] | [-0.011, 0.024] | 0 | 0.559 | 0 | 1.000 | 1.63 | 0.079 / 0.016 |
| SAST board + fusion (trained on dev) | +0.083 [0.057, 0.110] | [-0.001, 0.043] | 0 | 0.562 | 0 | 1.000 | 2.22 | 0.105 / 0.022 |
| LLM only, whole function, no SAST | +0.067 [0.044, 0.092] | [-0.024, 0.031] | 0 | 0.525 | 0.021 | 1.000 | 1.27 | 0.063 / 0.013 |
| LLM only, dev-tuned threshold | +0.068 [0.045, 0.093] | [-0.022, 0.032] | 0 | 0.525 | 0.021 | 1.000 | 1.28 | 0.063 / 0.013 |
| LLM only + same-file context, no SAST | +0.069 [0.044, 0.095] | [-0.021, 0.036] | 0 | 0.516 | 0.132 | 1.000 | 1.29 | 0.064 / 0.013 |
| LLM only + context, dev-tuned threshold | +0.078 [0.052, 0.105] | [-0.012, 0.045] | 0 | 0.516 | 0.132 | 1.000 | 1.38 | 0.068 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.102, -0.049] | 0.667 [0.667, 0.667] | 0.123 |
| Semgrep + Bandit | 0.570 | 0.252 | 0.190 | 0.531 | 0.075 [0.049, 0.102] | — | 0.349 [0.317, 0.381] | — |
| Semgrep alone | 0.630 | 0.109 | 0.064 | 0.522 | 0.080 [0.051, 0.112] | [-0.023, 0.035] | 0.185 [0.149, 0.224] | 0.329 |
| Bandit alone | 0.572 | 0.222 | 0.166 | 0.528 | 0.071 [0.045, 0.101] | [-0.011, 0.003] | 0.319 [0.285, 0.353] | 0.497 |
| SAST board: Judge vote | 0.615 | 0.184 | 0.115 | 0.534 | 0.097 [0.064, 0.132] | [-0.001, 0.044] | 0.283 [0.239, 0.324] | 0.616 |
| SAST board + evidence override (ablation) | 0.588 | 0.231 | 0.162 | 0.534 | 0.087 [0.061, 0.116] | [-0.004, 0.027] | 0.331 [0.296, 0.367] | 0.392 |
| SAST board: vote score, dev-tuned threshold | 0.620 | 0.178 | 0.109 | 0.534 | 0.098 [0.065, 0.133] | [-0.002, 0.047] | 0.276 [0.232, 0.318] | 0.630 |
| SAST board + fusion (trained on dev) | 0.690 | 0.151 | 0.068 | 0.541 | 0.133 [0.095, 0.169] | [0.027, 0.088] | 0.247 [0.203, 0.290] | 0.180 |
| LLM only, whole function, no SAST | 0.560 | 0.310 | 0.243 | 0.533 | 0.075 [0.049, 0.103] | [-0.034, 0.031] | 0.400 [0.366, 0.431] | 0.850 |
| LLM only, dev-tuned threshold | 0.561 | 0.311 | 0.243 | 0.534 | 0.076 [0.051, 0.105] | [-0.032, 0.032] | 0.401 [0.367, 0.433] | 0.813 |
| LLM only + same-file context, no SAST | 0.564 | 0.303 | 0.234 | 0.534 | 0.078 [0.051, 0.107] | [-0.029, 0.037] | 0.395 [0.357, 0.429] | 0.772 |
| LLM only + context, dev-tuned threshold | 0.581 | 0.280 | 0.203 | 0.539 | 0.091 [0.061, 0.122] | [-0.017, 0.051] | 0.378 [0.340, 0.416] | 0.474 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Semgrep + Bandit (no LLM) | 0 | 0.0 | 252 | 0 |
| SAST board (LLM only where static analysis flagged) | 442 | 1,312.0 | 178 | 14,771 |
| LLM only, whole function, no SAST | 2004 | 1,052.2 | 312 | 6,758 |
| LLM only + same-file context, no SAST | 2004 | 1,213.9 | 281 | 8,657 |


**On functions static analysis flagged** (442: 252 vulnerable, 190 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.570 | 1.000 | 1.000 | 0.000 | 0.726 | 0.0% | 100.0% |
| Semgrep + Bandit | 0.570 | 1.000 | 1.000 | 0.000 | 0.726 | — | — |
| Semgrep alone | 0.630 | 0.432 | 0.337 | 0.097 | 0.513 | 66.3% | 43.2% |
| Bandit alone | 0.572 | 0.881 | 0.874 | 0.011 | 0.694 | 12.6% | 88.1% |
| SAST board: Judge vote | 0.615 | 0.730 | 0.605 | 0.132 | 0.668 | 39.5% | 73.0% |
| SAST board + evidence override (ablation) | 0.588 | 0.917 | 0.853 | 0.101 | 0.716 | 14.7% | 91.7% |
| SAST board: vote score, dev-tuned threshold | 0.620 | 0.706 | 0.574 | 0.138 | 0.660 | 42.6% | 70.6% |
| SAST board + fusion (trained on dev) | 0.690 | 0.599 | 0.358 | 0.239 | 0.641 | 64.2% | 59.9% |
| LLM only, whole function, no SAST | 0.622 | 0.679 | 0.547 | 0.134 | 0.649 | 45.3% | 67.9% |
| LLM only, dev-tuned threshold | 0.622 | 0.679 | 0.547 | 0.134 | 0.649 | 45.3% | 67.9% |
| LLM only + same-file context, no SAST | 0.616 | 0.675 | 0.558 | 0.119 | 0.644 | 44.2% | 67.5% |
| LLM only + context, dev-tuned threshold | 0.660 | 0.639 | 0.437 | 0.201 | 0.649 | 56.3% | 63.9% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 1002 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit | 1002 | 0.072 [0.053, 0.094] | 0.180 | 0.739 | 0.010 | 0.082 | 0.878 |
| Semgrep alone | 1002 | 0.050 [0.033, 0.069] | 0.059 | 0.886 | 0.005 | 0.055 | 0.909 |
| Bandit alone | 1002 | 0.066 [0.047, 0.087] | 0.156 | 0.768 | 0.010 | 0.076 | 0.868 |
| SAST board: Judge vote | 1002 | 0.087 [0.064, 0.111] | 0.097 | 0.798 | 0.018 | 0.105 | 0.829 |
| SAST board + evidence override (ablation) | 1002 | 0.083 [0.062, 0.106] | 0.148 | 0.755 | 0.014 | 0.097 | 0.856 |
| SAST board: vote score, dev-tuned threshold | 1002 | 0.087 [0.064, 0.111] | 0.091 | 0.804 | 0.018 | 0.105 | 0.829 |
| SAST board + fusion (trained on dev) | 1002 | 0.099 [0.076, 0.124] | 0.052 | 0.833 | 0.016 | 0.115 | 0.861 |
| LLM only, whole function, no SAST | 1002 | 0.091 [0.071, 0.114] | 0.220 | 0.666 | 0.024 | 0.115 | 0.791 |
| LLM only, dev-tuned threshold | 1002 | 0.092 [0.072, 0.115] | 0.220 | 0.665 | 0.024 | 0.116 | 0.793 |
| LLM only + same-file context, no SAST | 1002 | 0.092 [0.070, 0.114] | 0.212 | 0.674 | 0.023 | 0.115 | 0.800 |
| LLM only + context, dev-tuned threshold | 1002 | 0.106 [0.084, 0.129] | 0.175 | 0.692 | 0.028 | 0.134 | 0.791 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.991 | 0.991 |
| SAST board + fusion (trained on dev) | 0.973 | 0.863 |
| LLM only, whole function, no SAST | 1.000 | 0.987 |
| LLM only, dev-tuned threshold | 1.000 | 0.987 |
| LLM only + same-file context, no SAST | 1.000 | 0.986 |
| LLM only + context, dev-tuned threshold | 1.000 | 0.986 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | sast MCC / R | semgrep MCC / R | bandit MCC / R | board_calibrated MCC / R | llm_only_calibrated MCC / R | llm_context_calibrated MCC / R |
|---|---|---|---|---|---|---|---|---|
| **logic_semantic** | 916 | 14.4% | 0.016 / 0.144 | 0.018 / 0.037 | 0.017 / 0.129 | 0.045 / 0.059 | 0.041 / 0.129 | 0.029 / 0.107 |
| **sast_reachable** | 1088 | 34.2% | 0.116 / 0.342 | 0.115 / 0.169 | 0.108 / 0.300 | 0.133 / 0.278 | 0.104 / 0.465 | 0.134 / 0.426 |
| injection | 600 | 40.7% | 0.130 / 0.407 | 0.124 / 0.200 | 0.132 / 0.383 | 0.147 / 0.333 | 0.090 / 0.507 | 0.142 / 0.477 |
| access_control (logic) | 306 | 15.7% | 0.028 / 0.157 | 0.018 / 0.039 | 0.019 / 0.137 | 0.051 / 0.085 | 0.010 / 0.131 | -0.020 / 0.111 |
| path_traversal | 190 | 17.9% | 0.073 / 0.179 | 0.074 / 0.063 | 0.078 / 0.158 | 0.123 / 0.137 | 0.183 / 0.390 | 0.212 / 0.368 |
| info_exposure (logic) | 168 | 15.5% | 0.034 / 0.155 | 0.000 / 0.059 | 0.038 / 0.119 | 0.046 / 0.083 | 0.086 / 0.107 | 0.079 / 0.071 |
| ssrf_redirect | 152 | 25.0% | 0.047 / 0.250 | 0.072 / 0.184 | -0.022 / 0.092 | 0.070 / 0.197 | 0.083 / 0.395 | 0.044 / 0.303 |
| other (logic) | 142 | 12.7% | 0.022 / 0.127 | 0.049 / 0.028 | 0.023 / 0.113 | 0.000 / 0.028 | 0.023 / 0.113 | 0.029 / 0.070 |
| input_validation (logic) | 140 | 10.0% | 0.025 / 0.100 | 0.000 / 0.043 | 0.051 / 0.100 | 0.086 / 0.043 | 0.079 / 0.186 | 0.060 / 0.171 |
| resource_dos (logic) | 106 | 3.8% | -0.044 / 0.038 | 0.000 / 0.000 | -0.044 / 0.038 | 0.000 / 0.000 | 0.082 / 0.075 | 0.134 / 0.075 |
| crypto_secrets | 82 | 14.6% | 0.000 / 0.146 | 0.000 / 0.000 | 0.000 / 0.146 | -0.131 / 0.049 | 0.030 / 0.220 | 0.069 / 0.171 |
| deserialization | 36 | 94.4% | 0.543 / 0.944 | 0.447 / 0.667 | 0.405 / 0.833 | 0.543 / 0.944 | 0.298 / 0.944 | 0.298 / 0.944 |
| memory_numeric (logic) | 28 | 57.1% | -0.073 / 0.571 | 0.000 / 0.000 | -0.073 / 0.571 | 0.000 / 0.000 | 0.000 / 0.000 | 0.000 / 0.000 |
| xml | 28 | 35.7% | 0.247 / 0.357 | 0.000 / 0.000 | 0.247 / 0.357 | 0.408 / 0.286 | 0.143 / 0.571 | 0.072 / 0.500 |
| unknown (logic) | 26 | 23.1% | 0.000 / 0.231 | 0.200 / 0.077 | 0.000 / 0.231 | 0.120 / 0.154 | 0.000 / 0.385 | 0.000 / 0.385 |

### Pipeline telemetry (test)

- flagged_functions: 442
- findings: 787
- findings_per_flagged_function: 1.78
- by_tool: {'bandit': 549, 'semgrep': 238}
- cpg_success_rate: 1.0
- cpg_taint_found_rate: 0.6722
- rag_context_rate: 1.0
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **function_board**: functions 442, mean_valid_votes 1.0, unanimous_rate 0.9977, split_vote_rate 0.0, no_valid_vote_rate 0.0023, majority_not_vulnerable_rate 0.3235, evidence_grounded_rate 0.129, evidence_reasons {'conceded': 330, 'no_span_match': 55, 'span_match': 57}, guard_grounded_rate 0.0, override_flip_rate 0.2127, code_truncated_rate 0.0, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0158, defender_parse_failed_rate 0.0023, mean_seconds_per_function 92.6
- **llm_baselines**: llm_only_parse_failed_rate 0.001, llm_only_vulnerable_rate 0.2769, llm_context_parse_failed_rate 0.0, llm_context_vulnerable_rate 0.269

## Test, clean subset (single-function fixes)

### clean — 676 functions, 338 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.099, -0.035] | 1.000 | — | — | 0.351 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.065 [0.035, 0.099] | — | 0.0004 | 0.532 | 0.001 | — | 1.30 | 0.064 / 0.013 |
| Semgrep alone | +0.062 [0.038, 0.091] | [-0.036, 0.027] | 0 | — | — | 1.000 | 2.00 | 0.095 / 0.020 |
| Bandit alone | +0.059 [0.029, 0.093] | [-0.015, 0.000] | 0.0005 | — | — | 1.000 | 1.31 | 0.064 / 0.013 |
| SAST board: Judge vote | +0.080 [0.047, 0.117] | [-0.014, 0.046] | 0.0002 | 0.544 | 0.0002 | 1.000 | 1.69 | 0.082 / 0.017 |
| SAST board + evidence override (ablation) | +0.068 [0.037, 0.101] | [-0.017, 0.024] | 0.0002 | — | — | 1.000 | 1.36 | 0.067 / 0.013 |
| SAST board: vote score, dev-tuned threshold | +0.077 [0.046, 0.113] | [-0.019, 0.044] | 0.0002 | 0.573 | 0 | 1.000 | 1.70 | 0.082 / 0.017 |
| SAST board + fusion (trained on dev) | +0.118 [0.077, 0.161] | [0.011, 0.096] | 0 | 0.578 | 0 | 0.854 | 3.50 | 0.156 / 0.034 |
| LLM only, whole function, no SAST | +0.071 [0.039, 0.106] | [-0.036, 0.048] | 0.0002 | 0.538 | 0.055 | 1.000 | 1.29 | 0.064 / 0.013 |
| LLM only, dev-tuned threshold | +0.074 [0.040, 0.111] | [-0.033, 0.051] | 0.0002 | 0.538 | 0.055 | 1.000 | 1.30 | 0.064 / 0.013 |
| LLM only + same-file context, no SAST | +0.080 [0.047, 0.115] | [-0.028, 0.058] | 0 | 0.525 | 0.200 | 1.000 | 1.37 | 0.067 / 0.014 |
| LLM only + context, dev-tuned threshold | +0.083 [0.047, 0.122] | [-0.027, 0.064] | 0 | 0.525 | 0.200 | 1.000 | 1.42 | 0.070 / 0.014 |

**End-to-end** (every function; SAST-board recall cannot exceed Semgrep + Bandit)

| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] | McNemar p (accuracy, uncorrected) |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 [0.000, 0.000] | [-0.114, -0.041] | 0.667 [0.667, 0.667] | 0.351 |
| Semgrep + Bandit | 0.565 | 0.284 | 0.219 | 0.532 | 0.075 [0.041, 0.114] | — | 0.378 [0.332, 0.421] | — |
| Semgrep alone | 0.667 | 0.124 | 0.062 | 0.531 | 0.107 [0.069, 0.153] | [-0.012, 0.074] | 0.209 [0.162, 0.258] | 1.000 |
| Bandit alone | 0.567 | 0.252 | 0.192 | 0.530 | 0.071 [0.035, 0.111] | [-0.015, 0.004] | 0.348 [0.299, 0.390] | 0.824 |
| SAST board: Judge vote | 0.629 | 0.195 | 0.115 | 0.540 | 0.110 [0.068, 0.157] | [-0.001, 0.073] | 0.298 [0.242, 0.353] | 0.620 |
| SAST board + evidence override (ablation) | 0.576 | 0.257 | 0.189 | 0.534 | 0.082 [0.045, 0.121] | [-0.016, 0.032] | 0.356 [0.308, 0.403] | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.630 | 0.186 | 0.110 | 0.538 | 0.108 [0.066, 0.155] | [-0.006, 0.073] | 0.288 [0.234, 0.341] | 0.720 |
| SAST board + fusion (trained on dev) | 0.778 | 0.166 | 0.047 | 0.559 | 0.192 [0.130, 0.250] | [0.056, 0.174] | 0.273 [0.214, 0.330] | 0.085 |
| LLM only, whole function, no SAST | 0.564 | 0.314 | 0.243 | 0.535 | 0.079 [0.043, 0.119] | [-0.041, 0.052] | 0.403 [0.356, 0.450] | 0.937 |
| LLM only, dev-tuned threshold | 0.566 | 0.317 | 0.243 | 0.537 | 0.082 [0.045, 0.123] | [-0.040, 0.056] | 0.406 [0.359, 0.454] | 0.875 |
| LLM only + same-file context, no SAST | 0.578 | 0.296 | 0.216 | 0.540 | 0.091 [0.054, 0.131] | [-0.035, 0.066] | 0.391 [0.340, 0.444] | 0.748 |
| LLM only + context, dev-tuned threshold | 0.588 | 0.278 | 0.195 | 0.541 | 0.097 [0.058, 0.141] | [-0.030, 0.076] | 0.378 [0.325, 0.433] | 0.695 |

**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST board costs nothing on functions static analysis did not flag. Tokens per true positive uses the dev-tuned threshold when that row exists.

| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |
|---|---|---|---|---|
| Semgrep + Bandit (no LLM) | 0 | 0.0 | 96 | 0 |
| SAST board (LLM only where static analysis flagged) | 170 | 1,543.7 | 63 | 16,565 |
| LLM only, whole function, no SAST | 676 | 1,108.9 | 107 | 7,006 |
| LLM only + same-file context, no SAST | 676 | 1,265.9 | 94 | 9,104 |


**On functions static analysis flagged** (170: 96 vulnerable, 74 fixed)

| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.565 | 1.000 | 1.000 | 0.000 | 0.722 | 0.0% | 100.0% |
| Semgrep + Bandit | 0.565 | 1.000 | 1.000 | 0.000 | 0.722 | — | — |
| Semgrep alone | 0.667 | 0.438 | 0.284 | 0.158 | 0.528 | 71.6% | 43.8% |
| Bandit alone | 0.567 | 0.885 | 0.878 | 0.011 | 0.691 | 12.2% | 88.5% |
| SAST board: Judge vote | 0.629 | 0.688 | 0.527 | 0.164 | 0.657 | 47.3% | 68.8% |
| SAST board + evidence override (ablation) | 0.576 | 0.906 | 0.865 | 0.065 | 0.705 | 13.5% | 90.6% |
| SAST board: vote score, dev-tuned threshold | 0.630 | 0.656 | 0.500 | 0.157 | 0.643 | 50.0% | 65.6% |
| SAST board + fusion (trained on dev) | 0.778 | 0.583 | 0.216 | 0.368 | 0.667 | 78.4% | 58.3% |
| LLM only, whole function, no SAST | 0.646 | 0.667 | 0.473 | 0.195 | 0.656 | 52.7% | 66.7% |
| LLM only, dev-tuned threshold | 0.646 | 0.667 | 0.473 | 0.195 | 0.656 | 52.7% | 66.7% |
| LLM only + same-file context, no SAST | 0.660 | 0.646 | 0.432 | 0.213 | 0.653 | 56.8% | 64.6% |
| LLM only + context, dev-tuned threshold | 0.702 | 0.615 | 0.338 | 0.274 | 0.656 | 66.2% | 61.5% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed | Verdicts differ | Right way round when they differ |
|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 338 | 0.000 [0.000, 0.000] | 1.000 | 0.000 | 0.000 | 0.000 | — |
| Semgrep + Bandit | 338 | 0.083 [0.057, 0.114] | 0.201 | 0.698 | 0.018 | 0.101 | 0.824 |
| Semgrep alone | 338 | 0.065 [0.042, 0.094] | 0.059 | 0.873 | 0.003 | 0.068 | 0.957 |
| Bandit alone | 338 | 0.077 [0.051, 0.107] | 0.175 | 0.731 | 0.018 | 0.095 | 0.812 |
| SAST board: Judge vote | 338 | 0.101 [0.071, 0.137] | 0.095 | 0.784 | 0.021 | 0.121 | 0.829 |
| SAST board + evidence override (ablation) | 338 | 0.083 [0.058, 0.115] | 0.175 | 0.728 | 0.015 | 0.098 | 0.849 |
| SAST board: vote score, dev-tuned threshold | 338 | 0.095 [0.067, 0.130] | 0.092 | 0.796 | 0.018 | 0.112 | 0.842 |
| SAST board + fusion (trained on dev) | 338 | 0.130 [0.093, 0.170] | 0.035 | 0.823 | 0.012 | 0.142 | 0.917 |
| LLM only, whole function, no SAST | 338 | 0.086 [0.057, 0.119] | 0.228 | 0.672 | 0.015 | 0.101 | 0.853 |
| LLM only, dev-tuned threshold | 338 | 0.089 [0.059, 0.124] | 0.228 | 0.669 | 0.015 | 0.104 | 0.857 |
| LLM only + same-file context, no SAST | 338 | 0.089 [0.058, 0.122] | 0.207 | 0.695 | 0.009 | 0.098 | 0.909 |
| LLM only + context, dev-tuned threshold | 338 | 0.095 [0.063, 0.133] | 0.183 | 0.710 | 0.012 | 0.106 | 0.889 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit | 1.000 | 1.000 |
| SAST board: Judge vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.991 | 0.852 |
| SAST board + fusion (trained on dev) | 0.911 | 0.831 |
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
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.387, -0.153] | 1.000 | — | — | 0.019 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.266 [0.153, 0.387] | — | 0 | 0.633 | 0 | — | 1.66 | 0.080 / 0.017 |
| Semgrep alone | +0.317 [0.193, 0.460] | [-0.040, 0.148] | 0 | — | — | 1.000 | 2.47 | 0.115 / 0.024 |
| Bandit alone | +0.240 [0.129, 0.366] | [-0.069, 0.000] | 0 | — | — | 1.000 | 1.76 | 0.085 / 0.018 |
| SAST board: Judge vote | +0.317 [0.193, 0.455] | [-0.065, 0.162] | 0 | 0.696 | 0 | 1.000 | 2.32 | 0.109 / 0.023 |
| SAST board + evidence override (ablation) | +0.279 [0.159, 0.406] | [-0.065, 0.098] | 0 | — | — | 1.000 | 1.81 | 0.087 / 0.018 |
| SAST board: vote score, dev-tuned threshold | +0.342 [0.210, 0.486] | [-0.052, 0.193] | 0 | 0.766 | 0 | 1.000 | 2.59 | 0.120 / 0.025 |
| SAST board + fusion (trained on dev) | +0.266 [0.138, 0.411] | [-0.135, 0.141] | 0 | 0.785 | 0 | 1.000 | 2.50 | 0.116 / 0.025 |
| LLM only, whole function, no SAST | +0.165 [0.064, 0.274] | [-0.235, 0.023] | 0.002 | 0.608 | 0.007 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only, dev-tuned threshold | +0.165 [0.064, 0.274] | [-0.235, 0.023] | 0.002 | 0.608 | 0.007 | 1.000 | 1.33 | 0.066 / 0.013 |
| LLM only + same-file context, no SAST | +0.203 [0.103, 0.312] | [-0.198, 0.074] | 0.0005 | 0.633 | 0.002 | 1.000 | 1.48 | 0.072 / 0.015 |
| LLM only + context, dev-tuned threshold | +0.228 [0.123, 0.360] | [-0.171, 0.110] | 0.0005 | 0.633 | 0.002 | 1.000 | 1.69 | 0.082 / 0.017 |

### ReposVul static check did not match — 646 functions, 323 pairs

**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? Score AUC: share of pairs where the vulnerable version gets the higher score. p values are Holm-corrected across systems; CIs resample whole repositories.

| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p | McNemar p vs SAST | LR+ | 5% / 1% prevalence: precision |
|---|---|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | +0.000 [0.000, 0.000] | [-0.045, 0.003] | 1.000 | — | — | 0.831 | 1.00 | 0.050 / 0.010 |
| Semgrep + Bandit | +0.019 [-0.003, 0.045] | — | 0.539 | 0.509 | 1.000 | — | 1.14 | 0.056 / 0.011 |
| Semgrep alone | -0.003 [-0.011, 0.000] | [-0.050, 0.003] | 1.000 | — | — | 1.000 | 0.90 | 0.045 / 0.009 |
| Bandit alone | +0.022 [0.000, 0.050] | [-0.000, 0.010] | 0.474 | — | — | 1.000 | 1.18 | 0.058 / 0.012 |
| SAST board: Judge vote | +0.028 [0.000, 0.059] | [-0.010, 0.029] | 0.466 | 0.511 | 1.000 | 1.000 | 1.41 | 0.069 / 0.014 |
| SAST board + evidence override (ablation) | +0.028 [0.004, 0.057] | [0.000, 0.020] | 0.294 | — | — | 1.000 | 1.23 | 0.061 / 0.012 |
| SAST board: vote score, dev-tuned threshold | +0.022 [-0.006, 0.054] | [-0.017, 0.025] | 0.539 | 0.519 | 0.403 | 1.000 | 1.35 | 0.066 / 0.013 |
| SAST board + fusion (trained on dev) | +0.040 [0.012, 0.075] | [-0.007, 0.051] | 0.072 | 0.529 | 0.101 | 1.000 | 2.18 | 0.103 / 0.022 |
| LLM only, whole function, no SAST | +0.046 [0.007, 0.087] | [-0.019, 0.071] | 0.073 | 0.501 | 1.000 | 1.000 | 1.25 | 0.061 / 0.012 |
| LLM only, dev-tuned threshold | +0.050 [0.011, 0.090] | [-0.015, 0.074] | 0.058 | 0.501 | 1.000 | 1.000 | 1.26 | 0.062 / 0.013 |
| LLM only + same-file context, no SAST | +0.043 [0.003, 0.084] | [-0.019, 0.070] | 0.100 | 0.486 | 1.000 | 1.000 | 1.23 | 0.061 / 0.012 |
| LLM only + context, dev-tuned threshold | +0.046 [0.010, 0.086] | [-0.018, 0.070] | 0.100 | 0.486 | 1.000 | 1.000 | 1.27 | 0.063 / 0.013 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | FPR | Accuracy | MCC | F1 |
|---|---|---|---|---|---|---|
| Flag every function (trivial reference) | 0.500 | 1.000 | 1.000 | 0.500 | 0.000 | 0.667 |
| Semgrep + Bandit | 0.608 | 0.191 | 0.123 | 0.534 | 0.093 | 0.291 |
| Semgrep alone | 0.611 | 0.088 | 0.056 | 0.516 | 0.062 | 0.153 |
| Bandit alone | 0.621 | 0.163 | 0.100 | 0.532 | 0.094 | 0.259 |
| SAST board: Judge vote | 0.727 | 0.159 | 0.060 | 0.550 | 0.159 | 0.261 |
| SAST board + evidence override (ablation) | 0.682 | 0.179 | 0.084 | 0.548 | 0.141 | 0.284 |
| SAST board: vote score, dev-tuned threshold | 0.727 | 0.159 | 0.060 | 0.550 | 0.159 | 0.261 |
| SAST board + fusion (trained on dev) | 0.857 | 0.119 | 0.020 | 0.550 | 0.196 | 0.210 |
| LLM only, whole function, no SAST | 0.642 | 0.279 | 0.155 | 0.562 | 0.150 | 0.389 |
| LLM only, dev-tuned threshold | 0.645 | 0.283 | 0.155 | 0.564 | 0.154 | 0.393 |
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
