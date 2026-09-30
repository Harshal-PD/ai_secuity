# HackerSec real-world evaluation (2026-09-30T00:14:29)

Status: **complete** — 1500/1500 samples evaluated (100.0%), 0 LLM failures, 0 errors. Pipeline: `v3-candidates-board`.

## Dev / test split

Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.

| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |
|---|---|---|---|
| cvefixes | 100 (52) | 400 (133) | 154 |
| vudenc | 50 (27) | 200 (103) | 90 |

- Dev functions evaluated: 300
- Board threshold on mean P(vulnerable) across Judge votes: **0.100** (max F1 on dev)
- Fusion: trained on 51 flagged dev functions (5-fold CV threshold), threshold 0.013, dev CV F1 0.328
- Candidates board threshold on mean P(vulnerable): **0.040** (max F1 on dev)
- Candidates fusion: trained on 294 flagged dev functions (5-fold CV threshold), threshold 0.286, dev CV F1 0.662

## Test split (primary)

### cvefixes — 800 functions, 400 pairs

**End-to-end** (every function; SAST-board recall is capped by SAST, candidates-board recall by the any-candidate row)

| System | Precision | Recall | F1 [95% CI] | ΔF1 vs SAST [95% CI] | FPR | McNemar p (accuracy) |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.568 | 0.230 | 0.327 [0.283, 0.367] | — | 0.175 | — |
| SAST board: Judge majority vote | 0.574 | 0.145 | 0.232 [0.186, 0.278] | [-0.127, -0.065] | 0.107 | 0.4426 |
| SAST board + evidence override (ablation) | 0.577 | 0.215 | 0.313 [0.270, 0.355] | [-0.031, -0.003] | 0.158 | 1.0000 |
| SAST board: vote score, dev-tuned threshold | 0.570 | 0.193 | 0.288 [0.243, 0.331] | [-0.061, -0.019] | 0.145 | 0.7011 |
| SAST board + fusion (trained on dev) | 0.568 | 0.230 | 0.327 [0.283, 0.367] | [0.000, 0.000] | 0.175 | 1.0000 |
| LLM auditor alone (no critic) | 0.498 | 0.980 | 0.660 [0.655, 0.665] | [0.292, 0.376] | 0.988 | 0.3371 |
| LLM-spec taint alone (no critic) | 0.496 | 0.698 | 0.580 [0.558, 0.600] | [0.212, 0.298] | 0.708 | 0.2427 |
| Any candidate: SAST, taint or auditor (no critic) | 0.499 | 0.988 | 0.663 [0.659, 0.666] | [0.295, 0.379] | 0.990 | 0.3804 |
| Candidates board: Judge majority vote | 0.512 | 0.527 | 0.520 [0.484, 0.554] | [0.144, 0.245] | 0.502 | 0.5632 |
| Candidates board + evidence override (ablation) | 0.510 | 0.935 | 0.660 [0.649, 0.671] | [0.291, 0.379] | 0.897 | 0.8073 |
| Candidates board: vote score, dev-tuned threshold | 0.492 | 0.917 | 0.640 [0.628, 0.652] | [0.273, 0.357] | 0.948 | 0.1742 |
| Candidates board + fusion (trained on dev) | 0.506 | 0.950 | 0.660 [0.650, 0.671] | [0.292, 0.376] | 0.927 | 0.6222 |

**On functions static analysis flagged** (162: 92 vulnerable, 70 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.568 | 1.000 | 0.724 | 1.000 | — | — |
| SAST board: Judge majority vote | 0.574 | 0.630 | 0.601 | 0.614 | 38.6% | 63.0% |
| SAST board + evidence override (ablation) | 0.577 | 0.935 | 0.714 | 0.900 | 10.0% | 93.5% |
| SAST board: vote score, dev-tuned threshold | 0.570 | 0.837 | 0.678 | 0.829 | 17.1% | 83.7% |
| SAST board + fusion (trained on dev) | 0.568 | 1.000 | 0.724 | 1.000 | 0.0% | 100.0% |
| LLM auditor alone (no critic) | 0.568 | 1.000 | 0.724 | 1.000 | 0.0% | 100.0% |
| LLM-spec taint alone (no critic) | 0.571 | 0.826 | 0.676 | 0.814 | 18.6% | 82.6% |
| Any candidate: SAST, taint or auditor (no critic) | 0.568 | 1.000 | 0.724 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.594 | 0.685 | 0.636 | 0.614 | 38.6% | 68.5% |
| Candidates board + evidence override (ablation) | 0.572 | 0.902 | 0.700 | 0.886 | 11.4% | 90.2% |
| Candidates board: vote score, dev-tuned threshold | 0.560 | 0.967 | 0.709 | 1.000 | 0.0% | 96.7% |
| Candidates board + fusion (trained on dev) | 0.569 | 0.989 | 0.722 | 0.986 | 1.4% | 98.9% |

**On functions any candidate source flagged (SAST, LLM-spec taint or auditor)** (791: 395 vulnerable, 396 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.568 | 0.233 | 0.330 | 0.177 | — | — |
| SAST board: Judge majority vote | 0.574 | 0.147 | 0.234 | 0.109 | 89.1% | 14.7% |
| SAST board + evidence override (ablation) | 0.577 | 0.218 | 0.316 | 0.159 | 84.1% | 21.8% |
| SAST board: vote score, dev-tuned threshold | 0.570 | 0.195 | 0.291 | 0.146 | 85.4% | 19.5% |
| SAST board + fusion (trained on dev) | 0.568 | 0.233 | 0.330 | 0.177 | 82.3% | 23.3% |
| LLM auditor alone (no critic) | 0.498 | 0.992 | 0.663 | 0.998 | 0.2% | 99.2% |
| LLM-spec taint alone (no critic) | 0.496 | 0.706 | 0.583 | 0.715 | 28.5% | 70.6% |
| Any candidate: SAST, taint or auditor (no critic) | 0.499 | 1.000 | 0.666 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.512 | 0.534 | 0.523 | 0.508 | 49.2% | 53.4% |
| Candidates board + evidence override (ablation) | 0.510 | 0.947 | 0.663 | 0.907 | 9.3% | 94.7% |
| Candidates board: vote score, dev-tuned threshold | 0.492 | 0.929 | 0.643 | 0.957 | 4.3% | 92.9% |
| Candidates board + fusion (trained on dev) | 0.506 | 0.962 | 0.663 | 0.937 | 6.3% | 96.2% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 400 | 0.065 [0.043, 0.090] | 0.165 | 0.760 | 0.010 |
| SAST board: Judge majority vote | 400 | 0.062 [0.040, 0.087] | 0.083 | 0.830 | 0.025 |
| SAST board + evidence override (ablation) | 400 | 0.070 [0.045, 0.095] | 0.145 | 0.772 | 0.013 |
| SAST board: vote score, dev-tuned threshold | 400 | 0.068 [0.045, 0.095] | 0.125 | 0.787 | 0.020 |
| SAST board + fusion (trained on dev) | 400 | 0.065 [0.043, 0.090] | 0.165 | 0.760 | 0.010 |
| LLM auditor alone (no critic) | 400 | 0.003 [0.000, 0.007] | 0.978 | 0.010 | 0.010 |
| LLM-spec taint alone (no critic) | 400 | 0.052 [0.032, 0.075] | 0.645 | 0.240 | 0.062 |
| Any candidate: SAST, taint or auditor (no critic) | 400 | 0.000 [0.000, 0.000] | 0.988 | 0.010 | 0.003 |
| Candidates board: Judge majority vote | 400 | 0.205 [0.167, 0.247] | 0.323 | 0.292 | 0.180 |
| Candidates board + evidence override (ablation) | 400 | 0.075 [0.050, 0.100] | 0.860 | 0.028 | 0.037 |
| Candidates board: vote score, dev-tuned threshold | 400 | 0.030 [0.013, 0.048] | 0.887 | 0.022 | 0.060 |
| Candidates board + fusion (trained on dev) | 400 | 0.052 [0.033, 0.075] | 0.897 | 0.020 | 0.030 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit (baseline) | 1.000 | 1.000 |
| SAST board: Judge majority vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.990 | 0.915 |
| SAST board + fusion (trained on dev) | 0.975 | 0.905 |
| LLM auditor alone (no critic) | 1.000 | 0.948 |
| Candidates board: Judge majority vote | 1.000 | 1.000 |
| Candidates board: vote score, dev-tuned threshold | 0.983 | 0.958 |
| Candidates board + fusion (trained on dev) | 0.985 | 0.927 |

### vudenc — 400 functions, 200 pairs

**End-to-end** (every function; SAST-board recall is capped by SAST, candidates-board recall by the any-candidate row)

| System | Precision | Recall | F1 [95% CI] | ΔF1 vs SAST [95% CI] | FPR | McNemar p (accuracy) |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.543 | 0.250 | 0.343 [0.282, 0.397] | — | 0.210 | — |
| SAST board: Judge majority vote | 0.642 | 0.215 | 0.322 [0.254, 0.381] | [-0.051, 0.005] | 0.120 | 0.0433 |
| SAST board + evidence override (ablation) | 0.583 | 0.245 | 0.345 [0.279, 0.401] | [-0.011, 0.012] | 0.175 | 0.0703 |
| SAST board: vote score, dev-tuned threshold | 0.603 | 0.235 | 0.338 [0.276, 0.395] | [-0.028, 0.015] | 0.155 | 0.0574 |
| SAST board + fusion (trained on dev) | 0.543 | 0.250 | 0.343 [0.282, 0.397] | [0.000, 0.000] | 0.210 | 1.0000 |
| LLM auditor alone (no critic) | 0.501 | 0.935 | 0.653 [0.639, 0.663] | [0.255, 0.371] | 0.930 | 0.7214 |
| LLM-spec taint alone (no critic) | 0.494 | 0.625 | 0.552 [0.520, 0.585] | [0.154, 0.270] | 0.640 | 0.4623 |
| Any candidate: SAST, taint or auditor (no critic) | 0.501 | 0.945 | 0.655 [0.642, 0.665] | [0.258, 0.373] | 0.940 | 0.7224 |
| Candidates board: Judge majority vote | 0.582 | 0.605 | 0.593 [0.550, 0.637] | [0.195, 0.314] | 0.435 | 0.0464 |
| Candidates board + evidence override (ablation) | 0.522 | 0.900 | 0.661 [0.641, 0.680] | [0.263, 0.377] | 0.825 | 0.7115 |
| Candidates board: vote score, dev-tuned threshold | 0.506 | 0.890 | 0.645 [0.626, 0.661] | [0.249, 0.361] | 0.870 | 0.8541 |
| Candidates board + fusion (trained on dev) | 0.511 | 0.905 | 0.653 [0.634, 0.671] | [0.257, 0.371] | 0.865 | 1.0000 |

**On functions static analysis flagged** (92: 50 vulnerable, 42 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.543 | 1.000 | 0.704 | 1.000 | — | — |
| SAST board: Judge majority vote | 0.642 | 0.860 | 0.735 | 0.571 | 42.9% | 86.0% |
| SAST board + evidence override (ablation) | 0.583 | 0.980 | 0.731 | 0.833 | 16.7% | 98.0% |
| SAST board: vote score, dev-tuned threshold | 0.603 | 0.940 | 0.734 | 0.738 | 26.2% | 94.0% |
| SAST board + fusion (trained on dev) | 0.543 | 1.000 | 0.704 | 1.000 | 0.0% | 100.0% |
| LLM auditor alone (no critic) | 0.538 | 0.980 | 0.695 | 1.000 | 0.0% | 98.0% |
| LLM-spec taint alone (no critic) | 0.550 | 0.880 | 0.677 | 0.857 | 14.3% | 88.0% |
| Any candidate: SAST, taint or auditor (no critic) | 0.543 | 1.000 | 0.704 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.606 | 0.860 | 0.711 | 0.667 | 33.3% | 86.0% |
| Candidates board + evidence override (ablation) | 0.563 | 0.980 | 0.715 | 0.905 | 9.5% | 98.0% |
| Candidates board: vote score, dev-tuned threshold | 0.562 | 1.000 | 0.719 | 0.929 | 7.1% | 100.0% |
| Candidates board + fusion (trained on dev) | 0.538 | 0.980 | 0.695 | 1.000 | 0.0% | 98.0% |

**On functions any candidate source flagged (SAST, LLM-spec taint or auditor)** (377: 189 vulnerable, 188 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.543 | 0.265 | 0.356 | 0.223 | — | — |
| SAST board: Judge majority vote | 0.642 | 0.228 | 0.336 | 0.128 | 87.2% | 22.8% |
| SAST board + evidence override (ablation) | 0.583 | 0.259 | 0.359 | 0.186 | 81.4% | 25.9% |
| SAST board: vote score, dev-tuned threshold | 0.603 | 0.249 | 0.352 | 0.165 | 83.5% | 24.9% |
| SAST board + fusion (trained on dev) | 0.543 | 0.265 | 0.356 | 0.223 | 77.7% | 26.5% |
| LLM auditor alone (no critic) | 0.501 | 0.989 | 0.665 | 0.989 | 1.1% | 98.9% |
| LLM-spec taint alone (no critic) | 0.494 | 0.661 | 0.566 | 0.681 | 31.9% | 66.1% |
| Any candidate: SAST, taint or auditor (no critic) | 0.501 | 1.000 | 0.668 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.582 | 0.640 | 0.610 | 0.463 | 53.7% | 64.0% |
| Candidates board + evidence override (ablation) | 0.522 | 0.952 | 0.674 | 0.878 | 12.2% | 95.2% |
| Candidates board: vote score, dev-tuned threshold | 0.506 | 0.942 | 0.658 | 0.925 | 7.4% | 94.2% |
| Candidates board + fusion (trained on dev) | 0.511 | 0.958 | 0.667 | 0.920 | 8.0% | 95.8% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 200 | 0.055 [0.025, 0.085] | 0.195 | 0.735 | 0.015 |
| SAST board: Judge majority vote | 200 | 0.110 [0.070, 0.150] | 0.105 | 0.770 | 0.015 |
| SAST board + evidence override (ablation) | 200 | 0.085 [0.050, 0.120] | 0.160 | 0.740 | 0.015 |
| SAST board: vote score, dev-tuned threshold | 200 | 0.095 [0.055, 0.135] | 0.140 | 0.750 | 0.015 |
| SAST board + fusion (trained on dev) | 200 | 0.055 [0.025, 0.085] | 0.195 | 0.735 | 0.015 |
| LLM auditor alone (no critic) | 200 | 0.030 [0.010, 0.055] | 0.905 | 0.040 | 0.025 |
| LLM-spec taint alone (no critic) | 200 | 0.035 [0.015, 0.060] | 0.590 | 0.325 | 0.050 |
| Any candidate: SAST, taint or auditor (no critic) | 200 | 0.025 [0.005, 0.050] | 0.920 | 0.035 | 0.020 |
| Candidates board: Judge majority vote | 200 | 0.250 [0.195, 0.310] | 0.355 | 0.315 | 0.080 |
| Candidates board + evidence override (ablation) | 200 | 0.115 [0.075, 0.160] | 0.785 | 0.060 | 0.040 |
| Candidates board: vote score, dev-tuned threshold | 200 | 0.060 [0.030, 0.095] | 0.830 | 0.070 | 0.040 |
| Candidates board + fusion (trained on dev) | 200 | 0.090 [0.050, 0.130] | 0.815 | 0.045 | 0.050 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit (baseline) | 1.000 | 1.000 |
| SAST board: Judge majority vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.995 | 0.990 |
| SAST board + fusion (trained on dev) | 0.990 | 0.895 |
| LLM auditor alone (no critic) | 1.000 | 0.915 |
| Candidates board: Judge majority vote | 1.000 | 1.000 |
| Candidates board: vote score, dev-tuned threshold | 1.000 | 0.940 |
| Candidates board + fusion (trained on dev) | 1.000 | 0.860 |

### combined — 1200 functions, 600 pairs

**End-to-end** (every function; SAST-board recall is capped by SAST, candidates-board recall by the any-candidate row)

| System | Precision | Recall | F1 [95% CI] | ΔF1 vs SAST [95% CI] | FPR | McNemar p (accuracy) |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.559 | 0.237 | 0.333 [0.297, 0.365] | — | 0.187 | — |
| SAST board: Judge majority vote | 0.601 | 0.168 | 0.263 [0.225, 0.301] | [-0.094, -0.046] | 0.112 | 0.7465 |
| SAST board + evidence override (ablation) | 0.579 | 0.225 | 0.324 [0.287, 0.358] | [-0.018, -0.001] | 0.163 | 0.1892 |
| SAST board: vote score, dev-tuned threshold | 0.582 | 0.207 | 0.305 [0.269, 0.340] | [-0.044, -0.012] | 0.148 | 0.5327 |
| SAST board + fusion (trained on dev) | 0.559 | 0.237 | 0.333 [0.297, 0.365] | [0.000, 0.000] | 0.187 | 1.0000 |
| LLM auditor alone (no critic) | 0.499 | 0.965 | 0.658 [0.652, 0.663] | [0.293, 0.361] | 0.968 | 0.3036 |
| LLM-spec taint alone (no critic) | 0.496 | 0.673 | 0.571 [0.552, 0.587] | [0.204, 0.275] | 0.685 | 0.1556 |
| Any candidate: SAST, taint or auditor (no critic) | 0.500 | 0.973 | 0.661 [0.656, 0.665] | [0.295, 0.364] | 0.973 | 0.3374 |
| Candidates board: Judge majority vote | 0.535 | 0.553 | 0.544 [0.513, 0.572] | [0.172, 0.251] | 0.480 | 0.5687 |
| Candidates board + evidence override (ablation) | 0.514 | 0.923 | 0.660 [0.650, 0.669] | [0.294, 0.364] | 0.873 | 1.0000 |
| Candidates board: vote score, dev-tuned threshold | 0.496 | 0.908 | 0.642 [0.632, 0.652] | [0.277, 0.345] | 0.922 | 0.2060 |
| Candidates board + fusion (trained on dev) | 0.508 | 0.935 | 0.658 [0.649, 0.667] | [0.292, 0.361] | 0.907 | 0.6819 |

**On functions static analysis flagged** (254: 142 vulnerable, 112 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.559 | 1.000 | 0.717 | 1.000 | — | — |
| SAST board: Judge majority vote | 0.601 | 0.711 | 0.652 | 0.598 | 40.2% | 71.1% |
| SAST board + evidence override (ablation) | 0.579 | 0.951 | 0.720 | 0.875 | 12.5% | 95.1% |
| SAST board: vote score, dev-tuned threshold | 0.582 | 0.873 | 0.699 | 0.795 | 20.5% | 87.3% |
| SAST board + fusion (trained on dev) | 0.559 | 1.000 | 0.717 | 1.000 | 0.0% | 100.0% |
| LLM auditor alone (no critic) | 0.557 | 0.993 | 0.714 | 1.000 | 0.0% | 99.3% |
| LLM-spec taint alone (no critic) | 0.563 | 0.845 | 0.676 | 0.830 | 17.0% | 84.5% |
| Any candidate: SAST, taint or auditor (no critic) | 0.559 | 1.000 | 0.717 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.599 | 0.747 | 0.665 | 0.634 | 36.6% | 74.7% |
| Candidates board + evidence override (ablation) | 0.569 | 0.930 | 0.706 | 0.893 | 10.7% | 93.0% |
| Candidates board: vote score, dev-tuned threshold | 0.560 | 0.979 | 0.713 | 0.973 | 2.7% | 97.9% |
| Candidates board + fusion (trained on dev) | 0.558 | 0.986 | 0.713 | 0.991 | 0.9% | 98.6% |

**On functions any candidate source flagged (SAST, LLM-spec taint or auditor)** (1168: 584 vulnerable, 584 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.559 | 0.243 | 0.339 | 0.192 | — | — |
| SAST board: Judge majority vote | 0.601 | 0.173 | 0.269 | 0.115 | 88.5% | 17.3% |
| SAST board + evidence override (ablation) | 0.579 | 0.231 | 0.331 | 0.168 | 83.2% | 23.1% |
| SAST board: vote score, dev-tuned threshold | 0.582 | 0.212 | 0.311 | 0.152 | 84.8% | 21.2% |
| SAST board + fusion (trained on dev) | 0.559 | 0.243 | 0.339 | 0.192 | 80.8% | 24.3% |
| LLM auditor alone (no critic) | 0.499 | 0.991 | 0.664 | 0.995 | 0.5% | 99.1% |
| LLM-spec taint alone (no critic) | 0.496 | 0.692 | 0.578 | 0.704 | 29.6% | 69.2% |
| Any candidate: SAST, taint or auditor (no critic) | 0.500 | 1.000 | 0.667 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.535 | 0.569 | 0.551 | 0.493 | 50.7% | 56.9% |
| Candidates board + evidence override (ablation) | 0.514 | 0.949 | 0.667 | 0.897 | 10.3% | 94.9% |
| Candidates board: vote score, dev-tuned threshold | 0.496 | 0.933 | 0.648 | 0.947 | 5.3% | 93.3% |
| Candidates board + fusion (trained on dev) | 0.508 | 0.961 | 0.664 | 0.931 | 6.9% | 96.1% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 600 | 0.062 [0.043, 0.082] | 0.175 | 0.752 | 0.012 |
| SAST board: Judge majority vote | 600 | 0.078 [0.058, 0.100] | 0.090 | 0.810 | 0.022 |
| SAST board + evidence override (ablation) | 600 | 0.075 [0.055, 0.097] | 0.150 | 0.762 | 0.013 |
| SAST board: vote score, dev-tuned threshold | 600 | 0.077 [0.057, 0.098] | 0.130 | 0.775 | 0.018 |
| SAST board + fusion (trained on dev) | 600 | 0.062 [0.043, 0.082] | 0.175 | 0.752 | 0.012 |
| LLM auditor alone (no critic) | 600 | 0.012 [0.005, 0.022] | 0.953 | 0.020 | 0.015 |
| LLM-spec taint alone (no critic) | 600 | 0.047 [0.030, 0.063] | 0.627 | 0.268 | 0.058 |
| Any candidate: SAST, taint or auditor (no critic) | 600 | 0.008 [0.002, 0.015] | 0.965 | 0.018 | 0.008 |
| Candidates board: Judge majority vote | 600 | 0.220 [0.185, 0.252] | 0.333 | 0.300 | 0.147 |
| Candidates board + evidence override (ablation) | 600 | 0.088 [0.068, 0.112] | 0.835 | 0.038 | 0.038 |
| Candidates board: vote score, dev-tuned threshold | 600 | 0.040 [0.027, 0.057] | 0.868 | 0.038 | 0.053 |
| Candidates board + fusion (trained on dev) | 600 | 0.065 [0.047, 0.087] | 0.870 | 0.028 | 0.037 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit (baseline) | 1.000 | 1.000 |
| SAST board: Judge majority vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.990 | 0.985 |
| SAST board + fusion (trained on dev) | 0.983 | 0.900 |
| LLM auditor alone (no critic) | 1.000 | 0.937 |
| Candidates board: Judge majority vote | 1.000 | 1.000 |
| Candidates board: vote score, dev-tuned threshold | 1.000 | 0.952 |
| Candidates board + fusion (trained on dev) | 0.997 | 0.917 |

### CWE families (test)

SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.

| Family | Functions | Vulnerable flagged by SAST | Vulnerable with any candidate | sast F1 / R | board_calibrated F1 / R | hunter_raw F1 / R | union_raw F1 / R | full_board F1 / R | full_fusion F1 / R |
|---|---|---|---|---|---|---|---|---|---|
| **logic_semantic** | 526 | 13.3% | 97.7% | 0.213 / 0.133 | 0.167 / 0.099 | 0.656 / 0.962 | 0.663 / 0.977 | 0.456 / 0.422 | 0.649 / 0.928 |
| **sast_reachable** | 674 | 31.8% | 97.0% | 0.407 / 0.318 | 0.390 / 0.291 | 0.659 / 0.967 | 0.659 / 0.970 | 0.603 / 0.656 | 0.665 / 0.941 |
| injection | 350 | 36.6% | 96.0% | 0.444 / 0.366 | 0.448 / 0.354 | 0.656 / 0.960 | 0.655 / 0.960 | 0.610 / 0.651 | 0.658 / 0.920 |
| access_control (logic) | 216 | 14.8% | 95.4% | 0.234 / 0.148 | 0.159 / 0.093 | 0.654 / 0.935 | 0.662 / 0.954 | 0.488 / 0.472 | 0.647 / 0.907 |
| path_traversal | 120 | 16.7% | 98.3% | 0.260 / 0.167 | 0.222 / 0.133 | 0.667 / 0.983 | 0.663 / 0.983 | 0.627 / 0.700 | 0.678 / 0.967 |
| ssrf_redirect | 116 | 25.9% | 98.3% | 0.349 / 0.259 | 0.342 / 0.241 | 0.659 / 0.966 | 0.663 / 0.983 | 0.576 / 0.621 | 0.663 / 0.966 |
| other (logic) | 92 | 10.9% | 100.0% | 0.179 / 0.109 | 0.151 / 0.087 | 0.667 / 1.000 | 0.667 / 1.000 | 0.380 / 0.326 | 0.647 / 0.935 |
| info_exposure (logic) | 88 | 11.4% | 100.0% | 0.192 / 0.114 | 0.157 / 0.091 | 0.656 / 0.977 | 0.667 / 1.000 | 0.578 / 0.591 | 0.656 / 0.977 |
| resource_dos (logic) | 64 | 6.2% | 100.0% | 0.108 / 0.062 | 0.108 / 0.062 | 0.653 / 0.969 | 0.667 / 1.000 | 0.346 / 0.281 | 0.659 / 0.938 |
| crypto_secrets | 52 | 15.4% | 96.2% | 0.229 / 0.154 | 0.121 / 0.077 | 0.658 / 0.962 | 0.658 / 0.962 | 0.481 / 0.500 | 0.667 / 0.923 |
| input_validation (logic) | 38 | 10.5% | 94.7% | 0.182 / 0.105 | 0.095 / 0.053 | 0.643 / 0.947 | 0.643 / 0.947 | 0.412 / 0.368 | 0.630 / 0.895 |
| deserialization | 20 | 100.0% | 100.0% | 0.769 / 1.000 | 0.720 / 0.900 | 0.667 / 1.000 | 0.667 / 1.000 | 0.692 / 0.900 | 0.667 / 1.000 |
| xml | 16 | 50.0% | 100.0% | 0.571 / 0.500 | 0.462 / 0.375 | 0.667 / 1.000 | 0.667 / 1.000 | 0.700 / 0.875 | 0.727 / 1.000 |
| unknown (logic) | 16 | 12.5% | 100.0% | 0.200 / 0.125 | 0.222 / 0.125 | 0.667 / 1.000 | 0.667 / 1.000 | 0.353 / 0.375 | 0.609 / 0.875 |
| memory_numeric (logic) | 12 | 66.7% | 100.0% | 0.571 / 0.667 | 0.571 / 0.667 | 0.667 / 1.000 | 0.667 / 1.000 | 0.000 / 0.000 | 0.706 / 1.000 |

### Pipeline telemetry (test)

- flagged_functions: 254
- findings: 451
- findings_per_flagged_function: 1.78
- by_tool: {'bandit': 335, 'semgrep': 116}
- cpg_success_rate: 0.9978
- cpg_taint_found_rate: 0.6497
- rag_context_rate: 1.0
- semgrep_failed_rate: 0.0
- bandit_failed_rate: 0.0
- **function_board**: functions 254, mean_valid_votes 5.0, unanimous_rate 1.0, split_vote_rate 0.0, no_valid_vote_rate 0.0, majority_not_vulnerable_rate 0.3386, evidence_grounded_rate 0.1024, override_flip_rate 0.2559, code_truncated_rate 0.0, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0197, defender_parse_failed_rate 0.0039, mean_seconds_per_function 445.5
- **candidates**: functions 1200, any_candidate_rate 0.9733, sast_rate 0.2117, llm_taint_rate 0.6792, auditor_rate 0.9667, only_llm_rate 0.7617, auditor_parse_failed_rate 0.0017, spec_parse_failed_rate 0.0367, mean_spec_sinks 3.31, mean_spec_sites_checked 3.24, mean_context_chars 424.8, mean_seconds_per_function 414.6
- **candidates_board**: functions 1168, mean_valid_votes 5.0, unanimous_rate 0.9923, split_vote_rate 0.0077, no_valid_vote_rate 0.0, majority_not_vulnerable_rate 0.4692, evidence_grounded_rate 0.083, override_flip_rate 0.3921, code_truncated_rate 0.0, context_overflow_rate 0.0, attacker_parse_failed_rate 0.0111, defender_parse_failed_rate 0.0009, mean_seconds_per_function 425.6

## Test, clean subset (single-function fixes)

### clean — 340 functions, 170 pairs

**End-to-end** (every function; SAST-board recall is capped by SAST, candidates-board recall by the any-candidate row)

| System | Precision | Recall | F1 [95% CI] | ΔF1 vs SAST [95% CI] | FPR | McNemar p (accuracy) |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.571 | 0.282 | 0.378 [0.309, 0.441] | — | 0.212 | — |
| SAST board: Judge majority vote | 0.641 | 0.200 | 0.305 [0.228, 0.377] | [-0.118, -0.032] | 0.112 | 0.7201 |
| SAST board + evidence override (ablation) | 0.603 | 0.277 | 0.379 [0.308, 0.444] | [-0.011, 0.011] | 0.182 | 0.2188 |
| SAST board: vote score, dev-tuned threshold | 0.627 | 0.247 | 0.354 [0.278, 0.429] | [-0.061, 0.006] | 0.147 | 0.3323 |
| SAST board + fusion (trained on dev) | 0.571 | 0.282 | 0.378 [0.309, 0.441] | [0.000, 0.000] | 0.212 | 1.0000 |
| LLM auditor alone (no critic) | 0.500 | 0.947 | 0.654 [0.642, 0.665] | [0.212, 0.344] | 0.947 | 0.4759 |
| LLM-spec taint alone (no critic) | 0.504 | 0.682 | 0.580 [0.546, 0.608] | [0.138, 0.272] | 0.671 | 0.4927 |
| Any candidate: SAST, taint or auditor (no critic) | 0.501 | 0.959 | 0.659 [0.649, 0.667] | [0.216, 0.349] | 0.953 | 0.5196 |
| Candidates board: Judge majority vote | 0.545 | 0.571 | 0.557 [0.504, 0.609] | [0.110, 0.251] | 0.476 | 0.8000 |
| Candidates board + evidence override (ablation) | 0.513 | 0.894 | 0.652 [0.632, 0.672] | [0.211, 0.342] | 0.847 | 0.8412 |
| Candidates board: vote score, dev-tuned threshold | 0.503 | 0.900 | 0.646 [0.627, 0.664] | [0.207, 0.334] | 0.888 | 0.5459 |
| Candidates board + fusion (trained on dev) | 0.513 | 0.929 | 0.661 [0.645, 0.675] | [0.222, 0.350] | 0.882 | 0.8412 |

**On functions static analysis flagged** (84: 48 vulnerable, 36 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.571 | 1.000 | 0.727 | 1.000 | — | — |
| SAST board: Judge majority vote | 0.641 | 0.708 | 0.673 | 0.528 | 47.2% | 70.8% |
| SAST board + evidence override (ablation) | 0.603 | 0.979 | 0.746 | 0.861 | 13.9% | 97.9% |
| SAST board: vote score, dev-tuned threshold | 0.627 | 0.875 | 0.730 | 0.694 | 30.6% | 87.5% |
| SAST board + fusion (trained on dev) | 0.571 | 1.000 | 0.727 | 1.000 | 0.0% | 100.0% |
| LLM auditor alone (no critic) | 0.571 | 1.000 | 0.727 | 1.000 | 0.0% | 100.0% |
| LLM-spec taint alone (no critic) | 0.563 | 0.833 | 0.672 | 0.861 | 13.9% | 83.3% |
| Any candidate: SAST, taint or auditor (no critic) | 0.571 | 1.000 | 0.727 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.607 | 0.771 | 0.679 | 0.667 | 33.3% | 77.1% |
| Candidates board + evidence override (ablation) | 0.577 | 0.938 | 0.714 | 0.917 | 8.3% | 93.8% |
| Candidates board: vote score, dev-tuned threshold | 0.578 | 1.000 | 0.733 | 0.972 | 2.8% | 100.0% |
| Candidates board + fusion (trained on dev) | 0.571 | 1.000 | 0.727 | 1.000 | 0.0% | 100.0% |

**On functions any candidate source flagged (SAST, LLM-spec taint or auditor)** (325: 163 vulnerable, 162 fixed)

| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |
|---|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.571 | 0.294 | 0.389 | 0.222 | — | — |
| SAST board: Judge majority vote | 0.641 | 0.209 | 0.315 | 0.117 | 88.3% | 20.9% |
| SAST board + evidence override (ablation) | 0.603 | 0.288 | 0.390 | 0.191 | 80.9% | 28.8% |
| SAST board: vote score, dev-tuned threshold | 0.627 | 0.258 | 0.365 | 0.154 | 84.6% | 25.8% |
| SAST board + fusion (trained on dev) | 0.571 | 0.294 | 0.389 | 0.222 | 77.8% | 29.4% |
| LLM auditor alone (no critic) | 0.500 | 0.988 | 0.664 | 0.994 | 0.6% | 98.8% |
| LLM-spec taint alone (no critic) | 0.504 | 0.712 | 0.590 | 0.704 | 29.6% | 71.2% |
| Any candidate: SAST, taint or auditor (no critic) | 0.501 | 1.000 | 0.668 | 1.000 | 0.0% | 100.0% |
| Candidates board: Judge majority vote | 0.545 | 0.595 | 0.569 | 0.500 | 50.0% | 59.5% |
| Candidates board + evidence override (ablation) | 0.513 | 0.932 | 0.662 | 0.889 | 11.1% | 93.2% |
| Candidates board: vote score, dev-tuned threshold | 0.503 | 0.939 | 0.655 | 0.932 | 6.8% | 93.9% |
| Candidates board + fusion (trained on dev) | 0.513 | 0.969 | 0.671 | 0.926 | 7.4% | 96.9% |

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 170 | 0.088 [0.041, 0.135] | 0.194 | 0.700 | 0.018 |
| SAST board: Judge majority vote | 170 | 0.106 [0.059, 0.159] | 0.094 | 0.782 | 0.018 |
| SAST board + evidence override (ablation) | 170 | 0.112 [0.065, 0.165] | 0.165 | 0.706 | 0.018 |
| SAST board: vote score, dev-tuned threshold | 170 | 0.135 [0.088, 0.194] | 0.112 | 0.718 | 0.035 |
| SAST board + fusion (trained on dev) | 170 | 0.088 [0.041, 0.135] | 0.194 | 0.700 | 0.018 |
| LLM auditor alone (no critic) | 170 | 0.012 [0.000, 0.029] | 0.935 | 0.041 | 0.012 |
| LLM-spec taint alone (no critic) | 170 | 0.059 [0.029, 0.100] | 0.624 | 0.271 | 0.047 |
| Any candidate: SAST, taint or auditor (no critic) | 170 | 0.012 [0.000, 0.029] | 0.947 | 0.035 | 0.006 |
| Candidates board: Judge majority vote | 170 | 0.235 [0.176, 0.306] | 0.335 | 0.288 | 0.141 |
| Candidates board + evidence override (ablation) | 170 | 0.088 [0.047, 0.135] | 0.806 | 0.065 | 0.041 |
| Candidates board: vote score, dev-tuned threshold | 170 | 0.053 [0.024, 0.088] | 0.847 | 0.059 | 0.041 |
| Candidates board + fusion (trained on dev) | 170 | 0.065 [0.029, 0.100] | 0.865 | 0.053 | 0.018 |

**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)

| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |
|---|---|---|
| Semgrep + Bandit (baseline) | 1.000 | 1.000 |
| SAST board: Judge majority vote | 1.000 | 1.000 |
| SAST board: vote score, dev-tuned threshold | 0.994 | 0.994 |
| SAST board + fusion (trained on dev) | 0.953 | 0.841 |
| LLM auditor alone (no critic) | 1.000 | 0.941 |
| Candidates board: Judge majority vote | 1.000 | 1.000 |
| Candidates board: vote score, dev-tuned threshold | 1.000 | 0.953 |
| Candidates board + fusion (trained on dev) | 0.977 | 0.882 |

## Dev split (used for calibration; not a held-out result)

| System | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.647 | 0.220 | 0.328 | 0.120 |
| SAST board: Judge majority vote | 0.769 | 0.200 | 0.318 | 0.060 |
| SAST board + evidence override (ablation) | 0.667 | 0.213 | 0.323 | 0.107 |
| SAST board: vote score, dev-tuned threshold | 0.673 | 0.220 | 0.332 | 0.107 |
| SAST board + fusion (trained on dev) | 0.647 | 0.220 | 0.328 | 0.120 |
| LLM auditor alone (no critic) | 0.498 | 0.967 | 0.658 | 0.973 |
| LLM-spec taint alone (no critic) | 0.485 | 0.753 | 0.590 | 0.800 |
| Any candidate: SAST, taint or auditor (no critic) | 0.497 | 0.973 | 0.658 | 0.987 |
| Candidates board: Judge majority vote | 0.572 | 0.607 | 0.589 | 0.453 |
| Candidates board + evidence override (ablation) | 0.523 | 0.913 | 0.665 | 0.833 |
| Candidates board: vote score, dev-tuned threshold | 0.509 | 0.967 | 0.667 | 0.933 |
| Candidates board + fusion (trained on dev) | 0.516 | 0.940 | 0.667 | 0.880 |

## Caveats

- Labels follow CVEfixes: a function changed by a security-fix commit is vulnerable before the fix and fixed after it. Tangled commits (> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded; the clean subset further keeps only commits that changed a single function.
- The SAST board only reasons about Semgrep/Bandit findings, so its recall cannot exceed theirs. The candidates board also sees LLM-spec taint flows (IRIS-style: the LLM labels the function's calls as sources/sinks and Joern checks the flows) and LLM auditor candidates (GPTLens-style), so its ceiling is the 'any candidate' recall. The *_flagged views isolate what each board adds over its candidates.
- The auditor and the spec labelling see only the code and same-file callers/callees, never the dataset's label or CWE. Context is limited to the same file; cross-file callers are not shown.
- The auditor-alone and taint-alone rows have no critic; they measure how much each candidate source finds, and how noisy it is, before the board filters it.
- Board thresholds and fusion models are fitted on the dev split only; test repositories never appear in dev. Dev numbers are in-sample and are shown for reference.
- Confidence intervals resample vulnerable/fixed pairs (1,000 draws); McNemar compares per-function correctness against SAST and only differs from it on flagged functions.
- VUDENC commits are keyword-mined and noisier than CVE-linked CVEfixes commits; compare within, not across, datasets.
