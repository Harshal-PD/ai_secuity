# HackerSec real-world evaluation (2026-09-28T07:32:11)

Status: **complete** — 1498/1500 samples evaluated (100.0%), 2 LLM failures, 0 errors.

## cvefixes — 999 functions, 500 pairs

**End-to-end** (recall capped by static analysis)

| System | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.573 | 0.220 | 0.318 | 0.164 | 0.528 |
| HackerSec: board verdict | 0.583 | 0.218 | 0.318 | 0.156 | 0.531 |
| HackerSec: board + fusion (provisional) | 0.573 | 0.220 | 0.318 | 0.164 | 0.528 |

**On functions static analysis flagged** (192: 110 vulnerable, 82 fixed)

| System | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.573 | 1.000 | 0.729 | 1.000 |
| HackerSec: board verdict | 0.583 | 0.991 | 0.734 | 0.951 |
| HackerSec: board + fusion (provisional) | 0.573 | 1.000 | 0.729 | 1.000 |

Board removed **4.9%** of static false positives while keeping **99.1%** of true positives.

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct | P-V both flagged | P-B both cleared | P-R reversed |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 499 | 0.064 | 0.156 | 0.771 | 0.008 |
| HackerSec: board verdict | 499 | 0.070 | 0.148 | 0.773 | 0.008 |
| HackerSec: board + fusion (provisional) | 499 | 0.064 | 0.156 | 0.771 | 0.008 |

## vudenc — 499 functions, 250 pairs

**End-to-end** (recall capped by static analysis)

| System | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.568 | 0.253 | 0.350 | 0.192 | 0.531 |
| HackerSec: board verdict | 0.574 | 0.249 | 0.347 | 0.184 | 0.533 |
| HackerSec: board + fusion (provisional) | 0.568 | 0.253 | 0.350 | 0.192 | 0.531 |

**On functions static analysis flagged** (111: 63 vulnerable, 48 fixed)

| System | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.568 | 1.000 | 0.724 | 1.000 |
| HackerSec: board verdict | 0.574 | 0.984 | 0.725 | 0.958 |
| HackerSec: board + fusion (provisional) | 0.568 | 1.000 | 0.724 | 1.000 |

Board removed **4.2%** of static false positives while keeping **98.4%** of true positives.

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct | P-V both flagged | P-B both cleared | P-R reversed |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 249 | 0.072 | 0.181 | 0.735 | 0.012 |
| HackerSec: board verdict | 249 | 0.080 | 0.169 | 0.735 | 0.016 |
| HackerSec: board + fusion (provisional) | 249 | 0.072 | 0.181 | 0.735 | 0.012 |

## combined — 1498 functions, 750 pairs

**End-to-end** (recall capped by static analysis)

| System | Precision | Recall | F1 | FPR | Accuracy |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.571 | 0.231 | 0.329 | 0.173 | 0.529 |
| HackerSec: board verdict | 0.580 | 0.229 | 0.328 | 0.165 | 0.532 |
| HackerSec: board + fusion (provisional) | 0.571 | 0.231 | 0.329 | 0.173 | 0.529 |

**On functions static analysis flagged** (303: 173 vulnerable, 130 fixed)

| System | Precision | Recall | F1 | FPR |
|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 0.571 | 1.000 | 0.727 | 1.000 |
| HackerSec: board verdict | 0.580 | 0.988 | 0.731 | 0.954 |
| HackerSec: board + fusion (provisional) | 0.571 | 1.000 | 0.727 | 1.000 |

Board removed **4.6%** of static false positives while keeping **98.8%** of true positives.

**Pairwise** (vulnerable vs fixed version of the same function)

| System | Pairs | P-C correct | P-V both flagged | P-B both cleared | P-R reversed |
|---|---|---|---|---|---|
| Semgrep + Bandit (baseline) | 748 | 0.067 | 0.164 | 0.759 | 0.009 |
| HackerSec: board verdict | 748 | 0.073 | 0.155 | 0.761 | 0.011 |
| HackerSec: board + fusion (provisional) | 748 | 0.067 | 0.164 | 0.759 | 0.009 |
