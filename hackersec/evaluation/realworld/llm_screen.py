"""
Soft LLM Screen (union gate) for functions deterministic SAST does not flag.

Gate rule, default (REALWORLD_LLM_SCREEN_RULE=flag):
  board_candidate(x) = SAST_Gate(x) OR LLM_flag(x)

LLM_flag is the single-pass context baseline's verdict (`llm_context_pred`, 1 when
it says VULNERABLE). Every function it flags goes to the Board; no score threshold
drops any of them.

Gate rule tau (REALWORLD_LLM_SCREEN_RULE=tau, the earlier percentile gate):
  board_candidate(x) = SAST_Gate(x) OR S_LLM(x) >= tau_recall

S_LLM is the single-pass LLM+context probability (`llm_context_p`).
tau_recall is the score at the (1 - pass_rate) quantile of DEV-split
SAST-unflagged scores, so roughly the top `pass_rate` most suspicious
unflagged functions pass (default 25%, mid of the 20–30% band).

Functions that fail both gates are SAFE (no Board tokens). gate_origin is
`sast` or `llm_screen` for Board candidates so Track 2 prompts can split.
"""

from __future__ import annotations

import logging
import math
import os
from pathlib import Path

from hackersec.evaluation.realworld import state

logger = logging.getLogger(__name__)

# Soft screen on by default; set REALWORLD_LLM_SCREEN=0 to restore SAST-only gate.
ENABLED = os.getenv("REALWORLD_LLM_SCREEN", "1") not in ("0", "false", "False")
# "flag": every function the context baseline flags as VULNERABLE goes to the Board.
# "tau": the earlier score threshold (tau_recall).
RULE = (os.getenv("REALWORLD_LLM_SCREEN_RULE") or "flag").strip().lower()
if RULE not in ("flag", "tau"):
    raise ValueError(f"REALWORLD_LLM_SCREEN_RULE must be 'flag' or 'tau', got {RULE!r}")
# Fraction of DEV unflagged functions that should pass the screen (mid of 20–30%).
PASS_RATE = float(os.getenv("REALWORLD_LLM_SCREEN_PASS_RATE", "0.25"))
if not 0.0 < PASS_RATE < 1.0:
    raise ValueError(f"REALWORLD_LLM_SCREEN_PASS_RATE must be in (0, 1), got {PASS_RATE!r}")
# Optional prior results dir / jsonl with llm_context_p to reuse instead of re-querying.
SCORE_SOURCE = (os.getenv("REALWORLD_LLM_SCREEN_FROM") or "").strip()
TAU_PATH = state.RESULTS_DIR / "tau_recall.json"
SCORE_KEY = "llm_context_p"


def percentile_threshold(scores: list[float], pass_rate: float = PASS_RATE) -> float | None:
    """Smallest threshold t such that the share of scores >= t is about pass_rate.

    Equivalent to the (1 - pass_rate) empirical quantile of the score list
    (e.g. pass_rate=0.25 → 75th percentile). Ties keep the inclusive cut so
    the passed share is never below the target when duplicates sit on the cut.
    """
    if not scores or pass_rate <= 0:
        return None
    ordered = sorted(float(s) for s in scores)
    n = len(ordered)
    # Boundary of the top ceil(n * pass_rate) scores (pass_rate=0.25 → ~75th pct).
    target_pass = max(1, int(math.ceil(n * pass_rate)))
    cut_idx = max(0, n - target_pass)
    return ordered[cut_idx]


def tune_tau_recall(
    records: list[dict],
    *,
    pass_rate: float = PASS_RATE,
    score_key: str = SCORE_KEY,
) -> dict | None:
    """Fit tau_recall on DEV SAST-unflagged functions that have a score.

    Returns a metadata dict (threshold, n, pass rate achieved) or None when
    there are not enough scored unflagged DEV functions.
    """
    unflagged = [
        r for r in records
        if r.get("split") == "dev"
        and not r.get("sast_pred")
        and r.get(score_key) is not None
    ]
    scores = [float(r[score_key]) for r in unflagged]
    if len(scores) < 5:
        return None
    tau = percentile_threshold(scores, pass_rate)
    if tau is None:
        return None
    passed = sum(1 for s in scores if s >= tau)
    return {
        "tau_recall": round(tau, 6),
        "pass_rate_target": pass_rate,
        "pass_rate_achieved": round(passed / len(scores), 4),
        "n_dev_unflagged_scored": len(scores),
        "n_dev_unflagged_passed": passed,
        "score_key": score_key,
    }


def gate_origin(
    sast_pred: int | bool,
    llm_flag: int | bool | None,
    llm_score: float | None = None,
    tau: float | None = None,
) -> str | None:
    """Return `sast`, `llm_screen`, or None (SAFE / skip Board).

    Rule flag: an LLM flag passes (llm_score and tau are ignored).
    Rule tau: llm_score must reach tau (llm_flag is ignored).
    """
    if sast_pred:
        return "sast"
    if not ENABLED:
        return None
    if RULE == "flag":
        return "llm_screen" if llm_flag else None
    if tau is not None and llm_score is not None and float(llm_score) >= tau:
        return "llm_screen"
    return None


def board_candidate(
    sast_pred: int | bool,
    llm_flag: int | bool | None,
    llm_score: float | None = None,
    tau: float | None = None,
) -> bool:
    return gate_origin(sast_pred, llm_flag, llm_score, tau) is not None


def load_tau() -> dict | None:
    data = state.read_json(TAU_PATH)
    if not data or data.get("tau_recall") is None:
        return None
    return data


def save_tau(meta: dict) -> Path:
    state.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    state.write_json_atomic(TAU_PATH, meta)
    return TAU_PATH


def _records_from_path(path: Path) -> list[dict]:
    if path.is_dir():
        path = path / "results.jsonl"
    if not path.exists():
        return []
    return state.read_jsonl(path)


def collect_score_records(splits: dict[str, dict], current: dict[str, dict] | None = None) -> list[dict]:
    """Merge llm_context_p (and sast_pred/split) from the live run and optional prior dir."""
    by_id: dict[str, dict] = {}

    def absorb(rows: list[dict]) -> None:
        for r in rows:
            sid = r.get("sample_id")
            if not sid or r.get(SCORE_KEY) is None:
                continue
            pid = r.get("pair_id")
            split = r.get("split") or (splits.get(pid) or {}).get("split")
            by_id[sid] = {
                "sample_id": sid,
                "pair_id": pid,
                "split": split,
                "sast_pred": int(bool(r.get("sast_pred"))),
                SCORE_KEY: r.get(SCORE_KEY),
                "label": r.get("label"),
            }

    if current:
        absorb(list(current.values()))
    if SCORE_SOURCE:
        absorb(_records_from_path(Path(SCORE_SOURCE)))
    # Always also try the active results file (may equal current).
    absorb(list((current or state.load_results()).values()))
    return list(by_id.values())


def ensure_tau(splits: dict[str, dict], current: dict[str, dict] | None = None) -> dict | None:
    """Load or retune tau_recall from scored DEV unflagged functions on disk."""
    if not ENABLED:
        return None
    scored = collect_score_records(splits, current)
    meta = tune_tau_recall(scored)
    if meta is None:
        existing = load_tau()
        if existing:
            logger.warning(
                "Soft LLM screen: not enough DEV unflagged scores to retune "
                f"(have {sum(1 for r in scored if r.get('split') == 'dev' and not r.get('sast_pred'))}); "
                f"reusing saved tau_recall={existing.get('tau_recall')}"
            )
            return existing
        logger.warning(
            "Soft LLM screen enabled but tau_recall is unset — Board stays SAST-gated "
            "until llm_context_p exists for DEV unflagged functions "
            f"(set REALWORLD_LLM_SCREEN_FROM to a prior results dir, or run with baselines including context)."
        )
        return None
    save_tau(meta)
    logger.info(
        f"Soft LLM screen: tau_recall={meta['tau_recall']:.4f} "
        f"(target top {meta['pass_rate_target']:.0%}, "
        f"achieved {meta['pass_rate_achieved']:.1%} of "
        f"{meta['n_dev_unflagged_scored']} DEV unflagged)"
    )
    return meta
