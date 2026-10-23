"""
Phase 3 — metrics. Safe to run at any time, including mid-run.

The primary numbers are on the repo-disjoint *test* split. The board's
calibrated threshold and the fusion model are fitted on *dev* only, so they
never see a test label. For each split and dataset:

  end_to_end    every function
  sast_flagged  only functions static analysis flagged — where the SAST board
                acts, and where removing false positives while keeping true
                positives is measured
  candidates_flagged
                older runs only: functions any candidate source flagged
                (SAST, LLM-spec taint, LLM auditor)
  pairwise      PrimeVul-style (Ding et al., ICSE 2025) scoring on each
                vulnerable/fixed pair: P-C correct, P-V both flagged,
                P-B both cleared, P-R reversed
  vd_s          PrimeVul's VD-S: the miss rate (FNR) at the best threshold
                whose false-positive rate stays within a fixed budget
  significance  repo-cluster bootstrap 95% CIs (pairs from one project are not
                independent) and an exact McNemar test of each system against
                the SAST baseline, Holm-corrected across systems
  per_family    CWE families, grouped into SAST-reachable and logic/semantic

On balanced pairs, Youden's J = TPR - FPR equals P-C - P-R and 2*accuracy - 1,
so "does the system work" is the test of P-C > P-R: an exact sign test on the
pairs whose two verdicts differ (a system with no signal has P-C = P-R).
"""

import datetime
import math
import os
from collections import Counter, defaultdict

import numpy as np

from hackersec.evaluation.realworld import families, fusion, split, state

BOOTSTRAP = int(os.getenv("REALWORLD_BOOTSTRAP", "1000"))
VDS_BUDGETS = (0.005, 0.05)
# Share of functions that are vulnerable in a real codebase; the test set is
# 50% by construction, which hides how many alerts a user would have to triage.
PREVALENCES = tuple(float(x) for x in os.getenv("REALWORLD_PREVALENCE", "0.05,0.01").split(",") if x.strip())

SYSTEM_LABELS = {
    "flag_all": "Flag every function (trivial reference)",
    "sast": "Semgrep + Bandit + AST Gate",
    "semgrep": "Semgrep alone",
    "bandit": "Bandit alone",
    "ast_sink": "AST sink gate alone",
    "codeql": "CodeQL alone",
    "board": "SAST board: Judge vote",
    "board_override": "SAST board + evidence override (ablation)",
    "board_calibrated": "SAST board: vote score, dev-tuned threshold",
    "fusion": "SAST board + fusion (ablation, trained on dev)",
    "llm_only": "LLM only, whole function, no SAST",
    "llm_only_calibrated": "LLM only, dev-tuned threshold",
    "llm_context": "LLM only + same-file context, no SAST",
    "llm_context_calibrated": "LLM only + context, dev-tuned threshold",
    "hunter_raw": "LLM auditor alone (no critic)",
    "taint_raw": "LLM-spec taint alone (no critic)",
    "union_raw": "Any candidate: SAST, taint or auditor (no critic)",
    "full_board": "Candidates board: Judge majority vote",
    "full_override": "Candidates board + evidence override (ablation)",
    "full_calibrated": "Candidates board: vote score, dev-tuned threshold",
    "full_fusion": "Candidates board + fusion (trained on dev)",
    "full_guard": "Candidates board: flagged unless the Judge's quoted check is in the code",
    "fusion_v1": "Board + synthetic fusion (v1)",
}
# (prediction key, score key); a None score marks a binary-only system.
SYSTEM_KEYS = {
    "flag_all": ("flag_all_pred", None),
    "sast": ("sast_pred", "sast_score"),
    "semgrep": ("semgrep_pred", None),
    "bandit": ("bandit_pred", None),
    "ast_sink": ("ast_pred", None),
    "codeql": ("codeql_pred", None),
    "board": ("board_pred", "vote_score"),
    "board_override": ("board_override_pred", None),
    "board_calibrated": ("board_calibrated_pred", "p_score"),
    "fusion": ("fusion_pred", "fusion_score"),
    "llm_only": ("llm_only_pred", "llm_only_p"),
    "llm_only_calibrated": ("llm_only_calibrated_pred", "llm_only_p"),
    "llm_context": ("llm_context_pred", "llm_context_p"),
    "llm_context_calibrated": ("llm_context_calibrated_pred", "llm_context_p"),
    "hunter_raw": ("hunter_pred", "hunter_score"),
    "taint_raw": ("taint_pred", None),
    "union_raw": ("union_pred", None),
    "full_board": ("full_pred", "full_vote_score"),
    "full_override": ("full_override_pred", None),
    "full_calibrated": ("full_calibrated_pred", "full_p_score"),
    "full_fusion": ("full_fusion_pred", "full_fusion_score"),
    "full_guard": ("full_guard_pred", None),
    "fusion_v1": ("fusion_v1_pred", None),
}
HEADLINE_ORDER = ("board", "board_calibrated", "fusion", "full_board", "full_calibrated", "full_fusion")
# Columns of the family table, which would be unreadable with every system.
FAMILY_SYSTEMS = ("sast", "semgrep", "bandit", "board", "board_calibrated", "fusion", "llm_only_calibrated", "llm_context_calibrated")
# LLM calls that produce each system's verdict. Calibrated rows share the calls.
COST_BUCKET = {
    "board": "board", "board_override": "board", "board_calibrated": "board", "fusion": "board",
    "llm_only": "llm_only", "llm_only_calibrated": "llm_only",
    "llm_context": "llm_context", "llm_context_calibrated": "llm_context",
}
COST_LABELS = {
    "sast": "Static Gate (no LLM)",
    "board": "SAST board (LLM only where static analysis flagged)",
    "llm_only": "LLM only, whole function, no SAST",
    "llm_context": "LLM only + same-file context, no SAST",
}


# ── Preparing records ───────────────────────────────────────────────────────

def _prepare(results: dict, pairs: dict, static_check: dict | None = None) -> list[dict]:
    rows = []
    for r in results.values():
        if r.get("status") != "ok":
            continue
        r = dict(r)
        meta = pairs.get(r["pair_id"], {})
        r["split"] = r.get("split") or meta.get("split")
        r["clean"] = meta.get("clean", r.get("clean"))
        r["dataset_static_check"] = (static_check or {}).get(r["sample_id"])
        r["flagged"] = (r.get("n_findings") or 0) > 0
        r["flag_all_pred"] = 1
        r["family"] = families.family(r.get("cwe"))
        r["family_group"] = families.group(r.get("cwe"))
        r["sast_score"] = 1.0 if r["flagged"] else None
        if "pipeline" in r:
            def score(value, flagged=r["flagged"], pred=r.get("board_pred")):
                return (float(value) if value is not None else float(pred)) if flagged else None

            r["vote_score"] = score(r.get("vote_share"))
            r["p_score"] = score(r.get("p_vulnerable"))
            if "full_pred" in r:
                r["union_flagged"] = bool(r.get("union_pred"))
                r["full_vote_score"] = score(r.get("full_vote_share"), r["union_flagged"], r["full_pred"])
                r["full_p_score"] = score(r.get("full_p_vulnerable"), r["union_flagged"], r["full_pred"])
                full_board = r.get("full_board") or {}
                if "guard_grounded" in full_board or not r["union_flagged"]:
                    r["full_guard_pred"] = int(r["union_flagged"] and full_board.get("guard_grounded") is not True)
                audit = r.get("auditor") or {}
                if audit.get("p_vulnerable") is not None:
                    r["hunter_score"] = float(audit["p_vulnerable"])
                else:
                    confs = [c.get("confidence") or 0.0 for c in audit.get("candidates") or []]
                    r["hunter_score"] = max(confs) if confs else None
        else:
            # v1: one debate per finding, the evidence rule applied as an
            # override, and the synthetic-trained fusion classifier.
            r["fusion_v1_pred"] = r.pop("fusion_pred", None)
            r["vote_score"] = float(r["board_pred"]) if r["flagged"] else None
        rows.append(r)
    return rows


def _calibrate(rows: list[dict]) -> dict:
    """Fit the board threshold and fusion on dev; apply both to every row."""
    dev = [r for r in rows if r["split"] == "dev"]
    out = {"dev_functions": len(dev), "metric": fusion.CALIBRATION_METRIC, "board_threshold": None,
           "fusion": None, "fusion_model": None}
    if not rows or any("p_score" not in r for r in rows):
        out["fusion"] = "not available for v1 results"
        return out

    labels = [r["label"] for r in dev]
    threshold = fusion.best_threshold([r["p_score"] for r in dev], labels) if dev else None
    out["board_threshold"] = threshold
    if threshold is not None:
        for r in rows:
            r["board_calibrated_pred"] = int(r["p_score"] is not None and r["p_score"] >= threshold)

    model, note = fusion.train(dev)
    out["fusion"] = note
    if model is not None:
        out["fusion_model"] = model.to_dict()
        for r in rows:
            r["fusion_score"] = model.score(r)
            r["fusion_pred"] = model.predict(r)

    if all("full_p_score" in r for r in rows):
        threshold = fusion.best_threshold([r["full_p_score"] for r in dev], labels) if dev else None
        out["full_threshold"] = threshold
        if threshold is not None:
            for r in rows:
                r["full_calibrated_pred"] = int(r["full_p_score"] is not None and r["full_p_score"] >= threshold)
        model, note = fusion.train(dev, kind="full")
        out["full_fusion"] = note
        out["full_fusion_model"] = model.to_dict() if model is not None else None
        if model is not None:
            for r in rows:
                r["full_fusion_score"] = model.score(r)
                r["full_fusion_pred"] = model.predict(r)

    for score_key, pred_key, name in (
        ("llm_only_p", "llm_only_calibrated_pred", "llm_only_threshold"),
        ("llm_context_p", "llm_context_calibrated_pred", "llm_context_threshold"),
    ):
        if rows and all(score_key in r for r in rows):
            t = fusion.best_threshold([r[score_key] for r in dev], labels) if dev else None
            out[name] = t
            if t is not None:
                for r in rows:
                    r[pred_key] = int(r[score_key] is not None and r[score_key] >= t)
    return out


def _systems(rows: list[dict]) -> list[str]:
    active = []
    for s, (key, _) in SYSTEM_KEYS.items():
        if not rows or not all(r.get(key) is not None for r in rows):
            continue
        if s == "codeql" and not any(r.get(key) for r in rows):
            continue
        active.append(s)
    return active


# ── Metrics ─────────────────────────────────────────────────────────────────

def _scores(rows: list[dict], key: str) -> dict:
    tp = sum(1 for r in rows if r[key] == 1 and r["label"] == 1)
    fp = sum(1 for r in rows if r[key] == 1 and r["label"] == 0)
    tn = sum(1 for r in rows if r[key] == 0 and r["label"] == 0)
    fn = sum(1 for r in rows if r[key] == 0 and r["label"] == 1)
    p = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * rec / (p + rec) if p + rec else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    acc = (tp + tn) / len(rows) if rows else 0.0
    return {
        "n": len(rows), "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(p, 4), "recall": round(rec, 4), "f1": round(f1, 4),
        "fpr": round(fpr, 4), "accuracy": round(acc, 4),
        "balanced_accuracy": round(fusion.metric(tp, fp, fn, tn, "balanced_accuracy"), 4),
        "mcc": round(fusion.metric(tp, fp, fn, tn, "mcc"), 4),
        "youden": round(rec - fpr, 4),
        # Likelihood ratio of a positive verdict; precision at prevalence pi is
        # 1 / (1 + (1 - pi) / (pi * LR+)), so it sets how usable alerts are.
        "lr_plus": round(rec / fpr, 4) if fpr else None,
        "precision_at_prevalence": {
            f"{pi:g}": round(pi * rec / (pi * rec + (1 - pi) * fpr), 4) if pi * rec + (1 - pi) * fpr else None
            for pi in PREVALENCES
        },
    }


def _binom_p(b: int, c: int) -> float:
    """Exact two-sided binomial test of b vs c successes at p = 1/2."""
    n = b + c
    if n == 0:
        return 1.0
    log_half = n * math.log(0.5)
    tail = sum(
        math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + log_half)
        for i in range(min(b, c) + 1)
    )
    return min(1.0, 2 * tail)


def _holm(pvals: dict) -> dict:
    """Holm step-down adjustment; keys with a None p are left out."""
    items = sorted((p, k) for k, p in pvals.items() if p is not None)
    out, running = {}, 0.0
    for i, (p, k) in enumerate(items):
        running = max(running, min(1.0, (len(items) - i) * p))
        out[k] = running
    return out


def _pairwise(rows: list[dict], key: str) -> dict:
    pairs = defaultdict(dict)
    for r in rows:
        pairs[r["pair_id"]][r["kind"]] = r[key]
    counts = {"P-C": 0, "P-V": 0, "P-B": 0, "P-R": 0}
    for p in pairs.values():
        if "vulnerable" not in p or "fixed" not in p:
            continue
        v, f = p["vulnerable"], p["fixed"]
        counts["P-C" if v and not f else "P-V" if v and f else "P-B" if not v and not f else "P-R"] += 1
    n = sum(counts.values())
    differ = counts["P-C"] + counts["P-R"]
    return {
        "pairs": n, **counts, **{f"{k}_rate": round(c / n, 4) if n else 0.0 for k, c in counts.items()},
        # Pairs whose two versions get different verdicts, and how often the
        # vulnerable one is the flagged one (0.5 = no signal).
        "differ_rate": round(differ / n, 4) if n else 0.0,
        "right_way_round": round(counts["P-C"] / differ, 4) if differ else None,
        # H0 "no signal": P-C and P-R are equally likely among differing pairs.
        "sign_test_p": _binom_p(counts["P-C"], counts["P-R"]),
    }


def _pairwise_scores(rows: list[dict], score_key: str) -> dict | None:
    """Within each pair, is the vulnerable version scored higher? Uses the
    pairs where both versions are flagged, which the binary verdict ignores.
    An unflagged function ranks below every flagged one."""
    pairs = defaultdict(dict)
    for r in rows:
        s = r.get(score_key)
        pairs[r["pair_id"]][r["kind"]] = -1.0 if s is None else float(s)
    wins = losses = ties = 0
    for p in pairs.values():
        if "vulnerable" not in p or "fixed" not in p:
            continue
        d = p["vulnerable"] - p["fixed"]
        wins, losses, ties = wins + (d > 1e-9), losses + (d < -1e-9), ties + (abs(d) <= 1e-9)
    n = wins + losses + ties
    if not n:
        return None
    return {
        "pairs": n, "higher": wins, "lower": losses, "tied": ties,
        "auc": round((wins + 0.5 * ties) / n, 4),
        "sign_test_p": _binom_p(wins, losses),
    }


def _vds(rows: list[dict], score_key: str, max_fpr: float) -> dict | None:
    scored = [(r.get(score_key), r["label"]) for r in rows]
    neg = sum(1 for _, y in scored if y == 0)
    pos = len(scored) - neg
    if not neg or not pos:
        return None
    best = {"fnr": 1.0, "fpr": 0.0, "threshold": None}
    for t in sorted({s for s, _ in scored if s is not None}, reverse=True):
        fp = sum(1 for s, y in scored if s is not None and s >= t and y == 0)
        if fp / neg > max_fpr:
            break  # lowering the threshold further only adds false positives
        tp = sum(1 for s, y in scored if s is not None and s >= t and y == 1)
        fnr = 1 - tp / pos
        if fnr < best["fnr"]:
            best = {"fnr": round(fnr, 4), "fpr": round(fp / neg, 4), "threshold": t}
    return best


def _mcnemar(rows: list[dict], key: str, baseline_key: str) -> dict:
    """Exact two-sided McNemar test on per-function correctness."""
    b = sum(1 for r in rows if r[key] == r["label"] and r[baseline_key] != r["label"])
    c = sum(1 for r in rows if r[key] != r["label"] and r[baseline_key] == r["label"])
    return {"system_only_correct": b, "baseline_only_correct": c, "p_value": _binom_p(b, c)}


def _ci(values: np.ndarray) -> list[float]:
    return [round(float(np.percentile(values, 2.5)), 4), round(float(np.percentile(values, 97.5)), 4)]


def _repo(pair_id: str) -> tuple[str, str]:
    return split._origin(pair_id)[:2]


def _bootstrap(rows: list[dict], systems: list[str]) -> dict:
    """Resamples whole repositories: pairs from one project share code, style
    and maintainers, so resampling pairs would give intervals that are too
    narrow."""
    if BOOTSTRAP <= 0 or not rows:
        return {}
    repos = sorted({_repo(r["pair_id"]) for r in rows})
    index = {g: i for i, g in enumerate(repos)}
    n = len(repos)

    conf = {s: np.zeros((n, 4)) for s in systems}  # tp, fp, fn, tn per repo
    correct_pair = {s: np.zeros(n) for s in systems}
    complete = np.zeros(n)
    by_pair: dict[str, dict] = defaultdict(dict)
    for r in rows:
        i = index[_repo(r["pair_id"])]
        by_pair[r["pair_id"]][r["kind"]] = r
        for s in systems:
            pred, y = r[SYSTEM_KEYS[s][0]], r["label"]
            conf[s][i] += (pred == 1 and y == 1, pred == 1 and y == 0, pred == 0 and y == 1, pred == 0 and y == 0)
    for pid, kinds in by_pair.items():
        if "vulnerable" in kinds and "fixed" in kinds:
            i = index[_repo(pid)]
            complete[i] += 1
            for s in systems:
                key = SYSTEM_KEYS[s][0]
                correct_pair[s][i] += kinds["vulnerable"][key] == 1 and kinds["fixed"][key] == 0

    draws = np.random.default_rng(0).integers(0, n, size=(BOOTSTRAP, n))
    n_complete = complete[draws].sum(axis=1)
    out, f1s, mccs, js = {}, {}, {}, {}
    for s in systems:
        c = conf[s][draws].sum(axis=1)
        tp, fp, fn, tn = c[:, 0], c[:, 1], c[:, 2], c[:, 3]
        denom = 2 * tp + fp + fn
        f1 = np.divide(2 * tp, denom, out=np.zeros_like(tp), where=denom > 0)
        mcc_denom = np.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
        mcc = np.divide(tp * tn - fp * fn, mcc_denom, out=np.zeros_like(tp), where=mcc_denom > 0)
        tpr = np.divide(tp, tp + fn, out=np.zeros_like(tp), where=tp + fn > 0)
        fpr = np.divide(fp, fp + tn, out=np.zeros_like(fp), where=fp + tn > 0)
        pc = np.divide(correct_pair[s][draws].sum(axis=1), n_complete,
                       out=np.zeros(BOOTSTRAP), where=n_complete > 0)
        f1s[s], mccs[s], js[s] = f1, mcc, tpr - fpr
        out[s] = {"f1_ci": _ci(f1), "mcc_ci": _ci(mcc), "youden_ci": _ci(tpr - fpr), "pc_rate_ci": _ci(pc)}
    for s in systems:
        if s != "sast" and "sast" in f1s:
            out[s]["delta_f1_vs_sast_ci"] = _ci(f1s[s] - f1s["sast"])
            out[s]["delta_mcc_vs_sast_ci"] = _ci(mccs[s] - mccs["sast"])
            out[s]["delta_youden_vs_sast_ci"] = _ci(js[s] - js["sast"])
    out["_resampling_unit"] = {"unit": "repository", "clusters": n, "draws": BOOTSTRAP}
    return out


# ── Views ───────────────────────────────────────────────────────────────────

def _flagged_view(rows: list[dict], systems: list[str], flag: str = "flagged") -> dict:
    flagged = [r for r in rows if r.get(flag)]
    out = {"n": len(flagged), "vulnerable": sum(r["label"] for r in flagged)}
    out["fixed"] = out["n"] - out["vulnerable"]
    for s in systems:
        out[s] = _scores(flagged, SYSTEM_KEYS[s][0])
    neg = [r for r in flagged if r["label"] == 0]
    pos = [r for r in flagged if r["label"] == 1]
    for s in systems:
        if s == "sast":
            continue
        key = SYSTEM_KEYS[s][0]
        out[f"{s}_false_positives_removed"] = round(sum(1 for r in neg if r[key] == 0) / len(neg), 4) if neg else None
        out[f"{s}_true_positives_kept"] = round(sum(1 for r in pos if r[key] == 1) / len(pos), 4) if pos else None
    return out


def _rate(items: list, pred) -> float | None:
    return round(sum(1 for x in items if pred(x)) / len(items), 4) if items else None


def _telemetry(rows: list[dict]) -> dict:
    flagged = [r for r in rows if r["flagged"]]
    fs = [f for r in flagged for f in r.get("findings", [])]
    out = {
        "flagged_functions": len(flagged),
        "findings": len(fs),
        "findings_per_flagged_function": round(len(fs) / len(flagged), 2) if flagged else None,
        "by_tool": {t: sum(1 for f in fs if f.get("tool") == t) for t in sorted({f.get("tool") for f in fs})},
        "cpg_success_rate": _rate(fs, lambda f: f.get("cpg_status") in ("success", "no_flow_found")),
        "cpg_taint_found_rate": _rate(fs, lambda f: (f.get("taint_paths") or 0) > 0),
        "cpg_unfiltered_taint_rate": _rate(fs, lambda f: (f.get("unfiltered_flows") or 0) > 0)
        if any("unfiltered_flows" in f for f in fs) else None,
        "cpg_sanitized_taint_rate": _rate(fs, lambda f: (f.get("sanitized_flows") or 0) > 0)
        if any("sanitized_flows" in f for f in fs) else None,
        "rag_context_rate": _rate(fs, lambda f: (f.get("rag_hits") or 0) > 0),
    }
    with_status = [r for r in rows if r.get("sast_status")]
    if with_status:
        out["semgrep_failed_rate"] = _rate(with_status, lambda r: r["sast_status"].get("semgrep") != "ok")
        out["bandit_failed_rate"] = _rate(with_status, lambda r: r["sast_status"].get("bandit") != "ok")

    if any(r.get("board") for r in flagged):
        out["function_board"] = _board_telemetry(flagged, "board", "board_pred", "board_override_pred")
    elif fs:
        out["per_finding_board"] = {
            "judge_false_positive_rate": _rate(fs, lambda f: f.get("judge_verdict") == "FALSE_POSITIVE"),
            "evidence_grounded_rate": _rate(fs, lambda f: f.get("evidence_grounded") is True),
            "evidence_rule_override_rate": _rate(fs, lambda f: f.get("verdict_source") == "evidence_rule"),
        }

    candidates = [r for r in rows if "n_candidates" in r]
    if candidates:
        n = [r["n_candidates"] for r in candidates]
        audited = [r for r in candidates if r.get("auditor")]
        specs = [r for r in candidates if r.get("taint_spec")]
        out["candidates"] = {
            "functions": len(candidates),
            "any_candidate_rate": _rate(candidates, lambda r: bool(r.get("union_pred"))),
            "sast_rate": _rate(n, lambda c: c.get("sast", 0) > 0),
            "llm_taint_rate": _rate(n, lambda c: c.get("taint", 0) > 0),
            "auditor_rate": _rate(n, lambda c: c.get("auditor", 0) > 0),
            "only_llm_rate": _rate(n, lambda c: not c.get("sast") and (c.get("taint") or c.get("auditor"))),
            "auditor_parse_failed_rate": _rate(audited, lambda r: r["auditor"].get("status") != "success"),
            "auditor_vulnerable_verdict_rate": _rate(
                [r for r in audited if r["auditor"].get("verdict")],
                lambda r: r["auditor"]["verdict"] == "VULNERABLE"),
            "spec_parse_failed_rate": _rate(
                specs, lambda r: r["taint_spec"].get("status") not in ("success", "no_calls")),
            "mean_spec_sinks": round(sum(len(r["taint_spec"].get("sinks") or []) for r in specs) / len(specs), 2)
            if specs else None,
            "mean_spec_sites_checked": round(sum(r["taint_spec"].get("sites_checked") or 0 for r in specs) / len(specs), 2)
            if specs else None,
            "mean_context_chars": round(sum(r.get("context_chars") or 0 for r in candidates) / len(candidates), 1),
            "mean_seconds_per_function": round(sum(r.get("seconds") or 0 for r in candidates) / len(candidates), 1),
        }
        full = [r for r in candidates if r.get("full_board")]
        if full:
            out["candidates_board"] = _board_telemetry(full, "full_board", "full_pred", "full_override_pred")

    with_repo = [r for r in rows if isinstance(r.get("repo_context"), dict)]
    if with_repo:
        out["repo_context"] = {
            "functions": len(with_repo),
            "available_rate": _rate(with_repo, lambda r: r["repo_context"].get("status") == "ok"),
            "cross_file_callers_rate": _rate(with_repo, lambda r: (r["repo_context"].get("call_sites") or 0) > 0),
            "entry_point_rate": _rate(with_repo, lambda r: bool(r["repo_context"].get("entry_point"))),
            "flagged_cross_file_callers_rate": _rate(
                [r for r in with_repo if r["flagged"]], lambda r: (r["repo_context"].get("call_sites") or 0) > 0),
            "flagged_entry_point_rate": _rate(
                [r for r in with_repo if r["flagged"]], lambda r: bool(r["repo_context"].get("entry_point"))),
            "mean_context_chars": round(sum(r.get("context_chars") or 0 for r in with_repo) / len(with_repo), 1),
        }

    baselines = {}
    for key in ("llm_only", "llm_context"):
        reviewed = [r for r in rows if isinstance(r.get(key), dict)]
        if reviewed:
            baselines[f"{key}_parse_failed_rate"] = _rate(reviewed, lambda r, key=key: r[key].get("status") != "success")
            baselines[f"{key}_vulnerable_rate"] = _rate(reviewed, lambda r, key=key: r.get(f"{key}_pred") == 1)
    if baselines:
        out["llm_baselines"] = baselines
    return out


def _board_telemetry(rows: list[dict], board_key: str, pred_key: str, override_key: str) -> dict:
    boards = [r for r in rows if r.get(board_key)]

    def valid(r):
        return [v for v in r[board_key].get("votes") or [] if v.get("verdict")]

    def unanimous(r):
        vs = valid(r)
        return bool(vs) and len({v["verdict"] for v in vs}) == 1

    return {
        "functions": len(boards),
        "mean_valid_votes": round(sum(len(valid(r)) for r in boards) / len(boards), 2),
        "unanimous_rate": _rate(boards, unanimous),
        "split_vote_rate": _rate(boards, lambda r: bool(valid(r)) and not unanimous(r)),
        "no_valid_vote_rate": _rate(boards, lambda r: not valid(r)),
        "majority_not_vulnerable_rate": _rate(boards, lambda r: r[pred_key] == 0),
        "evidence_grounded_rate": _rate(boards, lambda r: r[board_key].get("evidence_grounded") is True),
        "evidence_reasons": dict(sorted(Counter(r[board_key].get("evidence_reason") or "unknown"
                                                for r in boards).items())),
        "evidence_in_context_rate": _rate(boards, lambda r: r[board_key].get("evidence_location") == "context"),
        "guard_grounded_rate": _rate(boards, lambda r: r[board_key].get("guard_grounded") is True),
        "override_flip_rate": _rate(boards, lambda r: r.get(override_key) != r[pred_key]),
        "code_truncated_rate": _rate(boards, lambda r: bool(r[board_key].get("code_truncated"))),
        "context_overflow_rate": _rate(boards, lambda r: bool(r[board_key].get("context_overflow"))),
        "attacker_parse_failed_rate": _rate(boards, lambda r: r[board_key].get("attacker_status") != "success"),
        "defender_parse_failed_rate": _rate(boards, lambda r: r[board_key].get("defender_status") != "success"),
        "mean_seconds_per_function": round(sum(r.get("seconds") or 0 for r in boards) / len(boards), 1),
    }


def _block(rows: list[dict], systems: list[str]) -> dict:
    vulnerable = [r for r in rows if r["label"] == 1]
    out = {
        "samples": len(rows),
        "pairs": len({r["pair_id"] for r in rows}),
        "vulnerable_flagged_rate": _rate(vulnerable, lambda r: r["flagged"]),
        **{s: _scores(rows, SYSTEM_KEYS[s][0]) for s in systems},
    }
    if rows and all("union_flagged" in r for r in rows):
        out["vulnerable_candidate_rate"] = _rate(vulnerable, lambda r: r["union_flagged"])
    return out


def _per_family(rows: list[dict], systems: list[str]) -> dict:
    groups, fams = defaultdict(list), defaultdict(list)
    for r in rows:
        groups[r["family_group"]].append(r)
        fams[r["family"]].append(r)
    return {
        "groups": {g: _block(rs, systems) for g, rs in sorted(groups.items())},
        "families": {f: {"sast_reachable": f in families.SAST_REACHABLE, **_block(rs, systems)}
                     for f, rs in sorted(fams.items(), key=lambda kv: -len(kv[1]))},
    }


def _cost(rows: list[dict]) -> dict | None:
    """Token totals for each LLM call kind. Means divide by every function,
    including ones the SAST board never called the model for."""
    if not rows or not any(isinstance(r.get("tokens"), dict) for r in rows):
        return None
    out = {}
    n = len(rows)
    for bucket in ("board", "llm_only", "llm_context"):
        prompt = completion = calls = used = 0
        seen = False
        for r in rows:
            part = (r.get("tokens") or {}).get(bucket)
            if not isinstance(part, dict):
                continue
            seen = True
            prompt += int(part.get("prompt") or 0)
            completion += int(part.get("completion") or 0)
            c = int(part.get("calls") or 0)
            calls += c
            used += int(c > 0)
        if seen:
            total = prompt + completion
            out[bucket] = {
                "prompt_tokens": prompt,
                "completion_tokens": completion,
                "total_tokens": total,
                "calls": calls,
                "functions_with_calls": used,
                "mean_tokens": round(total / n, 1) if n else None,
            }
    return out or None


def _view(rows: list[dict], systems: list[str], stats: bool) -> dict:
    by_cwe = defaultdict(list)
    for r in rows:
        by_cwe[r["cwe"]].append(r)
    view = {
        "samples": len(rows),
        "pairs": len({r["pair_id"] for r in rows}),
        "end_to_end": {s: _scores(rows, SYSTEM_KEYS[s][0]) for s in systems},
        "sast_flagged": _flagged_view(rows, systems),
        "candidates_flagged": (_flagged_view(rows, systems, "union_flagged")
                               if rows and all("union_flagged" in r for r in rows) else None),
        "pairwise": {s: _pairwise(rows, SYSTEM_KEYS[s][0]) for s in systems},
        "pairwise_scores": {s: _pairwise_scores(rows, SYSTEM_KEYS[s][1]) for s in systems if SYSTEM_KEYS[s][1]},
        "vd_s": {
            s: {f"fpr_{b:g}": _vds(rows, SYSTEM_KEYS[s][1], b) for b in VDS_BUDGETS}
            for s in systems if SYSTEM_KEYS[s][1]
        },
        "telemetry": _telemetry(rows),
        "cost": _cost(rows),
        "per_family": _per_family(rows, systems),
        "per_cwe": {
            cwe: {"samples": len(rs), "flagged": sum(1 for r in rs if r["flagged"]),
                  **{s: _scores(rs, SYSTEM_KEYS[s][0]) for s in systems}}
            for cwe, rs in sorted(by_cwe.items(), key=lambda kv: -len(kv[1]))
        },
    }
    # Every system is tested, so p values are Holm-corrected across systems
    # (the trivial reference is not one of the hypotheses).
    tested = [s for s in systems if s != "flag_all"]
    for key, holm in (
        ("pairwise", _holm({s: view["pairwise"][s]["sign_test_p"] for s in tested})),
        ("pairwise_scores", _holm({s: (view["pairwise_scores"].get(s) or {}).get("sign_test_p") for s in tested})),
    ):
        for s, p in holm.items():
            view[key][s]["sign_test_p_holm"] = p
    if stats:
        mcnemar = {s: _mcnemar(rows, SYSTEM_KEYS[s][0], "sast_pred") for s in systems if s != "sast"}
        for s, p in _holm({s: m["p_value"] for s, m in mcnemar.items() if s != "flag_all"}).items():
            mcnemar[s]["p_holm"] = p
        view["significance"] = {"bootstrap": _bootstrap(rows, systems), "mcnemar_vs_sast": mcnemar}
    return view


def _split_views(rows: list[dict], systems: list[str], stats: bool) -> dict:
    by_dataset = defaultdict(list)
    for r in rows:
        by_dataset[r["dataset"]].append(r)
    out = {name: _view(rs, systems, stats) for name, rs in sorted(by_dataset.items())}
    if len(out) > 1:
        out["combined"] = _view(rows, systems, stats)
    return out


# ── Markdown ────────────────────────────────────────────────────────────────

def _fmt_ci(ci) -> str:
    return f" [{ci[0]:.3f}, {ci[1]:.3f}]" if ci else ""


def _fmt_p(p) -> str:
    if p is None:
        return "—"
    if p < 1e-4:
        return "<1e-4" if p == 0 else f"{p:.2g}"
    return f"{p:.2g}" if p < 0.001 else f"{p:.3f}"


def _md_signal(v: dict, systems: list[str]) -> list[str]:
    sig = v.get("significance") or {}
    boot, mcn = sig.get("bootstrap") or {}, sig.get("mcnemar_vs_sast") or {}
    prev = [f"{pi:g}" for pi in PREVALENCES]
    L = ["**Does it separate vulnerable from fixed code?** J = TPR − FPR, which on these pairs equals "
         "P-C − P-R (0 = no signal). Sign test: are correct pairs more common than reversed ones? "
         "Score AUC: share of pairs where the vulnerable version gets the higher score. "
         "p values are Holm-corrected across systems; CIs resample whole repositories.", "",
         "| System | J [95% CI] | ΔJ vs SAST [95% CI] | Pair sign test p | Score AUC on pairs | Score sign test p "
         "| McNemar p vs SAST | LR+ | " + " / ".join(f"{float(p):.0%}" for p in prev) + " prevalence: precision |",
         "|---|---|---|---|---|---|---|---|---|"]
    for s in systems:
        m, b, pw = v["end_to_end"][s], boot.get(s, {}), v["pairwise"][s]
        ps = (v.get("pairwise_scores") or {}).get(s)
        auc = "—" if not ps else f"{ps['auc']:.3f}"
        lr = m.get("lr_plus")
        precision = " / ".join("—" if m["precision_at_prevalence"].get(p) is None
                               else f"{m['precision_at_prevalence'][p]:.3f}" for p in prev)
        L.append(
            f"| {SYSTEM_LABELS[s]} | {m['youden']:+.3f}{_fmt_ci(b.get('youden_ci'))} "
            f"| {_fmt_ci(b.get('delta_youden_vs_sast_ci')).strip() or '—'} "
            f"| {_fmt_p(pw.get('sign_test_p_holm', pw['sign_test_p']))} | {auc} "
            f"| {_fmt_p(ps.get('sign_test_p_holm', ps['sign_test_p'])) if ps else '—'} "
            f"| {_fmt_p(mcn.get(s, {}).get('p_holm', mcn.get(s, {}).get('p_value')))} "
            f"| {'—' if lr is None else f'{lr:.2f}'} | {precision} |"
        )
    return L


def _md_cost(v: dict) -> list[str]:
    cost = v.get("cost")
    if not cost:
        return []
    e2e = v["end_to_end"]
    prefer = {"board": "board_calibrated", "llm_only": "llm_only_calibrated", "llm_context": "llm_context_calibrated"}
    fallback = {"board": "board", "llm_only": "llm_only", "llm_context": "llm_context"}
    L = ["", "**Tokens per detection** (prompt + completion). The mean is over every function, so the SAST "
         "board costs nothing on functions static analysis did not flag. Tokens per true positive uses the "
         "dev-tuned threshold when that row exists.", "",
         "| System | Functions sent to the LLM | Mean tokens / function | True positives | Tokens per true positive |",
         "|---|---|---|---|---|"]

    def line(label: str, calls: int, mean: float, tp: int, total: int) -> str:
        per = "—" if not tp else f"{total / tp:,.0f}"
        return f"| {label} | {calls} | {mean:,.1f} | {tp} | {per} |"

    if "sast" in e2e:
        L.append(line(COST_LABELS["sast"], 0, 0.0, e2e["sast"]["tp"], 0))
    for bucket, part in cost.items():
        sys = prefer[bucket] if prefer[bucket] in e2e else fallback[bucket]
        if sys not in e2e:
            continue
        L.append(line(COST_LABELS[bucket], part["functions_with_calls"], part["mean_tokens"],
                      e2e[sys]["tp"], part["total_tokens"]))
    L.append("")
    return L


def _md_view(name: str, v: dict, systems: list[str]) -> list[str]:
    sig = v.get("significance") or {}
    boot, mcn = sig.get("bootstrap") or {}, sig.get("mcnemar_vs_sast") or {}
    L = [f"### {name} — {v['samples']} functions, {v['pairs']} pairs", ""]
    L += _md_signal(v, systems) + [""]
    cap = "SAST-board recall cannot exceed Semgrep + Bandit"
    if "full_board" in systems:
        cap += "; candidates-board recall cannot exceed the any-candidate row"
    L += [f"**End-to-end** (every function; {cap})", "",
         "| System | Precision | Recall | FPR | Accuracy | MCC [95% CI] | ΔMCC vs SAST [95% CI] | F1 [95% CI] "
         "| McNemar p (accuracy, uncorrected) |",
         "|---|---|---|---|---|---|---|---|---|"]
    for s in systems:
        m, b = v["end_to_end"][s], boot.get(s, {})
        p = mcn.get(s, {}).get("p_value")
        L.append(
            f"| {SYSTEM_LABELS[s]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['fpr']:.3f} | {m['accuracy']:.3f} "
            f"| {m['mcc']:.3f}{_fmt_ci(b.get('mcc_ci'))} | {_fmt_ci(b.get('delta_mcc_vs_sast_ci')).strip() or '—'} "
            f"| {m['f1']:.3f}{_fmt_ci(b.get('f1_ci'))} | {_fmt_p(p)} |"
        )
    L += _md_cost(v)

    subsets = [("static analysis flagged", v["sast_flagged"])]
    if v.get("candidates_flagged"):
        subsets.append(("any candidate source flagged (SAST, LLM-spec taint or auditor)", v["candidates_flagged"]))
    for title, fl in subsets:
        L += ["", f"**On functions {title}** ({fl['n']}: {fl['vulnerable']} vulnerable, {fl['fixed']} fixed)", "",
              "| System | Precision | Recall | FPR | MCC | F1 | FPs removed | TPs kept |",
              "|---|---|---|---|---|---|---|---|"]
        for s in systems:
            m = fl[s]
            removed, kept = fl.get(f"{s}_false_positives_removed"), fl.get(f"{s}_true_positives_kept")
            L.append(
                f"| {SYSTEM_LABELS[s]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['fpr']:.3f} | {m['mcc']:.3f} "
                f"| {m['f1']:.3f} | {'—' if removed is None else f'{removed:.1%}'} "
                f"| {'—' if kept is None else f'{kept:.1%}'} |"
            )

    L += ["", "**Pairwise** (vulnerable vs fixed version of the same function)", "",
          "| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed "
          "| Verdicts differ | Right way round when they differ |",
          "|---|---|---|---|---|---|---|---|"]
    for s in systems:
        p = v["pairwise"][s]
        rwr = p.get("right_way_round")
        L.append(
            f"| {SYSTEM_LABELS[s]} | {p['pairs']} | {p['P-C_rate']:.3f}{_fmt_ci(boot.get(s, {}).get('pc_rate_ci'))} "
            f"| {p['P-V_rate']:.3f} | {p['P-B_rate']:.3f} | {p['P-R_rate']:.3f} "
            f"| {p['differ_rate']:.3f} | {'—' if rwr is None else f'{rwr:.3f}'} |"
        )

    if v["vd_s"]:
        L += ["", "**VD-S** (miss rate at the best threshold within a false-positive budget; lower is better)", "",
              "| System | FNR @ FPR ≤ 0.5% | FNR @ FPR ≤ 5% |", "|---|---|---|"]
        for s, d in v["vd_s"].items():
            cells = [f"{d[k]['fnr']:.3f}" if d.get(k) else "—" for k in ("fpr_0.005", "fpr_0.05")]
            L.append(f"| {SYSTEM_LABELS[s]} | {cells[0]} | {cells[1]} |")
    L.append("")
    return L


def _md_families(v: dict, systems: list[str]) -> list[str]:
    fam = v["per_family"]
    shown = [s for s in FAMILY_SYSTEMS if s in systems] or systems[:4]
    has_cand = any("vulnerable_candidate_rate" in b for b in fam["groups"].values())
    head = ("| Family | Functions | Vulnerable flagged by SAST | "
            + ("Vulnerable with any candidate | " if has_cand else "")
            + " | ".join(f"{s} MCC / R" for s in shown) + " |")
    sep = "|---|---|---|" + ("---|" if has_cand else "") + "---|" * len(shown)

    def row(name, b):
        cells = [name, str(b["samples"]), f"{(b['vulnerable_flagged_rate'] or 0):.1%}"]
        if has_cand:
            cells.append(f"{(b.get('vulnerable_candidate_rate') or 0):.1%}")
        cells += [f"{b[s]['mcc']:.3f} / {b[s]['recall']:.3f}" for s in shown]
        return "| " + " | ".join(cells) + " |"

    L = [head, sep]
    for g, b in fam["groups"].items():
        L.append(row(f"**{g}**", b))
    for f, b in fam["families"].items():
        L.append(row(f + ("" if b["sast_reachable"] else " (logic)"), b))
    return L


def _markdown(report: dict) -> str:
    systems = report["systems"]
    c = report["coverage"]
    L = [f"# HackerSec real-world evaluation ({report['generated_at']})", "",
         f"Status: **{'complete' if c['complete'] else 'PARTIAL'}** — {c['evaluated_ok']}/{c['samples_total']} "
         f"samples evaluated ({c['percent_done']}%), {c['llm_failed']} LLM failures, {c['errors']} errors. "
         f"Pipeline: `{report['pipeline']}`.", ""]

    L += ["## Dev / test split", "",
          "Repo-disjoint, per dataset. Thresholds and fusion are fitted on dev; test is the primary result.", "",
          "| Dataset | Dev pairs (repos) | Test pairs (repos) | Clean pairs |", "|---|---|---|---|"]
    for ds, s in report["split"].items():
        L.append(f"| {ds} | {s['dev_pairs']} ({s['dev_repos']}) | {s['test_pairs']} ({s['test_repos']}) | {s['clean_pairs']} |")
    cal = report["calibration"]
    objective = cal.get("metric", "f1")

    def fusion_extra(fm: dict) -> str:
        if fm.get("threshold") is None:
            return ""
        mcc = fm.get("dev_cv_mcc")
        return (f", threshold {fm['threshold']:.3f}, dev CV F1 {fm['dev_cv_f1']:.3f}"
                + ("" if mcc is None else f", dev CV MCC {mcc:.3f}"))

    L += ["", f"- Dev functions evaluated: {cal['dev_functions']}"]
    if cal.get("board_threshold") is not None:
        L.append(f"- Board threshold on mean P(vulnerable) across Judge votes: **{cal['board_threshold']:.3f}** "
                 f"(max {objective} on dev)")
    if cal.get("fusion"):
        L.append(f"- Fusion: {cal['fusion']}{fusion_extra(cal.get('fusion_model') or {})}")
    if cal.get("full_threshold") is not None:
        L.append(f"- Candidates board threshold on mean P(vulnerable): **{cal['full_threshold']:.3f}** "
                 f"(max {objective} on dev)")
    if cal.get("full_fusion"):
        L.append(f"- Candidates fusion: {cal['full_fusion']}{fusion_extra(cal.get('full_fusion_model') or {})}")
    if cal.get("llm_only_threshold") is not None:
        L.append(f"- LLM-only threshold on P(vulnerable): **{cal['llm_only_threshold']:.3f}** (max {objective} on dev)")
    if cal.get("llm_context_threshold") is not None:
        L.append(f"- LLM-only + context threshold on P(vulnerable): **{cal['llm_context_threshold']:.3f}** "
                 f"(max {objective} on dev)")
    L += ["", "Each pair contributes one vulnerable and one fixed function, so flagging every function scores "
          "F1 0.667, accuracy 0.5 and MCC 0 (the trivial reference row). MCC, accuracy and the pairwise "
          "columns show whether a system actually separates vulnerable from fixed code.", ""]

    test = report["views"]["test"]
    L += ["## Test split (primary)", ""]
    for name, v in test.items():
        L += _md_view(name, v, systems)
    headline = test.get("combined") or next(iter(test.values()), None)
    if headline:
        L += ["### CWE families (test)", "",
              "SAST-reachable families have a code pattern Semgrep/Bandit can match; logic families do not.", ""]
        L += _md_families(headline, systems)
        L.append("")
        tel = headline["telemetry"]
        L += ["### Pipeline telemetry (test)", ""]
        for k, val in tel.items():
            if isinstance(val, dict) and k != "by_tool":
                L.append(f"- **{k}**: " + ", ".join(f"{kk} {vv}" for kk, vv in val.items()))
            else:
                L.append(f"- {k}: {val}")
        L.append("")

    clean = report["views"]["test_clean"]
    clean_head = clean.get("combined") or next(iter(clean.values()), None)
    if clean_head:
        L += ["## Test, clean subset (single-function fixes)", ""]
        L += _md_view("clean", clean_head, systems)

    strata = report["views"].get("test_by_static_check") or {}
    if strata:
        L += ["## Test, split by ReposVul's own static check", "",
              "ReposVul's strict label requires Semgrep or RATS to flag the pre-fix file at the changed lines. "
              "SAST is favoured by construction where that check matched; the other stratum shows how each "
              "system does on fixes that pattern rules did not see.", ""]
        for name, v in strata.items():
            L += [f"### {name} — {v['samples']} functions, {v['pairs']} pairs", ""] + _md_signal(v, systems) + [""]

    strata = report["views"].get("test_by_repo_context") or {}
    if strata:
        L += ["## Test, split by what the repository shows about callers", "",
              "Pairs are grouped by the vulnerable version: callers of the function found in other files, a "
              "web-framework entry point with no such callers, or neither. This shows where cross-file context "
              "can matter.", ""]
        for name, v in strata.items():
            L += [f"### {name} — {v['samples']} functions, {v['pairs']} pairs", ""] + _md_signal(v, systems) + [""]

    dev = report["views"]["dev"]
    dev_head = dev.get("combined") or next(iter(dev.values()), None)
    if dev_head:
        L += ["## Dev split (used for calibration; not a held-out result)", "",
              "| System | Precision | Recall | FPR | Accuracy | MCC | F1 |", "|---|---|---|---|---|---|---|"]
        for s in systems:
            m = dev_head["end_to_end"][s]
            L.append(f"| {SYSTEM_LABELS[s]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['fpr']:.3f} "
                     f"| {m['accuracy']:.3f} | {m['mcc']:.3f} | {m['f1']:.3f} |")
        L.append("")

    L += ["## Caveats", ""] + [f"- {x}" for x in report["caveats"]]
    return "\n".join(L) + "\n"


# ── Entry point ─────────────────────────────────────────────────────────────

def build_report(write: bool = True) -> dict:
    results = state.load_results()
    samples = state.load_samples() or list(results.values())
    pairs = split.load_or_create(samples) if samples else {}
    statuses = defaultdict(int)
    for r in results.values():
        statuses[r.get("status")] += 1

    static_check = {s["sample_id"]: s.get("dataset_static_check") for s in samples if "sample_id" in s}
    rows = _prepare(results, pairs, static_check)
    calibration = _calibrate(rows)
    systems = _systems(rows)
    pipeline = next((r.get("pipeline") for r in rows if r.get("pipeline")), "v1-per-finding" if rows else "none")

    test = [r for r in rows if r["split"] == "test"]
    dev = [r for r in rows if r["split"] == "dev"]
    views = {
        "test": _split_views(test, systems, stats=True),
        "test_clean": _split_views([r for r in test if r["clean"]], systems, stats=True),
        "dev": _split_views(dev, systems, stats=False),
        "all": _split_views(rows, systems, stats=False),
    }
    if any(r["dataset_static_check"] is not None for r in test):
        views["test_by_static_check"] = {
            name: _view(rs, systems, stats=True)
            for name, rs in (
                ("ReposVul static check matched", [r for r in test if r["dataset_static_check"] == 1]),
                ("ReposVul static check did not match", [r for r in test if r["dataset_static_check"] == 0]),
            ) if rs
        }

    def repo(r: dict) -> dict:
        return r.get("repo_context") if isinstance(r.get("repo_context"), dict) else {}

    has_repo_context = any(repo(r).get("status") not in (None, "disabled") for r in test)
    if has_repo_context:
        # Stratified by the vulnerable version, so both halves of a pair stay together.
        by_pair = {r["pair_id"]: repo(r) for r in test if r["label"] == 1}

        def stratum(r: dict) -> str:
            info = by_pair.get(r["pair_id"], repo(r))
            if (info.get("call_sites") or 0) > 0:
                return "Callers found in other files"
            return "Framework entry point, no cross-file callers" if info.get("entry_point") else "Neither"

        views["test_by_repo_context"] = {
            name: _view(rs, systems, stats=True)
            for name in ("Callers found in other files", "Framework entry point, no cross-file callers", "Neither")
            if (rs := [r for r in test if stratum(r) == name])
        }

    datasets = {r["dataset"] for r in rows} or {s.get("dataset") for s in samples}
    total = len(samples)
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "pipeline": pipeline,
        "systems": systems,
        "coverage": {
            "samples_total": total,
            "evaluated_ok": len(rows),
            "evaluated_ok_dev": len(dev),
            "evaluated_ok_test": len(test),
            "llm_failed": statuses.get("llm_failed", 0),
            "errors": statuses.get("error", 0) + statuses.get("file_missing", 0),
            "pending": total - len(results),
            "percent_done": round(100 * len(results) / total, 1) if total else 0.0,
            "complete": total > 0 and len(results) >= total,
        },
        "split": split.summary(),
        "calibration": calibration,
        "build": state.read_json(state.BUILD_PROGRESS_PATH, {}) or {},
        "views": views,
        "caveats": [
            "Labels follow the fix-commit convention (CVEfixes, PrimeVul): a function changed by a security-fix "
            "commit is vulnerable before the fix and fixed after it. Tangled commits "
            "(> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded; the clean subset further keeps only "
            "commits that changed a single function.",
            "The SAST board only reasons about Semgrep and Bandit findings, so its recall cannot exceed theirs. "
            "The sast_flagged view isolates what the board adds on the functions it is asked to review.",
            "The LLM-only rows ask the same model once, with no static findings: the function alone, and the "
            "function plus the context the board sees. They are comparison baselines, not part of the shipped "
            "pipeline. They never see the dataset label or CWE. "
            + ("Context is same-file callers and callees, callers in other files of the repository at the same "
               "commit (resolved by name and imports, test files excluded), and the web-framework entry point "
               "when there is one."
               if has_repo_context else "Context is limited to the same file."),
            "Token counts are Ollama's prompt_eval_count plus eval_count. Tokens per true positive divides the "
            "tokens spent on that system by the true positives of its dev-tuned threshold.",
            "Board thresholds and fusion models are fitted on the dev split only (maximising "
            f"{fusion.CALIBRATION_METRIC}); test repositories never appear in dev. Dev numbers are in-sample and "
            "are shown for reference.",
            "Test and dev are balanced by construction (one vulnerable and one fixed function per pair), so F1 "
            "rewards flagging everything: compare every row with the trivial reference, and read MCC, accuracy "
            "and the pairwise columns for discrimination. 'Right way round' is the share of pairs with differing "
            "verdicts where the vulnerable version is the flagged one; 0.5 means no signal.",
            f"Confidence intervals resample whole repositories ({BOOTSTRAP:,} draws), since pairs from one project "
            "are not independent. McNemar compares per-function correctness against SAST. Sign-test and McNemar "
            "p values in the signal tables are Holm-corrected across the systems compared.",
            "Precision at a given prevalence is TPR·π / (TPR·π + FPR·(1 − π)): what a user would see if that "
            "share of functions were vulnerable, instead of the 50% this test set has by construction.",
        ],
    }
    has_phase3 = any(r.get("full_pred") is not None for r in rows)
    has_baselines = any(r.get("llm_only_pred") is not None for r in rows)
    if not has_baselines:
        report["caveats"] = [c for c in report["caveats"] if not c.startswith("The LLM-only") and not c.startswith("Token counts")]
    if has_phase3:
        report["caveats"].insert(
            2,
            "This run also has the older candidates board (LLM-spec taint and an LLM auditor). Its recall cannot "
            "exceed the any-candidate row. Those rows are kept so an older checkpoint can still be re-scored.",
        )
    if "vudenc" in datasets:
        report["caveats"].append("VUDENC commits are keyword-mined and noisier than CVE-linked CVEfixes commits; "
                                 "compare within, not across, datasets.")
    if "reposvul" in datasets:
        from hackersec.evaluation.realworld.sources import REPOSVUL_LABELS

        report["caveats"].append(
            f"ReposVul files are kept by its '{REPOSVUL_LABELS}' label policy (llm = its LLM untangling check "
            "marks the file as vulnerability-fixing; strict = its LLM and static checks both do), and patches it "
            "marks as outdated are skipped. Its static check is Semgrep/RATS, so the 'static check matched' "
            "stratum favours SAST by construction, and its LLM check may favour fixes an LLM recognises.")
    for dp in report["build"].values():
        if isinstance(dp, dict):
            dp.pop("done", None)  # thousands of commit keys; not useful in the report

    from hackersec.analysis.llm import board as llm_board
    from hackersec.analysis.static import SEMGREP_CONFIGS
    from hackersec.evaluation.realworld import repo_snapshot
    from hackersec.evaluation.metrics import collect_provenance

    report["provenance"] = collect_provenance({
        "repo_commit": os.getenv("REALWORLD_GIT_COMMIT", "unknown"),
        "max_funcs_per_commit": os.getenv("REALWORLD_MAX_FUNCS_PER_COMMIT", "4"),
        "seed": os.getenv("REALWORLD_SEED", "42"),
        "cpg_enabled": os.getenv("REALWORLD_USE_CPG", "1"),
        "judge_votes": llm_board.JUDGE_VOTES,
        "judge_vote_temperature": llm_board.TEMP_JUDGE_VOTE,
        "evidence_mode": llm_board.EVIDENCE_MODE,
        "split_seed": split.SEED,
        "dev_fraction": split.DEV_FRACTION,
        "bootstrap_draws": BOOTSTRAP,
        "calibration_metric": fusion.CALIBRATION_METRIC,
        "datasets": sorted(d for d in datasets if d),
        "reposvul_labels": os.getenv("REALWORLD_REPOSVUL_LABELS", "llm") if "reposvul" in datasets else None,
        "bootstrap_unit": "repository",
        "baselines": os.getenv("REALWORLD_BASELINES", "function,context"),
        "semgrep_packs": ",".join(SEMGREP_CONFIGS),
        "workers": os.getenv("REALWORLD_WORKERS", "1"),
        "num_ctx": os.getenv("OLLAMA_NUM_CTX", "4096"),
        "context_chars": os.getenv("LLM_CONTEXT_CHARS", "1200"),
        "repo_context": repo_snapshot.VERSION if has_repo_context else None,
        "repo_context_chars": os.getenv("LLM_REPO_CONTEXT_CHARS", "800") if has_repo_context else None,
    })

    # Keep the dashboard chart working: baseline vs HackerSec, end-to-end, test.
    headline = views["test"].get("combined") or next(iter(views["test"].values()), None)
    if headline:
        e2e = headline["end_to_end"]
        best = next((s for s in HEADLINE_ORDER if s in e2e), None)
        report["baseline_metrics"] = e2e.get("sast")
        report["hackersec_metrics"] = e2e.get(best)
        report["hackersec_system"] = best

    report["markdown"] = _markdown(report)

    if write:
        state.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        state.write_json_atomic(state.RESULTS_DIR / "report_latest.json", report)
        (state.RESULTS_DIR / "report_latest.md").write_text(report["markdown"], encoding="utf-8")
        if calibration.get("fusion_model"):
            state.write_json_atomic(state.RESULTS_DIR / "fusion_model.json", calibration["fusion_model"])
        if calibration.get("full_fusion_model"):
            state.write_json_atomic(state.RESULTS_DIR / "fusion_full_model.json", calibration["full_fusion_model"])
        if report["coverage"]["complete"]:
            state.write_json_atomic(state.RESULTS_DIR / f"report_{stamp}.json", report)
            # Top-level eval_results/*.json is what /api/metrics serves.
            state.write_json_atomic(state.RESULTS_DIR.parent / f"{stamp}_realworld_run.json", report)
    return report
