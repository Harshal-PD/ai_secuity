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
                the same for functions any candidate source flagged (SAST,
                LLM-spec taint, LLM auditor) — where the candidates board acts
  pairwise      PrimeVul-style (Ding et al., ICSE 2025) scoring on each
                vulnerable/fixed pair: P-C correct, P-V both flagged,
                P-B both cleared, P-R reversed
  vd_s          PrimeVul's VD-S: the miss rate (FNR) at the best threshold
                whose false-positive rate stays within a fixed budget
  significance  pair-level bootstrap 95% CIs (the pair is the unit, since its
                two functions are not independent) and an exact McNemar test
                of each system against the SAST baseline
  per_family    CWE families, grouped into SAST-reachable and logic/semantic
"""

import datetime
import math
import os
from collections import defaultdict

import numpy as np

from hackersec.evaluation.realworld import families, fusion, split, state

BOOTSTRAP = int(os.getenv("REALWORLD_BOOTSTRAP", "1000"))
VDS_BUDGETS = (0.005, 0.05)

SYSTEM_LABELS = {
    "sast": "Semgrep + Bandit (baseline)",
    "board": "SAST board: Judge majority vote",
    "board_override": "SAST board + evidence override (ablation)",
    "board_calibrated": "SAST board: vote score, dev-tuned threshold",
    "fusion": "SAST board + fusion (trained on dev)",
    "hunter_raw": "LLM auditor alone (no critic)",
    "taint_raw": "LLM-spec taint alone (no critic)",
    "union_raw": "Any candidate: SAST, taint or auditor (no critic)",
    "full_board": "Candidates board: Judge majority vote",
    "full_override": "Candidates board + evidence override (ablation)",
    "full_calibrated": "Candidates board: vote score, dev-tuned threshold",
    "full_fusion": "Candidates board + fusion (trained on dev)",
    "fusion_v1": "Board + synthetic fusion (v1)",
}
# (prediction key, score key); a None score marks a binary-only system.
SYSTEM_KEYS = {
    "sast": ("sast_pred", "sast_score"),
    "board": ("board_pred", "vote_score"),
    "board_override": ("board_override_pred", None),
    "board_calibrated": ("board_calibrated_pred", "p_score"),
    "fusion": ("fusion_pred", "fusion_score"),
    "hunter_raw": ("hunter_pred", "hunter_score"),
    "taint_raw": ("taint_pred", None),
    "union_raw": ("union_pred", None),
    "full_board": ("full_pred", "full_vote_score"),
    "full_override": ("full_override_pred", None),
    "full_calibrated": ("full_calibrated_pred", "full_p_score"),
    "full_fusion": ("full_fusion_pred", "full_fusion_score"),
    "fusion_v1": ("fusion_v1_pred", None),
}
HEADLINE_ORDER = ("full_fusion", "full_calibrated", "full_board", "fusion", "board_calibrated", "board")
# Columns of the family table, which would be unreadable with every system.
FAMILY_SYSTEMS = ("sast", "board_calibrated", "hunter_raw", "union_raw", "full_board", "full_fusion")


# ── Preparing records ───────────────────────────────────────────────────────

def _prepare(results: dict, pairs: dict) -> list[dict]:
    rows = []
    for r in results.values():
        if r.get("status") != "ok":
            continue
        r = dict(r)
        meta = pairs.get(r["pair_id"], {})
        r["split"] = r.get("split") or meta.get("split")
        r["clean"] = meta.get("clean", r.get("clean"))
        r["flagged"] = (r.get("n_findings") or 0) > 0
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
                confs = [c.get("confidence") or 0.0 for c in (r.get("auditor") or {}).get("candidates") or []]
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
    out = {"dev_functions": len(dev), "board_threshold": None, "fusion": None, "fusion_model": None}
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
    return out


def _systems(rows: list[dict]) -> list[str]:
    return [s for s, (key, _) in SYSTEM_KEYS.items() if rows and all(r.get(key) is not None for r in rows)]


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
    }


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
    return {"pairs": n, **counts, **{f"{k}_rate": round(c / n, 4) if n else 0.0 for k, c in counts.items()}}


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
    n = b + c
    if n == 0:
        p = 1.0
    else:
        log_half = n * math.log(0.5)
        tail = sum(
            math.exp(math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + log_half)
            for i in range(min(b, c) + 1)
        )
        p = min(1.0, 2 * tail)
    return {"system_only_correct": b, "baseline_only_correct": c, "p_value": round(p, 4)}


def _ci(values: np.ndarray) -> list[float]:
    return [round(float(np.percentile(values, 2.5)), 4), round(float(np.percentile(values, 97.5)), 4)]


def _bootstrap(rows: list[dict], systems: list[str]) -> dict:
    if BOOTSTRAP <= 0 or not rows:
        return {}
    pair_ids = sorted({r["pair_id"] for r in rows})
    index = {p: i for i, p in enumerate(pair_ids)}
    n = len(pair_ids)

    conf = {s: np.zeros((n, 3)) for s in systems}  # tp, fp, fn per pair
    correct_pair = {s: np.zeros(n) for s in systems}
    complete = np.zeros(n)
    by_pair: dict[int, dict] = defaultdict(dict)
    for r in rows:
        i = index[r["pair_id"]]
        by_pair[i][r["kind"]] = r
        for s in systems:
            pred, y = r[SYSTEM_KEYS[s][0]], r["label"]
            conf[s][i] += (pred == 1 and y == 1, pred == 1 and y == 0, pred == 0 and y == 1)
    for i, kinds in by_pair.items():
        if "vulnerable" in kinds and "fixed" in kinds:
            complete[i] = 1
            for s in systems:
                key = SYSTEM_KEYS[s][0]
                correct_pair[s][i] = kinds["vulnerable"][key] == 1 and kinds["fixed"][key] == 0

    draws = np.random.default_rng(0).integers(0, n, size=(BOOTSTRAP, n))
    n_complete = complete[draws].sum(axis=1)
    out, f1s = {}, {}
    for s in systems:
        c = conf[s][draws].sum(axis=1)
        tp, fp, fn = c[:, 0], c[:, 1], c[:, 2]
        denom = 2 * tp + fp + fn
        f1 = np.divide(2 * tp, denom, out=np.zeros_like(tp), where=denom > 0)
        pc = np.divide(correct_pair[s][draws].sum(axis=1), n_complete,
                       out=np.zeros(BOOTSTRAP), where=n_complete > 0)
        f1s[s] = f1
        out[s] = {"f1_ci": _ci(f1), "pc_rate_ci": _ci(pc)}
    for s in systems:
        if s != "sast" and "sast" in f1s:
            out[s]["delta_f1_vs_sast_ci"] = _ci(f1s[s] - f1s["sast"])
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
        "vd_s": {
            s: {f"fpr_{b:g}": _vds(rows, SYSTEM_KEYS[s][1], b) for b in VDS_BUDGETS}
            for s in systems if SYSTEM_KEYS[s][1]
        },
        "telemetry": _telemetry(rows),
        "per_family": _per_family(rows, systems),
        "per_cwe": {
            cwe: {"samples": len(rs), "flagged": sum(1 for r in rs if r["flagged"]),
                  **{s: _scores(rs, SYSTEM_KEYS[s][0]) for s in systems}}
            for cwe, rs in sorted(by_cwe.items(), key=lambda kv: -len(kv[1]))
        },
    }
    if stats:
        view["significance"] = {
            "bootstrap": _bootstrap(rows, systems),
            "mcnemar_vs_sast": {s: _mcnemar(rows, SYSTEM_KEYS[s][0], "sast_pred") for s in systems if s != "sast"},
        }
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


def _md_view(name: str, v: dict, systems: list[str]) -> list[str]:
    sig = v.get("significance") or {}
    boot, mcn = sig.get("bootstrap") or {}, sig.get("mcnemar_vs_sast") or {}
    L = [f"### {name} — {v['samples']} functions, {v['pairs']} pairs", "",
         "**End-to-end** (every function; SAST-board recall is capped by SAST, candidates-board recall "
         "by the any-candidate row)", "",
         "| System | Precision | Recall | F1 [95% CI] | ΔF1 vs SAST [95% CI] | FPR | McNemar p (accuracy) |",
         "|---|---|---|---|---|---|---|"]
    for s in systems:
        m, b = v["end_to_end"][s], boot.get(s, {})
        p = mcn.get(s, {}).get("p_value")
        L.append(
            f"| {SYSTEM_LABELS[s]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f}{_fmt_ci(b.get('f1_ci'))} "
            f"| {_fmt_ci(b.get('delta_f1_vs_sast_ci')).strip() or '—'} | {m['fpr']:.3f} | {'—' if p is None else f'{p:.4f}'} |"
        )

    subsets = [("static analysis flagged", v["sast_flagged"])]
    if v.get("candidates_flagged"):
        subsets.append(("any candidate source flagged (SAST, LLM-spec taint or auditor)", v["candidates_flagged"]))
    for title, fl in subsets:
        L += ["", f"**On functions {title}** ({fl['n']}: {fl['vulnerable']} vulnerable, {fl['fixed']} fixed)", "",
              "| System | Precision | Recall | F1 | FPR | FPs removed | TPs kept |", "|---|---|---|---|---|---|---|"]
        for s in systems:
            m = fl[s]
            removed, kept = fl.get(f"{s}_false_positives_removed"), fl.get(f"{s}_true_positives_kept")
            L.append(
                f"| {SYSTEM_LABELS[s]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} "
                f"| {'—' if removed is None else f'{removed:.1%}'} | {'—' if kept is None else f'{kept:.1%}'} |"
            )

    L += ["", "**Pairwise** (vulnerable vs fixed version of the same function)", "",
          "| System | Pairs | P-C correct [95% CI] | P-V both flagged | P-B both cleared | P-R reversed |",
          "|---|---|---|---|---|---|"]
    for s in systems:
        p = v["pairwise"][s]
        L.append(
            f"| {SYSTEM_LABELS[s]} | {p['pairs']} | {p['P-C_rate']:.3f}{_fmt_ci(boot.get(s, {}).get('pc_rate_ci'))} "
            f"| {p['P-V_rate']:.3f} | {p['P-B_rate']:.3f} | {p['P-R_rate']:.3f} |"
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
            + " | ".join(f"{s} F1 / R" for s in shown) + " |")
    sep = "|---|---|---|" + ("---|" if has_cand else "") + "---|" * len(shown)

    def row(name, b):
        cells = [name, str(b["samples"]), f"{(b['vulnerable_flagged_rate'] or 0):.1%}"]
        if has_cand:
            cells.append(f"{(b.get('vulnerable_candidate_rate') or 0):.1%}")
        cells += [f"{b[s]['f1']:.3f} / {b[s]['recall']:.3f}" for s in shown]
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
    L += ["", f"- Dev functions evaluated: {cal['dev_functions']}"]
    if cal.get("board_threshold") is not None:
        L.append(f"- Board threshold on mean P(vulnerable) across Judge votes: **{cal['board_threshold']:.3f}** (max F1 on dev)")
    if cal.get("fusion"):
        fm = cal.get("fusion_model") or {}
        extra = f", threshold {fm['threshold']:.3f}, dev CV F1 {fm['dev_cv_f1']:.3f}" if fm.get("threshold") is not None else ""
        L.append(f"- Fusion: {cal['fusion']}{extra}")
    if cal.get("full_threshold") is not None:
        L.append(f"- Candidates board threshold on mean P(vulnerable): **{cal['full_threshold']:.3f}** (max F1 on dev)")
    if cal.get("full_fusion"):
        fm = cal.get("full_fusion_model") or {}
        extra = f", threshold {fm['threshold']:.3f}, dev CV F1 {fm['dev_cv_f1']:.3f}" if fm.get("threshold") is not None else ""
        L.append(f"- Candidates fusion: {cal['full_fusion']}{extra}")
    L.append("")

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

    dev = report["views"]["dev"]
    dev_head = dev.get("combined") or next(iter(dev.values()), None)
    if dev_head:
        L += ["## Dev split (used for calibration; not a held-out result)", "",
              "| System | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|"]
        for s in systems:
            m = dev_head["end_to_end"][s]
            L.append(f"| {SYSTEM_LABELS[s]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} |")
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

    rows = _prepare(results, pairs)
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
            "Labels follow CVEfixes: a function changed by a security-fix commit is vulnerable before the fix "
            "and fixed after it. Tangled commits (> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded; the "
            "clean subset further keeps only commits that changed a single function.",
            "The SAST board only reasons about Semgrep/Bandit findings, so its recall cannot exceed theirs. The "
            "candidates board also sees LLM-spec taint flows (IRIS-style: the LLM labels the function's calls as "
            "sources/sinks and Joern checks the flows) and LLM auditor candidates (GPTLens-style), so its ceiling is "
            "the 'any candidate' recall. The *_flagged views isolate what each board adds over its candidates.",
            "The auditor and the spec labelling see only the code and same-file callers/callees, never the "
            "dataset's label or CWE. Context is limited to the same file; cross-file callers are not shown.",
            "The auditor-alone and taint-alone rows have no critic; they measure how much each candidate source "
            "finds, and how noisy it is, before the board filters it.",
            "Board thresholds and fusion models are fitted on the dev split only; test repositories never "
            "appear in dev. Dev numbers are in-sample and are shown for reference.",
            "Confidence intervals resample vulnerable/fixed pairs (1,000 draws); McNemar compares per-function "
            "correctness against SAST and only differs from it on flagged functions.",
            "VUDENC commits are keyword-mined and noisier than CVE-linked CVEfixes commits; compare within, "
            "not across, datasets.",
        ],
    }
    for dp in report["build"].values():
        if isinstance(dp, dict):
            dp.pop("done", None)  # thousands of commit keys; not useful in the report

    from hackersec.analysis.llm import board as llm_board
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
        "phase3": os.getenv("REALWORLD_PHASE3", "1"),
        "workers": os.getenv("REALWORLD_WORKERS", "1"),
        "num_ctx": os.getenv("OLLAMA_NUM_CTX", "4096"),
        "hunter_min_confidence": os.getenv("LLM_HUNTER_MIN_CONFIDENCE", "0.3"),
        "context_chars": os.getenv("LLM_CONTEXT_CHARS", "1200"),
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
