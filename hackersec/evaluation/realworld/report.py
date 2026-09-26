"""
Phase 3 — metrics. Safe to run at any time, including mid-run.

Three views, because the board can only filter what static analysis reports:

  end_to_end    every function; recall here is capped by Semgrep/Bandit recall
  sast_flagged  only functions static analysis flagged — where the board acts,
                and where its contribution (removing false positives while
                keeping true positives) is measured
  pairwise      PrimeVul-style (Ding et al., ICSE 2025) scoring on each
                vulnerable/fixed pair: P-C correct, P-V both flagged,
                P-B both cleared, P-R reversed
"""

import datetime
import os
from collections import defaultdict

from hackersec.evaluation.realworld import state

SYSTEMS = {"sast": "sast_pred", "board": "board_pred", "fusion": "fusion_pred"}
SYSTEM_LABELS = {
    "sast": "Semgrep + Bandit (baseline)",
    "board": "HackerSec: board verdict",
    "fusion": "HackerSec: board + fusion (provisional)",
}


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


def _flagged_view(rows: list[dict]) -> dict:
    flagged = [r for r in rows if r.get("n_findings", 0) > 0]
    out = {"n": len(flagged), "vulnerable": sum(r["label"] for r in flagged)}
    out["fixed"] = out["n"] - out["vulnerable"]
    for sys, key in SYSTEMS.items():
        out[sys] = _scores(flagged, key)
    neg = [r for r in flagged if r["label"] == 0]
    pos = [r for r in flagged if r["label"] == 1]
    for sys in ("board", "fusion"):
        key = SYSTEMS[sys]
        out[f"{sys}_false_positives_removed"] = round(sum(1 for r in neg if r[key] == 0) / len(neg), 4) if neg else None
        out[f"{sys}_true_positives_kept"] = round(sum(1 for r in pos if r[key] == 1) / len(pos), 4) if pos else None
    return out


def _board_telemetry(rows: list[dict]) -> dict:
    fs = [f for r in rows for f in r.get("findings", [])]
    n = len(fs)
    if not n:
        return {"findings": 0}

    def rate(pred):
        return round(sum(1 for f in fs if pred(f)) / n, 4)

    return {
        "findings": n,
        "cpg_success_rate": rate(lambda f: f.get("cpg_status") in ("success", "no_flow_found")),
        "cpg_taint_found_rate": rate(lambda f: (f.get("taint_paths") or 0) > 0),
        "rag_context_rate": rate(lambda f: (f.get("rag_hits") or 0) > 0),
        "judge_false_positive_rate": rate(lambda f: f.get("judge_verdict") == "FALSE_POSITIVE"),
        "evidence_grounded_rate": rate(lambda f: f.get("evidence_grounded") is True),
        "evidence_rule_override_rate": rate(lambda f: f.get("verdict_source") == "evidence_rule"),
        "by_tool": {t: sum(1 for f in fs if f.get("tool") == t) for t in sorted({f.get("tool") for f in fs})},
    }


def _view(rows: list[dict]) -> dict:
    by_cwe = defaultdict(list)
    for r in rows:
        by_cwe[r["cwe"]].append(r)
    return {
        "samples": len(rows),
        "pairs": len({r["pair_id"] for r in rows}),
        "end_to_end": {sys: _scores(rows, key) for sys, key in SYSTEMS.items()},
        "sast_flagged": _flagged_view(rows),
        "pairwise": {sys: _pairwise(rows, key) for sys, key in SYSTEMS.items()},
        "board_telemetry": _board_telemetry(rows),
        "per_cwe": {
            cwe: {
                "samples": len(rs),
                "flagged": sum(1 for r in rs if r.get("n_findings", 0) > 0),
                **{sys: _scores(rs, key) for sys, key in SYSTEMS.items()},
            }
            for cwe, rs in sorted(by_cwe.items(), key=lambda kv: -len(kv[1]))
        },
    }


def _markdown(report: dict) -> str:
    L = [f"# HackerSec real-world evaluation ({report['generated_at']})", ""]
    c = report["coverage"]
    L.append(
        f"Status: **{'complete' if c['complete'] else 'PARTIAL'}** — {c['evaluated_ok']}/{c['samples_total']} "
        f"samples evaluated ({c['percent_done']}%), {c['llm_failed']} LLM failures, {c['errors']} errors."
    )
    L.append("")
    for name, v in report["datasets"].items():
        L += [f"## {name} — {v['samples']} functions, {v['pairs']} pairs", ""]
        L += ["**End-to-end** (recall capped by static analysis)", "",
              "| System | Precision | Recall | F1 | FPR | Accuracy |", "|---|---|---|---|---|---|"]
        for sys, m in v["end_to_end"].items():
            L.append(f"| {SYSTEM_LABELS[sys]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} | {m['accuracy']:.3f} |")
        fl = v["sast_flagged"]
        L += ["", f"**On functions static analysis flagged** ({fl['n']}: {fl['vulnerable']} vulnerable, {fl['fixed']} fixed)", "",
              "| System | Precision | Recall | F1 | FPR |", "|---|---|---|---|---|"]
        for sys in SYSTEMS:
            m = fl[sys]
            L.append(f"| {SYSTEM_LABELS[sys]} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} |")
        if fl.get("board_false_positives_removed") is not None:
            L.append("")
            L.append(
                f"Board removed **{fl['board_false_positives_removed']:.1%}** of static false positives "
                f"while keeping **{(fl['board_true_positives_kept'] or 0):.1%}** of true positives."
            )
        L += ["", "**Pairwise** (vulnerable vs fixed version of the same function)", "",
              "| System | Pairs | P-C correct | P-V both flagged | P-B both cleared | P-R reversed |", "|---|---|---|---|---|---|"]
        for sys, p in v["pairwise"].items():
            L.append(f"| {SYSTEM_LABELS[sys]} | {p['pairs']} | {p['P-C_rate']:.3f} | {p['P-V_rate']:.3f} | {p['P-B_rate']:.3f} | {p['P-R_rate']:.3f} |")
        L.append("")
    return "\n".join(L)


def build_report(write: bool = True) -> dict:
    samples = state.load_samples()
    results = state.load_results()
    ok = [r for r in results.values() if r.get("status") == "ok"]
    statuses = defaultdict(int)
    for r in results.values():
        statuses[r.get("status")] += 1

    datasets = defaultdict(list)
    for r in ok:
        datasets[r["dataset"]].append(r)
    views = {name: _view(rows) for name, rows in sorted(datasets.items())}
    if len(views) > 1:
        views["combined"] = _view(ok)

    total = len(samples)
    report = {
        "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "coverage": {
            "samples_total": total,
            "evaluated_ok": len(ok),
            "llm_failed": statuses.get("llm_failed", 0),
            "errors": statuses.get("error", 0) + statuses.get("file_missing", 0),
            "pending": total - len(results),
            "percent_done": round(100 * len(results) / total, 1) if total else 0.0,
            "complete": total > 0 and len(results) >= total,
        },
        "build": state.read_json(state.BUILD_PROGRESS_PATH, {}) or {},
        "datasets": views,
        "caveats": [
            "Labels follow CVEfixes: a function changed by a security-fix commit is vulnerable before the fix "
            "and fixed after it. Tangled commits (> REALWORLD_MAX_FUNCS_PER_COMMIT functions) are excluded, "
            "but some label noise remains.",
            "The board only reasons about static-analysis findings, so end-to-end recall cannot exceed "
            "Semgrep + Bandit recall. The sast_flagged view isolates the board's contribution.",
            "The fusion classifier was not trained on real board outputs; treat the fusion row as provisional.",
            "VUDENC commits are keyword-mined and noisier than CVE-linked CVEfixes commits; compare within, "
            "not across, datasets.",
        ],
    }
    for key in ("build",):
        for dp in report[key].values():
            dp.pop("done", None)  # thousands of commit keys; not useful in the report

    from hackersec.evaluation.metrics import collect_provenance

    report["provenance"] = collect_provenance({
        "repo_commit": os.getenv("REALWORLD_GIT_COMMIT", "unknown"),
        "max_funcs_per_commit": os.getenv("REALWORLD_MAX_FUNCS_PER_COMMIT", "4"),
        "seed": os.getenv("REALWORLD_SEED", "42"),
        "cpg_enabled": os.getenv("REALWORLD_USE_CPG", "1"),
    })

    # Keep the dashboard chart working: baseline vs board, end-to-end, all data.
    headline = views.get("combined") or next(iter(views.values()), None)
    if headline:
        e2e = headline["end_to_end"]
        report["baseline_metrics"] = e2e["sast"]
        report["hackersec_metrics"] = e2e["board"]

    report["markdown"] = _markdown(report)

    if write:
        state.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
        state.write_json_atomic(state.RESULTS_DIR / "report_latest.json", report)
        (state.RESULTS_DIR / "report_latest.md").write_text(report["markdown"], encoding="utf-8")
        if report["coverage"]["complete"]:
            state.write_json_atomic(state.RESULTS_DIR / f"report_{stamp}.json", report)
            # Top-level eval_results/*.json is what /api/metrics serves.
            state.write_json_atomic(state.RESULTS_DIR.parent / f"{stamp}_realworld_run.json", report)
    return report
