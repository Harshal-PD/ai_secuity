import datetime
import json
import os
import subprocess
from pathlib import Path


def _scores(counts: dict) -> dict:
    tp, fp, tn, fn = counts["tp"], counts["fp"], counts["tn"], counts["fn"]
    p = tp / (tp + fp) if (tp + fp) > 0 else 0
    r = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    f1 = 2 * (p * r) / (p + r) if (p + r) > 0 else 0
    acc = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "accuracy": round(acc, 4),
    }


def _confuse(rows: list, pred_key: str = "prediction") -> dict:
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for row in rows:
        truth = row["true_label"]
        pred = row[pred_key]
        if pred == 1 and truth == 1:
            counts["tp"] += 1
        elif pred == 1 and truth == 0:
            counts["fp"] += 1
        elif pred == 0 and truth == 0:
            counts["tn"] += 1
        else:
            counts["fn"] += 1
    return counts


def calculate_metrics(eval_results: list) -> dict:
    """
    Two-way baseline vs full-pipeline comparison.

    Kept for the legacy `evaluate_pipeline` path and the dashboard contract.
    Ablation runs should use `build_report` instead.
    """
    baseline = _confuse(eval_results, pred_key="baseline_pred")
    hackersec = _confuse(eval_results, pred_key="hackersec_pred")

    return {
        "baseline_metrics": _scores(baseline),
        "hackersec_metrics": _scores(hackersec),
        "raw_counts": {"baseline": baseline, "hackersec": hackersec},
    }


def calculate_variant_metrics(results_by_variant: dict) -> dict:
    """Precision/Recall/F1/FPR per ablation variant."""
    out = {}
    for name, rows in results_by_variant.items():
        counts = _confuse(rows)
        out[name] = {
            "metrics": _scores(counts),
            "counts": counts,
            "n": len(rows),
        }
    return out


def calculate_per_cwe(results_by_variant: dict) -> dict:
    """Per-CWE breakdown, so a gain cannot hide behind one easy weakness class."""
    out = {}
    for name, rows in results_by_variant.items():
        by_cwe = {}
        for row in rows:
            by_cwe.setdefault(row.get("cwe") or "unknown", []).append(row)
        out[name] = {
            cwe: {"metrics": _scores(_confuse(r)), "n": len(r)}
            for cwe, r in sorted(by_cwe.items())
        }
    return out


def _git_hash() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def collect_provenance(extra: dict | None = None) -> dict:
    """Everything a reviewer needs to reproduce the numbers."""
    from hackersec.analysis.llm import client as llm_client
    from hackersec.analysis.llm import board as llm_board
    from hackersec.analysis.llm.evidence import MIN_SPAN
    from hackersec.analysis.ml.inference import DECISION_THRESHOLD
    from hackersec.evaluation.ablation import SINGLE_PASS_THRESHOLD

    prov = {
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "git_commit": _git_hash(),
        "models": {
            "attacker": llm_client.MODEL_ATTACKER,
            "defender": llm_client.MODEL_DEFENDER,
            "judge": llm_client.MODEL_JUDGE,
            "patcher": llm_client.MODEL_PATCHER,
        },
        "num_ctx": llm_client._DEFAULT_NUM_CTX,
        "temperatures": {
            "attacker": llm_board.TEMP_ATTACKER,
            "defender": llm_board.TEMP_DEFENDER,
            "judge": llm_board.TEMP_JUDGE,
        },
        "evidence_rule_min_span": MIN_SPAN,
        "decision_thresholds": {
            "single_pass_confidence": SINGLE_PASS_THRESHOLD,
            "fusion_probability": DECISION_THRESHOLD,
            "evidence_rule_override_floor": llm_board.OVERRIDE_CONFIDENCE_FLOOR,
        },
        "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    }
    if extra:
        prov.update(extra)
    return prov


def _markdown_table(variant_labels: dict, variant_metrics: dict) -> str:
    """Paper-ready results table."""
    lines = [
        "| Configuration | Precision | Recall | F1 | FPR |",
        "|---|---|---|---|---|",
    ]
    for name, label in variant_labels.items():
        m = variant_metrics.get(name, {}).get("metrics")
        if not m:
            continue
        lines.append(
            f"| {label} | {m['precision']:.3f} | {m['recall']:.3f} | "
            f"{m['f1']:.3f} | {m['fpr']:.3f} |"
        )
    return "\n".join(lines)


def build_report(ablation: dict, provenance_extra: dict | None = None) -> dict:
    """
    Assemble the full ablation report.

    `baseline_metrics` / `hackersec_metrics` are preserved at the top level so
    the existing /api/metrics endpoint and dashboard chart keep working.
    """
    results_by_variant = ablation["results_by_variant"]
    variant_metrics = calculate_variant_metrics(results_by_variant)
    variant_labels = ablation["variants"]

    baseline = variant_metrics.get("sast_only", {}).get("metrics") or _scores(
        {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    )
    headline_name = next(
        (n for n in ("board_fusion", "board_full") if n in variant_metrics),
        None,
    )
    headline = (
        variant_metrics[headline_name]["metrics"] if headline_name else baseline
    )

    return {
        # ── dashboard contract ──
        "baseline_metrics": baseline,
        "hackersec_metrics": headline,
        "raw_counts": {
            name: v["counts"] for name, v in variant_metrics.items()
        },
        # ── ablation detail ──
        "headline_variant": headline_name,
        "variant_labels": variant_labels,
        "variant_metrics": variant_metrics,
        "per_cwe": calculate_per_cwe(results_by_variant),
        "agreement": ablation.get("agreement", {}),
        "dataset_stats": ablation.get("dataset_stats", {}),
        "per_file": results_by_variant,
        "finding_records": ablation.get("finding_records", {}),
        "markdown_table": _markdown_table(variant_labels, variant_metrics),
        "provenance": collect_provenance(provenance_extra),
    }


def export_results(metrics: dict, out_dir: str = "eval_results") -> str:
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)

    # Second-resolution stamp so repeated same-day runs do not overwrite.
    stamp = datetime.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    file_path = base / f"{stamp}_run.json"

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    return str(file_path)
