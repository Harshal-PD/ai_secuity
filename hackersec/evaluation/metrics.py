import json
import datetime
from pathlib import Path

def calculate_metrics(eval_results: list) -> dict:
    """
    Computes absolute performance bounds comparing Baseline (SAST) against
    the full ML HackerSec pipeline masking zero-division exceptions.
    """
    # Which prediction columns are present. verified_pred only carries signal
    # when the dynamic verification stage ran, so gate it on real reproductions.
    has_verified = any(res.get("verified_pred") for res in eval_results)
    cols = {"baseline": "baseline_pred", "hackersec": "hackersec_pred"}
    if has_verified:
        cols["hackersec_verified"] = "verified_pred"

    metrics = {name: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for name in cols}

    for res in eval_results:
        true_label = res["true_label"]
        for name, key in cols.items():
            pred = res.get(key, 0)
            bucket = metrics[name]
            if pred == 1 and true_label == 1: bucket["tp"] += 1
            elif pred == 1 and true_label == 0: bucket["fp"] += 1
            elif pred == 0 and true_label == 0: bucket["tn"] += 1
            elif pred == 0 and true_label == 1: bucket["fn"] += 1

    def _get_f1(scores):
        p = scores["tp"] / (scores["tp"] + scores["fp"]) if (scores["tp"] + scores["fp"]) > 0 else 0
        r = scores["tp"] / (scores["tp"] + scores["fn"]) if (scores["tp"] + scores["fn"]) > 0 else 0
        fpr = scores["fp"] / (scores["fp"] + scores["tn"]) if (scores["fp"] + scores["tn"]) > 0 else 0
        f1 = 2 * (p * r) / (p + r) if (p + r) > 0 else 0
        return {"precision": p, "recall": r, "f1": f1, "fpr": fpr}

    out = {f"{name}_metrics": _get_f1(metrics[name]) for name in cols}
    out["raw_counts"] = metrics
    return out

def export_results(metrics: dict, out_dir: str = "eval_results") -> str:
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    
    filename = f"{datetime.date.today().isoformat()}_run.json"
    file_path = base / filename
    
    with open(file_path, "w") as f:
        json.dump(metrics, f, indent=2)
        
    return str(file_path)
