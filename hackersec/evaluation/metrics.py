import json
import datetime
from pathlib import Path

def calculate_metrics(eval_results: list) -> dict:
    """
    Computes absolute performance bounds comparing Baseline (SAST) against
    the full ML HackerSec pipeline masking zero-division exceptions.
    """
    metrics = {
        "baseline": {"tp": 0, "fp": 0, "tn": 0, "fn": 0},
        "hackersec": {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    }
    
    for res in eval_results:
        true_label = res["true_label"]
        b_pred = res["baseline_pred"]
        h_pred = res["hackersec_pred"]
        
        # Baseline Mapping
        if b_pred == 1 and true_label == 1: metrics["baseline"]["tp"] += 1
        elif b_pred == 1 and true_label == 0: metrics["baseline"]["fp"] += 1
        elif b_pred == 0 and true_label == 0: metrics["baseline"]["tn"] += 1
        elif b_pred == 0 and true_label == 1: metrics["baseline"]["fn"] += 1
            
        # HackerSec Mapping
        if h_pred == 1 and true_label == 1: metrics["hackersec"]["tp"] += 1
        elif h_pred == 1 and true_label == 0: metrics["hackersec"]["fp"] += 1
        elif h_pred == 0 and true_label == 0: metrics["hackersec"]["tn"] += 1
        elif h_pred == 0 and true_label == 1: metrics["hackersec"]["fn"] += 1
            
    def _get_f1(scores):
        p = scores["tp"] / (scores["tp"] + scores["fp"]) if (scores["tp"] + scores["fp"]) > 0 else 0
        r = scores["tp"] / (scores["tp"] + scores["fn"]) if (scores["tp"] + scores["fn"]) > 0 else 0
        fpr = scores["fp"] / (scores["fp"] + scores["tn"]) if (scores["fp"] + scores["tn"]) > 0 else 0
        f1 = 2 * (p * r) / (p + r) if (p + r) > 0 else 0
        return {"precision": p, "recall": r, "f1": f1, "fpr": fpr}
        
    return {
        "baseline_metrics": _get_f1(metrics["baseline"]),
        "hackersec_metrics": _get_f1(metrics["hackersec"]),
        "raw_counts": metrics
    }

def export_results(metrics: dict, out_dir: str = "eval_results") -> str:
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    
    filename = f"{datetime.date.today().isoformat()}_run.json"
    file_path = base / filename
    
    with open(file_path, "w") as f:
        json.dump(metrics, f, indent=2)
        
    return str(file_path)
