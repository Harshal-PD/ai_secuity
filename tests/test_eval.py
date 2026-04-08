import pytest
from hackersec.evaluation.metrics import calculate_metrics

def test_calculate_metrics_zero_division():
    # Test Empty Arrays mapped avoiding divisions by Zero
    res = calculate_metrics([])
    assert res["baseline_metrics"]["f1"] == 0
    assert res["hackersec_metrics"]["f1"] == 0

def test_calculate_metrics_f1():
    # Mocking arrays bounding HackerSec improvement manually
    eval_results = [
         {"true_label": 1, "baseline_pred": 1, "hackersec_pred": 1}, # TP
         {"true_label": 0, "baseline_pred": 1, "hackersec_pred": 0}, # Baseline FP, HackerSec TN
         {"true_label": 1, "baseline_pred": 1, "hackersec_pred": 1}, # TP
    ]
    
    # Baseline: TP=2, FP=1, FN=0 -> Precision=0.66, Recall=1.00
    # HackerSec: TP=2, FP=0, FN=0 -> Precision=1.00, Recall=1.00
    
    res = calculate_metrics(eval_results)
    
    b_f1 = res["baseline_metrics"]["f1"]
    h_f1 = res["hackersec_metrics"]["f1"]
    
    assert res["baseline_metrics"]["precision"] < 0.7
    assert res["hackersec_metrics"]["precision"] == 1.0
    
    assert h_f1 > b_f1
