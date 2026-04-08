import pytest
from hackersec.analysis.schema import Finding
from hackersec.analysis.ml.features import extract_features
from hackersec.analysis.ml.inference import FusionClassifier

def test_feature_extractor_valid_schema():
    f = Finding(
        file_path="app.py",
        line_start=1,
        line_end=5,
        rule_id="r1",
        tool="semgrep",
        severity="HIGH",
        message="err",
        cpg_context={"cpg_status": "success", "taint_paths": ["a", "b"]},
        llm_analysis={"confidence": 0.88}
    )
    
    feats = extract_features(f)
    assert len(feats) == 4
    # static=0.8, llm=0.88, depth=2.0, cwe=0.5
    assert feats[0] == 0.8
    assert feats[1] == 0.88
    assert feats[2] == 2.0
    assert feats[3] == 0.5


def test_feature_extractor_malformed():
    f = Finding(
         file_path="app.py",
         line_start=1,
         line_end=2,
         rule_id="r2",
         tool="bandit",
         severity="INVALID", # 0.5 static
         message="err",
         cpg_context={"cpg_status": "failed"}, # 0 depth
         llm_analysis={"confidence": "bad_string"} # 0.0 llm
    )
    
    feats = extract_features(f)
    assert feats[0] == 0.5
    assert feats[1] == 0.0
    assert feats[2] == 0.0
    assert feats[3] == 0.5

@pytest.fixture
def mock_classifier():
    return FusionClassifier(data_dir="data")

def test_inference_graceful_missing_model(mock_classifier):
    # Depending on state of directory, may or may not test valid mapping natively. 
    # Just asserting prediction executes without throwing exception.
    f = Finding(
        file_path="x", line_start=1, line_end=2, rule_id="y", tool="z", severity="LOW"
    )
    res = mock_classifier.predict(f)
    
    assert "prediction" in res
    assert res["prediction"] in ["true_positive", "false_positive", "uncertain"]
