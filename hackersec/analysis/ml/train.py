import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def train_model(data_dir: str = "data"):
    """
    Train a security-aware fusion classifier.
    
    Features: [static_confidence, llm_confidence, cpg_taint_depth, cwe_severity_score, has_cwe]
    Label: 1 = true_positive (real vulnerability), 0 = false_positive
    
    Training philosophy: Static analysis tools like Semgrep have HIGH precision
    for their security-audit rules. If Semgrep flags something as HIGH severity
    AND it maps to a known CWE, it's almost certainly a real vulnerability.
    The ML layer should confirm this, not second-guess it.
    """
    print("Generating security-aware training data...")
    
    np.random.seed(42)
    X = []
    y = []
    
    for _ in range(1000):  # 1000 samples for better generalization
        static_conf = np.random.uniform(0.1, 1.0)
        llm_conf = np.random.uniform(0.1, 1.0)
        cpg_depth = np.random.uniform(0.0, 5.0)
        cwe_sev = np.random.uniform(0.2, 1.0)
        has_cwe = np.random.choice([0.0, 1.0], p=[0.3, 0.7])
        
        # Security-aware labeling rules:
        # Rule 1: HIGH/CRITICAL static finding + known CWE = almost always real
        if static_conf >= 0.7 and has_cwe == 1.0:
            label = 1  # true positive
        # Rule 2: HIGH static + HIGH LLM = real vulnerability
        elif static_conf >= 0.7 and llm_conf >= 0.6:
            label = 1
        # Rule 3: MEDIUM static + strong LLM agreement + CPG evidence = real
        elif static_conf >= 0.4 and llm_conf >= 0.7 and cpg_depth >= 1.0:
            label = 1
        # Rule 4: Known critical CWE + any reasonable confidence = real
        elif cwe_sev >= 0.9 and static_conf >= 0.5:
            label = 1
        # Rule 5: Very low static confidence + no CWE = likely false positive
        elif static_conf < 0.3 and has_cwe == 0.0:
            label = 0
        # Rule 6: Low LLM confidence + low static = false positive
        elif static_conf < 0.4 and llm_conf < 0.3:
            label = 0
        else:
            # Boundary zone: slight bias toward true_positive (security conservative)
            label = np.random.choice([0, 1], p=[0.4, 0.6])
            
        X.append([static_conf, llm_conf, cpg_depth, cwe_sev, has_cwe])
        y.append(label)
        
    X = np.array(X)
    y = np.array(y)
    
    print(f"Dataset: {sum(y)} true_positive, {len(y) - sum(y)} false_positive")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # GradientBoosting is better than RandomForest for our feature interactions
    clf = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.1,
        random_state=42
    )
    
    print("Fitting model...")
    clf.fit(X_train, y_train)
    
    preds = clf.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, preds, target_names=["false_positive", "true_positive"]))
    
    # Feature importance
    feat_names = ["static_confidence", "llm_confidence", "cpg_taint_depth", "cwe_severity_score", "has_cwe"]
    importances = clf.feature_importances_
    print("\nFeature Importance:")
    for name, imp in sorted(zip(feat_names, importances), key=lambda x: -x[1]):
        print(f"  {name}: {imp:.4f}")
    
    out_dir = Path(data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "fusion_model.joblib"
    joblib.dump(clf, out_path)
    
    print(f"\nModel saved to {out_path}")

if __name__ == "__main__":
    train_model()
