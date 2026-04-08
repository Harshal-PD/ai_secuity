import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

def train_model(data_dir: str = "data"):
    """
    Simulates training against Big-Vul representations mapping boundaries
    into a serialized RandomForest estimator offline.
    """
    print("Initializing Simulated Big-Vul matrix...")
    
    # Generate Synthetic Dataset reflecting expected features:
    # [static_confidence, llm_confidence, cpg_taint_depth, cwe_severity_score]
    # We want patterns like: high LLM conf + deep CPG = True (1)
    
    np.random.seed(42)
    X = []
    y = []
    
    for _ in range(500): # 500 samples
        static_conf = np.random.uniform(0.1, 1.0)
        llm_conf = np.random.uniform(0.0, 1.0)
        cpg_depth = np.random.randint(0, 5)
        cwe_sev = np.random.uniform(0.2, 0.8)
        
        # Rule pattern: if both static and LLM are reasonably high, classify as true positive
        if llm_conf > 0.6 and static_conf > 0.5:
            label = 1
        elif llm_conf < 0.3:
            label = 0
        else:
            # Uncertain boundary, noise
            label = np.random.choice([0, 1])
            
        X.append([static_conf, llm_conf, cpg_depth, cwe_sev])
        y.append(label)
        
    X = np.array(X)
    y = np.array(y)
    
    # Train validation split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Model fulfilling roadmap plan: GradientBoosting / RandomForest + class_weight balanced
    clf = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
    
    print("Fitting model...")
    clf.fit(X_train, y_train)
    
    # Inference checking matrix targets
    preds = clf.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, preds))
    
    # Dump memory mapping bounds securely into offline
    out_dir = Path(data_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "fusion_model.joblib"
    joblib.dump(clf, out_path)
    
    print(f"Model saved to {out_path}")

if __name__ == "__main__":
    train_model()
