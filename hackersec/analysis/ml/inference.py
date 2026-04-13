import logging
import joblib
import numpy as np
from pathlib import Path

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

from hackersec.analysis.schema import Finding
from hackersec.analysis.ml.features import extract_features

logger = logging.getLogger(__name__)

# Security-conservative threshold: lower than 0.5 to bias toward flagging
# It's better to flag a false positive than miss a real vulnerability
DECISION_THRESHOLD = 0.4

class FusionClassifier:
    """Wrapper loading the Scikit-Learn pipeline and extracting SHAP values."""
    
    def __init__(self, data_dir: str = "data"):
        self.model_path = Path(data_dir) / "fusion_model.joblib"
        self.model = None
        self.feature_names = [
            "static_confidence", "llm_confidence", 
            "cpg_taint_depth", "cwe_severity_score", "has_cwe"
        ]
        
        self._load()

    def _load(self):
        if self.model_path.exists():
            try:
                self.model = joblib.load(str(self.model_path))
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
                self.model = None

    def predict(self, finding: Finding) -> dict:
        """
        Returns: {"prediction": "true_positive"|"false_positive"|"uncertain",
                  "confidence": float, "shap_values": dict|None}
        """
        if not self.model:
            # No model = can't dismiss findings, default to true_positive
            return {"prediction": "true_positive", "confidence": 0.5, 
                    "error": "No model loaded — defaulting to true_positive."}
            
        features = extract_features(finding)
        X = np.array([features])
        
        try:
            probs = self.model.predict_proba(X)[0]
            
            if len(probs) >= 2:
                prob_tp = probs[1]  # probability of true_positive
            else:
                prob_tp = float(self.model.predict(X)[0])
                
            # Use the security-conservative threshold
            prediction = "true_positive" if prob_tp >= DECISION_THRESHOLD else "false_positive"
            
            shap_dict = {}
            if SHAP_AVAILABLE:
                try:
                    explainer = shap.TreeExplainer(self.model)
                    shap_vals = explainer.shap_values(X)
                    
                    if isinstance(shap_vals, list) and len(shap_vals) >= 2:
                        target_shap = shap_vals[1][0]
                    elif isinstance(shap_vals, np.ndarray) and shap_vals.ndim == 2:
                        target_shap = shap_vals[0]
                    else:
                        target_shap = shap_vals[0] if isinstance(shap_vals, (list, np.ndarray)) else []
                        
                    for i, name in enumerate(self.feature_names):
                        if i < len(target_shap):
                            shap_dict[name] = round(float(target_shap[i]), 4)
                        
                except Exception as e:
                    logger.warning(f"SHAP explainer failed: {e}")

            return {
                "prediction": prediction,
                "confidence": round(float(prob_tp), 4),
                "shap_values": shap_dict if shap_dict else None
            }
            
        except Exception as e:
            logger.error(f"Fusion predict exception: {e}")
            # On error, default to true_positive (security conservative)
            return {"prediction": "true_positive", "confidence": 0.5, "error": str(e)}
