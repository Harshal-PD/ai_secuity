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

class FusionClassifier:
    """Wrapper loading the Scikit-Learn pipeline and extracting SHAP values."""
    
    def __init__(self, data_dir: str = "data"):
        self.model_path = Path(data_dir) / "fusion_model.joblib"
        self.model = None
        self.feature_names = ["static_confidence", "llm_confidence", "cpg_taint_depth", "cwe_severity_score"]
        
        self._load()

    def _load(self):
        if self.model_path.exists():
            try:
                self.model = joblib.load(str(self.model_path))
            except Exception as e:
                logger.error(f"Failed to load joblib matrix: {e}")
                self.model = None

    def predict(self, finding: Finding) -> dict:
        """
        Calculates inference bounds returning:
        {"prediction": "true_positive"|"false_positive"|"uncertain", "shap_values": dict}
        """
        if not self.model:
            return {"prediction": "uncertain", "error": "No model loaded."}
            
        features = extract_features(finding)
        
        # Scikit expects 2D
        X = np.array([features])
        
        try:
            # Our simulated dataset had 1 for True Positive, 0 for False Positive
            # Depending on model architecture, `predict_proba` returns list of classes
            probs = self.model.predict_proba(X)[0]
            
            # Binary classification [prob_0, prob_1]
            if len(probs) >= 2:
                prob_tp = probs[1]
            else:
                prob_tp = float(self.model.predict(X)[0])
                
            prediction = "true_positive" if prob_tp >= 0.5 else "false_positive"
            
            shap_dict = {}
            if prediction == "true_positive" and SHAP_AVAILABLE:
                # Calculate local SHAP explainability
                try:
                    explainer = shap.TreeExplainer(self.model)
                    shap_vals = explainer.shap_values(X)
                    
                    # Some versions return list of arrays for classification
                    if isinstance(shap_vals, list) and len(shap_vals) >= 2:
                        target_shap = shap_vals[1][0]
                    else:
                        target_shap = shap_vals[0]
                        
                    for i, name in enumerate(self.feature_names):
                        shap_dict[name] = float(target_shap[i])
                        
                except Exception as e:
                    logger.warning(f"SHAP explainer failed: {e}")

            return {
                "prediction": prediction,
                "confidence": float(prob_tp),
                "shap_values": shap_dict if shap_dict else None
            }
            
        except Exception as e:
            logger.error(f"Fusion predict exception: {e}")
            return {"prediction": "uncertain", "error": str(e)}
