"""
Fusion trained on the dev split with the board's real signals.

The shipped FusionClassifier was fitted on synthetic features, and on the
first run it reproduced SAST exactly. Here a logistic regression is fitted on
the dev split's flagged functions (static findings + board outputs -> label)
and applied unchanged to test. Its decision threshold, and the calibrated
board threshold, are chosen on dev from cross-validated scores, so neither
ever sees a test label.
"""

import logging
import math

import numpy as np

logger = logging.getLogger(__name__)

FEATURES = [
    "p_vulnerable",
    "vote_share",
    "attacker_confidence",
    "defender_safety",
    "evidence_grounded",
    "log_findings",
    "max_severity",
    "any_taint",
    "semgrep_share",
]
MIN_TRAIN = 20
_SEVERITY = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


def _num(value, default: float) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def features(record: dict) -> list[float] | None:
    """Feature vector for a flagged v2 record, or None when it has none."""
    findings = record.get("findings") or []
    board = record.get("board")
    if not findings or not board:
        return None
    semgrep = sum(1 for f in findings if f.get("tool") == "semgrep")
    return [
        _num(record.get("p_vulnerable"), 0.5),
        _num(record.get("vote_share"), 0.5),
        _num(board.get("attacker_confidence"), 0.5),
        _num(board.get("defender_safety"), 0.5),
        1.0 if board.get("evidence_grounded") else 0.0,
        math.log1p(len(findings)),
        max(_SEVERITY.get(f.get("severity"), 0.0) for f in findings),
        1.0 if any((f.get("taint_paths") or 0) > 0 for f in findings) else 0.0,
        semgrep / len(findings),
    ]


def best_threshold(scores: list[float | None], labels: list[int]) -> float | None:
    """Threshold on the scores that maximises F1 over every function in the
    split. A None score (nothing flagged) is always predicted safe."""
    candidates = sorted({s for s in scores if s is not None})
    if not candidates:
        return None
    best, best_f1 = None, -1.0
    for t in candidates:
        tp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and y == 1)
        fp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and y == 0)
        fn = sum(1 for s, y in zip(scores, labels) if (s is None or s < t) and y == 1)
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        if f1 > best_f1 + 1e-12:
            best, best_f1 = t, f1
    return best


class Fusion:
    def __init__(self, mean, scale, coef, intercept, threshold, n_train, dev_cv_f1=None):
        self.mean = np.asarray(mean, dtype=float)
        self.scale = np.asarray(scale, dtype=float)
        self.coef = np.asarray(coef, dtype=float)
        self.intercept = float(intercept)
        self.threshold = threshold
        self.n_train = n_train
        self.dev_cv_f1 = dev_cv_f1

    def score(self, record: dict) -> float | None:
        x = features(record)
        if x is None:
            return None
        z = (np.asarray(x) - self.mean) / self.scale
        return float(1.0 / (1.0 + math.exp(-(float(z @ self.coef) + self.intercept))))

    def predict(self, record: dict) -> int:
        s = self.score(record)
        return int(s is not None and self.threshold is not None and s >= self.threshold)

    def to_dict(self) -> dict:
        return {
            "features": FEATURES,
            "mean": self.mean.tolist(),
            "scale": self.scale.tolist(),
            "coef": self.coef.tolist(),
            "intercept": self.intercept,
            "threshold": self.threshold,
            "n_train": self.n_train,
            "dev_cv_f1": self.dev_cv_f1,
        }


def train(dev_records: list[dict]) -> tuple[Fusion | None, str]:
    """Fit on dev. Returns (model, note); model is None when dev is too small
    or has a single class among flagged functions."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    rows = [(features(r), r["label"]) for r in dev_records]
    flagged = [(x, y) for x, y in rows if x is not None]
    if len(flagged) < MIN_TRAIN:
        return None, f"only {len(flagged)} flagged dev functions (need {MIN_TRAIN})"
    X = np.asarray([x for x, _ in flagged])
    y = np.asarray([y for _, y in flagged])
    minority = int(min(y.sum(), len(y) - y.sum()))
    if minority < 2:
        return None, "flagged dev functions are all one class"

    def pipeline():
        return make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", C=1.0, max_iter=1000))

    folds = min(5, minority)
    cv_scores = cross_val_predict(
        pipeline(), X, y, cv=StratifiedKFold(folds, shuffle=True, random_state=0), method="predict_proba"
    )[:, 1]

    # Unflagged dev functions keep a None score, so the threshold trades off
    # the board's dismissals against the misses SAST already has.
    it = iter(cv_scores.tolist())
    all_scores = [next(it) if x is not None else None for x, _ in rows]
    all_labels = [y for _, y in rows]
    threshold = best_threshold(all_scores, all_labels)

    model = pipeline().fit(X, y)
    scaler, lr = model[0], model[1]
    fusion = Fusion(scaler.mean_, scaler.scale_, lr.coef_[0], lr.intercept_[0], threshold, len(flagged))
    tp = sum(1 for s, yy in zip(all_scores, all_labels) if s is not None and threshold is not None and s >= threshold and yy)
    fp = sum(1 for s, yy in zip(all_scores, all_labels) if s is not None and threshold is not None and s >= threshold and not yy)
    fn = sum(all_labels) - tp
    fusion.dev_cv_f1 = round(2 * tp / (2 * tp + fp + fn), 4) if tp else 0.0
    return fusion, f"trained on {len(flagged)} flagged dev functions ({folds}-fold CV threshold)"


def load(data: dict | None) -> Fusion | None:
    if not data or data.get("features") != FEATURES:
        return None
    return Fusion(data["mean"], data["scale"], data["coef"], data["intercept"],
                  data["threshold"], data["n_train"], data.get("dev_cv_f1"))
