"""
Fusion trained on the dev split with the board's real signals.

The shipped FusionClassifier was fitted on synthetic features, and on the
first run it reproduced SAST exactly. Here a logistic regression is fitted on
the dev split's flagged functions (candidate findings + board outputs ->
label) and applied unchanged to test. Its decision threshold, and the
calibrated board thresholds, are chosen on dev (the fusion one from
cross-validated scores) by CALIBRATION_METRIC, so none of them ever sees a
test label.

Two feature sets:
  board -- the SAST-only debate (Phase 2)
  full  -- the debate over SAST + LLM-spec taint + auditor candidates, plus
           which of those sources fired (Phase 3)
"""

import logging
import math
import os

import numpy as np

logger = logging.getLogger(__name__)

_BASE = [
    "p_vulnerable",
    "vote_share",
    "attacker_confidence",
    "defender_safety",
    "evidence_grounded",
    "guard_grounded",
    "log_findings",
    "max_severity",
    "any_taint",
    "semgrep_share",
]
FEATURES = _BASE
FULL_FEATURES = _BASE + ["has_sast", "has_llm_taint", "has_auditor", "auditor_confidence", "auditor_p_vulnerable"]
KINDS = {"board": FEATURES, "full": FULL_FEATURES}
# Record keys for each debate: (findings, board summary, P(vulnerable), vote share).
_KEYS = {
    "board": ("findings", "board", "p_vulnerable", "vote_share"),
    "full": ("full_findings", "full_board", "full_p_vulnerable", "full_vote_share"),
}
MIN_TRAIN = 20
# Objective for every dev-tuned threshold. Each pair contributes one
# vulnerable and one fixed function, so F1 is maximised by flagging
# everything (0.667); MCC and balanced accuracy are 0 for that.
CALIBRATION_METRIC = os.getenv("REALWORLD_CALIBRATE_METRIC", "mcc").strip().lower()
if CALIBRATION_METRIC not in ("mcc", "balanced_accuracy", "f1"):
    raise ValueError(f"REALWORLD_CALIBRATE_METRIC must be mcc, balanced_accuracy or f1, got {CALIBRATION_METRIC!r}")
_SEVERITY = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


def _num(value, default: float) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def features(record: dict, kind: str = "board") -> list[float] | None:
    """Feature vector for a record whose `kind` debate ran, else None."""
    findings_key, board_key, p_key, share_key = _KEYS[kind]
    findings = record.get(findings_key) or []
    board = record.get(board_key)
    if not findings or not board:
        return None
    semgrep = sum(1 for f in findings if f.get("tool") == "semgrep")
    x = [
        _num(record.get(p_key), 0.5),
        _num(record.get(share_key), 0.5),
        _num(board.get("attacker_confidence"), 0.5),
        _num(board.get("defender_safety"), 0.5),
        1.0 if board.get("evidence_grounded") else 0.0,
        # Share of Judge votes whose quoted guard is in the code; 0 before v5.
        _num(board.get("guard_grounded_share"), 0.0),
        math.log1p(len(findings)),
        max(_SEVERITY.get(f.get("severity"), 0.0) for f in findings),
        1.0 if any((f.get("taint_paths") or 0) > 0 for f in findings) else 0.0,
        semgrep / len(findings),
    ]
    if kind == "full":
        n = record.get("n_candidates") or {}
        audit = record.get("auditor") or {}
        auditor = audit.get("candidates") or []
        x += [
            1.0 if n.get("sast") else 0.0,
            1.0 if n.get("taint") else 0.0,
            1.0 if n.get("auditor") else 0.0,
            max((_num(c.get("confidence"), 0.0) for c in auditor), default=0.0),
            # Records without an auditor verdict get the uninformative 0.5.
            _num(audit.get("p_vulnerable"), 0.5),
        ]
    return x


def metric(tp: int, fp: int, fn: int, tn: int, name: str = "") -> float:
    """f1, mcc (Matthews correlation) or balanced_accuracy from counts."""
    name = name or CALIBRATION_METRIC
    if name == "f1":
        return 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    if name == "balanced_accuracy":
        tpr = tp / (tp + fn) if tp + fn else 0.0
        tnr = tn / (tn + fp) if tn + fp else 0.0
        return (tpr + tnr) / 2
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / denom if denom else 0.0


def best_threshold(scores: list[float | None], labels: list[int]) -> float | None:
    """Threshold on the scores that maximises CALIBRATION_METRIC over every
    function in the split; ties keep the stricter threshold. A None score
    (nothing flagged) is always predicted safe."""
    candidates = sorted({s for s in scores if s is not None}, reverse=True)
    if not candidates:
        return None
    best, best_value = None, -math.inf
    for t in candidates:
        tp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and y == 1)
        fp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and y == 0)
        fn = sum(1 for s, y in zip(scores, labels) if (s is None or s < t) and y == 1)
        tn = sum(1 for s, y in zip(scores, labels) if (s is None or s < t) and y == 0)
        value = metric(tp, fp, fn, tn)
        if value > best_value + 1e-12:
            best, best_value = t, value
    return best


class Fusion:
    def __init__(self, mean, scale, coef, intercept, threshold, n_train, dev_cv_f1=None, kind="board",
                 dev_cv_mcc=None, calibration_metric=None):
        self.mean = np.asarray(mean, dtype=float)
        self.scale = np.asarray(scale, dtype=float)
        self.coef = np.asarray(coef, dtype=float)
        self.intercept = float(intercept)
        self.threshold = threshold
        self.n_train = n_train
        self.dev_cv_f1 = dev_cv_f1
        self.dev_cv_mcc = dev_cv_mcc
        self.calibration_metric = calibration_metric or CALIBRATION_METRIC
        self.kind = kind

    def score(self, record: dict) -> float | None:
        x = features(record, self.kind)
        if x is None:
            return None
        z = (np.asarray(x) - self.mean) / self.scale
        return float(1.0 / (1.0 + math.exp(-(float(z @ self.coef) + self.intercept))))

    def predict(self, record: dict) -> int:
        s = self.score(record)
        return int(s is not None and self.threshold is not None and s >= self.threshold)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "features": KINDS[self.kind],
            "mean": self.mean.tolist(),
            "scale": self.scale.tolist(),
            "coef": self.coef.tolist(),
            "intercept": self.intercept,
            "threshold": self.threshold,
            "n_train": self.n_train,
            "calibration_metric": self.calibration_metric,
            "dev_cv_f1": self.dev_cv_f1,
            "dev_cv_mcc": self.dev_cv_mcc,
        }


def train(dev_records: list[dict], kind: str = "board") -> tuple[Fusion | None, str]:
    """Fit on dev. Returns (model, note); model is None when dev is too small
    or has a single class among flagged functions."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    rows = [(features(r, kind), r["label"]) for r in dev_records]
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
    # the board's dismissals against the misses the candidates already have.
    it = iter(cv_scores.tolist())
    all_scores = [next(it) if x is not None else None for x, _ in rows]
    all_labels = [y for _, y in rows]
    threshold = best_threshold(all_scores, all_labels)

    model = pipeline().fit(X, y)
    scaler, lr = model[0], model[1]
    # StandardScaler gives constant features scale 1, so score() never divides by 0.
    fusion = Fusion(scaler.mean_, scaler.scale_, lr.coef_[0], lr.intercept_[0], threshold, len(flagged), kind=kind)
    tp = sum(1 for s, yy in zip(all_scores, all_labels) if s is not None and threshold is not None and s >= threshold and yy)
    fp = sum(1 for s, yy in zip(all_scores, all_labels) if s is not None and threshold is not None and s >= threshold and not yy)
    fn = sum(all_labels) - tp
    tn = len(all_labels) - tp - fp - fn
    fusion.dev_cv_f1 = round(metric(tp, fp, fn, tn, "f1"), 4)
    fusion.dev_cv_mcc = round(metric(tp, fp, fn, tn, "mcc"), 4)
    return fusion, (f"trained on {len(flagged)} flagged dev functions "
                    f"({folds}-fold CV threshold, max {CALIBRATION_METRIC})")


def load(data: dict | None) -> Fusion | None:
    if not data:
        return None
    kind = data.get("kind", "board")
    if data.get("features") != KINDS.get(kind):
        return None
    return Fusion(data["mean"], data["scale"], data["coef"], data["intercept"],
                  data["threshold"], data["n_train"], data.get("dev_cv_f1"), kind=kind,
                  dev_cv_mcc=data.get("dev_cv_mcc"), calibration_metric=data.get("calibration_metric", "f1"))
