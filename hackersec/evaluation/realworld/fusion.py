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
    "defender_safety",
    "evidence_grounded",
    "static_strength",
]
# Expected direction of each feature on P(vulnerable): +1 increases risk, -1 decreases risk.
# Clamping inverted small-sample weights to 0 prevents noisy dev folds from flipping a safety signal.
_BASE_SIGNS = (+1, -1, -1, +1)
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
if CALIBRATION_METRIC not in ("mcc", "balanced_accuracy", "f1", "f0.5"):
    raise ValueError(f"REALWORLD_CALIBRATE_METRIC must be mcc, balanced_accuracy, f1 or f0.5, got {CALIBRATION_METRIC!r}")
FUSION_MIN_PRECISION = float(os.getenv("REALWORLD_FUSION_MIN_PRECISION", "0.72"))
# The calibrated Board threshold refines the Judge's own >= 0.5 majority vote
# upward for precision. It is never allowed below that vote: on v10's noisy dev
# split an unconstrained max-MCC search chose 0.2 and convicted functions the
# Judge had voted NOT_VULNERABLE.
BOARD_MIN_PRECISION = float(os.getenv("REALWORLD_BOARD_MIN_PRECISION", "0.60"))
BOARD_MIN_THRESHOLD = float(os.getenv("REALWORLD_BOARD_MIN_THRESHOLD", "0.50"))
# static_strength stand-in for a Board candidate that has no static finding.
SCREEN_STRENGTH_CAP = 0.25
_SEVERITY = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


def _num(value, default: float) -> float:
    try:
        return float(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def features(record: dict, kind: str = "board") -> list[float] | None:
    """Feature vector for a record whose `kind` debate ran, else None."""
    findings_key, board_key, p_key, _ = _KEYS[kind]
    findings = record.get(findings_key) or []
    board = record.get(board_key)
    # A Board verdict is what the model scores. Soft-LLM-Screen (Track 2)
    # candidates can have no static findings, and must not be dropped here.
    if not board:
        return None
    has_semgrep = bool(record.get("semgrep_pred")) or any(f.get("tool") == "semgrep" for f in findings)
    has_bandit = bool(record.get("bandit_pred")) or any(
        f.get("tool") == "bandit" or f.get("also_bandit") for f in findings
    )
    has_ast = bool(record.get("ast_pred")) or any(
        f.get("tool") == "ast_sink" or f.get("also_ast") for f in findings
    )
    has_codeql = bool(record.get("codeql_pred")) or any(
        f.get("tool") == "codeql" or f.get("also_codeql") for f in findings
    )
    tool_count = int(has_semgrep) + int(has_bandit) + int(has_ast) + int(has_codeql)
    multi_tool = 1.0 if tool_count >= 2 else 0.0
    if findings:
        max_sev = max(_SEVERITY.get(f.get("severity"), 0.0) for f in findings)
        static_strength = 0.5 * max_sev + 0.5 * multi_tool
    else:
        # No static lead: the screen's own score stands in, capped well below a
        # real finding so it cannot outrank one.
        static_strength = SCREEN_STRENGTH_CAP * _num(record.get("llm_context_p"), 0.5)
    x = [
        _num(record.get(p_key), 0.5),
        _num(board.get("defender_safety"), 0.5),
        1.0 if board.get("evidence_grounded") else 0.0,
        static_strength,
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
    """f1, f0.5, mcc (Matthews correlation) or balanced_accuracy from counts."""
    name = name or CALIBRATION_METRIC
    if name == "f1":
        return 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    if name == "f0.5":
        return 1.25 * tp / (1.25 * tp + 0.25 * fn + fp) if tp else 0.0
    if name == "balanced_accuracy":
        tpr = tp / (tp + fn) if tp + fn else 0.0
        tnr = tn / (tn + fp) if tn + fp else 0.0
        return (tpr + tnr) / 2
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / denom if denom else 0.0


def best_threshold(
    scores: list[float | None],
    labels: list[int],
    min_precision: float = 0.0,
    min_threshold: float = 0.0,
) -> float | None:
    """Threshold on the scores that maximises CALIBRATION_METRIC over every
    function in the split; ties keep the stricter threshold. When
    `min_precision > 0`, prefers thresholds achieving at least `min_precision`
    (with >= 10% recall on flagged positives) if any such threshold has
    positive discrimination. Candidates below `min_threshold` are never
    chosen; if no score reaches it, `min_threshold` itself is returned."""
    candidates = sorted({s for s in scores if s is not None}, reverse=True)
    if not candidates:
        return None
    if min_threshold > 0:
        candidates = [c for c in candidates if c >= min_threshold]
        if not candidates:
            return min_threshold
    flagged_pos = sum(1 for s, y in zip(scores, labels) if s is not None and y == 1)
    min_tp = max(3, int(0.15 * flagged_pos))
    best, best_value = None, -math.inf
    best_hp, best_hp_value = None, -math.inf
    for t in candidates:
        tp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and y == 1)
        fp = sum(1 for s, y in zip(scores, labels) if s is not None and s >= t and y == 0)
        fn = sum(1 for s, y in zip(scores, labels) if (s is None or s < t) and y == 1)
        tn = sum(1 for s, y in zip(scores, labels) if (s is None or s < t) and y == 0)
        value = metric(tp, fp, fn, tn)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        if value > best_value + 1e-12:
            best, best_value = t, value
        if min_precision > 0 and prec >= min_precision and tp >= min_tp and value > best_hp_value + 1e-12:
            best_hp, best_hp_value = t, value
    if best_hp is not None and best_hp_value >= 0.85 * best_value and best_hp_value > 0:
        return best_hp
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

    def pipeline(c_val: float):
        return make_pipeline(StandardScaler(), LogisticRegression(class_weight="balanced", C=c_val, max_iter=1000))

    folds = min(5, minority)
    cv = StratifiedKFold(folds, shuffle=True, random_state=0)
    all_labels = [y for _, y in rows]

    def eval_scores(flagged_scores: list[float]) -> tuple[float, float | None, list[float | None]]:
        it = iter(flagged_scores)
        full = [next(it) if x is not None else None for x, _ in rows]
        t = best_threshold(full, all_labels, min_precision=FUSION_MIN_PRECISION)
        if t is None:
            return -math.inf, None, full
        tp = sum(1 for s, yy in zip(full, all_labels) if s is not None and s >= t and yy)
        fp = sum(1 for s, yy in zip(full, all_labels) if s is not None and s >= t and not yy)
        fn = sum(all_labels) - tp
        tn = len(all_labels) - tp - fp - fn
        return metric(tp, fp, fn, tn), t, full

    best_c, best_val, threshold, all_scores = 0.15, -math.inf, None, []
    for c_val in (0.05, 0.15, 0.4, 1.0):
        cv_probs = cross_val_predict(pipeline(c_val), X, y, cv=cv, method="predict_proba")[:, 1].tolist()
        val, t, full = eval_scores(cv_probs)
        if val > best_val + 1e-12:
            best_c, best_val, threshold, all_scores = c_val, val, t, full

    model = pipeline(best_c).fit(X, y)
    scaler, lr = model[0], model[1]
    coef, intercept = lr.coef_[0].copy(), float(lr.intercept_[0])
    # Clamp any feature weight that flipped against its domain sign on a small dev fold.
    for idx, sign in enumerate(_BASE_SIGNS):
        if idx < len(coef) and coef[idx] * sign < 0:
            coef[idx] = 0.0
    # Re-tune the decision threshold on the sign-constrained logits so test
    # scores and the threshold are on the exact same scale.
    constrained_probs = [
        float(1.0 / (1.0 + math.exp(-(float(((np.asarray(x) - scaler.mean_) / scaler.scale_) @ coef) + intercept))))
        for x, _ in flagged
    ]
    c_val_score, c_t, c_full = eval_scores(constrained_probs)
    if c_t is not None:
        threshold, all_scores = c_t, c_full

    # Guard against small-sample overfitting: if out-of-fold CV on dev is
    # worse than raw p_vulnerable alone, fall back to the p_vulnerable axis.
    p_only_probs = [float(1.0 / (1.0 + math.exp(-((x[0] - scaler.mean_[0]) / scaler.scale_[0])))) for x, _ in flagged]
    p_val, p_t, p_full = eval_scores(p_only_probs)
    if p_val > best_val + 1e-12:
        coef = np.zeros_like(coef)
        coef[0] = 1.0
        intercept = 0.0
        threshold, all_scores = p_t, p_full

    # StandardScaler gives constant features scale 1, so score() never divides by 0.
    fusion = Fusion(scaler.mean_, scaler.scale_, coef, intercept, threshold, len(flagged), kind=kind)
    tp = sum(1 for s, yy in zip(all_scores, all_labels) if s is not None and threshold is not None and s >= threshold and yy)
    fp = sum(1 for s, yy in zip(all_scores, all_labels) if s is not None and threshold is not None and s >= threshold and not yy)
    fn = sum(all_labels) - tp
    tn = len(all_labels) - tp - fp - fn
    fusion.dev_cv_f1 = round(metric(tp, fp, fn, tn, "f1"), 4)
    fusion.dev_cv_mcc = round(metric(tp, fp, fn, tn, "mcc"), 4)
    return fusion, (f"trained on {len(flagged)} flagged dev functions "
                    f"({folds}-fold CV C={best_c}, max {CALIBRATION_METRIC})")


def load(data: dict | None) -> Fusion | None:
    if not data:
        return None
    kind = data.get("kind", "board")
    if data.get("features") != KINDS.get(kind):
        return None
    return Fusion(data["mean"], data["scale"], data["coef"], data["intercept"],
                  data["threshold"], data["n_train"], data.get("dev_cv_f1"), kind=kind,
                  dev_cv_mcc=data.get("dev_cv_mcc"), calibration_metric=data.get("calibration_metric", "f1"))
