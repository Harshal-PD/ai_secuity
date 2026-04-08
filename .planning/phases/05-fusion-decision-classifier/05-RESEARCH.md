# Phase 5 Research: Fusion / Decision Classifier

## RESEARCH COMPLETE

**Phase:** 5 — Fusion / Decision Classifier
**Goal:** Abstract multi-dimensional findings attributes (LLM, CPG, SAST) into bounded ML features. Train and execute a Scikit-Learn `GradientBoostingClassifier` determining ultimate true positive / false positive states transparently via `SHAP`.

---

## 1. Feature Engineering

The `Finding` dataclass houses complex dictionaries that aren't natively matrix-compatible.
Vectors mapped per finding:
- `static_confidence`: Integer maps from SAST severity ranges (e.g. LOW=0.2, HIGH=0.8)
- `llm_confidence`: Direct mappings from `finding.llm_analysis["confidence"]` bounding (0.0 to 1.0).
- `cpg_taint_depth`: Integers mapped via length of `finding.cpg_context["taint_paths"]` arrays (default `0`).
- `cwe_severity_score`: Mapped categorical float from specific rules or default `0.5`.

## 2. Model Pipeline

Given performance requirements, `scikit-learn` `GradientBoostingClassifier` is requested.
Training utilizes offline arrays (`Big-Vul` simulation for research). The system must securely dump `.pkl` weights executing inside celery. 
`joblib` provides optimal matrix de-serialization loading sub-second.

## 3. SHAP Abstraction

`shap.TreeExplainer(model)` provides local feature importance values mapping directly against specific model runs. 
Requirements explicitly constrain SHAP mappings purely for `"true_positive"` classified elements, avoiding massive performance degradations computing explainability matrices on obvious false positives.

We integrate:
- `numpy.array` ingestion bounding.
- SHAP dictionary extractions `{ "feature_name": severity_impact_float }`.

## 4. Concurrency Bounds

Scikit-Learn natively blocks Python's thread mechanisms (GIL) during inference strings. This usually happens rapidly (<0.01s). The classifier instance therefore should ideally be cached globally inside Celery routines to avoid disk I/O penalties unpacking `.pkl` archives on every file chunk payload natively. 

## Validation Strategy
1. **Mock Dimension Tests:** Verifying feature extraction pipelines return deterministic floats without NaN errors even on completely malformed JSON dumps.
2. **Predict Bounds:** Inject deterministic float lists verifying SHAP only triggers on predictions `>=0.5`.
