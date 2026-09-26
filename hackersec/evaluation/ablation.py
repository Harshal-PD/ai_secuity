"""
Ablation harness.

Runs the real pipeline (Semgrep/Bandit -> Joern -> FAISS -> board -> fusion)
over a labeled set and reports each configuration separately, so the paper can
attribute any gain to a specific component rather than to the system as a whole.

Static analysis, CPG enrichment, and RAG retrieval happen ONCE per file. Every
variant then reasons over a copy of those identical findings with the disabled
evidence stripped. That makes the comparison paired: two variants can only
differ because of the factor under test, never because Semgrep or Joern behaved
differently between runs.
"""

import copy
import logging
from dataclasses import dataclass
from pathlib import Path

from hackersec.analysis.dedup import dedup_findings
from hackersec.analysis.enrich import enrich_with_cpg, enrich_with_rag
from hackersec.analysis.llm.board import AdversarialBoard
from hackersec.analysis.llm.client import OllamaClient
from hackersec.analysis.ml.inference import FusionClassifier
from hackersec.analysis.static import run_static_analysis

logger = logging.getLogger(__name__)

# A single-pass model reports P(real) but no verdict, so it needs a threshold.
# 0.5 is the neutral choice; the board is not given any such tuned advantage.
SINGLE_PASS_THRESHOLD = 0.5


@dataclass(frozen=True)
class Variant:
    name: str
    label: str          # column heading for the results table
    llm_mode: str       # none | single | board
    use_cpg: bool
    use_rag: bool
    use_fusion: bool
    evidence_rule: bool


# Ordered as they should appear in the paper: each row adds exactly one factor.
VARIANTS: dict[str, Variant] = {
    v.name: v
    for v in [
        Variant(
            name="sast_only",
            label="Semgrep + Bandit (baseline)",
            llm_mode="none",
            use_cpg=False,
            use_rag=False,
            use_fusion=False,
            evidence_rule=False,
        ),
        Variant(
            name="llm_single",
            label="+ single-pass LLM (CPG + RAG)",
            llm_mode="single",
            use_cpg=True,
            use_rag=True,
            use_fusion=False,
            evidence_rule=False,
        ),
        Variant(
            name="board_no_cpg",
            label="+ board, no CPG",
            llm_mode="board",
            use_cpg=False,
            use_rag=True,
            use_fusion=False,
            evidence_rule=True,
        ),
        Variant(
            name="board_no_rag",
            label="+ board, no RAG",
            llm_mode="board",
            use_cpg=True,
            use_rag=False,
            use_fusion=False,
            evidence_rule=True,
        ),
        Variant(
            name="board_no_rule",
            label="+ board (CPG + RAG), no evidence rule",
            llm_mode="board",
            use_cpg=True,
            use_rag=True,
            use_fusion=False,
            evidence_rule=False,
        ),
        Variant(
            name="board_full",
            label="+ board (CPG + RAG) + evidence rule",
            llm_mode="board",
            use_cpg=True,
            use_rag=True,
            use_fusion=False,
            evidence_rule=True,
        ),
        Variant(
            name="board_fusion",
            label="+ ML fusion",
            llm_mode="board",
            use_cpg=True,
            use_rag=True,
            use_fusion=True,
            evidence_rule=True,
        ),
    ]
}

DEFAULT_VARIANTS = list(VARIANTS.keys())


def _strip_evidence(findings: list, variant: Variant) -> list:
    """Copy the findings and remove whatever this variant is not allowed to see."""
    clone = copy.deepcopy(findings)
    for f in clone:
        if not variant.use_cpg:
            f.cpg_context = None
        if not variant.use_rag:
            f.rag_docs = []
        f.llm_analysis = None
        f.fusion_verdict = None
    return clone


def _finding_record(f, variant: Variant, meta: dict) -> dict:
    """Per-finding telemetry, used for agreement stats and paper examples."""
    analysis = f.llm_analysis or {}
    board = analysis.get("board") or {}
    attacker = board.get("attacker") or {}
    defender = board.get("defender") or {}
    judge = board.get("judge") or {}
    evidence = board.get("evidence_check") or {}

    return {
        "variant": variant.name,
        "file": f.file_path,
        "line": f.line_start,
        "rule_id": f.rule_id,
        "tool": f.tool,
        "severity": f.severity,
        "cwe_ids": f.cwe_ids,
        "true_label": meta.get("label"),
        "kind": meta.get("kind"),
        "expected_sanitizer": meta.get("expected_sanitizer"),
        "llm_status": analysis.get("llm_status"),
        "confidence": analysis.get("confidence"),
        "board_verdict": analysis.get("board_verdict"),
        "judge_verdict": judge.get("verdict"),
        "verdict_source": board.get("verdict_source"),
        "attacker_confidence": attacker.get("exploitability_confidence"),
        "defender_safety": defender.get("safety_confidence"),
        "defender_evidence": defender.get("sanitization_evidence"),
        "evidence_grounded": evidence.get("grounded"),
        "evidence_reason": evidence.get("reason"),
        "evidence_span": evidence.get("matched_span"),
        "fusion_verdict": f.fusion_verdict,
    }


def _predict_file(findings: list, variant: Variant, board, classifier) -> tuple:
    """
    Decide whether this file is vulnerable under one variant.

    Returns (prediction, llm_failures). A file counts as predicted-vulnerable if
    any surviving finding is judged real, which mirrors how the dashboard
    summarizes a scan.
    """
    if not findings:
        return 0, 0

    if variant.llm_mode == "none":
        return 1, 0

    llm_failures = 0
    for f in findings:
        f.llm_analysis = board.deliberate(f)
        if f.llm_analysis.get("llm_status") != "success":
            llm_failures += 1

    if variant.use_fusion:
        for f in findings:
            try:
                res = classifier.predict(f)
                f.fusion_verdict = res["prediction"]
            except Exception as e:  # classifier must never sink the sweep
                logger.warning(f"Fusion predict failed: {e}")
                f.fusion_verdict = "true_positive"
        predicted = any(f.fusion_verdict == "true_positive" for f in findings)
        return int(predicted), llm_failures

    if variant.llm_mode == "board":
        predicted = any(
            (f.llm_analysis or {}).get("board_verdict") == "TRUE_POSITIVE"
            for f in findings
        )
        return int(predicted), llm_failures

    # single pass: no verdict field, so threshold the reported confidence
    predicted = any(
        (f.llm_analysis or {}).get("llm_status") == "success"
        and ((f.llm_analysis or {}).get("confidence") or 0.0) >= SINGLE_PASS_THRESHOLD
        for f in findings
    )
    return int(predicted), llm_failures


def _aggregate_agreement(records: list) -> dict:
    """Collapse per-finding telemetry into the disagreement statistics."""
    board_records = [r for r in records if r.get("judge_verdict")]
    n = len(board_records)
    if n == 0:
        return {"n_findings": 0}

    def _rate(predicate) -> float:
        return round(sum(1 for r in board_records if predicate(r)) / n, 4)

    def _mean(key) -> float:
        vals = [r[key] for r in board_records if isinstance(r.get(key), (int, float))]
        return round(sum(vals) / len(vals), 4) if vals else 0.0

    return {
        "n_findings": n,
        # Both adversaries confident at once: the debate was genuinely contested.
        "contested_rate": _rate(
            lambda r: (r.get("attacker_confidence") or 0) >= 0.5
            and (r.get("defender_safety") or 0) >= 0.5
        ),
        "defender_conceded_rate": _rate(
            lambda r: r.get("evidence_reason") == "conceded"
        ),
        "evidence_grounded_rate": _rate(lambda r: r.get("evidence_grounded") is True),
        "evidence_rule_override_rate": _rate(
            lambda r: r.get("verdict_source") == "evidence_rule"
        ),
        "judge_false_positive_rate": _rate(
            lambda r: r.get("judge_verdict") == "FALSE_POSITIVE"
        ),
        "mean_attacker_confidence": _mean("attacker_confidence"),
        "mean_defender_safety": _mean("defender_safety"),
        "mean_final_confidence": _mean("confidence"),
    }


def run_ablation(
    data: dict,
    variant_names: list[str] | None = None,
    limit: int | None = None,
    models: dict | None = None,
) -> dict:
    """
    Execute the selected variants over a labeled dataset.

    `data` maps file path -> {"label": 0|1, "cwe": ..., "kind": ..., ...} as
    produced by `hackersec.evaluation.dataset.load_dataset`.
    """
    variant_names = variant_names or DEFAULT_VARIANTS
    unknown = [v for v in variant_names if v not in VARIANTS]
    if unknown:
        raise ValueError(
            f"Unknown variant(s): {', '.join(unknown)}. "
            f"Available: {', '.join(VARIANTS)}"
        )

    selected = [VARIANTS[n] for n in variant_names]
    needs_llm = any(v.llm_mode != "none" for v in selected)
    needs_cpg = any(v.use_cpg for v in selected)
    needs_rag = any(v.use_rag for v in selected)
    needs_fusion = any(v.use_fusion for v in selected)

    client = OllamaClient()
    if needs_llm and not client.ping():
        raise RuntimeError(
            f"Ollama unreachable at {client.base_url}. Refusing to run an LLM "
            "ablation that would silently degrade to the static baseline. "
            "Start Ollama, or select only --variants sast_only."
        )

    classifier = FusionClassifier() if needs_fusion else None
    if needs_fusion and classifier.model is None:
        logger.warning(
            "No fusion_model.joblib found — the board_fusion variant will mark "
            "every finding true_positive. Train it before reporting this row."
        )

    # One sentence-transformer load for the whole sweep.
    rag_store = None
    if needs_rag:
        try:
            from hackersec.analysis.rag import LocalRAGStore

            rag_store = LocalRAGStore()
            if rag_store.index.ntotal == 0:
                logger.warning(
                    "FAISS index is empty — RAG variants will receive no "
                    "context. Run: python -m hackersec.ingestion.seed_kb"
                )
        except Exception as e:
            logger.error(f"Could not load RAG store: {e}")

    items = list(data.items())
    if limit:
        items = items[:limit]

    results_by_variant = {v.name: [] for v in selected}
    records_by_variant = {v.name: [] for v in selected}
    stats = {
        "files": len(items),
        "static_findings": 0,
        "files_with_findings": 0,
        "llm_failures": 0,
        "cpg_status": None,
        "rag_status": None,
    }

    for idx, (filepath, meta) in enumerate(items, start=1):
        target = Path(filepath)
        job_id = f"eval_{idx}"
        logger.info(f"[{job_id}] {filepath} ({idx}/{len(items)})")

        base_findings = dedup_findings(run_static_analysis(target, job_id=job_id))
        stats["static_findings"] += len(base_findings)
        if base_findings:
            stats["files_with_findings"] += 1

        # Enrich once; every variant reasons over copies of this same evidence.
        if base_findings and needs_cpg:
            stats["cpg_status"] = enrich_with_cpg(base_findings, target, job_id=job_id)
        if base_findings and needs_rag:
            stats["rag_status"] = enrich_with_rag(
                base_findings, job_id=job_id, rag=rag_store
            )

        for variant in selected:
            findings = _strip_evidence(base_findings, variant)

            board = None
            if variant.llm_mode != "none":
                board = AdversarialBoard(
                    client=client,
                    mode="board" if variant.llm_mode == "board" else "single",
                    models=models,
                    use_evidence_rule=variant.evidence_rule,
                )

            prediction, failures = _predict_file(findings, variant, board, classifier)
            stats["llm_failures"] += failures

            results_by_variant[variant.name].append(
                {
                    "file": filepath,
                    "cwe": meta.get("cwe"),
                    "pair_id": meta.get("pair_id"),
                    "kind": meta.get("kind"),
                    "true_label": meta.get("label"),
                    "prediction": prediction,
                    "n_findings": len(findings),
                }
            )
            records_by_variant[variant.name].extend(
                _finding_record(f, variant, meta) for f in findings
            )

    agreement = {
        name: _aggregate_agreement(recs) for name, recs in records_by_variant.items()
    }

    return {
        "variants": {v.name: v.label for v in selected},
        "results_by_variant": results_by_variant,
        "agreement": agreement,
        "finding_records": records_by_variant,
        "dataset_stats": stats,
    }
