import logging
from pathlib import Path

from hackersec.analysis.static import run_static_analysis
from hackersec.analysis.dedup import dedup_findings
from hackersec.analysis.pipeline import analyze_findings

logger = logging.getLogger(__name__)


def evaluate_pipeline(
    meta_path: str,
    data: dict,
    *,
    enable_cpg: bool = True,
    enable_llm: bool = True,
    enable_verify: bool = False,
    limit: int | None = 50,
) -> list:
    """Run the REAL pipeline over labeled targets and collect predictions.

    For each target file this runs the same chain as the worker
    (static → dedup → CPG → RAG → LLM → fusion [→ verify]) — no mocks.

    Three predictions per file:
      - baseline_pred:  1 if Semgrep/Bandit produced any finding (SAST-only).
      - hackersec_pred: 1 if fusion labels any finding `true_positive`.
      - verified_pred:  1 if any finding was reproduced in the sandbox
                        (only meaningful when enable_verify=True).
    """
    eval_results = []
    items = list(data.items())
    if limit is not None:
        items = items[:limit]

    for filepath, meta in items:
        logger.info(f"[eval] Analyzing {filepath}")
        findings = dedup_findings(run_static_analysis(Path(filepath), job_id="eval"))

        baseline_pred = 1 if findings else 0

        analyze_findings(
            findings, filepath, job_id="eval",
            enable_cpg=enable_cpg, enable_llm=enable_llm, enable_verify=enable_verify,
        )

        hackersec_pred = 1 if any(f.fusion_verdict == "true_positive" for f in findings) else 0
        verified_pred = 1 if any(getattr(f, "reproduced", None) is True for f in findings) else 0

        eval_results.append({
            "file": filepath,
            "cwe": meta["cwe"],
            "true_label": meta["label"],
            "baseline_pred": baseline_pred,
            "hackersec_pred": hackersec_pred,
            "verified_pred": verified_pred,
        })

    return eval_results
