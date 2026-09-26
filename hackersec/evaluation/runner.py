import logging

from hackersec.evaluation.ablation import run_ablation

logger = logging.getLogger(__name__)


def evaluate_pipeline(meta_path: str, data: dict, limit: int | None = None) -> list:
    """
    Legacy two-way comparison: static baseline vs the full pipeline.

    Previously this mocked the CPG and LLM steps and scored the mock, which made
    the result meaningless. It now delegates to the real ablation harness and
    reshapes two of its variants into the original row format.

    Prefer `run_ablation` directly — it reports every configuration.
    """
    ablation = run_ablation(
        data, variant_names=["sast_only", "board_fusion"], limit=limit
    )

    baseline = ablation["results_by_variant"]["sast_only"]
    full = {r["file"]: r for r in ablation["results_by_variant"]["board_fusion"]}

    return [
        {
            "file": row["file"],
            "cwe": row["cwe"],
            "true_label": row["true_label"],
            "baseline_pred": row["prediction"],
            "hackersec_pred": full.get(row["file"], {}).get("prediction", 0),
        }
        for row in baseline
    ]
