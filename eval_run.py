"""
Ablation runner.

    python eval_run.py                                  # every variant, local paired set
    python eval_run.py --variants sast_only,board_full  # subset
    python eval_run.py --limit 6                        # smoke run
    python eval_run.py --judge-model deepseek-coder-v2:16b
    python eval_run.py --dataset data/eval_set/metadata.json --no-regenerate
    python eval_run.py --list

Each variant adds exactly one factor, so a difference between two rows is
attributable to that factor. Results land in eval_results/ as JSON with the
git commit, model tags, temperatures, and thresholds attached.
"""

import argparse
import json
import logging
import sys


def main() -> int:
    from hackersec.evaluation.ablation import DEFAULT_VARIANTS, VARIANTS, run_ablation
    from hackersec.evaluation.dataset import generate_test_suite, load_dataset
    from hackersec.evaluation.metrics import build_report, export_results

    parser = argparse.ArgumentParser(description="HackerSec ablation evaluation")
    parser.add_argument(
        "--variants",
        default=",".join(DEFAULT_VARIANTS),
        help="comma-separated variant names (see --list)",
    )
    parser.add_argument("--limit", type=int, default=None, help="only N files")
    parser.add_argument("--dataset", default=None, help="path to a metadata.json")
    parser.add_argument(
        "--no-regenerate",
        action="store_true",
        help="use the dataset on disk instead of rewriting it",
    )
    parser.add_argument("--attacker-model", default=None)
    parser.add_argument("--defender-model", default=None)
    parser.add_argument(
        "--judge-model",
        default=None,
        help="use a different family for the judge to remove correlated bias",
    )
    parser.add_argument("--out-dir", default="eval_results")
    parser.add_argument("--list", action="store_true", help="list variants and exit")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.list:
        print("Available variants:\n")
        for name, v in VARIANTS.items():
            print(f"  {name:<16} {v.label}")
            print(
                f"  {'':<16} llm={v.llm_mode} cpg={v.use_cpg} rag={v.use_rag} "
                f"fusion={v.use_fusion} evidence_rule={v.evidence_rule}"
            )
        return 0

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    logger = logging.getLogger("evaluator")

    if args.dataset:
        meta_path = args.dataset
    elif args.no_regenerate:
        meta_path = "data/eval_set/metadata.json"
    else:
        logger.info("Writing the paired labeled evaluation set...")
        meta_path = generate_test_suite()

    data = load_dataset(meta_path)
    variant_names = [v.strip() for v in args.variants.split(",") if v.strip()]

    models = {}
    if args.attacker_model:
        models["attacker"] = args.attacker_model
    if args.defender_model:
        models["defender"] = args.defender_model
    if args.judge_model:
        models["judge"] = args.judge_model

    n_files = args.limit or len(data)
    logger.info(
        f"Running {len(variant_names)} variant(s) over {n_files} file(s): "
        f"{', '.join(variant_names)}"
    )

    try:
        ablation = run_ablation(
            data,
            variant_names=variant_names,
            limit=args.limit,
            models=models or None,
        )
    except (RuntimeError, ValueError) as e:
        print(f"\nAblation aborted: {e}\n", file=sys.stderr)
        return 1

    report = build_report(
        ablation,
        provenance_extra={
            "dataset": meta_path,
            "variants_requested": variant_names,
            "model_overrides": models,
        },
    )
    out_file = export_results(report, out_dir=args.out_dir)

    stats = report["dataset_stats"]
    print("\n" + "=" * 68)
    print("ABLATION RESULTS")
    print("=" * 68)
    print(
        f"files={stats['files']}  with_findings={stats['files_with_findings']}  "
        f"static_findings={stats['static_findings']}  "
        f"llm_failures={stats['llm_failures']}"
    )
    print(f"cpg={stats['cpg_status']}  rag={stats['rag_status']}")
    print()
    print(report["markdown_table"])

    print("\nBoard agreement:")
    for name, agg in report["agreement"].items():
        if not agg.get("n_findings"):
            continue
        print(
            f"  {name:<16} contested={agg['contested_rate']:.2f} "
            f"grounded={agg['evidence_grounded_rate']:.2f} "
            f"rule_overrides={agg['evidence_rule_override_rate']:.2f} "
            f"judge_FP={agg['judge_false_positive_rate']:.2f}"
        )

    if stats["llm_failures"]:
        print(
            f"\nWARNING: {stats['llm_failures']} LLM call(s) failed. "
            "Treat these numbers as provisional."
        )

    print(f"\nFull report: {out_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
