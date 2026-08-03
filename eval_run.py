import argparse
import logging

from hackersec.evaluation.dataset import generate_test_suite, load_dataset
from hackersec.evaluation.runner import evaluate_pipeline
from hackersec.evaluation.metrics import calculate_metrics, export_results


def main():
    parser = argparse.ArgumentParser(description="Run the HackerSec evaluation harness against a labeled dataset.")
    parser.add_argument("--dataset", default="mock",
                        choices=["mock", "bigvul", "diversevul", "juliet"],
                        help="mock = 3 offline files; others pull from HuggingFace.")
    parser.add_argument("--samples", type=int, default=100, help="Samples to pull from HF datasets.")
    parser.add_argument("--limit", type=int, default=50, help="Max files actually analyzed (bounds runtime).")
    parser.add_argument("--no-cpg", action="store_true", help="Skip Joern CPG stage.")
    parser.add_argument("--no-llm", action="store_true", help="Skip Ollama LLM + patch stages (fast).")
    parser.add_argument("--verify", action="store_true", help="Run the dynamic exploit-verification sandbox.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("evaluator")

    source = "mock" if args.dataset == "mock" else args.dataset
    logger.info(f"Building test suite (dataset={args.dataset}, samples={args.samples})...")
    meta_path = generate_test_suite(source=source, samples=args.samples)
    data = load_dataset(meta_path)

    logger.info(f"Running REAL pipeline on {len(data)} targets (limit={args.limit})...")
    results = evaluate_pipeline(
        meta_path, data,
        enable_cpg=not args.no_cpg,
        enable_llm=not args.no_llm,
        enable_verify=args.verify,
        limit=args.limit,
    )

    metrics = calculate_metrics(results)
    out_file = export_results(metrics)

    logger.info(f"Results exported: {out_file}")
    b, h = metrics["baseline_metrics"], metrics["hackersec_metrics"]
    print("\n--- RESULTS ---")
    print(f"Baseline (SAST)  P={b['precision']:.2f} R={b['recall']:.2f} F1={b['f1']:.2f} FPR={b['fpr']:.2f}")
    print(f"HackerSec        P={h['precision']:.2f} R={h['recall']:.2f} F1={h['f1']:.2f} FPR={h['fpr']:.2f}")
    if "hackersec_verified_metrics" in metrics:
        v = metrics["hackersec_verified_metrics"]
        print(f"HackerSec+Verify P={v['precision']:.2f} R={v['recall']:.2f} F1={v['f1']:.2f} FPR={v['fpr']:.2f}")
    print()


if __name__ == "__main__":
    main()
