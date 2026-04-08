if __name__ == "__main__":
    from hackersec.evaluation.dataset import generate_test_suite, load_dataset
    from hackersec.evaluation.runner import evaluate_pipeline
    from hackersec.evaluation.metrics import calculate_metrics, export_results
    import logging

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("evaluator")

    logger.info("Generating localized test variables simulating Juliet loops...")
    meta_path = generate_test_suite()
    data = load_dataset(meta_path)
    
    logger.info(f"Running hackersec pipeline evaluation bounds on {len(data)} test scripts...")
    results = evaluate_pipeline(meta_path, data)
    
    logger.info("Computing validation matrices limiting null anomalies...")
    metrics = calculate_metrics(results)
    
    out_file = export_results(metrics)
    
    logger.info(f"Evaluation bounds fully extracted. Reporting Matrix exported locally: {out_file}")
    print(f"\n--- RESULTS ---\nBaseline F1: {metrics['baseline_metrics']['f1']:.2f}")
    print(f"HackerSec F1: {metrics['hackersec_metrics']['f1']:.2f}\n")
