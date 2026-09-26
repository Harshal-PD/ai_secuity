"""
    python -m hackersec.evaluation.realworld build    # phase 1: needs internet
    python -m hackersec.evaluation.realworld run      # phase 2: offline pipeline
    python -m hackersec.evaluation.realworld report   # any time, even mid-run
    python -m hackersec.evaluation.realworld status
"""

import argparse
import json
import logging
import sys

from hackersec.evaluation.realworld import state


def _logging() -> None:
    state.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in (logging.StreamHandler(sys.stdout), logging.FileHandler(state.LOG_PATH, encoding="utf-8")):
        handler.setFormatter(fmt)
        root.addHandler(handler)
    for noisy in ("httpx", "urllib3", "huggingface_hub", "sentence_transformers", "filelock", "fsspec"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def _status() -> int:
    status = state.read_json(state.STATUS_PATH, {}) or {}
    samples = state.load_samples()
    results = state.load_results()
    counts = {}
    for r in results.values():
        counts[r.get("status")] = counts.get(r.get("status"), 0) + 1

    print(f"phase         : {status.get('phase', 'not started')}  ({status.get('detail') or '-'})")
    print(f"last update   : {status.get('updated_at', '-')}")
    if status.get("waiting_for"):
        print(f"WAITING FOR   : {status['waiting_for']} — {status.get('waiting_context') or ''} "
              f"({status.get('waited_seconds', 0)}s)")
    build = state.read_json(state.BUILD_PROGRESS_PATH, {}) or {}
    for name, dp in build.items():
        print(f"dataset       : {name:<9} {dp.get('pairs', 0)}/{dp.get('target', '?')} pairs "
              f"from {len(dp.get('done', []))}/{dp.get('commits_total', '?')} commits tried"
              f"{'  (exhausted)' if dp.get('exhausted') else ''}")
    print(f"samples       : {len(samples)} functions")
    done = sum(counts.values())
    pct = f"{100 * done / len(samples):.1f}%" if samples else "-"
    print(f"evaluated     : {done}/{len(samples)} ({pct})  " + "  ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    if status.get("eta_hours") is not None:
        print(f"speed / ETA   : {status.get('sec_per_sample')} s per sample, ~{status['eta_hours']} h remaining")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m hackersec.evaluation.realworld")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="download datasets + offline assets (needs internet)")
    b.add_argument("--datasets", default="cvefixes,vudenc")
    b.add_argument("--target-cvefixes", type=int, default=None, help="function pairs (default 500)")
    b.add_argument("--target-vudenc", type=int, default=None, help="function pairs (default 250)")

    r = sub.add_parser("run", help="evaluate every sample with the full pipeline (offline)")
    r.add_argument("--retry-failed", action="store_true", help="re-run samples that failed")
    r.add_argument("--limit", type=int, default=None, help="only the first N pairs (smoke test)")

    sub.add_parser("report", help="write report_latest.{json,md} from the checkpoints")
    sub.add_parser("status", help="print progress")
    args = parser.parse_args()

    if args.cmd == "status":
        return _status()

    _logging()
    if args.cmd == "build":
        from hackersec.evaluation.realworld.build import build_all

        targets = {}
        if args.target_cvefixes is not None:
            targets["cvefixes"] = args.target_cvefixes
        if args.target_vudenc is not None:
            targets["vudenc"] = args.target_vudenc
        build_all([d.strip() for d in args.datasets.split(",") if d.strip()], targets)
    elif args.cmd == "run":
        from hackersec.evaluation.realworld.runner import run_evaluation

        run_evaluation(retry_failed=args.retry_failed, limit=args.limit)
    elif args.cmd == "report":
        from hackersec.evaluation.realworld.report import build_report

        report = build_report()
        print(report["markdown"])
        print(f"\nWritten: {state.RESULTS_DIR / 'report_latest.json'}")
        print(json.dumps(report["coverage"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
