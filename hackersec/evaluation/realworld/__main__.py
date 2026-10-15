"""
    python -m hackersec.evaluation.realworld build    # phase 1: needs internet
    python -m hackersec.evaluation.realworld run      # phase 2: offline pipeline
    python -m hackersec.evaluation.realworld report   # any time, even mid-run
    python -m hackersec.evaluation.realworld status
    python -m hackersec.evaluation.realworld check    # is Ollama on GPU and Joern up?
"""

import argparse
import json
import logging
import os
import sys
import time

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
    if status.get("pipeline"):
        print(f"pipeline      : {status['pipeline']}, {status.get('workers', 1)} workers")
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
    if status.get("llm_tokens_per_sec") is not None:
        gpu = status.get("llm_gpu_fraction")
        print(f"LLM health    : {status['llm_tokens_per_sec']} tokens/s, "
              f"{'?' if gpu is None else f'{100 * gpu:.0f}%'} of the model on GPU")
    if status.get("sast_prescan"):
        print(f"SAST prescan  : {status['sast_prescan']}")
    splits = {}
    for r in results.values():
        if r.get("split"):
            splits[r["split"]] = splits.get(r["split"], 0) + 1
    if splits:
        print("by split      : " + "  ".join(f"{k}={v}" for k, v in sorted(splits.items())))
    return 0


def _check(wait: int) -> int:
    """Exit 0 only if every board model generates on GPU at a usable speed on
    every Ollama server, and every Joern server answers queries. Retries for
    up to `wait` seconds."""
    from concurrent.futures import ThreadPoolExecutor

    from hackersec.analysis.joern.client import JoernClient
    from hackersec.analysis.llm.client import MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE, OllamaClient
    from hackersec.evaluation.realworld.runner import (
        BASELINES, MIN_TOKENS_PER_SEC, REQUIRE_GPU, USE_CPG, WORKERS, joern_urls, ollama_urls,
    )

    models = sorted({MODEL_ATTACKER, MODEL_DEFENDER, MODEL_JUDGE})
    clients = [OllamaClient(u) for u in ollama_urls()]
    joerns = [JoernClient(u) for u in joern_urls()] if USE_CPG else []
    print(f"{WORKERS} workers over {len(clients)} Ollama and {len(joerns)} Joern server(s); "
          f"baselines {', '.join(sorted(BASELINES)) or 'off'}")

    def ollama_health(client):
        return client, [(m, client.health(m, min_tokens_per_sec=MIN_TOKENS_PER_SEC, require_gpu=REQUIRE_GPU))
                        for m in models]

    deadline = time.time() + wait
    while True:
        problems = []
        with ThreadPoolExecutor(max_workers=len(clients)) as pool:
            checked = list(pool.map(ollama_health, clients))
        for client, results in checked:
            for model, h in results:
                gpu = "?" if h["gpu_fraction"] is None else f"{100 * h['gpu_fraction']:.0f}%"
                print(f"ollama {client.base_url} {model}: {'OK' if h['ok'] else 'NOT OK'}  "
                      f"tokens/s={h['tokens_per_sec']}  on GPU={gpu}"
                      f"{'  (' + h['reason'] + ')' if h['reason'] else ''}")
                if not h["ok"]:
                    problems.append(f"{client.base_url} {model}: {h['reason']}")
        for joern in joerns:
            joern_ok = joern.ready()
            print(f"joern {joern.base_url}: {'OK' if joern_ok else 'NOT READY'}")
            if not joern_ok:
                problems.append(f"joern {joern.base_url} not ready")
        if not problems:
            return 0
        if time.time() >= deadline:
            print("CHECK FAILED: " + "; ".join(problems))
            return 1
        print(f"retrying in 20s (up to {int(deadline - time.time())}s more)")
        time.sleep(20)


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m hackersec.evaluation.realworld")
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="download datasets + offline assets (needs internet)")
    b.add_argument("--datasets", default=os.getenv("REALWORLD_DATASETS", "cvefixes,vudenc,reposvul"),
                   help="comma-separated: cvefixes, vudenc, reposvul")
    b.add_argument("--target-cvefixes", type=int, default=None, help="function pairs (default 500)")
    b.add_argument("--target-vudenc", type=int, default=None, help="function pairs (default 250)")
    b.add_argument("--target-reposvul", type=int, default=None, help="function pairs (default 1000)")

    r = sub.add_parser("run", help="evaluate every sample with the full pipeline (offline)")
    r.add_argument("--retry-failed", action="store_true", help="re-run samples that failed")
    r.add_argument("--limit", type=int, default=None, help="only the first N pairs (smoke test)")

    sub.add_parser("report", help="write report_latest.{json,md} from the checkpoints")
    sub.add_parser("status", help="print progress")
    c = sub.add_parser("check", help="verify Ollama runs on GPU at a usable speed and Joern is up")
    c.add_argument("--wait", type=int, default=0, help="keep retrying for this many seconds")
    args = parser.parse_args()

    if args.cmd == "status":
        return _status()
    if args.cmd == "check":
        return _check(args.wait)

    _logging()
    if args.cmd == "build":
        from hackersec.evaluation.realworld.build import build_all

        targets = {}
        if args.target_cvefixes is not None:
            targets["cvefixes"] = args.target_cvefixes
        if args.target_vudenc is not None:
            targets["vudenc"] = args.target_vudenc
        if args.target_reposvul is not None:
            targets["reposvul"] = args.target_reposvul
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
