"""
One-time backfill of companion files for a dataset that is already built.

For every (repo, commit, file) in samples.jsonl it stores the local files the
target imports, and the files that call it (from the repo-context cache), next
to the existing target files:

    files/<dataset>/<slug>/<sha12>/{before,after}/<repo-relative path>

Target files, line ranges and pair ids are never touched, so existing results
stay valid. Progress is saved after every commit file (backfill_progress.json),
the run pauses when the disk is nearly full, and a lost internet connection is
waited out and retried (net.with_network_retry).

    python -m hackersec.evaluation.realworld.backfill_companions [--limit N] [--dry-run]
"""

from __future__ import annotations

import argparse
import logging
import os
import shutil
import time

from hackersec.evaluation.realworld import gitfetch, state
from hackersec.evaluation.realworld.gitfetch import GitFetcher, Unavailable, version_root_of
from hackersec.evaluation.realworld.net import with_network_retry

logger = logging.getLogger(__name__)

MIN_FREE_GB = float(os.getenv("REALWORLD_MIN_FREE_GB", "5"))
PROGRESS_PATH = state.ROOT / "backfill_progress.json"


def _wait_for_disk(path, min_gb: float = MIN_FREE_GB) -> None:
    while shutil.disk_usage(path).free / 1024**3 < min_gb:
        logger.warning(f"Less than {min_gb:.0f} GB free; pausing 60s")
        state.update_status(waiting_for="disk_space")
        time.sleep(60)


def _caller_paths(sample_id: str) -> list[str]:
    from hackersec.evaluation.realworld import repo_snapshot

    rec = repo_snapshot.lookup(sample_id) or {}
    return sorted({s["path"] for s in rec.get("sites") or [] if s.get("path")})


def collect_tasks(samples: list[dict]) -> dict[str, dict]:
    """One task per (dataset, repo, commit, path), holding both version roots."""
    tasks: dict[str, dict] = {}
    for s in samples:
        root = version_root_of(s["file"])
        if root is None or not s.get("repo_url") or not s.get("sha"):
            continue
        key = f"{s['dataset']}:{s['repo_url']}@{s['sha']}:{s['path']}"
        task = tasks.setdefault(key, {
            "key": key, "repo_url": s["repo_url"], "sha": s["sha"], "path": s["path"],
            "before": None, "after": None, "callers": set(),
        })
        task["before" if s["kind"] == "vulnerable" else "after"] = root
        task["callers"].update(_caller_paths(s["sample_id"]))
    return tasks


def _store(root, files: dict[str, str]) -> int:
    written = 0
    for rel, text in files.items():
        dest = root / rel
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
            written += 1
    return written


def run_backfill(limit: int | None = None, dry_run: bool = False) -> dict:
    state.ensure_dirs()
    samples = state.load_samples()
    if not samples:
        raise RuntimeError(f"No samples in {state.SAMPLES_PATH}. Run the build phase first.")

    done = set((state.read_json(PROGRESS_PATH, {}) or {}).get("done", []))
    tasks = collect_tasks(samples)
    pending = sorted((t for k, t in tasks.items() if k not in done), key=lambda t: (t["repo_url"], t["sha"]))
    if limit is not None:
        pending = pending[:limit]
    logger.info(f"{len(tasks)} commit files: {len(tasks) - len(pending)} done, {len(pending)} to backfill")
    if dry_run:
        return {"tasks": len(tasks), "pending": len(pending), "written": 0}

    fetcher, written, skipped = GitFetcher(), 0, 0
    for i, task in enumerate(pending, start=1):
        _wait_for_disk(state.FILES_DIR)
        before_root, after_root = task["before"], task["after"]
        if before_root is None or after_root is None:
            skipped += 1
            continue
        try:
            before_src = (before_root / task["path"]).read_text(encoding="utf-8", errors="replace")
            after_src = (after_root / task["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.warning(f"[{i}/{len(pending)}] target file missing on disk: {task['key']}")
            skipped += 1
            continue
        try:
            before_comp, after_comp = with_network_retry(
                lambda t=task, b=before_src, a=after_src: fetcher.companion_files(
                    t["repo_url"], t["sha"], t["path"], b, a, sorted(t["callers"])
                ),
                task["key"],
            )
        except Unavailable as e:
            logger.info(f"[{i}/{len(pending)}] unavailable: {task['key']}: {e}")
            skipped += 1
        else:
            n = _store(before_root, before_comp) + _store(after_root, after_comp)
            written += n
            logger.info(f"[{i}/{len(pending)}] {task['path']} @ {task['sha'][:10]}: +{n} files (total {written})")
        done.add(task["key"])
        state.write_json_atomic(PROGRESS_PATH, {"done": sorted(done)})
        state.update_status(phase="backfill_companions", detail=f"{i}/{len(pending)} commit files")

    return {"tasks": len(tasks), "pending": len(pending), "written": written, "skipped": skipped}


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill companion .py files for an already-built dataset.")
    parser.add_argument("--limit", type=int, default=None, help="only the first N pending commit files")
    parser.add_argument("--dry-run", action="store_true", help="count the work, write nothing")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if gitfetch.MAX_COMPANIONS <= 0:
        raise SystemExit("REALWORLD_COMPANION_FILES=0 disables companion files; nothing to do.")
    print(run_backfill(limit=args.limit, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
