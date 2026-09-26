"""
Paths, crash-safe JSONL checkpoints, and the status file.

Everything the long-running evaluation writes goes through here, so a crash,
`docker stop`, or reboot at any moment loses at most the sample in flight.
"""

import json
import logging
import os
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Dataset files must sit under /app/workspace: Joern imports code by path and
# only that volume is shared between the eval and joern containers.
ROOT = Path(os.getenv("REALWORLD_DIR", "workspace/realworld"))
RESULTS_DIR = Path(os.getenv("REALWORLD_RESULTS_DIR", "eval_results/realworld"))

CACHE_DIR = ROOT / "cache"
REPOS_DIR = ROOT / "repos"
FILES_DIR = ROOT / "files"
RULES_DIR = ROOT / "semgrep_rules"
SAMPLES_PATH = ROOT / "samples.jsonl"
BUILD_PROGRESS_PATH = ROOT / "build_progress.json"

RESULTS_PATH = RESULTS_DIR / "results.jsonl"
STATUS_PATH = RESULTS_DIR / "status.json"
LOG_PATH = RESULTS_DIR / "eval.log"


def ensure_dirs() -> None:
    for d in (CACHE_DIR, REPOS_DIR, FILES_DIR, RULES_DIR, RESULTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def append_jsonl(path: Path, record: dict) -> None:
    """Append one record and force it to disk before returning."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_jsonl(path: Path) -> list[dict]:
    """Read records, skipping a torn final line left by a hard kill."""
    if not path.exists():
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for n, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                logger.warning(f"Skipping unreadable line {n} in {path.name}")
    return out


def write_json_atomic(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def read_json(path: Path, default=None):
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return default


def update_status(**fields) -> None:
    status = read_json(STATUS_PATH, {}) or {}
    status.update(fields)
    status["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    write_json_atomic(STATUS_PATH, status)


def load_samples() -> list[dict]:
    """Samples in build order, de-duplicated (a crash can re-append a commit)."""
    seen = {}
    for s in read_jsonl(SAMPLES_PATH):
        seen.setdefault(s["sample_id"], s)
    return list(seen.values())


def load_results() -> dict[str, dict]:
    """Latest result per sample_id — a retried sample overrides its failure."""
    out = {}
    for r in read_jsonl(RESULTS_PATH):
        out[r["sample_id"]] = r
    return out
