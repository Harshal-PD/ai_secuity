"""
Phase 1 step: cross-file callers and entry points of every sample.

Each fix commit's bare repo already holds the commit and its parent, with
blobs filtered out. Here the .py blobs of the pre-fix tree (vulnerable
samples) and of the fix tree (fixed samples) are fetched in one request per
tree and analysed with hackersec/analysis/llm/repo_context.py. Only the result
is kept, in cache/repo_context.jsonl, so the offline run phase never needs
the network or the files themselves.
"""

import logging
import os
import subprocess
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

from hackersec.analysis.llm import repo_context
from hackersec.evaluation.realworld import state
from hackersec.evaluation.realworld.functions import skip_reason
from hackersec.evaluation.realworld.gitfetch import _GIT_ENV, FETCH_TIMEOUT, GitFetcher, Unavailable
from hackersec.evaluation.realworld.net import NetworkDown, internet_up, with_network_retry

logger = logging.getLogger(__name__)

# Bump when what is extracted changes, so stale cache lines are recomputed.
VERSION = "repo-context-v1"
ENABLED = os.getenv("REALWORLD_REPO_CONTEXT", "1") not in ("0", "false", "False")
MAX_FILES = int(os.getenv("REALWORLD_REPO_MAX_FILES", "4000"))
MAX_FILE_BYTES = 400_000
WORKERS = max(1, int(os.getenv("REALWORLD_REPO_CONTEXT_WORKERS", "4")))
CACHE_PATH = state.CACHE_DIR / "repo_context.jsonl"
_VENDORED = {"vendor", "vendored", "third_party", "thirdparty", "site-packages", "node_modules", "_vendor"}

_cache: dict | None = None
_cache_lock = threading.Lock()


def _keep(path: str) -> bool:
    return skip_reason(path) is None and not any(p.lower() in _VENDORED for p in PurePosixPath(path).parts[:-1])


def _run(repo: Path, args: list[str], stdin: bytes | None, timeout: int) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", "-C", str(repo), *args], input=stdin, capture_output=True,
                              timeout=timeout, env={**_GIT_ENV, "GIT_NO_LAZY_FETCH": "1"})
    except subprocess.TimeoutExpired:
        if not internet_up():
            raise NetworkDown(f"git {args[0]} timed out with no internet")
        raise Unavailable(f"git {args[0]} timed out after {timeout}s")


def _tree(fetcher: GitFetcher, repo: Path, rev: str, near: list[str]) -> list[tuple[str, str]]:
    """(path, blob id) of the kept .py files at `rev`, nearest to `near` first
    when there are more than MAX_FILES."""
    proc = _run(repo, ["ls-tree", "-r", "-z", rev], None, 120)
    if proc.returncode != 0:
        fetcher._fail(f"ls-tree {rev[:12]}", proc)
    out = []
    for entry in proc.stdout.decode("utf-8", "replace").split("\0"):
        meta, _, path = entry.partition("\t")
        fields = meta.split()
        if len(fields) == 3 and fields[1] == "blob" and path.endswith(".py") and _keep(path):
            out.append((path, fields[2]))
    if len(out) > MAX_FILES:
        out.sort(key=lambda e: (-max(repo_context._shared_prefix(e[0], n) for n in near), e[0]))
        out = out[:MAX_FILES]
    return out


def _present(repo: Path) -> set[str]:
    proc = _run(repo, ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], None, 300)
    return set(proc.stdout.decode().split()) if proc.returncode == 0 else set()


def _files(fetcher: GitFetcher, repo: Path, rev: str, near: list[str]) -> dict[str, str]:
    entries = _tree(fetcher, repo, rev, near)
    if not entries:
        return {}
    have = _present(repo)
    missing = sorted({oid for _, oid in entries} - have)
    if missing:
        # The same request git sends to lazily fill a partial clone, for all
        # blobs at once instead of one round trip per file.
        proc = _run(repo, ["-c", "protocol.version=2", "-c", "fetch.negotiationAlgorithm=noop", "fetch", "origin",
                           "--no-tags", "--no-write-fetch-head", "--recurse-submodules=no", "--stdin"],
                    ("\n".join(missing) + "\n").encode(), FETCH_TIMEOUT * 2)
        if proc.returncode != 0:
            fetcher._fail(f"fetch {len(missing)} blobs at {rev[:12]}", proc)

    oids = [oid for _, oid in entries]
    proc = _run(repo, ["cat-file", "--batch"], ("\n".join(oids) + "\n").encode(), 600)
    data, i, blobs = proc.stdout, 0, {}
    for oid in oids:
        nl = data.find(b"\n", i)
        if nl < 0:
            break
        header = data[i:nl].split()
        i = nl + 1
        if len(header) < 3 or header[1] != b"blob":
            continue
        size = int(header[2])
        body = data[i:i + size]
        i += size + 1
        if size <= MAX_FILE_BYTES and b"\x00" not in body:
            blobs[oid] = body.decode("utf-8", "replace")
    return {path: blobs[oid] for path, oid in entries if oid in blobs}


def _analyse(sample: dict, files: dict[str, str] | None, status: str) -> dict:
    record = {"sample_id": sample["sample_id"], "version": VERSION, "status": status}
    if files is None:
        return record
    with open(sample["file"], "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()
    start, end = sample["line_start"], sample["line_end"]
    return {
        **record,
        "repo_files": len(files),
        **repo_context.find_callers(files, sample["path"], source, start, end),
        "entry_point": repo_context.entry_point(source, start, end, files),
    }


def _repo_job(fetcher: GitFetcher, repo_url: str, commits: dict[str, list[dict]], progress) -> None:
    # Every failure is recorded as a status, never raised: an exception here
    # would fail the build phase, which the entrypoint retries forever.
    for sha, samples in commits.items():
        try:
            repo = fetcher._repo(repo_url)
            with_network_retry(lambda: fetcher._ensure_commit(repo, sha), f"repo context {repo_url}@{sha[:10]}")
        except Exception as e:
            logger.info(f"repo context unavailable for {repo_url}@{sha[:10]}: {e}")
            for s in samples:
                state.append_jsonl(CACHE_PATH, _analyse(s, None, "unavailable"))
            progress(len(samples))
            continue
        for rev, kind in ((f"{sha}^", "vulnerable"), (sha, "fixed")):
            side = [s for s in samples if s["kind"] == kind]
            if not side:
                continue
            near = [s["path"] for s in side]
            try:
                files = with_network_retry(lambda: _files(fetcher, repo, rev, near),
                                           f"repo files {repo_url}@{rev[:12]}")
                status = "ok"
            except Exception as e:
                logger.info(f"repo files unavailable for {repo_url}@{rev[:12]}: {e}")
                files, status = None, "unavailable"
            for s in side:
                try:
                    record = _analyse(s, files, status)
                except Exception as e:
                    logger.warning(f"repo context failed for {s['sample_id']}: {e}")
                    record = _analyse(s, None, "error")
                state.append_jsonl(CACHE_PATH, record)
            progress(len(side))


def prepare(samples: list[dict] | None = None) -> dict:
    """Compute and cache repo context for every sample that lacks it."""
    if not ENABLED:
        return {"enabled": False}
    samples = samples if samples is not None else state.load_samples()
    done = {r["sample_id"] for r in state.read_jsonl(CACHE_PATH) if r.get("version") == VERSION}
    todo = [s for s in samples if s["sample_id"] not in done and s.get("repo_url") and s.get("sha")]
    if not todo:
        return {"enabled": True, "samples": len(samples), "computed": 0}

    by_repo: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for s in todo:
        by_repo[s["repo_url"]][s["sha"]].append(s)
    logger.info(f"Repo context: {len(todo)} samples from {len(by_repo)} repositories ({WORKERS} workers)")

    lock, counter = threading.Lock(), {"done": 0}

    def progress(n: int) -> None:
        with lock:
            counter["done"] += n
            state.update_status(phase="repo_context", detail=f"{counter['done']}/{len(todo)} samples")

    fetcher = GitFetcher()
    state.update_status(phase="repo_context", detail=f"0/{len(todo)} samples")
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for fut in [pool.submit(_repo_job, fetcher, url, commits, progress) for url, commits in by_repo.items()]:
            fut.result()

    records = [r for r in state.read_jsonl(CACHE_PATH) if r.get("version") == VERSION]
    summary = {
        "enabled": True,
        "samples": len(samples),
        "computed": len(todo),
        "ok": sum(r.get("status") == "ok" for r in records),
        "with_callers": sum((r.get("call_sites") or 0) > 0 for r in records),
        "entry_points": sum(bool(r.get("entry_point")) for r in records),
    }
    logger.info(f"Repo context done: {summary}")
    return summary


def lookup(sample_id: str) -> dict | None:
    global _cache
    with _cache_lock:
        if _cache is None:
            _cache = {r["sample_id"]: r for r in state.read_jsonl(CACHE_PATH) if r.get("version") == VERSION}
    return _cache.get(sample_id)
