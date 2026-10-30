"""
Semgrep + Bandit results, computed in batches and cached on disk.

Semgrep parses the whole rule set on every start-up, which cost ~80 s per file
in the first run. Scanning files in batches parses the rules once per batch,
and the cache (keyed by file content, path and the exact rule set) lets later
runs and restarts reuse the scans. Each tool's status is stored per file, so a
Semgrep failure is visible in the report instead of looking like "no findings".
"""

import hashlib
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from functools import lru_cache
from pathlib import Path

from hackersec.analysis.dedup import dedup_findings
from hackersec.analysis.schema import Finding
from hackersec.evaluation.realworld import gitfetch, state

logger = logging.getLogger(__name__)

SAST_DIR = state.CACHE_DIR / "sast"
BATCH_SIZE = int(os.getenv("REALWORLD_SAST_BATCH", "25"))
# Version-root CodeQL databases built at the same time in tree mode.
CODEQL_WORKERS = int(os.getenv("REALWORLD_CODEQL_WORKERS", "2"))
TOOLS = ("semgrep", "bandit", "ast_sink", "codeql")


@lru_cache(maxsize=1)
def _signature() -> str:
    from hackersec.analysis.static import rules_signature

    return rules_signature()


def _key(file: str, signature: str) -> str:
    h = hashlib.sha1(Path(file).read_bytes())
    h.update(file.encode())
    h.update(signature.encode())
    return h.hexdigest()


def _entry_path(file: str, signature: str) -> Path:
    key = _key(file, signature)
    return SAST_DIR / key[:2] / f"{key}.json"


def _load(file: str, signature: str) -> dict | None:
    path = _entry_path(file, signature)
    entry = state.read_json(path)
    return entry if entry and all(t in entry for t in TOOLS) else None


def _save(file: str, signature: str, entry: dict) -> None:
    state.write_json_atomic(_entry_path(file, signature), entry)


def _as_dicts(findings: list[Finding], file: str) -> list[dict]:
    out = []
    for f in findings:
        d = asdict(f)
        d["file_path"] = file
        out.append(d)
    return out


def _tree_size(root: Path, _memo: dict | None = None) -> int:
    """Number of .py files under a version root (changes when companions are added)."""
    if _memo is not None and root in _memo:
        return _memo[root]
    n = sum(1 for _ in root.rglob("*.py"))
    if _memo is not None:
        _memo[root] = n
    return n


def _scan_codeql_flat(files: list[str]) -> dict[str, dict]:
    """Files copied flat into one database (no cross-file imports)."""
    from hackersec.analysis import static

    paths = [Path(f) for f in files]
    by_path = static.run_codeql_batch(paths, job_id="realworld") if len(paths) > 1 else None
    if by_path is not None:
        return {
            f: {"status": "ok", "findings": _as_dicts(by_path.get(str(p.resolve()), []), f)}
            for f, p in zip(files, paths)
        }
    out = {}
    for f, p in zip(files, paths):
        res = static._run_codeql_cmd([p], "realworld")
        if res is None:
            out[f] = {"status": "failed", "findings": []}
        else:
            out[f] = {"status": "ok", "findings": _as_dicts(res, f)}
    return out


def _scan_codeql_tree(root: Path, files: list[str]) -> dict[str, dict]:
    """One database for a whole before/after tree; keep findings in `files` only."""
    from hackersec.analysis import static

    findings = static.run_codeql_tree(root, job_id="realworld")
    if findings is None:
        return {f: {"status": "failed", "findings": []} for f in files}
    per_file: dict[str, list[Finding]] = {}
    for fd in findings:
        per_file.setdefault(str(Path(fd.file_path).resolve()), []).append(fd)
    n = _tree_size(root)
    return {
        f: {
            "status": "ok", "tree_files": n,
            "findings": _as_dicts(per_file.get(str(Path(f).resolve()), []), f),
        }
        for f in files
    }


def _scan_codeql(files: list[str]) -> dict[str, dict]:
    """CodeQL over a batch. In tree mode each version root gets its own database
    (two commits share relative paths, so roots must not be merged); files that
    are not in a version root fall back to the flat batch."""
    if not gitfetch.TREE_MODE:
        return _scan_codeql_flat(files)
    by_root: dict[Path, list[str]] = {}
    loose: list[str] = []
    for f in files:
        root = gitfetch.version_root_of(f)
        (by_root.setdefault(root, []) if root else loose).append(f)

    out: dict[str, dict] = _scan_codeql_flat(loose) if loose else {}
    with ThreadPoolExecutor(max_workers=max(1, CODEQL_WORKERS)) as pool:
        futures = [pool.submit(_scan_codeql_tree, root, fs) for root, fs in by_root.items()]
        for fut in futures:
            out.update(fut.result())
    return out


def _codeql_stale(file: str, entry: dict, memo: dict) -> bool:
    """A cached CodeQL result computed without the file's companions."""
    cq = entry["codeql"]
    if not gitfetch.TREE_MODE or cq["status"] == "unavailable":
        return False
    root = gitfetch.version_root_of(file)
    if root is None:
        return False
    return cq.get("tree_files") != _tree_size(root, memo)


def _scan_tool(tool: str, files: list[str]) -> dict[str, dict]:
    """{file: {"status", "findings"}} for one tool over a batch of files."""
    from hackersec.analysis import static

    paths = [Path(f) for f in files]
    if tool == "ast_sink":
        by_path = static.run_ast_sinks_batch(paths, job_id="realworld")
        return {
            f: {"status": "ok", "findings": _as_dicts(by_path.get(str(p.resolve()), []), f)}
            for f, p in zip(files, paths)
        }

    if tool == "codeql":
        if not static.codeql_available():
            return {f: {"status": "unavailable", "findings": []} for f in files}
        return _scan_codeql(files)

    batch_fn = static.run_semgrep_batch if tool == "semgrep" else static.run_bandit_batch
    single_fn = static._run_semgrep_cmd if tool == "semgrep" else static._bandit_cmd if hasattr(static, "_bandit_cmd") else static._run_bandit_cmd
    parse_fn = static._semgrep_findings if tool == "semgrep" else static._bandit_findings

    by_path = batch_fn(paths, job_id="realworld") if len(paths) > 1 else None
    out = {}
    if by_path is not None:
        for f, p in zip(files, paths):
            out[f] = {"status": "ok", "findings": _as_dicts(by_path.get(str(p.resolve()), []), f)}
        return out

    for f, p in zip(files, paths):
        data = single_fn([p], "realworld")
        if data is None:
            out[f] = {"status": "failed", "findings": []}
        else:
            out[f] = {"status": "ok", "findings": _as_dicts(parse_fn(data, "realworld"), f)}
    return out


def prescan(files: list[str], progress=None) -> dict:
    """Fill the cache for every file not in it yet. Returns scan counts."""
    signature = _signature()
    files = sorted({f for f in files if Path(f).exists()})
    todo = [f for f in files if _load(f, signature) is None]
    logger.info(f"SAST prescan: {len(files)} files, {len(files) - len(todo)} cached, {len(todo)} to scan")

    failed = _refresh_stale_codeql(files, todo, signature, progress)
    failed += _scan_missing(todo, signature, progress)
    return {"files": len(files), "scanned": len(todo), "failed": failed}


def _refresh_stale_codeql(files: list[str], todo: list[str], signature: str, progress) -> int:
    """Re-run only CodeQL for cached files whose version root gained companions."""
    memo: dict = {}
    pending = set(todo)
    stale = []
    for f in files:
        if f in pending:
            continue
        entry = _load(f, signature)
        if entry is not None and _codeql_stale(f, entry, memo):
            stale.append(f)
    if not stale:
        return 0
    logger.info(f"SAST prescan: re-running CodeQL for {len(stale)} cached files (tree mode)")
    failed = 0
    for i in range(0, len(stale), BATCH_SIZE):
        chunk = stale[i : i + BATCH_SIZE]
        results = _scan_tool("codeql", chunk)
        for f in chunk:
            entry = _load(f, signature)
            entry["codeql"] = results[f]
            failed += results[f]["status"] == "failed"
            _save(f, signature, entry)
        if progress:
            progress(min(i + BATCH_SIZE, len(stale)), len(stale))
    return failed


def _scan_missing(todo: list[str], signature: str, progress) -> int:
    failed = 0
    for i in range(0, len(todo), BATCH_SIZE):
        chunk = todo[i : i + BATCH_SIZE]
        results = {tool: _scan_tool(tool, chunk) for tool in TOOLS}
        for f in chunk:
            entry = {"file": f, "rules_signature": signature}
            for tool in TOOLS:
                entry[tool] = results[tool][f]
            failed += any(entry[t]["status"] == "failed" for t in TOOLS)
            _save(f, signature, entry)
        if progress:
            progress(min(i + BATCH_SIZE, len(todo)), len(todo))
    return failed


def findings_for(file: str) -> tuple[list[Finding], dict]:
    """Deduplicated findings for one file, plus each tool's status."""
    signature = _signature()
    entry = _load(file, signature)
    if entry is None:
        prescan([file])
        entry = _load(file, signature)
    if entry is None:
        return [], {t: "failed" for t in TOOLS}

    findings = [Finding(**d) for t in TOOLS for d in entry[t]["findings"]]
    return dedup_findings(findings), {t: entry[t]["status"] for t in TOOLS}
