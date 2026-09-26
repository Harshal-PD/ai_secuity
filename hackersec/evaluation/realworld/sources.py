"""
Fix-commit lists for the two real-world datasets.

CVEfixes (Bhandari et al., PROMISE 2021) — CVE-linked fix commits, read from
the `hitoshura25/cvefixes` Hugging Face mirror (v1.0.8). Only the metadata
columns are read, so the 3 GB code payload is never downloaded; the code itself
is fetched per commit from GitHub, because the mirror stores concatenated diff
lines rather than parseable source.

VUDENC (Wartschinski et al., IST 2022) — keyword-mined Python fix commits for
seven vulnerability classes, from the authors' Zenodo release (record 3559841).

Both are reduced to the same record: repo URL, fix commit SHA, touched .py
paths, and a CWE. The downstream pipeline is identical for both.
"""

import json
import logging
import urllib.request
from pathlib import Path

from hackersec.evaluation.realworld import state
from hackersec.evaluation.realworld.net import NetworkDown, internet_up, with_network_retry

logger = logging.getLogger(__name__)

CVEFIXES_REPO = "datasets/hitoshura25/cvefixes"
CVEFIXES_COLUMNS = ["cve_id", "hash", "repo_url", "cwe_id", "cwe_name", "file_paths", "language", "severity"]

VUDENC_RECORD = "https://zenodo.org/api/records/3559841/files/plain_{name}/content"
# VUDENC class -> CWE. "path_disclosure" in VUDENC denotes directory traversal.
VUDENC_TYPES = {
    "sql": ("CWE-89", "SQL Injection"),
    "xss": ("CWE-79", "Cross-site Scripting"),
    "command_injection": ("CWE-78", "OS Command Injection"),
    "xsrf": ("CWE-352", "Cross-Site Request Forgery"),
    "remote_code_execution": ("CWE-94", "Code Injection"),
    "path_disclosure": ("CWE-22", "Path Traversal"),
    "open_redirect": ("CWE-601", "Open Redirect"),
}


def _norm_cwe(cwe: str | None) -> str:
    if not cwe or not cwe.startswith("CWE-"):
        return "CWE-unknown"  # NVD-CWE-noinfo / NVD-CWE-Other
    return cwe


def _net_guard(fn, context: str):
    """Turn an exception into NetworkDown when the link is actually down."""
    def run():
        try:
            return fn()
        except NetworkDown:
            raise
        except Exception as e:
            if not internet_up():
                raise NetworkDown(str(e))
            raise
    return with_network_retry(run, context)


# ── CVEfixes ────────────────────────────────────────────────────────────────

def load_cvefixes_commits() -> list[dict]:
    cache = state.CACHE_DIR / "cvefixes_commits.json"
    cached = state.read_json(cache)
    if cached:
        return cached

    import pyarrow.parquet as pq
    from huggingface_hub import HfFileSystem

    fs = HfFileSystem()
    shards = _net_guard(lambda: sorted(fs.glob(f"{CVEFIXES_REPO}/**/*.parquet")), "list CVEfixes shards")
    logger.info(f"CVEfixes: reading metadata from {len(shards)} parquet shard(s)")

    commits: dict[tuple, dict] = {}
    for shard in shards:
        def read(shard=shard):
            with fs.open(shard, "rb") as fh:
                return pq.ParquetFile(fh).read(columns=CVEFIXES_COLUMNS).to_pylist()

        rows = _net_guard(read, f"read {Path(shard).name}")
        for r in rows:
            if (r.get("language") or "").lower() != "python":
                continue
            paths = [p for p in (r.get("file_paths") or []) if p and p.endswith(".py")]
            if not paths or not r.get("repo_url") or not r.get("hash"):
                continue
            key = (r["repo_url"].rstrip("/"), r["hash"])
            rec = commits.setdefault(key, {
                "dataset": "cvefixes",
                "repo_url": key[0],
                "sha": key[1],
                "paths": sorted(set(paths)),
                "cwe": _norm_cwe(r.get("cwe_id")),
                "cwe_name": r.get("cwe_name") or "",
                "cve": [],
                "severity": r.get("severity"),
            })
            if r.get("cve_id") and r["cve_id"] not in rec["cve"]:
                rec["cve"].append(r["cve_id"])

    out = sorted(commits.values(), key=lambda c: (c["repo_url"], c["sha"]))
    state.write_json_atomic(cache, out)
    logger.info(f"CVEfixes: {len(out)} Python fix commits")
    return out


# ── VUDENC ──────────────────────────────────────────────────────────────────

def _download(url: str, dest: Path) -> None:
    if dest.exists() and dest.stat().st_size > 0:
        return
    part = dest.with_suffix(dest.suffix + ".part")

    def fetch():
        with urllib.request.urlopen(url, timeout=300) as resp, open(part, "wb") as f:
            while chunk := resp.read(1 << 20):
                f.write(chunk)
        part.replace(dest)

    _net_guard(fetch, f"download {dest.name}")


def load_vudenc_commits() -> list[dict]:
    cache = state.CACHE_DIR / "vudenc_commits.json"
    cached = state.read_json(cache)
    if cached:
        return cached

    zdir = state.CACHE_DIR / "zenodo"
    zdir.mkdir(parents=True, exist_ok=True)

    commits: dict[tuple, dict] = {}
    for name, (cwe, cwe_name) in VUDENC_TYPES.items():
        dest = zdir / f"plain_{name}.json"
        logger.info(f"VUDENC: fetching plain_{name}")
        _download(VUDENC_RECORD.format(name=name), dest)
        with open(dest, "r", encoding="utf-8") as f:
            data = json.load(f)

        for repo_url, repo_commits in data.items():
            if not isinstance(repo_commits, dict):
                continue
            for sha, cdata in repo_commits.items():
                files = (cdata or {}).get("files") or {}
                paths = sorted({p.lstrip("/") for p in files if p.endswith(".py")})
                if not paths:
                    continue
                key = (repo_url.rstrip("/"), sha)
                # A commit mined under several keywords keeps its first class.
                commits.setdefault(key, {
                    "dataset": "vudenc",
                    "repo_url": key[0],
                    "sha": sha,
                    "paths": paths,
                    "cwe": cwe,
                    "cwe_name": cwe_name,
                    "cve": [],
                    "severity": None,
                })

    out = sorted(commits.values(), key=lambda c: (c["repo_url"], c["sha"]))
    state.write_json_atomic(cache, out)
    logger.info(f"VUDENC: {len(out)} Python fix commits")
    return out


LOADERS = {"cvefixes": load_cvefixes_commits, "vudenc": load_vudenc_commits}
