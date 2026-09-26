"""
Fetch the exact pre-fix and post-fix versions of a file from GitHub.

One bare repo per project; each fix commit is fetched shallow (the commit and
its parent) with blobs filtered out, so only the files actually read are ever
downloaded. A commit costs a few seconds and a few KB — no API token and no
rate limit, which matters for an unattended overnight build.
"""

import logging
import os
import re
import subprocess
from pathlib import Path

from hackersec.evaluation.realworld import state
from hackersec.evaluation.realworld.net import NetworkDown, internet_up

logger = logging.getLogger(__name__)

FETCH_TIMEOUT = int(os.getenv("REALWORLD_GIT_TIMEOUT", "240"))
MAX_FILE_BYTES = 1_000_000

_GIT_ENV = {
    **os.environ,
    # A deleted or private repo must fail, not block forever on a password prompt.
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "true",
    "GCM_INTERACTIVE": "never",
}


class Unavailable(Exception):
    """The repo, commit, or file genuinely does not exist — drop it."""


def _slug(repo_url: str) -> str:
    tail = repo_url.rstrip("/").removesuffix(".git").split("github.com/")[-1]
    return re.sub(r"[^A-Za-z0-9_.-]+", "__", tail)


class GitFetcher:
    def __init__(self, repos_dir: Path = state.REPOS_DIR):
        self.repos_dir = repos_dir
        self.repos_dir.mkdir(parents=True, exist_ok=True)

    def _git(self, repo: Path, *args: str, timeout: int = FETCH_TIMEOUT) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["git", "-C", str(repo), *args],
                capture_output=True,
                timeout=timeout,
                env=_GIT_ENV,
            )
        except subprocess.TimeoutExpired:
            if not internet_up():
                raise NetworkDown(f"git {args[0]} timed out with no internet")
            raise Unavailable(f"git {args[0]} timed out after {timeout}s")

    def _fail(self, what: str, proc: subprocess.CompletedProcess):
        """Decide whether a failure is the network (retry) or the data (drop)."""
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        tail = err[-1] if err else f"exit {proc.returncode}"
        if not internet_up():
            raise NetworkDown(f"{what}: {tail}")
        raise Unavailable(f"{what}: {tail}")

    def _repo(self, repo_url: str) -> Path:
        path = self.repos_dir / f"{_slug(repo_url)}.git"
        if not (path / "HEAD").exists():
            path.mkdir(parents=True, exist_ok=True)
            subprocess.run(["git", "init", "-q", "--bare", str(path)], check=True, env=_GIT_ENV)
            subprocess.run(
                ["git", "-C", str(path), "remote", "add", "origin", repo_url.rstrip("/")],
                check=True,
                env=_GIT_ENV,
            )
        return path

    def _has_commit_with_parent(self, repo: Path, sha: str) -> bool:
        ok = self._git(repo, "cat-file", "-e", f"{sha}^{{commit}}", timeout=30).returncode == 0
        return ok and self._git(repo, "cat-file", "-e", f"{sha}^^{{commit}}", timeout=30).returncode == 0

    def _ensure_commit(self, repo: Path, sha: str) -> None:
        if self._has_commit_with_parent(repo, sha):
            return
        proc = self._git(
            repo, "-c", "protocol.version=2", "fetch", "--quiet",
            "--depth=2", "--filter=blob:none", "origin", sha,
        )
        if proc.returncode != 0:
            # Some servers reject partial clone; a plain shallow fetch still works.
            proc = self._git(repo, "-c", "protocol.version=2", "fetch", "--quiet", "--depth=2", "origin", sha)
        if proc.returncode != 0:
            self._fail(f"fetch {sha[:10]}", proc)
        if not self._has_commit_with_parent(repo, sha):
            raise Unavailable(f"{sha[:10]} has no parent (root commit)")

    def _show(self, repo: Path, rev: str, path: str) -> str | None:
        proc = self._git(repo, "show", f"{rev}:{path}")
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace")
            if "does not exist" in err or "exists on disk, but not in" in err:
                return None  # file added or deleted by the fix
            self._fail(f"show {rev[:12]}:{path}", proc)
        data = proc.stdout
        if len(data) > MAX_FILE_BYTES or b"\x00" in data:
            raise Unavailable(f"{path} is binary or larger than {MAX_FILE_BYTES} bytes")
        return data.decode("utf-8", "replace")

    def file_pair(self, repo_url: str, sha: str, path: str) -> tuple[str | None, str | None]:
        """(before, after) source of `path` around fix commit `sha`."""
        repo = self._repo(repo_url)
        self._ensure_commit(repo, sha)
        return self._show(repo, f"{sha}^", path), self._show(repo, sha, path)

    def changed_py_files(self, repo_url: str, sha: str) -> list[str]:
        """Python files touched by the commit, when the dataset does not list them."""
        repo = self._repo(repo_url)
        self._ensure_commit(repo, sha)
        proc = self._git(repo, "diff", "--name-only", f"{sha}^", sha)
        if proc.returncode != 0:
            self._fail(f"diff {sha[:10]}", proc)
        return [p for p in proc.stdout.decode("utf-8", "replace").splitlines() if p.endswith(".py")]
