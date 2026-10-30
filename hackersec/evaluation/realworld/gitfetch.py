"""
Fetch the exact pre-fix and post-fix versions of a file from GitHub.

One bare repo per project; each fix commit is fetched shallow (the commit and
its parent) with blobs filtered out, so only the files actually read are ever
downloaded. A commit costs a few seconds and a few KB — no API token and no
rate limit, which matters for an unattended overnight build.
"""

import ast
import logging
import os
import posixpath
import re
import subprocess
import warnings
from pathlib import Path, PurePosixPath

from hackersec.evaluation.realworld import state
from hackersec.evaluation.realworld.net import NetworkDown, internet_up

logger = logging.getLogger(__name__)

FETCH_TIMEOUT = int(os.getenv("REALWORLD_GIT_TIMEOUT", "240"))
MAX_FILE_BYTES = 1_000_000
# Local files a sample's file imports (plus its callers) that are stored next to
# it, so Joern and CodeQL can resolve cross-file imports. 0 turns this off.
MAX_COMPANIONS = int(os.getenv("REALWORLD_COMPANION_FILES", "15"))
# Joern and CodeQL analyse the whole before/after tree instead of one file
# (set REALWORLD_TREE_MODE=0 to restore the one-file behaviour).
TREE_MODE = os.getenv("REALWORLD_TREE_MODE", "1").lower() not in ("0", "false", "no", "off")

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


def version_root_of(file: str) -> Path | None:
    """The `<dataset>/<slug>/<sha12>/{before,after}` directory that holds this
    sample file and its companion files, or None when `file` is not under
    FILES_DIR in that layout."""
    try:
        rel = Path(file).resolve().relative_to(state.FILES_DIR.resolve())
    except (ValueError, OSError):
        return None
    if len(rel.parts) < 5 or rel.parts[3] not in ("before", "after"):
        return None
    return Path(file).parents[len(rel.parts) - 5]


def resolve_local_imports(
    source_code: str,
    target_rel_path: str,
    repo_py_files: set[str],
    max_files: int = MAX_COMPANIONS,
) -> list[str]:
    """Repo-relative .py files that `source_code` imports: relative imports,
    absolute imports from the repo root or from any directory above the target
    (src/ layouts), and the package `__init__.py` files above the target."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        try:
            tree = ast.parse(source_code)
        except (SyntaxError, ValueError):
            return []

    target_dir = PurePosixPath(target_rel_path).parent
    found: list[str] = []

    def add(candidate) -> None:
        norm = posixpath.normpath(str(candidate))
        if norm in repo_py_files and norm != target_rel_path and norm not in found:
            found.append(norm)

    cur = target_dir
    while str(cur) not in ("", "."):
        add(cur / "__init__.py")
        cur = cur.parent

    modules: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update((0, a.name) for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            level, mod = node.level or 0, node.module or ""
            modules.add((level, mod))
            modules.update((level, f"{mod}.{a.name}" if mod else a.name) for a in node.names)

    ancestors = [target_dir, *target_dir.parents]
    for level, mod in sorted(modules):
        parts = [p for p in mod.split(".") if p]
        if level > 0:
            base = target_dir
            for _ in range(level - 1):
                base = base.parent
            rel = base.joinpath(*parts)
            if parts:
                add(f"{rel}.py")
            add(rel / "__init__.py")
        elif parts:
            rel = PurePosixPath(*parts)
            for anc in ancestors:
                add(f"{anc / rel}.py")
                add(anc / rel / "__init__.py")
        if len(found) >= max_files:
            break
    return found[:max_files]


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

    def py_files(self, repo_url: str, rev: str) -> set[str]:
        """Every .py path in the repository tree at `rev` (git ls-tree)."""
        repo = self._repo(repo_url)
        proc = self._git(repo, "ls-tree", "-r", "-z", "--name-only", rev, timeout=120)
        if proc.returncode != 0:
            self._fail(f"ls-tree {rev[:12]}", proc)
        return {p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p.endswith(".py")}

    def companion_files(
        self,
        repo_url: str,
        sha: str,
        path: str,
        before_src: str,
        after_src: str,
        extra_paths: list[str] | None = None,
        max_files: int = MAX_COMPANIONS,
    ) -> tuple[dict[str, str], dict[str, str]]:
        """({path: source} before, {path: source} after): the local files that
        `path` imports at `sha^` and at `sha`, plus `extra_paths` (callers)
        that exist in that tree. A file that is binary or too large is skipped."""
        repo = self._repo(repo_url)
        self._ensure_commit(repo, sha)
        extras = [posixpath.normpath(p.lstrip("/")) for p in (extra_paths or [])]
        sides = []
        for rev, src in ((f"{sha}^", before_src), (sha, after_src)):
            tree = self.py_files(repo_url, rev)
            paths = resolve_local_imports(src, path, tree, max_files)
            for p in extras:
                if p in tree and p != path and p not in paths and len(paths) < max_files:
                    paths.append(p)
            files: dict[str, str] = {}
            for p in paths:
                try:
                    text = self._show(repo, rev, p)
                except Unavailable:
                    continue
                if text is not None:
                    files[p] = text
            sides.append(files)
        return sides[0], sides[1]

    def changed_py_files(self, repo_url: str, sha: str) -> list[str]:
        """Python files touched by the commit, when the dataset does not list them."""
        repo = self._repo(repo_url)
        self._ensure_commit(repo, sha)
        proc = self._git(repo, "diff", "--name-only", f"{sha}^", sha)
        if proc.returncode != 0:
            self._fail(f"diff {sha[:10]}", proc)
        return [p for p in proc.stdout.decode("utf-8", "replace").splitlines() if p.endswith(".py")]
