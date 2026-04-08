import shutil
from pathlib import Path
import git


def clone_repo(url: str, dest: Path) -> Path:
    """Shallow clone a public git repository. Returns path to cloned directory."""
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    try:
        git.Repo.clone_from(url, str(dest), depth=1, no_single_branch=True)
    except git.GitCommandError as e:
        raise ValueError(f"Failed to clone repository '{url}': {e}") from e
    return dest
