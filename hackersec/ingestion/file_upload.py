import shutil
from pathlib import Path


def save_upload(content: bytes, filename: str, dest_dir: Path) -> Path:
    """Save raw upload bytes to dest_dir/filename. Returns full path."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / filename
    dest.write_bytes(content)
    return dest
