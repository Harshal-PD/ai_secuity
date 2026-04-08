from pathlib import Path

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".cs": "csharp",
    ".rb": "ruby",
    ".php": "php",
}

SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "go", "java"}


def detect_language(file_path: str | Path) -> str:
    ext = Path(file_path).suffix.lower()
    return LANGUAGE_MAP.get(ext, "unknown")


def collect_source_files(target_path: Path) -> list[Path]:
    """Recursively collect all source files with known extensions."""
    files = []
    if target_path.is_file():
        if detect_language(target_path) != "unknown":
            files.append(target_path)
    elif target_path.is_dir():
        for ext in LANGUAGE_MAP:
            files.extend(target_path.rglob(f"*{ext}"))
        # Exclude common non-source dirs
        files = [
            f for f in files
            if not any(part in {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
                       for part in f.parts)
        ]
    return sorted(files)
