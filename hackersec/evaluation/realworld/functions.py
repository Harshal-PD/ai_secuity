"""
Extract the functions a fix commit changed, as (vulnerable, fixed) pairs.

This follows how CVEfixes builds its method-level table: a function that the
security fix modified is labeled vulnerable in its pre-fix form and fixed in its
post-fix form. Test code, packaging files, and oversized functions are dropped
because a fix commit's edits there are almost never the vulnerability itself.
"""

import ast
import difflib
import warnings
from dataclasses import dataclass
from pathlib import PurePosixPath

MIN_LINES = 3
MAX_LINES = 250

_SKIP_DIRS = {"test", "tests", "testing", "unittests", "migrations", "docs", "doc", "examples", "example"}
_SKIP_FILES = {"setup.py", "conftest.py", "version.py", "_version.py", "__version__.py"}


@dataclass
class Span:
    qualname: str
    start: int  # first line, decorators included (1-based)
    end: int
    code: str


@dataclass
class FunctionPair:
    qualname: str
    before: Span
    after: Span


def skip_reason(path: str) -> str | None:
    p = PurePosixPath(path.lstrip("/"))
    if p.suffix != ".py":
        return "not_python"
    name = p.name.lower()
    if name in _SKIP_FILES:
        return "packaging_file"
    if name.startswith("test_") or name.endswith("_test.py") or name == "tests.py":
        return "test_file"
    if any(part.lower() in _SKIP_DIRS for part in p.parts[:-1]):
        return "test_or_docs_dir"
    return None


def _spans(src: str) -> dict[str, Span] | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)  # old '\d' escapes etc.
            tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return None
    lines = src.splitlines()
    out: dict[str, Span] = {}

    def visit(node, prefix: str):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{child.name}"
                start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                end = child.end_lineno or child.lineno
                # Overloaded/redefined names: keep the first, like a reader would.
                out.setdefault(qual, Span(qual, start, end, "\n".join(lines[start - 1:end])))
                visit(child, f"{qual}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            else:
                visit(child, prefix)

    visit(tree, "")
    return out


def _changed_lines(before: str, after: str) -> tuple[set[int], set[int]]:
    a, b = before.splitlines(), after.splitlines()
    changed_a, changed_b = set(), set()
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        # Pure insertions/deletions have an empty range on one side; mark the
        # neighbouring line so the enclosing function still counts as changed.
        changed_a.update(range(i1 + 1, i2 + 1) if i2 > i1 else {max(i1, 1), i1 + 1})
        changed_b.update(range(j1 + 1, j2 + 1) if j2 > j1 else {max(j1, 1), j1 + 1})
    return changed_a, changed_b


def _innermost(spans: dict[str, Span], line: int) -> str | None:
    best = None
    for s in spans.values():
        if s.start <= line <= s.end and (best is None or s.end - s.start < best.end - best.start):
            best = s
    return best.qualname if best else None


def _normalize(code: str) -> str:
    return "\n".join(l.rstrip() for l in code.splitlines() if l.strip())


def extract_pairs(before_src: str, after_src: str) -> tuple[list[FunctionPair], str | None]:
    """
    Returns (pairs, drop_reason). drop_reason is set when the file yields nothing
    and explains why, so the report can account for every excluded file.
    """
    spans_a, spans_b = _spans(before_src), _spans(after_src)
    if spans_a is None or spans_b is None:
        return [], "syntax_error"  # typically Python 2 source

    changed_a, changed_b = _changed_lines(before_src, after_src)
    touched = {q for q in (_innermost(spans_a, l) for l in changed_a) if q}
    touched |= {q for q in (_innermost(spans_b, l) for l in changed_b) if q}
    if not touched:
        return [], "no_function_changed"  # module-level edits only

    pairs, reasons = [], []
    for qual in sorted(touched):
        a, b = spans_a.get(qual), spans_b.get(qual)
        if a is None or b is None:
            reasons.append("function_added_or_removed")
            continue
        if _normalize(a.code) == _normalize(b.code):
            reasons.append("whitespace_only")
            continue
        length = a.end - a.start + 1
        if length < MIN_LINES or length > MAX_LINES:
            reasons.append("function_size")
            continue
        pairs.append(FunctionPair(qual, a, b))

    if not pairs:
        return [], reasons[0] if reasons else "no_pairs"
    return pairs, None
