"""
Same-file callers and callees of a function, for the board's prompt.

Whether a function is exploitable often depends on code around it: a caller
that validates input first, or a helper that does the dangerous work. Judging
the function alone is a known source of wrong function-level verdicts (Risse &
Böhme, USENIX Security 2024). The dataset stores only the changed file, so the
context is limited to definitions in that file.
"""

import ast
import os

MAX_CONTEXT_CHARS = int(os.getenv("LLM_CONTEXT_CHARS", "1200"))
CALLEE_LINES = 8
MAX_ITEMS = 3

_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)


def _calls(node: ast.AST) -> list[tuple[str, int]]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
            if name:
                out.append((name, n.lineno))
    return out


def _within(inner: ast.AST, outer: ast.AST) -> bool:
    return outer.lineno <= inner.lineno and (inner.end_lineno or inner.lineno) <= (outer.end_lineno or outer.lineno)


def _target(funcs: list, start: int, end: int):
    exact = [n for n in funcs if n.lineno == start]
    if exact:
        return exact[0]
    inside = [n for n in funcs if start <= n.lineno <= end]
    if inside:
        return min(inside, key=lambda n: n.lineno)
    covering = [n for n in funcs if n.lineno <= start <= (n.end_lineno or n.lineno)]
    return max(covering, key=lambda n: n.lineno) if covering else None


def _numbered(lines: list[str], first: int, last: int) -> list[str]:
    return [f"{n:>5}| {lines[n - 1]}" for n in range(first, min(last, len(lines)) + 1)]


def function_context(source: str, start_line: int, end_line: int, max_chars: int = MAX_CONTEXT_CHARS) -> str:
    """Callees defined in the file and callers of the function, as numbered
    snippets; empty when the file does not parse or nothing is related."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return ""
    lines = source.splitlines()
    funcs = [n for n in ast.walk(tree) if isinstance(n, _FUNCS)]
    target = _target(funcs, start_line, end_line)
    if target is None:
        return ""

    called = {name for name, _ in _calls(target)}
    callees = [n for n in funcs if n is not target and n.name in called and not _within(n, target)]
    callers = []
    for n in funcs:
        if n is target or _within(n, target):
            continue
        sites = [ln for name, ln in _calls(n) if name == target.name
                 and not (target.lineno <= ln <= (target.end_lineno or target.lineno))]
        if sites and not _within(target, n):
            callers.append((n, sites))

    parts = []
    if callees:
        parts.append("Callees defined in this file (first lines):")
        for n in sorted(callees, key=lambda n: n.lineno)[:MAX_ITEMS]:
            parts += _numbered(lines, n.lineno, min(n.end_lineno or n.lineno, n.lineno + CALLEE_LINES - 1))
            parts.append("  ...|")
    if callers:
        parts.append("Callers in this file (definition and call sites):")
        for n, sites in sorted(callers, key=lambda c: c[0].lineno)[:MAX_ITEMS]:
            parts += _numbered(lines, n.lineno, n.lineno)
            for ln in sites[:2]:
                parts += _numbered(lines, max(n.lineno + 1, ln - 1), ln + 1)
            parts.append("  ...|")
    text = "\n".join(parts)
    return text if len(text) <= max_chars else text[: max_chars - 20].rstrip() + "\n  ...| (truncated)"
