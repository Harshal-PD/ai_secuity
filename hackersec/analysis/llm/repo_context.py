"""
Callers elsewhere in the repository, and web-framework entry points.

context.py only sees the changed file, because that is all the dataset
stores. Whether a flagged function is reachable with attacker input usually
depends on its callers in other modules, or on it being a request handler that
the framework calls directly. Given the other Python files of the repository
at the same commit, this finds both.

Calls are resolved by name and imports, without type inference: `f(...)`
counts when the file imports `f` from the target module, `mod.f(...)` when it
imports the module, and `obj.method(...)` only when the file also names the
method's class. A call that matches by name alone is not reported.
"""

import ast
import os
import re
import warnings
from pathlib import PurePosixPath

from hackersec.analysis.llm.context import _FUNCS, _numbered, _target

REPO_CONTEXT_CHARS = int(os.getenv("LLM_REPO_CONTEXT_CHARS", "800"))
MAX_CALLERS = 3
STORED_SITES = 10
LINE_CHARS = 160

_ROUTE_METHODS = {"route", "get", "post", "put", "patch", "delete", "head", "options", "websocket", "api_route"}
_VIEW_DECORATORS = {
    "api_view", "action", "view_config", "expose", "require_http_methods", "require_POST", "require_GET",
    "require_safe", "csrf_exempt", "login_required", "permission_required",
}
_VIEW_BASES = ("View", "ViewSet", "APIView", "Handler", "Resource", "MethodView", "Endpoint", "Controller")
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "dispatch"}
_URL_CALLS = {"path", "re_path", "url", "add_url_rule", "add_route", "add_api_route", "Rule", "Route"}
_URL_HINTS = ("urlpatterns", "add_url_rule", "add_route", "add_api_route", "Rule(", "Route(")


def _parse(source: str):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            return ast.parse(source)
    except (SyntaxError, ValueError):
        return None


def _name(node) -> str | None:
    return node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else None


def _dotted(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _clip(text: str) -> str:
    text = text.strip()
    return text if len(text) <= LINE_CHARS else text[: LINE_CHARS - 3] + "..."


def _locate(source: str, start: int, end: int):
    """(tree, target def, enclosing class or None), or None if unparseable."""
    tree = _parse(source)
    if tree is None:
        return None
    target = _target([n for n in ast.walk(tree) if isinstance(n, _FUNCS)], start, end)
    if target is None:
        return None
    cls = next((n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and target in n.body), None)
    return tree, target, cls


def _module_parts(path: str) -> list[str]:
    parts = list(PurePosixPath(path).with_suffix("").parts)
    return parts[:-1] if parts and parts[-1] == "__init__" else parts


def _suffix_match(dotted: str | None, parts: list[str]) -> bool:
    seg = [s for s in (dotted or "").split(".") if s]
    return bool(seg) and parts[-len(seg):] == seg


# ── Entry points ────────────────────────────────────────────────────────────

def _is_route_decorator(d) -> bool:
    node = d.func if isinstance(d, ast.Call) else d
    name = _name(node)
    if name in _VIEW_DECORATORS:
        return True
    if isinstance(d, ast.Call) and isinstance(node, ast.Attribute) and name in _ROUTE_METHODS:
        first = d.args[0] if d.args else None
        return name == "route" or (isinstance(first, ast.Constant) and isinstance(first.value, str))
    return False


def _url_registration(files: dict[str, str], name: str) -> dict | None:
    for path in sorted(files):
        text = files[path]
        if name not in text or not any(h in text for h in _URL_HINTS):
            continue
        tree = _parse(text)
        if tree is None:
            continue
        lines = text.splitlines()
        for call in ast.walk(tree):
            if not (isinstance(call, ast.Call) and _name(call.func) in _URL_CALLS):
                continue
            values = list(call.args) + [k.value for k in call.keywords]
            if any(_name(n) == name for v in values for n in ast.walk(v)):
                return {"kind": "url", "path": path, "line": call.lineno, "text": _clip(lines[call.lineno - 1])}
    return None


def entry_point(source: str, start: int, end: int, files: dict[str, str] | None = None) -> dict | None:
    """How a web framework reaches the function, if it does: a route or view
    decorator, an HTTP-method handler on a view class, or a URL registration
    in another file."""
    located = _locate(source, start, end)
    if located is None:
        return None
    _, target, cls = located
    lines = source.splitlines()
    for d in target.decorator_list:
        if _is_route_decorator(d):
            return {"kind": "decorator", "path": None, "line": d.lineno, "text": _clip(lines[d.lineno - 1])}
    handler = cls is not None and (target.name in _HTTP_METHODS or target.name.startswith("do_"))
    if handler and any((_name(b) or "").endswith(_VIEW_BASES) for b in cls.bases):
        return {"kind": "view_method", "path": None, "line": cls.lineno, "text": _clip(lines[cls.lineno - 1])}
    if files:
        return _url_registration(files, cls.name if handler else target.name)
    return None


# ── Callers in other files ──────────────────────────────────────────────────

def _local_names(tree, parts: list[str], name: str) -> tuple[set[str], set[str]]:
    """Names under which this file can call the target: the function itself
    (`from mod import f`) and the target module (`import pkg.mod`)."""
    funcs, mods = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            from_target = _suffix_match(node.module, parts) or (node.level > 0 and node.module is None)
            from_parent = _suffix_match(node.module, parts[:-1]) or (node.level > 0 and node.module is None)
            for a in node.names:
                if from_target and a.name in (name, "*"):
                    funcs.add(name if a.name == "*" else a.asname or a.name)
                elif parts and from_parent and a.name == parts[-1]:
                    mods.add(a.asname or a.name)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if _suffix_match(a.name, parts):
                    mods.add(a.asname or a.name)
    return funcs, mods


def _call_sites(text: str, parts: list[str], name: str, cls_name: str | None) -> list[int]:
    tree = _parse(text)
    if tree is None:
        return []
    funcs, mods = _local_names(tree, parts, name)
    method_ok = cls_name is not None and re.search(rf"\b{re.escape(cls_name)}\b", text) is not None
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name) and f.id in funcs:
            out.append(n.lineno)
        elif isinstance(f, ast.Attribute) and f.attr == name and (_dotted(f.value) in mods or method_ok):
            out.append(n.lineno)
    return sorted(set(out))


def _shared_prefix(a: str, b: str) -> int:
    n = 0
    for x, y in zip(PurePosixPath(a).parts, PurePosixPath(b).parts):
        if x != y:
            break
        n += 1
    return n


def find_callers(files: dict[str, str], target_path: str, source: str, start: int, end: int) -> dict:
    """Call sites of the function in the other files, nearest files first."""
    empty = {"call_sites": 0, "caller_files": 0, "sites": []}
    located = _locate(source, start, end)
    if located is None:
        return empty
    _, target, cls = located
    if target.name == "__init__" and cls is not None:
        name, cls_name = cls.name, None
    elif target.name.startswith("__"):
        return empty
    else:
        name, cls_name = target.name, cls.name if cls is not None else None
    parts = _module_parts(target_path)

    sites = []
    for path in sorted(files, key=lambda p: (-_shared_prefix(p, target_path), p)):
        text = files[path]
        if path == target_path or name not in text:
            continue
        lines = text.splitlines()
        tree_funcs = None
        for line in _call_sites(text, parts, name, cls_name):
            if tree_funcs is None:
                tree = _parse(text)
                tree_funcs = [n for n in ast.walk(tree) if isinstance(n, _FUNCS)] if tree else []
            covering = [n for n in tree_funcs if n.lineno <= line <= (n.end_lineno or n.lineno)]
            caller = max(covering, key=lambda n: n.lineno) if covering else None
            snippet = _numbered(lines, caller.lineno, caller.lineno) if caller else []
            snippet += _numbered(lines, max(caller.lineno + 1 if caller else 1, line - 1), line + 1)
            sites.append({"path": path, "line": line, "caller_line": caller.lineno if caller else None,
                          "snippet": [_clip(s) if len(s) > LINE_CHARS else s for s in snippet]})

    distinct, seen = [], set()
    for s in sites:
        key = (s["path"], s["caller_line"] or s["line"])
        if key not in seen:
            seen.add(key)
            distinct.append(s)
    return {"call_sites": len(sites), "caller_files": len({s["path"] for s in sites}),
            "sites": distinct[:STORED_SITES]}


def render(entry: dict | None, callers: dict | None, max_chars: int = REPO_CONTEXT_CHARS) -> str:
    """Prompt text for the entry point and the cross-file callers. `callers`
    None means the repository was not available, so nothing is said about
    callers; an empty result is reported as none found."""
    parts = []
    if entry:
        where = f"{entry['path']}:{entry['line']}" if entry.get("path") else f"line {entry['line']}"
        parts.append(f"Web framework entry point ({where}): {entry['text']}")
    if callers is not None:
        sites = callers.get("sites") or []
        if sites:
            shown = sites[:MAX_CALLERS]
            parts.append(f"Callers in other files of the repository ({callers['call_sites']} call sites in "
                         f"{callers['caller_files']} files; {len(shown)} shown):")
            for s in shown:
                parts.append(f"  [{s['path']}]")
                parts += s["snippet"]
                parts.append("  ...|")
        else:
            parts.append("Callers in other files of the repository: none found.")
    text = "\n".join(parts)
    return text if len(text) <= max_chars else text[: max_chars - 20].rstrip() + "\n  ...| (truncated)"
