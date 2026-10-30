import hashlib
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from hackersec.analysis.schema import (
    Finding,
    SEMGREP_SEVERITY_MAP,
    BANDIT_SEVERITY_MAP,
)

logger = logging.getLogger(__name__)

def _extract_snippet(file_path: str, start_line: int, end_line: int, context_lines: int = 3) -> str | None:
    """Reads the physical file to extract the vulnerable block with context."""
    path = Path(file_path)
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        
        start_idx = max(0, start_line - 1 - context_lines)
        end_idx = min(len(lines), end_line + context_lines)
        
        snippet = "".join(lines[start_idx:end_idx])
        return snippet.strip()
    except Exception as e:
        logger.warning(f"Failed to extract snippet from {file_path}: {e}")
        return None

# ─── Semgrep ────────────────────────────────────────────────────────────────

SEMGREP_CONFIGS = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/python",
    "p/flask",
    "p/django",
    "p/sql-injection",
    "p/xss",
    "p/command-injection",
    "p/trailofbits",
    "p/secrets",
]


# Semgrep spawns one worker per visible core by default (80 on the DGX).
SEMGREP_JOBS = int(os.getenv("SEMGREP_JOBS", "2"))
MERGED_RULES_NAME = "_merged.yaml"


def _load_rules(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        import yaml

        data = yaml.safe_load(text)
    return list((data or {}).get("rules") or [])


def _merged_rules(rules_dir: Path) -> Path | None:
    """
    One config holding every vendored rule once.

    The packs overlap heavily (p/security-audit and p/owasp-top-ten share most
    Python rules), and Semgrep parses every config on every run, so merging
    removes both the duplicate work and duplicate findings. The merged file
    uses a different suffix so it is never picked up as a pack itself.
    """
    packs = sorted(rules_dir.glob("*.yml"))
    if not packs:
        return None
    merged = rules_dir / MERGED_RULES_NAME
    if merged.exists() and merged.stat().st_mtime >= max(p.stat().st_mtime for p in packs):
        return merged
    try:
        rules: dict[str, dict] = {}
        total = 0
        for p in packs:
            for rule in _load_rules(p):
                total += 1
                rules.setdefault(rule.get("id") or f"anon-{total}", rule)
        tmp = merged.with_suffix(".tmp")
        tmp.write_text(json.dumps({"rules": list(rules.values())}), encoding="utf-8")
        os.replace(tmp, merged)
        logger.info(f"Merged {total} vendored Semgrep rules into {len(rules)} unique rules")
        return merged
    except Exception as e:
        logger.warning(f"Could not merge vendored Semgrep packs ({e}); scanning them separately")
        return None


def _semgrep_configs() -> list[str]:
    """
    Registry packs are downloaded from semgrep.dev on every scan, so a dropped
    connection silently yields zero findings. When SEMGREP_RULES_DIR holds
    vendored copies of the packs, scan offline against those instead.
    """
    rules_dir = os.getenv("SEMGREP_RULES_DIR")
    if rules_dir:
        merged = _merged_rules(Path(rules_dir))
        if merged:
            return [str(merged)]
        local = sorted(Path(rules_dir).glob("*.yml"))
        if local:
            return [str(p) for p in local]
        logger.warning(f"SEMGREP_RULES_DIR={rules_dir} has no .yml files; using the registry")
    return SEMGREP_CONFIGS


def rules_signature() -> str:
    """Identifies the exact rule set, so cached scan results are reused only
    while the rules are unchanged."""
    # The wide AST gate changes what ast_sink reports, so it gets its own cache
    # generation; with it off the old key is kept and old cache entries are reused.
    h = hashlib.sha1(b"v7.2-ast-surface-param-taint" if ENABLE_AST_WIDE else b"v7.1-precision-ast-low-codeql")
    for cfg in _semgrep_configs():
        p = Path(cfg)
        h.update(p.read_bytes() if p.is_file() else cfg.encode())
    h.update(b"codeql:1" if codeql_available() else b"codeql:0")
    return h.hexdigest()[:16]


def _rule_id(check_id: str) -> str:
    """Semgrep prefixes local rules with their directory path
    (`workspace.realworld.semgrep_rules.python...`); keep the registry id."""
    rules_dir = os.getenv("SEMGREP_RULES_DIR")
    if rules_dir:
        marker = Path(rules_dir).name + "."
        idx = check_id.find(marker)
        if idx != -1:
            return check_id[idx + len(marker):]
    return check_id


def _run_semgrep_cmd(targets: list[Path], job_id: str) -> dict | None:
    cmd = ["semgrep", "scan", "--json", "--timeout", "60", "--metrics=off", "--jobs", str(SEMGREP_JOBS)]
    for cfg in _semgrep_configs():
        cmd += ["--config", cfg]
    cmd += [str(t) for t in targets]
    timeout = 120 + 30 * max(0, len(targets) - 1)

    logger.info(f"[{job_id}] Running Semgrep on {len(targets)} target(s): {' '.join(cmd[:12])} ...")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0"},
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"[{job_id}] Semgrep timed out after {timeout}s")
        return None
    except FileNotFoundError:
        logger.error(f"[{job_id}] Semgrep binary not found in container")
        return None

    # Exit code 0 = no findings, 1 = findings found, 2+ = error
    if result.returncode >= 2:
        logger.error(f"[{job_id}] Semgrep exited with code {result.returncode}")
        logger.error(f"[{job_id}] Semgrep stderr: {result.stderr[:500]}")
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error(f"[{job_id}] Semgrep produced invalid JSON. stdout[:200]: {result.stdout[:200]}")
        return None


def run_semgrep(target_path: Path, job_id: str) -> list[Finding]:
    """Run Semgrep with security rule sets. Returns normalized Finding list."""
    data = _run_semgrep_cmd([target_path], job_id)
    return _semgrep_findings(data, job_id) if data else []


def run_semgrep_batch(paths: list[Path], job_id: str) -> dict[str, list[Finding]] | None:
    """
    Scan many files in one Semgrep process, so the rules are parsed once.
    Returns {resolved path: findings}, or None if the batch failed and the
    caller should fall back to scanning files one by one.
    """
    data = _run_semgrep_cmd(paths, job_id)
    if data is None:
        return None
    out: dict[str, list[Finding]] = {str(Path(p).resolve()): [] for p in paths}
    for f in _semgrep_findings(data, job_id):
        out.setdefault(str(Path(f.file_path).resolve()), []).append(f)
    return out


def _semgrep_findings(data: dict, job_id: str) -> list[Finding]:
    findings = []
    for r in data.get("results", []):
        severity_raw = r.get("extra", {}).get("severity", "INFO")
        severity = SEMGREP_SEVERITY_MAP.get(severity_raw)
        if severity is None:
            continue  # Skip INFO findings

        meta = r.get("extra", {}).get("metadata", {})
        cwe_raw = meta.get("cwe", [])
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        cwe_ids = [c if c.startswith("CWE-") else f"CWE-{c}" for c in cwe_raw]

        owasp = meta.get("owasp", None)
        if isinstance(owasp, list):
            owasp = owasp[0] if owasp else None

        snippet = _extract_snippet(r["path"], r["start"]["line"], r["end"]["line"])

        findings.append(Finding(
            job_id=job_id,
            file_path=r["path"],
            line_start=r["start"]["line"],
            line_end=r["end"]["line"],
            rule_id=_rule_id(r["check_id"]),
            tool="semgrep",
            severity=severity,
            message=r["extra"]["message"],
            cwe_ids=cwe_ids,
            owasp_category=owasp,
            code_snippet=snippet,
        ))

    return findings


# ─── Bandit ─────────────────────────────────────────────────────────────────

def _run_bandit_cmd(targets: list[Path], job_id: str, recursive: bool = False) -> dict | None:
    # -l = severity >= LOW, -i = confidence >= LOW so the gate is recall-heavy
    cmd = ["bandit"] + (["-r"] if recursive else []) + [str(t) for t in targets] + ["-f", "json", "-l", "-i"]
    timeout = 60 + 5 * max(0, len(targets) - 1)

    logger.info(f"[{job_id}] Running Bandit on {len(targets)} target(s)")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"[{job_id}] Bandit timed out after {timeout}s")
        return None
    except FileNotFoundError:
        logger.error(f"[{job_id}] Bandit binary not found in container")
        return None

    logger.info(f"[{job_id}] Bandit exit code: {result.returncode}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error(f"[{job_id}] Bandit produced invalid JSON. stderr: {result.stderr[:200]}")
        return None


def run_bandit(target_path: Path, job_id: str) -> list[Finding]:
    """Run Bandit on Python files. Returns normalized Finding list."""
    # Bandit only works on Python — skip non-Python targets
    if target_path.is_file() and not str(target_path).endswith(".py"):
        logger.info(f"[{job_id}] Skipping Bandit (not a .py file)")
        return []

    data = _run_bandit_cmd([target_path], job_id, recursive=target_path.is_dir())
    findings = _bandit_findings(data, job_id) if data else []
    logger.info(f"[{job_id}] Bandit found {len(findings)} findings")
    return findings


def run_bandit_batch(paths: list[Path], job_id: str) -> dict[str, list[Finding]] | None:
    """Scan many .py files in one Bandit process. None means fall back per file."""
    data = _run_bandit_cmd(paths, job_id)
    if data is None:
        return None
    out: dict[str, list[Finding]] = {str(Path(p).resolve()): [] for p in paths}
    for f in _bandit_findings(data, job_id):
        out.setdefault(str(Path(f.file_path).resolve()), []).append(f)
    return out


def _bandit_findings(data: dict, job_id: str) -> list[Finding]:
    findings = []
    for r in data.get("results", []):
        severity_raw = r.get("issue_severity", "LOW")
        severity = BANDIT_SEVERITY_MAP.get(severity_raw, "low")

        # Extract CWE if available (Bandit >= 1.7.5)
        cwe_info = r.get("issue_cwe", {})
        cwe_id = cwe_info.get("id")
        cwe_ids = [f"CWE-{cwe_id}"] if cwe_id else []

        start_line = r["line_number"]
        end_line = r.get("line_range", [r["line_number"]])[-1]
        snippet = _extract_snippet(r["filename"], start_line, end_line)

        findings.append(Finding(
            job_id=job_id,
            file_path=r["filename"],
            line_start=start_line,
            line_end=end_line,
            rule_id=r["test_id"],
            tool="bandit",
            severity=severity,
            message=r["issue_text"],
            cwe_ids=cwe_ids,
            code_snippet=snippet,
        ))

    return findings


# ─── Zero-Token Python AST Sink & Guard Scanner ─────────────────────────────

import ast
import re
import shutil
import tempfile

ENABLE_AST_SINKS = os.getenv("SAST_ENABLE_AST_SINKS", "1") not in ("0", "false", "False")
# Wide mode: security-surface presence flags plus parameter taint through string
# formatting. SAST_AST_PARAM_TAINT=0 restores the narrow sink list.
ENABLE_AST_WIDE = os.getenv("SAST_AST_PARAM_TAINT", "1") not in ("0", "false", "False")

_AST_INPUT_ATTRS = {
    "args", "form", "values", "GET", "POST", "cookies", "headers",
    "data", "json", "files", "query_params", "body", "params", "get_json",
    "environ", "argv",
}
_AST_PATH_GUARDS = {
    "realpath", "abspath", "normpath", "commonpath", "commonprefix",
    "basename", "secure_filename", "safe_join", "is_safe_path", "relative_to",
}
_AST_URL_GUARDS = {
    "urlparse", "urlsplit", "url_has_allowed_host_and_scheme",
    "is_safe_url", "is_valid_url", "validate_url",
}
_AST_VALUE_GUARDS = {
    "int", "float", "bool", "UUID", "uuid4", "ip_address", "isinstance",
    "isdigit", "isalnum", "isalpha", "quote", "quote_plus", "escape",
    "clean", "sanitize", "validate",
}
_AST_GUARD_NAMES = _AST_PATH_GUARDS | _AST_URL_GUARDS | _AST_VALUE_GUARDS

_AST_PATH_SINKS = {
    "open", "io.open", "os.open", "os.remove", "os.unlink", "os.rmdir",
    "os.listdir", "os.stat", "os.lstat", "os.makedirs", "os.mkdir",
    "shutil.rmtree", "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.move",
    "send_file", "flask.send_file", "send_from_directory", "flask.send_from_directory",
    "tarfile.open", "zipfile.ZipFile", "Path", "pathlib.Path",
}
_AST_PATH_METHODS = {"extractall", "extract", "read_text", "read_bytes", "write_text", "write_bytes"}
_AST_SSRF_SINKS = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.patch", "requests.request",
    "urllib.request.urlopen", "urllib.urlopen", "urlopen",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
}
_AST_REDIRECT_SINKS = {
    "redirect", "flask.redirect", "django.shortcuts.redirect",
    "HttpResponseRedirect", "RedirectResponse",
}
_AST_CMD_SINKS = {
    "os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput",
    "subprocess.Popen", "subprocess.run", "subprocess.call",
    "subprocess.check_output", "subprocess.check_call",
}
_AST_CODE_SINKS = {"eval", "exec", "compile", "__import__", "importlib.import_module"}
_AST_DESER_SINKS = {
    "pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load",
    "marshal.loads", "marshal.load", "yaml.unsafe_load", "jsonpickle.decode",
}


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _has_input_source(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in _AST_INPUT_ATTRS:
            base = _call_name(sub.value)
            if base in ("request", "flask.request", "self.request", "os", "sys"):
                return True
        if isinstance(sub, ast.Call) and _call_name(sub.func) in ("input", "raw_input", "os.getenv"):
            return True
    return False


def _calls_guard(node: ast.AST, extra_guards: set[str] | None = None) -> bool:
    guards = _AST_GUARD_NAMES | (extra_guards or set())
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            cname = _call_name(sub.func)
            leaf = cname.split(".")[-1]
            if cname in guards or leaf in guards or leaf.startswith(("sanitize", "validate", "check_", "is_safe", "safe_")):
                return True
            if leaf == "startswith":
                return True
    return False


def _has_raise_or_return(stmts: list[ast.stmt]) -> bool:
    for s in stmts:
        for sub in ast.walk(s):
            if isinstance(sub, (ast.Raise, ast.Return)):
                return True
    return False


# ── Wide mode ───────────────────────────────────────────────────────────────
# 1. Security surface: a call whose name says it touches a database, shell,
#    HTTP client, deserializer, file path, template, token or permission is
#    flagged by presence alone (low severity, once per kind per function).
# 2. Parameter taint: a parameter-derived value is built into a string
#    (f-string, %, .format(), +) and then passed to an external call.

_CAMEL_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+")

# (kind, CWE, OWASP, word prefixes, exact words). A call name is split into
# words (`run_shell`, `executeQuery`, `os.popen`) and the first kind with a
# matching word wins. Prefixes keep `load` from matching `download`/`payload`.
_SURFACE_KINDS = (
    ("sql", "CWE-89", "A03:2021", ("sql", "query", "execute", "fetchall", "fetchone", "fetchmany"), ()),
    ("shell", "CWE-78", "A03:2021", ("cmd", "shell", "popen"), ()),
    ("code", "CWE-94", "A03:2021", (), ("eval", "exec", "execfile")),
    ("deser", "CWE-502", "A08:2021", ("deserialize", "load", "pickle", "unpickle", "yaml"), ()),
    ("path", "CWE-22", "A01:2021", ("extract",), ()),
    ("render", "CWE-79", "A03:2021", ("render",), ()),
    ("http", "CWE-918", "A10:2021", ("request", "fetch", "urlopen", "urlretrieve"), ()),
    ("auth", "CWE-287", "A07:2021", ("jwt", "token", "password"), ()),
    ("perm", "CWE-732", "A01:2021", ("chmod",), ()),
)
_SURFACE_PATH = ("path", "CWE-22", "A01:2021")
_SURFACE_PATH_CALLS = {
    "open", "io.open", "codecs.open", "os.open",
    "os.path.join", "posixpath.join", "ntpath.join",
}
_SURFACE_PATH_LEAVES = {"Path", "PurePath", "PosixPath", "WindowsPath", "joinpath"}
_JSON_LIBS = {"json", "simplejson", "ujson", "orjson"}
_SURFACE_WHAT = {
    "sql": "database access", "shell": "shell/command execution", "code": "dynamic code execution",
    "deser": "deserialization", "path": "file path handling", "render": "template rendering",
    "http": "outbound HTTP request", "auth": "authentication token/credential handling",
    "perm": "file permission change",
}

# Calls that stay inside the function or only log/raise: formatting a
# parameter into these is not a flow into an external call.
_AST_BENIGN_CALLS = frozenset({
    "print", "len", "str", "int", "float", "bool", "repr", "bytes", "bytearray", "list", "dict", "set",
    "tuple", "frozenset", "sorted", "reversed", "min", "max", "sum", "any", "all", "range", "enumerate",
    "zip", "map", "filter", "isinstance", "issubclass", "hasattr", "getattr", "setattr", "type", "id",
    "hash", "format", "ord", "chr", "round", "abs", "super", "iter", "next", "vars", "dir", "callable",
    "ascii", "bin", "hex", "oct", "abort", "_", "gettext", "ngettext", "lazy_gettext",
})
_AST_BENIGN_METHODS = frozenset({
    "format", "join", "append", "extend", "insert", "add", "update", "get", "pop", "setdefault", "remove",
    "discard", "split", "rsplit", "splitlines", "strip", "lstrip", "rstrip", "replace", "startswith",
    "endswith", "lower", "upper", "title", "capitalize", "encode", "decode", "items", "keys", "values",
    "copy", "index", "count", "find", "rfind", "write", "writelines", "flush",
    "debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log",
})
_AST_EXC_SUFFIXES = ("Error", "Exception", "Warning")


def _call_words(cname: str) -> list[str]:
    parts = cname.split(".")
    words: list[str] = []
    for i, part in enumerate(parts):
        if part == "request" and i < len(parts) - 1:
            continue  # the framework request object (`request.args.get`), not an HTTP call
        for chunk in part.split("_"):
            words.extend(w.lower() for w in _CAMEL_WORD.findall(chunk))
    return words


def _surface_kind(cname: str, leaf: str) -> tuple[str, str, str] | None:
    """(kind, CWE, OWASP) when the call name is on the security surface."""
    if not cname:
        return None
    words = _call_words(cname)
    root = cname.split(".")[0]
    for kind, cwe, owasp, prefixes, exact in _SURFACE_KINDS:
        if kind == "deser" and root in _JSON_LIBS:
            continue  # JSON cannot execute code on load
        if any(w in exact or w.startswith(prefixes) for w in words):
            return kind, cwe, owasp
    if (
        cname in _SURFACE_PATH_CALLS
        or cname.startswith("pathlib.")
        or leaf in _SURFACE_PATH_LEAVES
        or "send_file" in cname.lower()
    ):
        return _SURFACE_PATH
    return None


def _is_external_call(func: ast.AST, leaf: str) -> bool:
    if leaf.endswith(_AST_EXC_SUFFIXES) or leaf.startswith(("assert", "_assert")):
        return False
    if isinstance(func, ast.Name):
        return leaf not in _AST_BENIGN_CALLS
    if isinstance(func, ast.Attribute):
        return leaf not in _AST_BENIGN_METHODS
    return False


def _is_strish(expr: ast.AST, str_vars: set[str]) -> bool:
    """An operand known to be a string: literal, f-string, formatted
    expression, or a variable already holding one."""
    if isinstance(expr, ast.Constant):
        return isinstance(expr.value, str)
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.Name):
        return expr.id in str_vars
    return _is_str_format(expr, str_vars)


def _is_str_format(expr: ast.AST, str_vars: set[str]) -> bool:
    """f"..{x}", "..%s" % x, "..{}".format(x), or "..." + x."""
    if isinstance(expr, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in expr.values)
    if isinstance(expr, ast.BinOp):
        if isinstance(expr.op, ast.Mod):
            return _is_strish(expr.left, str_vars)
        if isinstance(expr.op, ast.Add):
            return _is_strish(expr.left, str_vars) or _is_strish(expr.right, str_vars)
        return False
    return isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format"


def _formats_taint(expr: ast.AST, taint: set[str], formatted: dict[str, int], guarded: set[str]) -> bool:
    if _calls_guard(expr):
        return False
    names = _names_in(expr)
    return bool((names & taint) or (names & (set(formatted) - guarded)) or _has_input_source(expr))


def _track_formatted_strings(
    fn: ast.AST,
    taint: set[str],
    guarded: set[str],
    str_vars: set[str],
    formatted: dict[str, int],
) -> None:
    """Fills `str_vars` (variables holding a string) and `formatted` (variables
    built by formatting a parameter-derived value, with the line where that
    happened). Assignments are read in source order, so a call only sees
    formatting that came before it."""
    assigns = [n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AugAssign))]
    for node in sorted(assigns, key=lambda n: (n.lineno, n.col_offset)):
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            built = _is_str_format(node.value, str_vars)
            if built or _is_strish(node.value, str_vars):
                str_vars.update(targets)
            tainted_build = built and _formats_taint(node.value, taint, formatted, guarded)
            for t in targets:
                if tainted_build and t not in guarded:
                    formatted.setdefault(t, node.lineno)
                elif not built:
                    formatted.pop(t, None)
        elif isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            t = node.target.id
            if (
                (t in str_vars or _is_strish(node.value, str_vars))
                and t not in guarded
                and _formats_taint(node.value, taint, formatted, guarded)
            ):
                str_vars.add(t)
                formatted.setdefault(t, node.lineno)


def _scan_ast_function(
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    file_path: str,
    job_id: str,
) -> list[Finding]:
    params: set[str] = set()
    for arg in (
        list(getattr(fn.args, "posonlyargs", []))
        + list(fn.args.args)
        + list(fn.args.kwonlyargs)
    ):
        if arg.arg not in ("self", "cls"):
            params.add(arg.arg)
    if fn.args.vararg and fn.args.vararg.arg not in ("self", "cls"):
        params.add(fn.args.vararg.arg)
    if fn.args.kwarg and fn.args.kwarg.arg not in ("self", "cls"):
        params.add(fn.args.kwarg.arg)

    tainted: set[str] = set(params)
    guarded_vars: set[str] = set()
    has_path_guard = False
    has_url_guard = False

    # Pass 1: find branch guards (`if ...: raise/return`) and sanitizer calls
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            cname = _call_name(node.func)
            leaf = cname.split(".")[-1]
            if leaf in _AST_PATH_GUARDS or cname in _AST_PATH_GUARDS or leaf == "startswith":
                has_path_guard = True
                for a in node.args:
                    guarded_vars.update(_names_in(a))
            if leaf in _AST_URL_GUARDS or cname in _AST_URL_GUARDS:
                has_url_guard = True
                for a in node.args:
                    guarded_vars.update(_names_in(a))
        elif isinstance(node, ast.If):
            if _has_raise_or_return(node.body) or _has_raise_or_return(node.orelse):
                test_names = _names_in(node.test)
                test_src = ast.unparse(node.test) if hasattr(ast, "unparse") else ""
                if (
                    _calls_guard(node.test)
                    or ".." in test_src
                    or " in " in test_src
                    or "not in" in test_src
                    or "startswith" in test_src
                    or "scheme" in test_src
                    or "netloc" in test_src
                ):
                    guarded_vars.update(test_names)
                    if ".." in test_src or "startswith" in test_src or "realpath" in test_src or "abspath" in test_src:
                        has_path_guard = True
                    if "scheme" in test_src or "netloc" in test_src or "host" in test_src:
                        has_url_guard = True

    # Pass 2: propagate taint through assignments
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and node.value is not None:
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if _calls_guard(node.value):
                for t in targets:
                    guarded_vars.add(t)
                    tainted.discard(t)
            else:
                rhs_names = _names_in(node.value)
                if (rhs_names & (tainted - guarded_vars)) or _has_input_source(node.value):
                    for t in targets:
                        if t not in guarded_vars:
                            tainted.add(t)

    active_taint = tainted - guarded_vars
    has_explicit_source = _has_input_source(fn)
    heuristic_sev = "medium" if has_explicit_source else "low"
    findings: list[Finding] = []
    seen_lines: set[tuple[int, str]] = set()

    def emit(line: int, end_line: int, rule_id: str, severity: str, cwe: str, owasp: str, msg: str) -> None:
        key = (line, cwe)
        if key in seen_lines:
            return
        seen_lines.add(key)
        findings.append(
            Finding(
                job_id=job_id,
                file_path=file_path,
                line_start=line,
                line_end=max(line, end_line),
                rule_id=rule_id,
                tool="ast_sink",
                severity=severity,
                message=msg,
                cwe_ids=[cwe],
                owasp_category=owasp,
                code_snippet=_extract_snippet(file_path, line, max(line, end_line)),
            )
        )

    str_vars: set[str] = set()
    formatted_vars: dict[str, int] = {}
    surface_seen: set[str] = set()
    if ENABLE_AST_WIDE:
        _track_formatted_strings(fn, active_taint, guarded_vars, str_vars, formatted_vars)

    def formatted_flow(expr: ast.AST, call_line: int) -> bool:
        """The argument is a string built from a parameter-derived value, on or before this call."""
        if isinstance(expr, ast.Name):
            return expr.id in formatted_vars and formatted_vars[expr.id] <= call_line and expr.id not in guarded_vars
        return _is_str_format(expr, str_vars) and _formats_taint(expr, active_taint, formatted_vars, guarded_vars)

    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        cname = _call_name(node.func)
        leaf = cname.split(".")[-1]
        line = getattr(node, "lineno", fn.lineno)
        end_line = getattr(node, "end_lineno", line) or line
        arg_nodes = list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]
        arg_names = set().union(*(_names_in(a) for a in arg_nodes)) if arg_nodes else set()
        arg_tainted = bool(arg_names & active_taint) or any(_has_input_source(a) for a in arg_nodes)
        arg_guarded_inline = any(_calls_guard(a) for a in arg_nodes)

        # 1. Path traversal sinks (CWE-22)
        if (cname in _AST_PATH_SINKS or leaf in ("send_file", "send_from_directory")) and arg_tainted and not arg_guarded_inline and not has_path_guard:
            emit(
                line, end_line, "HS-AST-PATH", heuristic_sev, "CWE-22", "A01:2021",
                f"Unguarded parameter or input reaches file/path sink `{cname}` without path normalization or prefix validation.",
            )
        elif cname in ("os.path.join", "posixpath.join", "ntpath.join") and len(node.args) >= 2:
            tail_names = set().union(*(_names_in(a) for a in node.args[1:]))
            if ((tail_names & active_taint) or any(_has_input_source(a) for a in node.args[1:])) and not arg_guarded_inline and not has_path_guard:
                emit(
                    line, end_line, "HS-AST-PATH-JOIN", heuristic_sev, "CWE-22", "A01:2021",
                    f"Unguarded parameter joined into path via `{cname}` without `realpath`/`abspath` + `startswith` or `safe_join` check.",
                )
        elif isinstance(node.func, ast.Attribute) and node.func.attr in _AST_PATH_METHODS:
            recv_names = _names_in(node.func.value)
            if ((recv_names | arg_names) & active_taint) and not arg_guarded_inline and not has_path_guard:
                emit(
                    line, end_line, "HS-AST-PATH-METHOD", heuristic_sev, "CWE-22", "A01:2021",
                    f"Unguarded path/archive operation `.{node.func.attr}()` on parameter-derived value without traversal check.",
                )

        # 2. SSRF sinks (CWE-918)
        elif cname in _AST_SSRF_SINKS and arg_tainted and not arg_guarded_inline and not has_url_guard:
            emit(
                line, end_line, "HS-AST-SSRF", heuristic_sev, "CWE-918", "A10:2021",
                f"Unguarded parameter or input reaches outbound request sink `{cname}` without URL host/scheme validation.",
            )

        # 3. Open Redirect sinks (CWE-601)
        elif (cname in _AST_REDIRECT_SINKS or leaf in ("HttpResponseRedirect", "RedirectResponse")) and node.args:
            first_arg = node.args[0]
            if (
                ((_names_in(first_arg) & active_taint) or _has_input_source(first_arg))
                and not _calls_guard(first_arg)
                and not has_url_guard
            ):
                emit(
                    line, end_line, "HS-AST-REDIRECT", heuristic_sev, "CWE-601", "A01:2021",
                    f"Unguarded parameter or input controls redirect target in `{cname}` without host validation.",
                )

        # 4. Command injection sinks (CWE-78)
        elif cname in _AST_CMD_SINKS and arg_tainted and not arg_guarded_inline:
            emit(
                line, end_line, "HS-AST-CMDI", "high", "CWE-78", "A03:2021",
                f"Unguarded parameter or input reaches command execution sink `{cname}`.",
            )

        # 5. Dynamic code evaluation sinks (CWE-94)
        elif cname in _AST_CODE_SINKS and arg_tainted and not arg_guarded_inline:
            emit(
                line, end_line, "HS-AST-CODE", "high", "CWE-94", "A03:2021",
                f"Unguarded parameter or input reaches dynamic code execution sink `{cname}`.",
            )

        # 6. Unsafe deserialization sinks (CWE-502)
        elif (cname in _AST_DESER_SINKS or cname == "yaml.load") and arg_tainted:
            if cname == "yaml.load":
                kws = {kw.arg: (_call_name(kw.value) if kw.value else "") for kw in node.keywords}
                if "SafeLoader" in kws.get("Loader", ""):
                    continue
            emit(
                line, end_line, "HS-AST-DESER", "high", "CWE-502", "A08:2021",
                f"Untrusted input reaches unsafe deserialization sink `{cname}`.",
            )

        # 7. SQL query string interpolation (CWE-89)
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany", "raw") and node.args:
            q_arg = node.args[0]
            is_dynamic = isinstance(q_arg, (ast.JoinedStr, ast.BinOp)) or (
                isinstance(q_arg, ast.Call)
                and isinstance(q_arg.func, ast.Attribute)
                and q_arg.func.attr == "format"
            )
            if is_dynamic and ((_names_in(q_arg) & active_taint) or _has_input_source(q_arg)):
                emit(
                    line, end_line, "HS-AST-SQLI", "high", "CWE-89", "A03:2021",
                    f"Dynamic SQL query constructed from unguarded parameter in `.{node.func.attr}()`.",
                )

    # Wide mode runs as a second pass so every narrow rule above fires exactly as
    # before; it only adds findings, and skips lines a narrow rule already covered.
    if ENABLE_AST_WIDE:
        narrow_lines = {l for l, _ in seen_lines}
        raised = {id(n.exc) for n in ast.walk(fn) if isinstance(n, ast.Raise) and isinstance(n.exc, ast.Call)}
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call) or id(node) in raised:
                continue
            cname = _call_name(node.func)
            leaf = cname.split(".")[-1]
            line = getattr(node, "lineno", fn.lineno)
            end_line = getattr(node, "end_lineno", line) or line
            if line in narrow_lines:
                continue
            arg_nodes = list(node.args) + [kw.value for kw in node.keywords if kw.value is not None]
            surface = _surface_kind(cname, leaf)
            kind = surface[0] if surface else None
            flows = (
                _is_external_call(node.func, leaf)
                and (kind or not leaf.startswith("_"))  # unnamed internal helpers are not external
                and not any(_calls_guard(a) for a in arg_nodes)
                and any(formatted_flow(a, line) for a in arg_nodes)
                and not (kind == "path" and has_path_guard)
                and not (kind == "http" and has_url_guard)
            )
            if flows:
                cwe, owasp = (surface[1], surface[2]) if surface else ("CWE-74", "A03:2021")
                severity = "high" if kind in ("sql", "shell", "code") else (
                    "medium" if kind or has_explicit_source else "low"
                )
                emit(
                    line, end_line, "HS-AST-PARAM-TAINT", severity, cwe, owasp,
                    f"Parameter-derived value is built into a string by formatting (f-string, %, .format() or +) "
                    f"and passed to `{cname}` with no validation or escaping in this function.",
                )
            elif surface and kind not in surface_seen:
                surface_seen.add(kind)
                emit(
                    line, end_line, f"HS-AST-SURFACE-{kind.upper()}", "low", surface[1], surface[2],
                    f"Security-surface match: `{cname}` is {_SURFACE_WHAT[kind]}. Flagged by name only; "
                    f"no tainted flow into it was established.",
                )

    return findings


def run_ast_sinks(target_path: Path, job_id: str = "standalone") -> list[Finding]:
    """Deterministic zero-token Python AST sink & guard scanner."""
    if not ENABLE_AST_SINKS:
        return []
    files: list[Path] = []
    if target_path.is_file():
        if str(target_path).endswith(".py"):
            files = [target_path]
    elif target_path.is_dir():
        files = sorted(target_path.rglob("*.py"))

    out: list[Finding] = []
    for p in files:
        try:
            source = p.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(p))
        except (SyntaxError, OSError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                out.extend(_scan_ast_function(node, str(p), job_id))
    return out


def run_ast_sinks_batch(paths: list[Path], job_id: str = "standalone") -> dict[str, list[Finding]]:
    out: dict[str, list[Finding]] = {str(Path(p).resolve()): [] for p in paths}
    if not ENABLE_AST_SINKS:
        return out
    for p in paths:
        resolved = str(Path(p).resolve())
        out[resolved] = run_ast_sinks(Path(p), job_id=job_id)
    return out


# ─── CodeQL Static Analysis (Python) ────────────────────────────────────────

ENABLE_CODEQL = os.getenv("SAST_ENABLE_CODEQL", "1") not in ("0", "false", "False")
CODEQL_BIN = os.getenv("CODEQL_BIN", "codeql")
CODEQL_SUITE = os.getenv(
    "CODEQL_PYTHON_SUITE",
    "codeql/python-queries:codeql-suites/python-security-extended.qls",
)
CODEQL_JOBS = int(os.getenv("CODEQL_JOBS", "2"))
_CWE_TAG_RE = re.compile(r"external/cwe/cwe-0*(\d+)", re.I)


def _resolve_codeql_bin() -> str | None:
    if not ENABLE_CODEQL:
        return None
    found = shutil.which(CODEQL_BIN)
    if found:
        return found
    opt_bin = Path("/opt/codeql/codeql")
    return str(opt_bin) if opt_bin.is_file() else None


def codeql_available() -> bool:
    """True when CodeQL CLI is enabled and present on PATH or /opt/codeql."""
    return _resolve_codeql_bin() is not None


def _codeql_severity(rule_meta: dict, result_level: str) -> str:
    props = rule_meta.get("properties") or {}
    try:
        sec_sev = float(props.get("security-severity", 0.0))
        if sec_sev >= 9.0:
            return "critical"
        if sec_sev >= 7.0:
            return "high"
        if sec_sev >= 4.0:
            return "medium"
        if sec_sev > 0.0:
            return "low"
    except (TypeError, ValueError):
        pass
    prob_sev = str(props.get("problem.severity", "")).lower()
    if prob_sev == "error" or result_level == "error":
        return "high"
    if prob_sev == "warning" or result_level == "warning":
        return "medium"
    return "low"


def _parse_codeql_sarif(sarif: dict, path_map: dict[str, str], job_id: str) -> list[Finding]:
    findings: list[Finding] = []
    for run in sarif.get("runs") or []:
        rules_by_id: dict[str, dict] = {}
        driver_rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        for r in driver_rules:
            if r.get("id"):
                rules_by_id[r["id"]] = r
        for ext in run.get("tool", {}).get("extensions") or []:
            for r in ext.get("rules") or []:
                if r.get("id"):
                    rules_by_id[r["id"]] = r

        for res in run.get("results") or []:
            rule_id = res.get("ruleId") or "codeql-python"
            rule_meta = rules_by_id.get(rule_id) or {}
            tags = (rule_meta.get("properties") or {}).get("tags") or []
            cwe_ids = []
            for t in tags:
                m = _CWE_TAG_RE.search(str(t))
                if m:
                    cwe = f"CWE-{m.group(1)}"
                    if cwe not in cwe_ids:
                        cwe_ids.append(cwe)
            if not cwe_ids:
                continue  # Ignore non-security CodeQL quality/lint rules

            severity = _codeql_severity(rule_meta, str(res.get("level") or "warning").lower())
            msg = ((res.get("message") or {}).get("text") or rule_meta.get("shortDescription", {}).get("text") or rule_id).strip()

            for loc in res.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                uri = ((phys.get("artifactLocation") or {}).get("uri") or "").lstrip("/")
                region = phys.get("region") or {}
                start_line = int(region.get("startLine") or 1)
                end_line = int(region.get("endLine") or start_line)
                orig_path = path_map.get(uri) or path_map.get(Path(uri).name) or uri
                if not orig_path:
                    continue
                findings.append(
                    Finding(
                        job_id=job_id,
                        file_path=orig_path,
                        line_start=start_line,
                        line_end=end_line,
                        rule_id=rule_id,
                        tool="codeql",
                        severity=severity,
                        message=msg,
                        cwe_ids=cwe_ids,
                        code_snippet=_extract_snippet(orig_path, start_line, end_line),
                    )
                )
    return findings


def _run_codeql_cmd(targets: list[Path], job_id: str) -> list[Finding] | None:
    bin_path = _resolve_codeql_bin()
    if not bin_path:
        return []
    py_targets = [Path(t) for t in targets if Path(t).is_dir() or str(t).endswith(".py")]
    if not py_targets:
        return []

    timeout = 240 + 20 * max(0, len(py_targets) - 1)
    with tempfile.TemporaryDirectory(prefix=f"hs_codeql_{job_id}_") as tmp:
        tmp_root = Path(tmp)
        src_root = tmp_root / "src"
        src_root.mkdir(parents=True, exist_ok=True)

        path_map: dict[str, str] = {}
        for idx, t in enumerate(py_targets):
            if t.is_file():
                rel = f"f{idx}_{t.name}"
                dest = src_root / rel
                shutil.copy2(t, dest)
                path_map[rel] = str(t)
            elif t.is_dir():
                for sub in t.rglob("*.py"):
                    rel = f"d{idx}_{sub.relative_to(t).as_posix().replace('/', '_')}"
                    dest = src_root / rel
                    shutil.copy2(sub, dest)
                    path_map[rel] = str(sub)

        if not path_map:
            return []

        return _codeql_scan(bin_path, src_root, tmp_root, path_map, job_id, timeout)


def _codeql_scan(
    bin_path: str, src_root: Path, tmp_root: Path, path_map: dict[str, str], job_id: str, timeout: int
) -> list[Finding] | None:
    """Build one CodeQL database from `src_root`, analyze it, and map the SARIF
    locations (relative to `src_root`) back to real paths with `path_map`."""
    db_dir = tmp_root / "db"
    sarif_path = tmp_root / "results.sarif"
    create_cmd = [
        bin_path, "database", "create", str(db_dir),
        "--language=python", f"--source-root={src_root}",
        f"--threads={CODEQL_JOBS}", "--overwrite",
    ]
    analyze_cmd = [
        bin_path, "database", "analyze", str(db_dir), CODEQL_SUITE,
        "--format=sarif-latest", f"--output={sarif_path}",
        f"--threads={CODEQL_JOBS}",
    ]
    started = time.monotonic()
    try:
        c_res = subprocess.run(create_cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        if c_res.returncode != 0:
            logger.warning(f"[{job_id}] CodeQL database create exited {c_res.returncode}: {c_res.stderr[:300]}")
            return None
        a_res = subprocess.run(analyze_cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        if a_res.returncode != 0 or not sarif_path.is_file():
            logger.warning(f"[{job_id}] CodeQL analyze exited {a_res.returncode}: {a_res.stderr[:300]}")
            return None
        sarif = json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
        findings = _parse_codeql_sarif(sarif, path_map, job_id)
        logger.info(
            f"[{job_id}] CodeQL on {len(path_map)} files: {time.monotonic() - started:.0f}s, {len(findings)} findings"
        )
        return findings
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
        logger.warning(f"[{job_id}] CodeQL execution failed after {time.monotonic() - started:.0f}s: {e}")
        return None


def run_codeql_tree(source_root: Path, job_id: str = "standalone") -> list[Finding] | None:
    """Analyze a whole source tree in place (no flat renaming), so imports between
    its files resolve. Findings are returned for every .py file under the root;
    the caller keeps the ones it asked for. None means the analysis failed."""
    bin_path = _resolve_codeql_bin()
    if not bin_path or not codeql_available():
        return []
    root = Path(source_root)
    path_map = {p.relative_to(root).as_posix(): str(p) for p in root.rglob("*.py")}
    if not path_map:
        return []
    timeout = 240 + 20 * min(len(path_map) - 1, 40)
    with tempfile.TemporaryDirectory(prefix=f"hs_codeql_{job_id}_") as tmp:
        return _codeql_scan(bin_path, root, Path(tmp), path_map, job_id, timeout)


def run_codeql(target_path: Path, job_id: str = "standalone") -> list[Finding]:
    """Run CodeQL Python analysis when the CodeQL CLI is available."""
    if not codeql_available():
        return []
    res = _run_codeql_cmd([target_path], job_id)
    return res if res is not None else []


def run_codeql_batch(paths: list[Path], job_id: str = "standalone") -> dict[str, list[Finding]] | None:
    """Scan a batch of Python files in a single CodeQL database."""
    if not codeql_available():
        return {str(Path(p).resolve()): [] for p in paths}
    findings = _run_codeql_cmd(paths, job_id)
    if findings is None:
        return None
    out: dict[str, list[Finding]] = {str(Path(p).resolve()): [] for p in paths}
    for f in findings:
        out.setdefault(str(Path(f.file_path).resolve()), []).append(f)
    return out


# ─── Orchestrator ────────────────────────────────────────────────────────────

def run_static_analysis(target_path: Path, job_id: str = "standalone") -> list[Finding]:
    """Run all static analysis tools and return combined findings."""
    findings: list[Finding] = []

    semgrep_findings = run_semgrep(target_path, job_id)
    logger.info(f"[{job_id}] Semgrep: {len(semgrep_findings)} findings")
    findings.extend(semgrep_findings)

    bandit_findings = run_bandit(target_path, job_id)
    logger.info(f"[{job_id}] Bandit: {len(bandit_findings)} findings")
    findings.extend(bandit_findings)

    ast_findings = run_ast_sinks(target_path, job_id)
    logger.info(f"[{job_id}] AST sink gate: {len(ast_findings)} findings")
    findings.extend(ast_findings)

    if codeql_available():
        codeql_findings = run_codeql(target_path, job_id)
        logger.info(f"[{job_id}] CodeQL: {len(codeql_findings)} findings")
        findings.extend(codeql_findings)

    logger.info(f"[{job_id}] Total static analysis: {len(findings)} findings")
    return findings


