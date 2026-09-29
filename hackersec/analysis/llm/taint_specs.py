"""
IRIS-style taint specifications (Li et al., ICLR 2025).

Fixed source/sink lists miss project-specific APIs: a framework's request
wrapper, an ORM's raw-SQL helper, a project's own `run_command`. Following
IRIS, the LLM labels the calls a function actually makes as sources, sinks
or neither; Joern then checks which labelled sinks are reached by labelled
sources or by the function's parameters, and each flow becomes a candidate
finding that the board judges, as IRIS's LLM filtering step does.
"""

import ast
import os
import re
import textwrap

from hackersec.analysis.llm.parser import _extract_json
from hackersec.analysis.llm.prompter import _INJECTION_GUARD
from hackersec.analysis.schema import Finding

MAX_CALLS = 40
MAX_SINK_SITES = int(os.getenv("LLM_TAINT_MAX_SINKS", "6"))
TEMP_SPEC = 0.0
_CWE = re.compile(r"CWE-(\d+)", re.I)
_CALL = re.compile(r"([A-Za-z_][\w.]*)\s*\(")
# Calls that can never be a source or a sink; listing them only costs tokens.
_TRIVIAL = {
    "len", "str", "int", "float", "bool", "list", "dict", "set", "tuple", "range", "enumerate", "zip",
    "isinstance", "issubclass", "hasattr", "print", "sorted", "reversed", "min", "max", "sum", "any", "all",
    "super", "type", "repr", "abs", "round", "map", "filter", "iter", "next", "id", "hash", "format",
}


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        base = _dotted(node.func)
        return f"{base}()" if base else None
    if isinstance(node, ast.Subscript):
        base = _dotted(node.value)
        return f"{base}[]" if base else None
    return None


def candidate_calls(code: str, start_line: int) -> list[dict]:
    """Distinct callees in the function with their (absolute) line numbers."""
    calls: dict[str, set[int]] = {}
    try:
        tree = ast.parse(textwrap.dedent(code))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                name = _dotted(n.func)
                if name:
                    calls.setdefault(name, set()).add(start_line + n.lineno - 1)
    except (SyntaxError, ValueError):
        for i, line in enumerate(code.splitlines()):
            for m in _CALL.finditer(line):
                calls.setdefault(m.group(1), set()).add(start_line + i)
    items = [
        {"callee": name, "lines": sorted(lines)}
        for name, lines in calls.items()
        if name.split(".")[-1] not in _TRIVIAL or "." in name
    ]
    items.sort(key=lambda c: c["lines"][0])
    return items[:MAX_CALLS]


def build_spec_prompt(function_name: str, code_text: str, calls: list[dict]) -> str:
    listing = "\n".join(f"- {c['callee']} (line {', '.join(map(str, c['lines'][:4]))})" for c in calls)
    return f"""You are labelling APIs for a taint analysis of one Python function.
For each call listed below decide its role:
- "source": returns data an attacker can influence (HTTP request data, uploaded files, network reads, environment variables, command-line arguments, message queues, data read from user-supplied paths or deserialized from untrusted input).
- "sink": performs a security-sensitive operation on its arguments (runs a shell command, evaluates or imports code, runs SQL, opens/reads/writes/deletes a file path, deserializes, renders HTML or templates, redirects, makes an outbound request, compiles a regular expression, sets permissions, writes secrets to logs).
- anything else is not listed.
For every sink give the CWE a vulnerability at that call would be, e.g. "CWE-78", "CWE-89", "CWE-22", "CWE-502", "CWE-79", "CWE-918", "CWE-1333".
Label by what the API does, not by whether this particular use looks safe.
{_INJECTION_GUARD}

===== CALLS IN {function_name} =====
{listing}

===== FUNCTION (for reference) =====
[UNTRUSTED_CODE_START]
{code_text}
[UNTRUSTED_CODE_END]

Output one JSON object exactly matching this schema, listing only sources and sinks:
{{"labels": [{{"callee": "subprocess.call", "role": "sink", "cwe": "CWE-78"}}, {{"callee": "request.args.get", "role": "source", "cwe": ""}}]}}

Respond with the JSON object only, starting with {{:"""


def parse_spec_response(raw_text: str, calls: list[dict]) -> dict:
    """{"status", "sources": [callee], "sinks": [{"callee", "cwe", "lines"}]},
    keeping only callees that really occur in the function."""
    data = _extract_json(raw_text)
    if data is None or not isinstance(data.get("labels", []), list):
        return {"status": "failed_parsing", "sources": [], "sinks": []}
    by_name = {c["callee"]: c for c in calls}
    sources, sinks = [], []
    for item in data.get("labels") or []:
        if not isinstance(item, dict):
            continue
        callee = str(item.get("callee") or "").strip()
        call = by_name.get(callee)
        if call is None:
            continue
        role = str(item.get("role") or "").strip().lower()
        if role == "source":
            sources.append(callee)
        elif role == "sink":
            m = _CWE.search(str(item.get("cwe") or ""))
            sinks.append({"callee": callee, "cwe": f"CWE-{m.group(1)}" if m else None, "lines": call["lines"]})
    return {"status": "success", "sources": sorted(set(sources)), "sinks": sinks}


def infer_specs(client, model: str, function_name: str, code_text: str, calls: list[dict]) -> dict:
    """Ask the LLM to label the function's calls. Transport failures are
    returned as-is so the caller can wait for Ollama and retry."""
    if not calls:
        return {"llm_status": "success", "status": "no_calls", "sources": [], "sinks": []}
    res = client.generate(
        build_spec_prompt(function_name, code_text, calls),
        model=model, temperature=TEMP_SPEC, seed=11, max_tokens=600,
    )
    if res["llm_status"] != "success":
        return res
    return {"llm_status": "success", **parse_spec_response(res["response"], calls)}


def sink_sites(sinks: list[dict]) -> list[dict]:
    """(callee, cwe, line, Joern call name) for each labelled sink occurrence."""
    sites = []
    for s in sinks:
        name = s["callee"].split(".")[-1].rstrip("()[]") or s["callee"]
        for line in s["lines"]:
            sites.append({"callee": s["callee"], "cwe": s["cwe"], "line": line, "call_name": name})
    return sites[:MAX_SINK_SITES]


def taint_findings(site_results: list[tuple[dict, dict]], file_path: str, file_lines: list[str], job_id: str) -> list[Finding]:
    """One candidate finding per labelled sink that a source actually reaches."""
    findings = []
    for site, cpg in site_results:
        if cpg.get("cpg_status") != "success" or not cpg.get("taint_paths"):
            continue
        line = site["line"]
        findings.append(Finding(
            job_id=job_id,
            file_path=file_path,
            line_start=line,
            line_end=line,
            rule_id=f"llm-spec:{site['callee']}",
            tool="llm_taint",
            severity="high",
            message=f"Untrusted data reaches {site['callee']}, labelled a sink for {site['cwe'] or 'an unspecified weakness'}",
            cwe_ids=[site["cwe"]] if site["cwe"] else [],
            code_snippet=file_lines[line - 1].strip() if 0 < line <= len(file_lines) else None,
            cpg_context=cpg,
        ))
    return findings
