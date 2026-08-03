"""CPG-guided PoC synthesis — fallback driver builder for `verify/`.

When the heuristic `oracles.build_probe` can't construct a driver (multi-arg
sinks, non-obvious entrypoints), ask the LLM — guided by the CPG taint path the
pipeline already computed — to write the *call snippet* that routes attacker
input into the vulnerable function.

Trust boundary: the LLM never touches the marker plumbing. It only supplies a
call snippet that uses a variable `HS_INPUT` (the attacker value) and the
imported module `mod`. WE render the payload driver (HS_INPUT = exploit payload
with the marker) and the control driver (HS_INPUT = benign input) from the SAME
snippet. So a hardcoded/faked PoC is still caught by the differential control
run in `verify_finding`, and the per-run random marker can't be pre-baked.

Returns the same probe shape as the heuristic:
    {files, marker, payload_driver, control_driver}
or {"error": <reason>} on failure. Never raises into the pipeline.
"""
import json
import logging
import uuid
from pathlib import Path

from hackersec.analysis.verify.oracles import (
    _find_target_function, _payloads, _control_inputs, ORACLE_CWES,
)

logger = logging.getLogger(__name__)

# We own the import + try/except scaffold; the LLM only fills the call body.
_IMPORT_SHIM = (
    'import importlib.util, sys\n'
    'sys.path.insert(0, "/work")\n'
    'spec = importlib.util.spec_from_file_location("target", "/work/target.py")\n'
    'mod = importlib.util.module_from_spec(spec)\n'
    'try:\n'
    '    spec.loader.exec_module(mod)\n'
    'except Exception as e:\n'
    '    print("LOAD_ERR", e); sys.exit(0)\n'
)


def _render(call_snippet: str, input_value: str) -> str:
    body = "\n".join("    " + ln for ln in call_snippet.splitlines()) or "    pass"
    return (
        _IMPORT_SHIM
        + f"HS_INPUT = {input_value!r}\n"
        + "try:\n" + body + "\n"
        + "except Exception as e:\n    print('CALL_ERR', type(e).__name__)\n"
    )


def _build_prompt(source: str, func: str | None, cwe: set, taint_paths) -> str:
    taint = ""
    if taint_paths:
        try:
            taint = "\n".join(str(p) for p in taint_paths[:5])
        except Exception:
            taint = str(taint_paths)[:500]
    return (
        "You write a minimal Python proof-of-concept CALL for a vulnerable function.\n"
        "The target file is importable as the module `mod`. A variable `HS_INPUT` (str) holds the\n"
        "attacker-controlled input. Write ONLY the code that calls the vulnerable function so that\n"
        "HS_INPUT reaches the dangerous sink; pass benign literals for any other required arguments.\n"
        "Do NOT print anything. Do NOT hardcode outputs. Use `mod.` and `HS_INPUT`.\n\n"
        f"CWE: {', '.join(sorted(cwe))}\n"
        f"Vulnerable function (best guess): {func or 'unknown — pick it from the source'}\n"
        f"CPG taint path (source -> sink):\n{taint or 'n/a'}\n\n"
        f"Target source:\n{source[:2000]}\n\n"
        'Respond as JSON: {"call": "<python call snippet>"}'
    )


def synthesize_probe(finding, *, llm=None) -> dict:
    """Return a probe dict, or {"error": reason}. Never raises."""
    cwe = set(finding.cwe_ids or [])
    if not (cwe & ORACLE_CWES):
        return {"error": "no_driver"}

    # Resolve source (real file preferred, else the captured snippet).
    source = None
    try:
        p = Path(finding.file_path)
        if p.is_file():
            source = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        source = None
    source = source or finding.code_snippet
    if not source:
        return {"error": "no_driver"}

    func = _find_target_function(source, finding.line_start)
    taint = (finding.cpg_context or {}).get("taint_paths") if isinstance(finding.cpg_context, dict) else None

    if llm is None:
        from hackersec.analysis.llm.client import OllamaClient
        llm = OllamaClient()

    try:
        res = llm.generate(_build_prompt(source, func, cwe, taint))
    except Exception as e:
        logger.warning(f"PoC agent LLM call failed: {e}")
        return {"error": "llm_unavailable"}

    if res.get("llm_status") != "success":
        return {"error": "llm_unavailable"}

    try:
        call = json.loads(res.get("response") or "{}").get("call", "")
    except (json.JSONDecodeError, TypeError):
        return {"error": "no_driver"}

    # The snippet must actually route HS_INPUT through the target module.
    if not call or "HS_INPUT" not in call or "mod" not in call:
        return {"error": "no_driver"}

    marker = f"PWNED_{uuid.uuid4().hex[:12]}"
    payload = _payloads(cwe, marker)[0]
    control = _control_inputs(cwe)[0]
    return {
        "files": {"target.py": source},
        "marker": marker,
        "payload_driver": _render(call, payload),
        "control_driver": _render(call, control),
    }
