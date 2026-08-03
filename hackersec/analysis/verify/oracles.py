"""Per-CWE exploit probes: build a driver + success oracle for a finding.

MVP covers the Python injection / RCE family, where a cheap, deterministic
success oracle exists: feed a malicious payload to the *real* flagged function
and see whether it executes attacker code (prints a unique sentinel marker).
If the function sanitizes the input, the marker never appears → reproduced=False.
That False-vs-True split is exactly the false-positive killer the static layer
can't provide.

Classes without a cheap code-level oracle (crypto, auth, config CWEs) are not
in ORACLE_CWES, so `verify_finding` returns reproduced=None for them — honest
"not dynamically checkable", never a false negative.

# ponytail: driver invokes the first positional arg only; multi-arg sinks and
# non-function entrypoints fall back to reproduced=None. Upgrade path: have the
# LLM synthesize a tailored PoC (Part C), and drive live web apps for DAST.
"""
import re
import uuid
from pathlib import Path

# CWE families we can dynamically probe today.
COMMAND_INJECTION = {"CWE-78", "CWE-77"}
CODE_INJECTION = {"CWE-94", "CWE-95"}
ORACLE_CWES = COMMAND_INJECTION | CODE_INJECTION


def _payloads(cwe_ids: set, marker: str) -> list:
    """Payload strings crafted to print `marker` iff the sink executes them."""
    out = []
    if cwe_ids & CODE_INJECTION:
        # eval/exec: payload is Python that shells out to echo the marker.
        out.append(f"__import__('os').system('echo {marker}')")
    if cwe_ids & COMMAND_INJECTION:
        # os.system/subprocess string concat: break out and echo the marker.
        out.append(f"; echo {marker}")
        out.append(f"| echo {marker}")   # ';' and '|' both print; '$()' would not (dropped)
    return out


def _control_inputs(cwe_ids: set) -> list:
    """Benign inputs that exercise the same function but must NOT print the marker.

    The differential test: a real vuln fires with the payload and stays silent
    with the control. A hardcoded/faked PoC prints the marker regardless of
    input — so if the marker shows up under the control too, we reject it.
    """
    out = []
    if cwe_ids & CODE_INJECTION:
        out.append("1 + 1")          # valid expr, evaluates harmlessly
    if cwe_ids & COMMAND_INJECTION:
        out.append("hello")          # no shell metacharacters
    return out or ["benign"]


def _find_target_function(source: str, line_start: int) -> str | None:
    """Name of the `def` enclosing/nearest above the flagged line."""
    lines = source.splitlines()
    best = None
    for i, line in enumerate(lines, start=1):
        m = re.match(r"\s*def\s+([A-Za-z_]\w*)\s*\(", line)
        if m and i <= line_start:
            best = m.group(1)  # last def at/above the finding wins
    return best


# Driver template: import the target file, call the flagged function with each
# payload, and print the marker only if the payload actually executed.
_DRIVER = '''\
import importlib.util, sys
sys.path.insert(0, "/work")
spec = importlib.util.spec_from_file_location("target", "/work/target.py")
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
except Exception as e:
    print("LOAD_ERR", e)
    sys.exit(0)

fn = getattr(mod, {func!r}, None)
if fn is None:
    print("NO_FUNC")
    sys.exit(0)

payloads = {payloads!r}
for p in payloads:
    try:
        fn(p)
    except Exception as e:
        print("CALL_ERR", type(e).__name__)
'''


def build_probe(finding) -> dict | None:
    """Return a differential probe, or None if not buildable.

    {files, marker, payload_driver, control_driver}: same target function driven
    with the exploit payloads vs. benign control inputs.
    """
    cwe = set(finding.cwe_ids or [])
    if not (cwe & ORACLE_CWES):
        return None

    # Prefer the real file on disk; fall back to the captured snippet.
    source = None
    try:
        p = Path(finding.file_path)
        if p.is_file():
            source = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        source = None
    if source is None:
        source = finding.code_snippet
    if not source:
        return None

    func = _find_target_function(source, finding.line_start)
    if not func:
        return None

    marker = f"PWNED_{uuid.uuid4().hex[:12]}"
    return {
        "files": {"target.py": source},
        "marker": marker,
        "payload_driver": _DRIVER.format(func=func, payloads=_payloads(cwe, marker)),
        "control_driver": _DRIVER.format(func=func, payloads=_control_inputs(cwe)),
    }


def detect(stdout: str, marker: str) -> bool:
    """Reproduced iff the sentinel marker shows up in container output."""
    return marker in (stdout or "")
