"""Self-check for the CPG-guided PoC agent (Phase 1b).

No GPU/Ollama/Docker: inject a fake LLM (returns a call snippet) and a fake
sandbox runner (simulates execution). Verifies the synthesized PoC is still
gated by the SAME differential oracle — a genuine PoC reproduces, a hardcoded
one is rejected, and LLM failures degrade to None.

The findings here have NO `def` in the snippet, so the heuristic
`oracles.build_probe` returns None and `verify_finding` falls back to the agent.

Run: python test_poc_agent.py
"""
import json
import re

from hackersec.analysis.schema import Finding
from hackersec.analysis.verify import verify_finding


def _finding(**kw):
    base = dict(
        job_id="t", file_path="<snippet>", line_start=1, line_end=1,
        rule_id="r", tool="semgrep", severity="high", message="m",
        fusion_verdict="true_positive", cwe_ids=["CWE-78"],
        # No `def` → heuristic build_probe returns None → agent fallback.
        code_snippet="result = os.system('ping ' + user_host)\n",
    )
    base.update(kw)
    return Finding(**base)


class FakeLLM:
    def __init__(self, call="mod.handler('safe', HS_INPUT)", raise_=False, status="success"):
        self.call, self.raise_, self.status = call, raise_, status

    def generate(self, prompt, model=None):
        if self.raise_:
            raise RuntimeError("ollama unreachable")
        if self.status != "success":
            return {"llm_status": self.status}
        return {"llm_status": "success", "response": json.dumps({"call": self.call})}


# Genuine: sink runs the given input, so the marker (in the payload driver only)
# appears for the payload and not the control.
def genuine_runner(files, driver, *, timeout=20):
    m = re.search(r"PWNED_[0-9a-f]+", driver)
    return {"status": "ran", "stdout": (m.group(0) + "\n") if m else "quiet\n", "exit_code": 0}


# Hardcoded/faked PoC: prints the marker regardless of input (payload AND control).
def hardcoded_runner():
    seen = {}
    def run(files, driver, *, timeout=20):
        m = re.search(r"PWNED_[0-9a-f]+", driver)
        if m:
            seen["m"] = m.group(0)
        return {"status": "ran", "stdout": seen.get("m", "") + "\n", "exit_code": 0}
    return run


def test_synthesized_poc_reproduces():
    f = _finding()
    verify_finding(f, runner=genuine_runner, llm=FakeLLM())
    assert f.reproduced is True, f.repro_evidence
    assert f.repro_evidence["status"] == "reproduced"


def test_synthesized_hardcoded_rejected():
    f = _finding()
    verify_finding(f, runner=hardcoded_runner(), llm=FakeLLM())
    assert f.reproduced is False, f.repro_evidence
    assert f.repro_evidence["status"] == "hardcoded_rejected"


def test_invalid_poc_no_driver():
    # Call snippet that ignores HS_INPUT / mod is unusable → no_driver.
    f = _finding()
    verify_finding(f, runner=genuine_runner, llm=FakeLLM(call="print(1)"))
    assert f.reproduced is None
    assert f.repro_evidence["status"] == "no_driver"


def test_llm_unavailable():
    f = _finding()
    verify_finding(f, runner=genuine_runner, llm=FakeLLM(raise_=True))
    assert f.reproduced is None
    assert f.repro_evidence["status"] == "llm_unavailable"


def test_llm_error_status():
    f = _finding()
    verify_finding(f, runner=genuine_runner, llm=FakeLLM(status="failed_connection"))
    assert f.reproduced is None
    assert f.repro_evidence["status"] == "llm_unavailable"


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} checks passed.")
