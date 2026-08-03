"""Self-check for the dynamic exploit-verification stage.

Runs without Docker by injecting a fake sandbox runner that simulates a
container: it extracts the probe's sentinel marker from the driver and echoes
it back for an exploitable target, or returns nothing for a safe one. This
exercises the full oracle → orchestrator wiring deterministically.

Run: python test_verify.py
"""
import re

from hackersec.analysis.schema import Finding
from hackersec.analysis.verify import verify_finding
from hackersec.analysis.verify.oracles import build_probe, detect
from hackersec.analysis.verify.sandbox import docker_available


def _finding(**kw):
    base = dict(
        job_id="t", file_path="<snippet>", line_start=2, line_end=2,
        rule_id="r", tool="semgrep", severity="high", message="m",
        fusion_verdict="true_positive",
    )
    base.update(kw)
    return Finding(**base)


# Genuine exploit: the sink executes whatever input it's given, so the marker
# appears ONLY for the payload driver (which contains it), not the control.
def genuine_runner(files, driver, *, timeout=20):
    m = re.search(r"PWNED_[0-9a-f]+", driver)
    return {"status": "ran", "stdout": (m.group(0) + "\n") if m else "sanitized\n", "exit_code": 0}


# Sanitized: input never reaches a live sink, marker never printed.
def safe_runner(files, driver, *, timeout=20):
    return {"status": "ran", "stdout": "sanitized\n", "exit_code": 0}


# Hardcoded/faked PoC: prints the marker regardless of input (payload AND
# control). Stateful so it can echo the marker even on the control driver,
# which doesn't contain it — exactly the POC-GYM cheat the differential rejects.
def hardcoded_runner():
    seen = {}
    def run(files, driver, *, timeout=20):
        m = re.search(r"PWNED_[0-9a-f]+", driver)
        if m:
            seen["m"] = m.group(0)
        return {"status": "ran", "stdout": (seen.get("m", "") + "\n"), "exit_code": 0}
    return run


def test_reproduced_true():
    f = _finding(
        cwe_ids=["CWE-95"],
        code_snippet="def process_user(input_str):\n    return eval(input_str)\n",
    )
    verify_finding(f, runner=genuine_runner)
    assert f.reproduced is True, f.repro_evidence
    assert f.repro_evidence["status"] == "reproduced"


def test_reproduced_false():
    f = _finding(
        cwe_ids=["CWE-95"],
        code_snippet="def process_user(input_str):\n    return eval(int(input_str))\n",
    )
    verify_finding(f, runner=safe_runner)
    assert f.reproduced is False, f.repro_evidence
    assert f.repro_evidence["status"] == "not_triggered"


def test_hardcoded_poc_rejected():
    # A PoC that prints the marker no matter the input must NOT count as reproduced.
    f = _finding(
        cwe_ids=["CWE-95"],
        code_snippet="def process_user(input_str):\n    return eval(input_str)\n",
    )
    verify_finding(f, runner=hardcoded_runner())
    assert f.reproduced is False, f.repro_evidence
    assert f.repro_evidence["status"] == "hardcoded_rejected"
    assert f.repro_evidence["control_fired"] is True


def test_not_checkable_cwe():
    # Weak-hash CWE has no code-level RCE oracle -> None, never a false negative.
    f = _finding(cwe_ids=["CWE-328"], code_snippet="def h(p):\n    return md5(p)\n")
    verify_finding(f, runner=genuine_runner)
    assert f.reproduced is None
    assert f.repro_evidence["status"] == "not_checkable"


def test_skipped_when_not_candidate():
    f = _finding(cwe_ids=["CWE-95"], fusion_verdict="false_positive",
                 code_snippet="def process_user(x):\n    return eval(x)\n")
    verify_finding(f, runner=genuine_runner)
    assert f.reproduced is None
    assert f.repro_evidence["status"] == "skipped_verdict"


class _DeclineLLM:
    # PoC agent fallback returns an unusable call snippet → no_driver.
    def generate(self, prompt, model=None):
        return {"llm_status": "success", "response": '{"call": "print(1)"}'}


def test_no_driver_without_function():
    f = _finding(cwe_ids=["CWE-78"], file_path="<snippet>",
                 code_snippet="os.system(user_in)\n")  # no def -> heuristic can't build
    verify_finding(f, runner=genuine_runner, llm=_DeclineLLM())
    assert f.reproduced is None
    assert f.repro_evidence["status"] == "no_driver"


def test_probe_extracts_function_and_marker():
    f = _finding(cwe_ids=["CWE-78"],
                 code_snippet="def run(cmd):\n    os.system('ping ' + cmd)\n")
    probe = build_probe(f)
    assert probe is not None
    assert "run" in probe["payload_driver"]
    assert re.match(r"PWNED_[0-9a-f]{12}", probe["marker"])
    assert detect(f"x {probe['marker']} y", probe["marker"]) is True
    assert detect("nothing", probe["marker"]) is False


def test_real_docker_roundtrip():
    """Opportunistic: only runs if a real Docker daemon is present."""
    if not docker_available():
        print("  (skipped real-docker roundtrip — daemon unavailable)")
        return
    f = _finding(
        cwe_ids=["CWE-95"],
        code_snippet="def process_user(input_str):\n    return eval(input_str)\n",
    )
    verify_finding(f)  # real sandbox
    assert f.reproduced is True, f.repro_evidence


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
    print(f"\n{len(tests)} checks passed.")
