import pytest
from hackersec.analysis.patch import build_patch_prompt, parse_patch, compute_diff, validate_patch
from hackersec.analysis.schema import Finding

def test_parse_patch_clean():
    markdown = """Here is your patch.
```python
import os
os.system("echo safe")
```
Hope it helps!
"""
    parsed = parse_patch(markdown)
    assert parsed == 'import os\nos.system("echo safe")'

def test_parse_patch_no_markdown():
    text = """import sys\nsys.exit(0)"""
    parsed = parse_patch(text)
    assert parsed == text

def test_compute_diff():
    # unified_diff needs specific structure, additions should be +
    org = "x = 1"
    patch = "x = 2"
    diff = compute_diff(org, patch)
    
    assert "--- vulnerable_code.py" in diff
    assert "+++ patched_code.py" in diff
    assert "-x = 1" in diff
    assert "+x = 2" in diff

def test_build_patch_prompt():
    f = Finding(
        file_path="app.py",
        line_start=1,
        line_end=1,
        rule_id="r1",
        tool="test",
        severity="HIGH",
        message="err",
        code_snippet="x=1",
        llm_analysis={"explanation": "Bad code", "fix_suggestion": "Good code"}
    )
    prompt = build_patch_prompt(f)
    assert "Bad code" in prompt
    assert "Good code" in prompt
    assert "[UNTRUSTED_CODE_START]" in prompt
    assert "x=1" in prompt
