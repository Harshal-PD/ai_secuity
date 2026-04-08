"""
Phase 1 Integration Tests: Static Analysis Pipeline

Tests run WITHOUT Redis/Celery — they call the analysis functions directly.
FastAPI endpoint tests require a running server (marked with @pytest.mark.integration).
"""
import pytest
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "vuln_sample.py"


# ── Unit Tests: Static Analysis ──────────────────────────────────────────────

class TestSemgrep:
    def test_returns_findings_for_vulnerable_file(self):
        from hackersec.analysis.static import run_semgrep
        findings = run_semgrep(FIXTURE_PATH, job_id="test-semgrep")
        assert len(findings) > 0, "Expected at least 1 finding for vuln_sample.py"

    def test_no_info_findings(self):
        from hackersec.analysis.static import run_semgrep
        findings = run_semgrep(FIXTURE_PATH, job_id="test-info")
        severities = {f.severity for f in findings}
        assert "info" not in severities, "INFO findings should be filtered out"
        assert None not in severities

    def test_finding_has_required_fields(self):
        from hackersec.analysis.static import run_semgrep
        findings = run_semgrep(FIXTURE_PATH, job_id="test-fields")
        if findings:
            f = findings[0]
            assert f.file_path, "file_path must not be empty"
            assert f.line_start > 0, "line_start must be positive"
            assert f.severity in {"critical", "high", "medium", "low"}
            assert f.rule_id, "rule_id must not be empty"
            assert f.message, "message must not be empty"
            assert f.tool == "semgrep"

    def test_sql_injection_detected(self):
        from hackersec.analysis.static import run_semgrep
        findings = run_semgrep(FIXTURE_PATH, job_id="test-sqli")
        messages = [f.message.lower() for f in findings]
        rule_ids = [f.rule_id.lower() for f in findings]
        found = any("sql" in m or "injection" in m for m in messages) or \
                any("sql" in r for r in rule_ids)
        assert found, "SQL injection in vuln_sample.py should be detected by Semgrep"


class TestBandit:
    def test_returns_findings_for_vulnerable_file(self):
        from hackersec.analysis.static import run_bandit
        findings = run_bandit(FIXTURE_PATH, job_id="test-bandit")
        assert len(findings) > 0, "Expected Bandit to find issues in vuln_sample.py"

    def test_finding_has_required_fields(self):
        from hackersec.analysis.static import run_bandit
        findings = run_bandit(FIXTURE_PATH, job_id="test-bandit-fields")
        if findings:
            f = findings[0]
            assert f.tool == "bandit"
            assert f.severity in {"high", "medium", "low"}
            assert f.line_start > 0

    def test_skips_non_python_file(self, tmp_path):
        from hackersec.analysis.static import run_bandit
        js_file = tmp_path / "app.js"
        js_file.write_text("console.log('hello')")
        findings = run_bandit(js_file, job_id="test-js")
        assert findings == [], "Bandit should return [] for non-Python files"


class TestDeduplication:
    def test_dedup_removes_duplicate_location(self):
        from hackersec.analysis.schema import Finding
        from hackersec.analysis.dedup import dedup_findings
        f1 = Finding(job_id="t", file_path="a.py", line_start=5, line_end=5,
                     rule_id="r1", tool="semgrep", severity="high",
                     message="sql", cwe_ids=["CWE-89"])
        f2 = Finding(job_id="t", file_path="a.py", line_start=5, line_end=5,
                     rule_id="B608", tool="bandit", severity="high",
                     message="sql bandit", cwe_ids=["CWE-89"])
        result = dedup_findings([f1, f2])
        assert len(result) == 1

    def test_dedup_prefers_higher_severity(self):
        from hackersec.analysis.schema import Finding
        from hackersec.analysis.dedup import dedup_findings
        low = Finding(job_id="t", file_path="a.py", line_start=10, line_end=10,
                      rule_id="r1", tool="bandit", severity="medium",
                      message="x", cwe_ids=[])
        high = Finding(job_id="t", file_path="a.py", line_start=10, line_end=10,
                       rule_id="r2", tool="semgrep", severity="high",
                       message="x", cwe_ids=[])
        result = dedup_findings([low, high])
        assert result[0].severity == "high"

    def test_empty_list_returns_empty(self):
        from hackersec.analysis.dedup import dedup_findings
        assert dedup_findings([]) == []


class TestFullPipeline:
    def test_run_static_analysis_on_fixture(self):
        from hackersec.analysis.static import run_static_analysis
        from hackersec.analysis.dedup import dedup_findings
        raw = run_static_analysis(FIXTURE_PATH, job_id="test-pipeline")
        findings = dedup_findings(raw)
        assert len(findings) > 0, "Full pipeline must detect findings in vuln_sample.py"
        assert all(f.severity in {"critical", "high", "medium", "low"} for f in findings)

    def test_findings_have_valid_severity(self):
        from hackersec.analysis.static import run_static_analysis
        from hackersec.analysis.dedup import dedup_findings
        findings = dedup_findings(run_static_analysis(FIXTURE_PATH, job_id="test-sev"))
        for f in findings:
            assert f.severity in {"critical", "high", "medium", "low"}, \
                f"Invalid severity '{f.severity}' in finding {f.rule_id}"
