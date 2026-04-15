import json
import logging
import subprocess
from pathlib import Path
from typing import Optional

from hackersec.analysis.schema import (
    Finding,
    SEMGREP_SEVERITY_MAP,
    BANDIT_SEVERITY_MAP,
)

logger = logging.getLogger(__name__)

# ─── Semgrep ────────────────────────────────────────────────────────────────

SEMGREP_CONFIGS = [
    "p/security-audit",
    "p/owasp-top-ten",
    "p/python",
]


def run_semgrep(target_path: Path, job_id: str) -> list[Finding]:
    """Run Semgrep with security rule sets. Returns normalized Finding list."""
    cmd = ["semgrep", "scan", "--json", "--timeout", "60", "--metrics=off"]
    for cfg in SEMGREP_CONFIGS:
        cmd += ["--config", cfg]
    cmd.append(str(target_path))

    logger.info(f"[{job_id}] Running Semgrep: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"[{job_id}] Semgrep timed out after 120s")
        return []
    except FileNotFoundError:
        logger.error(f"[{job_id}] Semgrep binary not found in container")
        return []

    # Exit code 0 = no findings, 1 = findings found, 2+ = error
    if result.returncode >= 2:
        logger.error(f"[{job_id}] Semgrep exited with code {result.returncode}")
        logger.error(f"[{job_id}] Semgrep stderr: {result.stderr[:500]}")
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error(f"[{job_id}] Semgrep produced invalid JSON. stdout[:200]: {result.stdout[:200]}")
        return []

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

        findings.append(Finding(
            job_id=job_id,
            file_path=r["path"],
            line_start=r["start"]["line"],
            line_end=r["end"]["line"],
            rule_id=r["check_id"],
            tool="semgrep",
            severity=severity,
            message=r["extra"]["message"],
            cwe_ids=cwe_ids,
            owasp_category=owasp,
        ))

    return findings


# ─── Bandit ─────────────────────────────────────────────────────────────────

def run_bandit(target_path: Path, job_id: str) -> list[Finding]:
    """Run Bandit on Python files. Returns normalized Finding list."""
    # Bandit only works on Python — skip non-Python targets
    if target_path.is_file() and not str(target_path).endswith(".py"):
        logger.info(f"[{job_id}] Skipping Bandit (not a .py file)")
        return []

    cmd = [
        "bandit", "-r" if target_path.is_dir() else "",
        str(target_path), "-f", "json", "-ll",  # -ll = medium + high only
    ]
    cmd = [c for c in cmd if c]  # Remove empty strings

    logger.info(f"[{job_id}] Running Bandit: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        logger.warning(f"[{job_id}] Bandit timed out after 60s")
        return []
    except FileNotFoundError:
        logger.error(f"[{job_id}] Bandit binary not found in container")
        return []

    logger.info(f"[{job_id}] Bandit exit code: {result.returncode}")

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error(f"[{job_id}] Bandit produced invalid JSON. stderr: {result.stderr[:200]}")
        return []

    findings = []
    for r in data.get("results", []):
        severity_raw = r.get("issue_severity", "LOW")
        severity = BANDIT_SEVERITY_MAP.get(severity_raw, "low")

        # Extract CWE if available (Bandit >= 1.7.5)
        cwe_info = r.get("issue_cwe", {})
        cwe_id = cwe_info.get("id")
        cwe_ids = [f"CWE-{cwe_id}"] if cwe_id else []

        findings.append(Finding(
            job_id=job_id,
            file_path=r["filename"],
            line_start=r["line_number"],
            line_end=r.get("line_range", [r["line_number"]])[-1],
            rule_id=r["test_id"],
            tool="bandit",
            severity=severity,
            message=r["issue_text"],
            cwe_ids=cwe_ids,
        ))

    logger.info(f"[{job_id}] Bandit found {len(findings)} findings")
    return findings


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

    logger.info(f"[{job_id}] Total static analysis: {len(findings)} findings")
    return findings

