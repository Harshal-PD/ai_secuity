import hashlib
import json
import logging
import os
import subprocess
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
    h = hashlib.sha1()
    for cfg in _semgrep_configs():
        p = Path(cfg)
        h.update(p.read_bytes() if p.is_file() else cfg.encode())
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
    cmd = ["bandit"] + (["-r"] if recursive else []) + [str(t) for t in targets] + ["-f", "json", "-l"]  # -l = low + medium + high
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

