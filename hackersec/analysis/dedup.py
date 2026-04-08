from hackersec.analysis.schema import Finding, SEVERITY_RANK


def _get_cwe_category(cwe_ids: list[str]) -> str:
    """Extract primary CWE number for dedup grouping.
    
    e.g. ["CWE-89", "CWE-20"] -> "89"
    e.g. [] -> "unknown"
    """
    if not cwe_ids:
        return "unknown"
    first = cwe_ids[0]
    return first.replace("CWE-", "").split(":")[0]


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 0)


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate findings by (file_path, line_start, cwe_category).
    
    When two findings map to the same key:
    - Keep the one with higher severity
    - Prefer the Semgrep finding for richer metadata (CWE, OWASP)
    
    Also filters out any remaining INFO-equivalent findings (severity=None or unknown).
    """
    # First pass: filter out any sneaked-through low/unknown severity
    valid = [f for f in findings if f.severity in SEVERITY_RANK]

    seen: dict[tuple, Finding] = {}
    for f in valid:
        key = (f.file_path, f.line_start, _get_cwe_category(f.cwe_ids))
        if key not in seen:
            seen[key] = f
        else:
            existing = seen[key]
            # Keep higher severity; on tie, prefer Semgrep (richer metadata)
            if _severity_rank(f.severity) > _severity_rank(existing.severity):
                seen[key] = f
            elif _severity_rank(f.severity) == _severity_rank(existing.severity):
                if f.tool == "semgrep" and existing.tool != "semgrep":
                    # Semgrep has CWE + OWASP mapping — prefer it
                    seen[key] = f

    return list(seen.values())


def summarize_findings(findings: list[Finding]) -> dict:
    """Return severity counts for the job summary."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
