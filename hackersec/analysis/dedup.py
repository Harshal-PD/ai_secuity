from dataclasses import replace
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


def _merge_pair(winner: Finding, other: Finding) -> Finding:
    """Combine metadata and note cross-tool agreement when two findings collide."""
    cwes = list(dict.fromkeys((winner.cwe_ids or []) + (other.cwe_ids or [])))
    owasp = winner.owasp_category or other.owasp_category
    line_end = max(winner.line_end or winner.line_start, other.line_end or other.line_start)
    msg = winner.message or ""
    tag = f"[also flagged by {other.tool}"
    if other.tool != winner.tool and tag not in msg:
        msg = f"{msg} [also flagged by {other.tool} {other.rule_id}: {other.message}]".strip()
    return replace(winner, line_end=line_end, message=msg, cwe_ids=cwes, owasp_category=owasp)


def has_tool(finding: Finding, tool: str) -> bool:
    """True if `finding` came from `tool` or absorbed a finding from `tool`."""
    return finding.tool == tool or f"[also flagged by {tool} " in (finding.message or "")


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """
    Deduplicate findings by (file_path, line_start, cwe_category).
    
    When two findings map to the same key:
    - Keep the one with higher severity
    - Prefer the Semgrep finding for richer metadata (CWE, OWASP)
    - Preserve cross-tool agreement in the merged finding's message and CWEs
    
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
                seen[key] = _merge_pair(f, existing)
            elif _severity_rank(f.severity) == _severity_rank(existing.severity) and f.tool == "semgrep" and existing.tool != "semgrep":
                seen[key] = _merge_pair(f, existing)
            else:
                seen[key] = _merge_pair(existing, f)

    return list(seen.values())


def summarize_findings(findings: list[Finding]) -> dict:
    """Return severity counts for the job summary."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts
