import logging
from hackersec.analysis.schema import Finding

logger = logging.getLogger(__name__)

# Maps severity text to a numeric confidence proxy
SEVERITY_CONFIDENCE = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.1,
    # lowercase variants from our schema
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
}

def extract_features(finding: Finding) -> list[float]:
    """
    Extracts a 5-dimensional feature vector from a Finding:
    [static_confidence, llm_confidence, cpg_taint_depth, cwe_severity_score, has_cwe]
    
    Key design decisions:
    - When LLM confidence is missing, we fall back to static severity as a proxy
      (a HIGH severity Semgrep rule IS high confidence from the static tool)
    - When CPG is unavailable, we use 1.0 (assume-risk) instead of 0.0
      because absence of CPG data does NOT mean absence of vulnerability
    - has_cwe is 1.0 if the finding has CWE IDs (Semgrep mapped it to a known weakness)
    """
    # 1. Static Confidence — derived from SAST tool severity
    sev = finding.severity if finding.severity else "MEDIUM"
    static_confidence = SEVERITY_CONFIDENCE.get(sev, 0.5)
    
    # 2. LLM Confidence — from the LLM's self-reported confidence score
    llm_confidence = static_confidence  # Default: trust static tool when LLM is absent
    if finding.llm_analysis and finding.llm_analysis.get("llm_status") == "success":
        raw = finding.llm_analysis.get("confidence", None)
        if raw is not None:
            try:
                parsed = float(raw)
                if parsed > 0.0:  # Only override if LLM actually provided a score
                    llm_confidence = parsed
            except (ValueError, TypeError):
                pass
    
    # 3. CPG Taint Depth — number of taint paths found
    #    Default to 1.0 when CPG is unavailable (assume risk, don't assume safety)
    cpg_taint_depth = 1.0
    if finding.cpg_context:
        if finding.cpg_context.get("cpg_status") == "success":
            paths = finding.cpg_context.get("taint_paths", [])
            if isinstance(paths, list):
                cpg_taint_depth = max(float(len(paths)), 1.0)
        elif finding.cpg_context.get("cpg_status") == "failed":
            cpg_taint_depth = 1.0  # CPG failed, don't penalize the finding
            
    # 4. CWE Severity Score — higher for known dangerous CWEs
    CRITICAL_CWES = {"CWE-89", "CWE-78", "CWE-94", "CWE-502", "CWE-798", "CWE-77"}
    HIGH_CWES = {"CWE-79", "CWE-22", "CWE-918", "CWE-287", "CWE-306", "CWE-434"}
    
    cwe_severity_score = 0.5  # default mid-range
    if finding.cwe_ids:
        cwe_set = set(finding.cwe_ids)
        if cwe_set & CRITICAL_CWES:
            cwe_severity_score = 1.0
        elif cwe_set & HIGH_CWES:
            cwe_severity_score = 0.8
        else:
            cwe_severity_score = 0.6  # known CWE, just not in our critical list
    
    # 5. Has CWE — binary indicator whether static tool mapped this to a known weakness
    has_cwe = 1.0 if finding.cwe_ids and len(finding.cwe_ids) > 0 else 0.0
    
    return [static_confidence, llm_confidence, cpg_taint_depth, cwe_severity_score, has_cwe]
