import logging
from hackersec.analysis.schema import Finding

logger = logging.getLogger(__name__)

def extract_features(finding: Finding) -> list[float]:
    """
    Extracts a dense numerical feature vector from a Finding instance
    for classification bounds mapping:
    [static_confidence, llm_confidence, cpg_taint_depth, cwe_severity_score]
    """
    # 1. Static Confidence
    sev_map = {
        "CRITICAL": 1.0,
        "HIGH": 0.8,
        "MEDIUM": 0.5,
        "LOW": 0.2,
        "INFO": 0.1
    }
    sev = finding.severity.upper() if finding.severity else "MEDIUM"
    static_confidence = sev_map.get(sev, 0.5)
    
    # 2. LLM Confidence
    llm_confidence = 0.0
    if finding.llm_analysis and "confidence" in finding.llm_analysis:
        try:
            llm_confidence = float(finding.llm_analysis.get("confidence", 0.0))
        except (ValueError, TypeError):
            llm_confidence = 0.0
            
    # 3. CPG Taint Depth
    cpg_taint_depth = 0.0
    if finding.cpg_context and finding.cpg_context.get("cpg_status") == "success":
        paths = finding.cpg_context.get("taint_paths", [])
        if paths and isinstance(paths, list):
            # Depth can be approximated by number of paths or nodes in longest path
            # Here we just use the length of the longest path or total paths
            cpg_taint_depth = float(len(paths))
            
    # 4. CWE Severity default
    cwe_severity_score = 0.5
    
    return [static_confidence, llm_confidence, cpg_taint_depth, cwe_severity_score]
