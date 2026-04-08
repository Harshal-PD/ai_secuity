from dataclasses import dataclass, field
from typing import Optional
import uuid


@dataclass
class Finding:
    job_id: str
    file_path: str
    line_start: int
    line_end: int
    rule_id: str
    tool: str                         # "semgrep" | "bandit"
    severity: str                     # "critical" | "high" | "medium" | "low"
    message: str
    cwe_ids: list[str] = field(default_factory=list)   # e.g. ["CWE-89"]
    owasp_category: Optional[str] = None               # e.g. "A03:2021"
    code_snippet: Optional[str] = None
    # Filled by later phases:
    cpg_context: Optional[dict] = None
    rag_docs: Optional[list] = None
    llm_analysis: Optional[dict] = None
    fusion_verdict: Optional[str] = None   # "true_positive"|"false_positive"|"uncertain"
    patch: Optional[str] = None


SEMGREP_SEVERITY_MAP = {
    "ERROR": "critical",
    "WARNING": "high",
    "INFO": None,      # Filtered — never stored
}

BANDIT_SEVERITY_MAP = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
