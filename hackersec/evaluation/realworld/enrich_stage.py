"""
Findings that go through Joern, RAG and the Board.

Pipeline per function:

  gate      Semgrep, Bandit, CodeQL           -> origin "sast"
  screen    Soft LLM Screen (context verdict) -> origin "llm_screen"
  enrich    AST sink scanner, Joern taint, RAG    (for either origin)
  board     Static Indictment -> Defender -> Prosecutor rebuttal -> Judge

The AST scanner is not a gate. It adds sink and parameter-taint leads to a
function something else already flagged. A Soft-LLM-Screen candidate with no
AST lead still needs a concrete target for Joern and RAG, so it gets a
synthetic lead covering the whole function, built from the screen's suspicion.
"""

from __future__ import annotations

import copy

from hackersec.analysis.dedup import dedup_findings
from hackersec.analysis.schema import Finding

SCREEN_TOOL = "llm_screen"
SCREEN_RULE_ID = "HS-LLM-SCREEN"
_MESSAGE_CHARS = 300
_DEFAULT_SUSPICION = "the LLM+context screen rated this function suspicious"


def screen_lead(sample: dict, suspicion: str | None) -> Finding:
    """Synthetic whole-function lead for a Soft-LLM-Screen candidate."""
    text = (suspicion or "").strip() or _DEFAULT_SUSPICION
    return Finding(
        job_id="realworld",
        file_path=sample["file"],
        line_start=sample["line_start"],
        line_end=sample["line_end"],
        rule_id=SCREEN_RULE_ID,
        tool=SCREEN_TOOL,
        severity="low",
        message=f"Soft LLM Screen suspicion: {text}"[:_MESSAGE_CHARS],
    )


def active_findings(
    origin: str | None,
    gate_findings: list[Finding],
    ast_findings: list[Finding],
    sample: dict,
    suspicion: str | None,
) -> list[Finding]:
    """Findings for Joern, RAG and the Board; empty when nothing flagged the function.

    Inputs are copied, because Joern and RAG attach their results to the
    findings in place."""
    if origin is None:
        return []
    merged = dedup_findings(copy.deepcopy(list(gate_findings)) + copy.deepcopy(list(ast_findings)))
    if merged:
        return merged
    return [screen_lead(sample, suspicion)]
