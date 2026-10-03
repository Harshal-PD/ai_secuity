"""
LLM auditor ("hunter"): proposes candidate vulnerabilities for any function,
including the many that Semgrep/Bandit never flag.

It first gives a function-level verdict and lists candidates only for a
VULNERABLE verdict, so a function it considers safe adds nothing for the
board to judge. The board is the critic that keeps or dismisses the
function, as in GPTLens (Hu et al., 2023). The auditor sees only the code and
its same-file context, never the dataset's CWE label.
"""

import os
import re

from hackersec.analysis.llm.parser import _bounded_float, _extract_json
from hackersec.analysis.llm.prompter import _INJECTION_GUARD
from hackersec.analysis.schema import Finding

MAX_CANDIDATES = 3
MIN_CONFIDENCE = float(os.getenv("LLM_HUNTER_MIN_CONFIDENCE", "0.3"))
TEMP_HUNTER = float(os.getenv("LLM_TEMP_HUNTER", "0.3"))
_CWE = re.compile(r"CWE-(\d+)", re.I)


def build_hunter_prompt(function_name: str, code_text: str, context: str = "") -> str:
    context_block = (
        f"\n===== SAME-FILE CONTEXT (callers and callees; not under review) =====\n{context}\n" if context else ""
    )
    return f"""You are a security AUDITOR reviewing one Python function.
Decide whether the function below, AS WRITTEN, contains a security vulnerability, and if so where.

Rules:
1. Consider every class, including ones pattern-matching tools miss: missing authorization or authentication checks, path traversal, unbounded resource use (ReDoS, recursion, huge inputs), information exposure, improper input validation, insecure defaults, race conditions, as well as injection and unsafe deserialization.
2. A vulnerability needs a concrete path: input an attacker can influence reaches a dangerous operation on a line shown, with no validation, escaping, parameterization, allowlist or permission check on that path. If the code shown already has such a check, the function is NOT_VULNERABLE for that issue.
3. Do not report hardening advice, style issues, or problems that only arise if a caller misuses the function.
4. If the verdict is NOT_VULNERABLE, return an empty candidates list. If it is VULNERABLE, list at most {MAX_CANDIDATES} candidates, most likely first, each naming a line number shown on the left of the code.
5. confidence is your certainty in the verdict: 0.5 means genuinely unsure, 0.9 means you would bet heavily. Do not inflate it.
6. cwe is your best guess, formatted "CWE-<number>".
7. {_INJECTION_GUARD}
8. Output one JSON object exactly matching this schema:
   {{
     "verdict": "VULNERABLE" or "NOT_VULNERABLE",
     "confidence": 0.0 to 1.0,
     "candidates": [
       {{"line": 12, "cwe": "CWE-22", "vulnerability": "What is wrong and how it is reached...", "confidence": 0.0 to 1.0}}
     ]
   }}
{context_block}
===== FUNCTION UNDER REVIEW: {function_name} =====
[UNTRUSTED_CODE_START]
{code_text}
[UNTRUSTED_CODE_END]

Respond with the JSON object only, starting with {{:"""


def _verdict(raw) -> str | None:
    raw = str(raw or "").strip().upper().replace(" ", "_").replace("-", "_")
    if any(k in raw for k in ("NOT", "SAFE", "FALSE", "BENIGN")):
        return "NOT_VULNERABLE"
    if any(k in raw for k in ("VULN", "TRUE", "EXPLOIT")):
        return "VULNERABLE"
    return None


def parse_hunter_response(raw_text: str, start_line: int, end_line: int) -> dict:
    """{"status", "verdict", "confidence", "p_vulnerable", "candidates"}.

    Candidates below MIN_CONFIDENCE are dropped, lines outside the function
    are moved to its first line, and a NOT_VULNERABLE verdict keeps none.
    Without a readable verdict, listing any candidate counts as VULNERABLE.
    """
    data = _extract_json(raw_text)
    if data is None or not isinstance(data.get("candidates", []), list):
        return {"status": "failed_parsing", "verdict": None, "confidence": None, "p_vulnerable": None,
                "candidates": []}
    out = []
    for c in data.get("candidates") or []:
        if not isinstance(c, dict):
            continue
        conf = _bounded_float(c.get("confidence", 0.0), default=0.0)
        if conf < MIN_CONFIDENCE:
            continue
        try:
            line = int(c.get("line"))
        except (TypeError, ValueError):
            line = start_line
        if not start_line <= line <= end_line:
            line = start_line
        m = _CWE.search(str(c.get("cwe") or ""))
        out.append({
            "line": line,
            "cwe": f"CWE-{m.group(1)}" if m else None,
            "vulnerability": str(c.get("vulnerability") or "")[:400],
            "confidence": conf,
        })
    out.sort(key=lambda c: -c["confidence"])
    out = out[:MAX_CANDIDATES]

    verdict = _verdict(data.get("verdict")) or ("VULNERABLE" if out else "NOT_VULNERABLE")
    if verdict == "NOT_VULNERABLE":
        out = []
    default = out[0]["confidence"] if out else 0.5
    confidence = _bounded_float(data.get("confidence", default), default=default)
    p_vuln = confidence if verdict == "VULNERABLE" else 1.0 - confidence
    return {"status": "success", "verdict": verdict, "confidence": confidence,
            "p_vulnerable": round(p_vuln, 4), "candidates": out}


def hunt(client, model: str, function_name: str, code_text: str, start_line: int, end_line: int,
         context: str = "") -> dict:
    """Run the auditor once. Transport failures are returned as-is so the
    caller can wait for Ollama and retry."""
    res = client.generate(
        build_hunter_prompt(function_name, code_text, context),
        model=model, temperature=TEMP_HUNTER, seed=7, max_tokens=700,
    )
    if res["llm_status"] != "success":
        return res
    return {"llm_status": "success", **parse_hunter_response(res["response"], start_line, end_line)}


def hunter_findings(candidates: list[dict], file_path: str, file_lines: list[str], job_id: str) -> list[Finding]:
    findings = []
    for c in candidates:
        conf = c["confidence"]
        findings.append(Finding(
            job_id=job_id,
            file_path=file_path,
            line_start=c["line"],
            line_end=c["line"],
            rule_id=f"auditor:{c['cwe'] or 'unspecified'}",
            tool="llm_auditor",
            severity="high" if conf >= 0.7 else "medium" if conf >= 0.4 else "low",
            message=f"{c['vulnerability']} (auditor confidence {conf:.2f})",
            cwe_ids=[c["cwe"]] if c["cwe"] else [],
            code_snippet=file_lines[c["line"] - 1].strip() if 0 < c["line"] <= len(file_lines) else None,
        ))
    return findings
