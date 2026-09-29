"""
Prompts for reviewing a whole function at once.

The per-finding board judges "is this alert technically right"; the question
that matches function-level labels (CVEfixes, PrimeVul) is "is this function
exploitable as written". Every seat therefore sees the complete function with
all of its static findings, and the Judge rules once per function.
"""

from hackersec.analysis.llm.prompter import _INJECTION_GUARD, _format_flow
from hackersec.analysis.schema import Finding

# Rough characters per token for Python source under the Qwen tokenizer.
CHARS_PER_TOKEN = 3.2
# Instructions, schema, and the other seats' arguments, plus room to answer.
RESERVED_TOKENS = 1900
MIN_CODE_CHARS = 2500
MAX_FINDINGS_CHARS = 1800
MAX_RAG_CHARS = 1000
ARGUMENT_CHARS = 700


def _clip(text, n: int) -> str:
    text = str(text or "").strip()
    return text if len(text) <= n else text[: n - 3].rstrip() + "..."


def code_budget(num_ctx: int) -> int:
    return max(MIN_CODE_CHARS, int((num_ctx - RESERVED_TOKENS) * CHARS_PER_TOKEN))


def fit_function_code(code: str, start_line: int, focus_lines: list[int], max_chars: int) -> tuple[str, bool]:
    """
    Number the function's lines with their real line numbers (so findings and
    flows can be matched to code) and, if it is too long for the context,
    keep the signature plus windows around the flagged lines.

    Returns (text, truncated).
    """
    lines = code.splitlines()
    numbered = [f"{start_line + i:>5}| {line}" for i, line in enumerate(lines)]
    full = "\n".join(numbered)
    if len(full) <= max_chars:
        return full, False

    focus = [l - start_line for l in focus_lines if start_line <= l < start_line + len(lines)] or [0]
    for radius in (40, 25, 15, 8, 4, 2):
        keep = set(range(min(3, len(lines))))
        for f in focus:
            keep.update(range(max(0, f - radius), min(len(lines), f + radius + 1)))
        out, prev = [], -1
        for i in sorted(keep):
            if i != prev + 1:
                out.append("  ...| (lines omitted)")
            out.append(numbered[i])
            prev = i
        if prev != len(lines) - 1:
            out.append("  ...| (lines omitted)")
        text = "\n".join(out)
        if len(text) <= max_chars:
            return text, True
    return text[:max_chars], True


def _format_taint(f: Finding) -> str:
    cpg = f.cpg_context or {}
    status = cpg.get("cpg_status")
    if status == "success" and cpg.get("taint_paths"):
        flows = cpg["taint_paths"][:2]
        return " | ".join(_format_flow(p) for p in flows)
    if status == "no_flow_found":
        return "Joern found no flow from a parameter or user input into this call"
    return "no data-flow information"


def format_findings(findings: list[Finding]) -> str:
    rows = []
    for i, f in enumerate(findings, start=1):
        cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "no CWE"
        rows.append(
            f"[F{i}] {f.tool} {f.rule_id} ({f.severity}, {cwe}) at line {f.line_start}: {_clip(f.message, 220)}\n"
            f"      data flow: {_clip(_format_taint(f), 300)}"
        )
    return _clip("\n".join(rows), MAX_FINDINGS_CHARS)


def format_rag(findings: list[Finding]) -> str:
    seen, rows = set(), []
    for f in findings:
        for doc in f.rag_docs or []:
            key = doc.get("id")
            if key in seen:
                continue
            seen.add(key)
            rows.append(f"- [{key}] {_clip(doc.get('text'), 320)}")
    return _clip("\n".join(rows), MAX_RAG_CHARS) if rows else "No reference definitions retrieved."


def _evidence_packet(function_name: str, code_text: str, findings: list[Finding], context: str = "") -> str:
    context_block = (
        f"\n===== SAME-FILE CONTEXT (callers and callees; not under review) =====\n{context}\n" if context else ""
    )
    return f"""===== FUNCTION UNDER REVIEW: {function_name} =====

===== CANDIDATE FINDINGS (leads, often false alarms) =====
Sources: semgrep/bandit = static rules, llm_taint = a labelled source reaches a labelled sink, llm_auditor = an LLM's guess.
"data flow" (Joern) only shows that a parameter or input reaches the flagged line; it does not show whether the value is validated, escaped, or passed as a bound parameter.
{format_findings(findings)}

===== REFERENCE DEFINITIONS (OWASP/CWE) =====
{format_rag(findings)}
{context_block}
===== UNTRUSTED SOURCE CODE (line numbers on the left) =====
[UNTRUSTED_CODE_START]
{code_text}
[UNTRUSTED_CODE_END]"""


def build_function_attacker_prompt(function_name: str, code_text: str, findings: list[Finding], context: str = "") -> str:
    return f"""You are the ATTACKER on an application security review board (Red Team).
Automated tools flagged the function below. Argue that the function, AS WRITTEN, contains a real, exploitable security vulnerability.

Rules:
1. Use the findings as leads. Name the finding id(s) your argument rests on, e.g. ["F1"].
2. Trace concretely: which input an attacker controls, which lines it passes through, and which call it reaches. Use the data-flow lines when they exist.
3. Use ONLY the reference definitions to name the vulnerability class. Never cite a CWE or CVE from memory.
4. If no finding is actually exploitable, say so and give a low exploitability_confidence. Overclaiming loses the debate.
5. {_INJECTION_GUARD}
6. Output one JSON object exactly matching this schema:
   {{
     "finding_ids": ["F1"],
     "vulnerability": "The vulnerability class and where it is...",
     "exploit_path": "Attacker-controlled input -> line -> line -> dangerous call...",
     "preconditions": "What the attacker needs to reach this code...",
     "exploitability_confidence": 0.0 to 1.0 (float)
   }}

{_evidence_packet(function_name, code_text, findings, context)}

Respond with the JSON object only, starting with {{:"""


def build_function_defender_prompt(
    function_name: str, code_text: str, findings: list[Finding], attacker: dict, context: str = ""
) -> str:
    return f"""You are the DEFENDER on an application security review board (Blue Team).
Argue that the function below is NOT exploitable as written, and rebut the Attacker's specific claim.

===== ATTACKER'S CLAIM =====
Findings: {attacker.get("finding_ids") or "none named"}
Vulnerability: {_clip(attacker.get("vulnerability"), ARGUMENT_CHARS)}
Exploit path: {_clip(attacker.get("exploit_path"), ARGUMENT_CHARS)}
Preconditions: {_clip(attacker.get("preconditions"), 300)}

Rules:
1. Look for concrete neutralization in the code: parameterized queries, int()/float() casts, allowlists, validation, escaping, shell=False, safe loaders, framework auto-escaping, or input that is not attacker-controlled at all.
2. Copy the exact code that neutralizes the input into sanitization_evidence, character for character, without the line-number prefix.
3. If nothing in the code neutralizes the Attacker's path, write "none found" and give a low safety_confidence. Never invent code that is not shown.
4. Use ONLY the reference definitions for the vulnerability class.
5. {_INJECTION_GUARD}
6. Output one JSON object exactly matching this schema:
   {{
     "sanitization_evidence": "exact code copied from the function, or 'none found'",
     "mitigating_controls": "Framework, configuration, or call-site controls that reduce risk...",
     "rebuttal": "Why the Attacker's path fails, or a concession if it holds...",
     "safety_confidence": 0.0 to 1.0 (float)
   }}

{_evidence_packet(function_name, code_text, findings, context)}

Respond with the JSON object only, starting with {{:"""


def build_function_judge_prompt(
    function_name: str, code_text: str, findings: list[Finding], attacker: dict, defender: dict, context: str = ""
) -> str:
    return f"""You are the JUDGE on an application security review board.
Decide whether the function below, AS WRITTEN, contains an exploitable security vulnerability.

===== ATTACKER (Red Team) =====
Findings: {attacker.get("finding_ids") or "none named"}
Vulnerability: {_clip(attacker.get("vulnerability"), ARGUMENT_CHARS)}
Exploit path: {_clip(attacker.get("exploit_path"), ARGUMENT_CHARS)}
Self-reported exploitability: {attacker.get("exploitability_confidence", "unstated")}

===== DEFENDER (Blue Team) =====
Sanitization evidence: {_clip(defender.get("sanitization_evidence"), 400)}
Mitigating controls: {_clip(defender.get("mitigating_controls"), 400)}
Rebuttal: {_clip(defender.get("rebuttal"), ARGUMENT_CHARS)}
Self-reported safety: {defender.get("safety_confidence", "unstated")}

Rules:
1. Decide from the code itself. The arguments are aids; neither side's rhetoric or confidence numbers decide the case.
2. Candidate findings are frequently false alarms. A finding only makes the function vulnerable if attacker-controlled input can actually reach the flagged operation without being neutralized.
3. A defence counts only if the neutralizing code is really present in the function shown.
4. Report calibrated confidence in your verdict: 0.5 means genuinely unsure, 0.9 means you would bet heavily. Do not inflate it.
5. Use ONLY the reference definitions for the vulnerability class. Never cite a CWE or CVE from memory.
6. {_INJECTION_GUARD}
7. Output one JSON object exactly matching this schema:
   {{
     "verdict": "VULNERABLE" or "NOT_VULNERABLE",
     "confidence": 0.0 to 1.0 (float, certainty in the verdict itself),
     "finding_ids": ["F1"],
     "reasoning": "Which lines decide it, and why..."
   }}

{_evidence_packet(function_name, code_text, findings, context)}

Respond with the JSON object only, starting with {{:"""
