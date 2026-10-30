"""
Prompts for reviewing a whole function at once.

The per-finding board judges "is this alert technically right"; the question
that matches function-level labels (CVEfixes, PrimeVul) is "is this function
exploitable as written". Every seat therefore sees the complete function with
all of its static findings, and the Judge rules once per function.
"""

from hackersec.analysis.dedup import has_tool
from hackersec.analysis.joern.queries import classify_taint_paths
from hackersec.analysis.llm.prompter import _INJECTION_GUARD, _format_flow
from hackersec.analysis.schema import Finding

# Rough characters per token for Python source under the Qwen tokenizer.
CHARS_PER_TOKEN = 3.2
# Instructions, schema, and the other seats' arguments, plus room to answer.
RESERVED_TOKENS = 1900
MIN_CODE_CHARS = 2500
DEFENDER_CODE_CHARS = 2800
MAX_FINDINGS_CHARS = 1400
MAX_RAG_CHARS = 800
ARGUMENT_CHARS = 550

_SEV_PRIOR = {"critical": 0.90, "high": 0.78, "medium": 0.62, "low": 0.42}

# Board debate tracks keyed by gate origin.
# Track 1 (sast): sink & taint verification for SAST-flagged sinks.
# Track 2 (llm_screen): semantic invariant / missing-guard for Soft LLM Screen.
TRACK_SAST = "sast"
TRACK_LLM_SCREEN = "llm_screen"


def resolve_board_track(gate_origin: str | None, findings: list[Finding] | None = None) -> str:
    """
    Choose Track 1 (sast) vs Track 2 (llm_screen).

    Prefer an explicit gate_origin from the Soft LLM Screen / union gate when
    present; otherwise fall back to whether the function has SAST findings.
    """
    origin = (gate_origin or "").strip().lower()
    if origin in (TRACK_SAST, TRACK_LLM_SCREEN):
        return origin
    return TRACK_SAST if findings else TRACK_LLM_SCREEN


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
        unfiltered = cpg.get("unfiltered_taint_paths")
        sanitized = cpg.get("sanitized_taint_paths")
        if unfiltered is None and sanitized is None:
            unfiltered, sanitized = classify_taint_paths(cpg.get("taint_paths") or [])
        if unfiltered:
            flows = " | ".join(_format_flow(p) for p in unfiltered[:2])
            return f"UNFILTERED FLOW (no sanitizer on path): {flows}"
        if sanitized:
            flows = " | ".join(_format_flow(p) for p in sanitized[:2])
            return f"GUARDED/SANITIZED FLOW (passes through validation/sanitizer): {flows}"
        flows = " | ".join(_format_flow(p) for p in cpg["taint_paths"][:2])
        return flows
    if status == "no_flow_found":
        return "no direct flow found by Joern (inconclusive: CPG taint does not track self.*, dicts, or decorators)"
    return "no data-flow information"


def synthesize_sast_attacker(findings: list[Finding]) -> dict:
    """
    Deterministic Challenger brief built directly from SAST + Joern CPG
    findings. Eliminates the redundant Attacker LLM call while giving the
    Defender and Judge a concrete, non-hallucinated claim to rebut and weigh.
    """
    if not findings:
        return {
            "finding_ids": [],
            "vulnerability": "none",
            "exploit_path": "none",
            "preconditions": "none",
            "exploitability_confidence": 0.0,
            "status": "success",
            "source": "sast_cpg",
        }

    fids = [f"F{i}" for i in range(1, len(findings) + 1)]
    vuln_parts = []
    path_parts = []
    has_unfiltered = False
    has_sanitized = False
    tools_seen: set[str] = set()

    for i, f in enumerate(findings[:3], start=1):
        cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "no CWE"
        vuln_parts.append(f"[F{i}] {f.tool} {f.rule_id} ({f.severity}, {cwe}) line {f.line_start}: {_clip(f.message, 150)}")
        path_parts.append(f"[F{i}] line {f.line_start}: {_clip(_format_taint(f), 180)}")
        cpg = f.cpg_context or {}
        uf = cpg.get("unfiltered_flows")
        sf = cpg.get("sanitized_flows")
        if uf is None and sf is None and cpg.get("taint_paths"):
            u_list, s_list = classify_taint_paths(cpg["taint_paths"])
            uf, sf = len(u_list), len(s_list)
        if (uf or 0) > 0:
            has_unfiltered = True
        if (sf or 0) > 0:
            has_sanitized = True
        for t in ("semgrep", "bandit", "ast_sink", "codeql"):
            if has_tool(f, t):
                tools_seen.add(t)

    base = max((_SEV_PRIOR.get(f.severity, 0.45) for f in findings), default=0.45)
    if has_unfiltered:
        base += 0.10
    elif has_sanitized:
        base -= 0.12
    if len(tools_seen) >= 2:
        base += 0.06
    conf = round(min(0.98, max(0.20, base)), 4)

    return {
        "finding_ids": fids,
        "vulnerability": " | ".join(vuln_parts),
        "exploit_path": " | ".join(path_parts),
        "preconditions": "Caller or user-controlled input reaching the flagged sink(s) without neutralization",
        "exploitability_confidence": conf,
        "status": "success",
        "source": "sast_cpg",
    }


def synthesize_screen_indictment(suspicion: str | None, p_screen: float | None = None) -> dict:
    """Static Indictment for a Soft-LLM-Screen candidate (no SAST alert): the
    screen's 1-line suspicion trace is the charge. 0 LLM tokens."""
    trace = _clip(suspicion, 240) or "The LLM+context screen rated this function suspicious; no SAST alert."
    score = f" (screen P(vulnerable)={p_screen:.2f})" if p_screen is not None else ""
    return {
        "finding_ids": [],
        "vulnerability": f"Soft LLM Screen suspicion{score}: {trace}",
        "exploit_path": trace,
        "preconditions": "Caller or user-controlled input reaching the suspected operation without the required check",
        "exploitability_confidence": round(float(p_screen), 4) if p_screen is not None else 0.5,
        "status": "success",
        "source": "llm_screen",
    }


def build_prosecutor_rebuttal_prompt(
    function_name: str,
    code_text: str,
    findings: list[Finding],
    indictment: dict,
    defender: dict,
    context: str = "",
    evidence: dict | None = None,
    *,
    track: str = TRACK_SAST,
) -> str:
    """Grounded Prosecutor: runs after the Defender and may only verify the
    Defender's cited guard against the Static Indictment."""
    track = resolve_board_track(track, findings)
    track2_fields = ""
    track2_rule = ""
    if track == TRACK_LLM_SCREEN:
        track2_rule = (
            "\n4. Also name the external input parameter of this function that the charge rests on "
            "(input_parameter) and copy the one line inside the function that mutates state or exposes data "
            "(state_line), character for character without the line-number prefix. Use \"\" if none exists."
        )
        track2_fields = '\n     "input_parameter": "parameter name or empty",\n     "state_line": "exact code line or empty",'
    return f"""You are the PROSECUTOR on an application security review board, giving a grounded rebuttal.
You may NOT invent a new sink or new CWE. Inspect ONLY the Static Indictment and the Defender's cited guard/caller.

===== STATIC INDICTMENT =====
Findings: {indictment.get("finding_ids") or "none (Soft LLM Screen)"}
Charge: {_clip(indictment.get("vulnerability"), ARGUMENT_CHARS)}
Path: {_clip(indictment.get("exploit_path"), ARGUMENT_CHARS)}

===== DEFENDER'S CITED GUARD =====
Sanitization evidence: {_clip(defender.get("sanitization_evidence"), 400)}{_format_evidence_status(evidence)}
Mitigating controls: {_clip(defender.get("mitigating_controls"), 400)}
Rebuttal: {_clip(defender.get("rebuttal"), ARGUMENT_CHARS)}

Answer two questions in 3 sentences:
(1) In the caller code or local guard cited by the Defender, is the tainted variable actually sanitized/authenticated on ALL paths, or does a path pass through raw?
(2) If the function was patched, state PATCH_VERIFIED if the Defender's cited guard completely blocks the CWE.

Rules:
1. Judge only the cited guard against the indicted variable and sink. A guard that is not in the code shown does not count.
2. raw_path is "YES" if at least one path reaches the indicted sink/operation without the guard, else "NO".
3. patch_verified is "PATCH_VERIFIED" only if the cited guard completely blocks the CWE on every path, else "NO".{track2_rule}
5. {_INJECTION_GUARD}
6. Output one JSON object exactly matching this schema:
   {{
     "raw_path": "YES" or "NO",
     "patch_verified": "PATCH_VERIFIED" or "NO",{track2_fields}
     "rebuttal": "At most 3 sentences answering (1) and (2), naming the lines."
   }}

{_evidence_packet(function_name, code_text, findings, context, include_rag=False)}

Respond with the JSON object only, starting with {{:"""


def format_findings(findings: list[Finding]) -> str:
    rows = []
    for i, f in enumerate(findings, start=1):
        cwe = ", ".join(f.cwe_ids) if f.cwe_ids else "no CWE"
        rows.append(
            f"[F{i}] {f.tool} {f.rule_id} ({f.severity}, {cwe}) at line {f.line_start}: {_clip(f.message, 200)}\n"
            f"      data flow: {_clip(_format_taint(f), 260)}"
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
            rows.append(f"- [{key}] {_clip(doc.get('text'), 260)}")
    return _clip("\n".join(rows), MAX_RAG_CHARS) if rows else "No reference definitions retrieved."


def _evidence_packet(
    function_name: str,
    code_text: str,
    findings: list[Finding],
    context: str = "",
    include_rag: bool = True,
) -> str:
    context_block = (
        f"\n===== CONTEXT (callers and callees from this file and the repository; not under review) =====\n"
        f"{context}\n" if context else ""
    )
    rag_block = f"\n===== REFERENCE DEFINITIONS (OWASP/CWE) =====\n{format_rag(findings)}\n" if include_rag else ""
    return f"""===== FUNCTION UNDER REVIEW: {function_name} =====

===== CANDIDATE FINDINGS (static + Joern CPG leads) =====
{format_findings(findings)}
{rag_block}{context_block}
===== UNTRUSTED SOURCE CODE (line numbers on the left) =====
[UNTRUSTED_CODE_START]
{code_text}
[UNTRUSTED_CODE_END]"""


def build_function_attacker_prompt(
    function_name: str,
    code_text: str,
    findings: list[Finding],
    context: str = "",
    *,
    track: str = TRACK_SAST,
) -> str:
    track = resolve_board_track(track, findings)
    if track == TRACK_LLM_SCREEN:
        # Track 2 — Semantic Invariant & Missing-Guard Check (LLM-Screen Flagged)
        duty = f"""You are the ATTACKER (Prosecutor) on an application security review board (Red Team).
TRACK: Semantic Invariant & Missing-Guard Check. No SAST line-numbered sink is required.
Argue that the function, AS WRITTEN, contains a real, exploitable security vulnerability.

Rules:
1. Name the privileged state change or sensitive resource in the function (e.g. authz decision, ownership mutation, file/DB write, crypto key use, dangerous call).
2. Specify the exact missing check (e.g. missing ownership check, missing bounds check, unchecked return value, missing authz/allowlist).
2b. Cite ONE concrete external input parameter of this function (input_parameter, its name exactly as in the signature) and ONE concrete line inside the function that mutates state or exposes data (state_line, copied character for character without the line-number prefix). Without both, your claim will not convict.
3. Trace how a caller or attacker reaches that state change without the check. Use CONTEXT when present.
4. Use ONLY the reference definitions to name the vulnerability class. Never cite a CWE or CVE from memory.
5. If no real missing guard exists, say so and give a low exploitability_confidence. Overclaiming loses the debate.
6. {_INJECTION_GUARD}
7. Output one JSON object exactly matching this schema:
   {{
     "finding_ids": ["F1"],
     "vulnerability": "Privileged state change / sensitive resource and the missing check...",
     "exploit_path": "How the missing guard is reached...",
     "preconditions": "What the attacker needs to reach this code...",
     "input_parameter": "name of the external input parameter",
     "state_line": "exact code line that mutates state or exposes data",
     "exploitability_confidence": 0.0 to 1.0 (float)
   }}"""
    else:
        # Track 1 — Sink & Taint Verification (SAST-Flagged)
        duty = f"""You are the ATTACKER (Prosecutor) on an application security review board (Red Team).
TRACK: Sink & Taint Verification. Automated SAST flagged an explicit sink line.
Argue that the function, AS WRITTEN, contains a real, exploitable security vulnerability.

Rules:
1. Use the findings as leads. Name the finding id(s) your argument rests on, e.g. ["F1"].
2. Prove an unbroken path from function input (parameter, request/CLI/file/env, or caller-controlled state) to the SAST-flagged sink line. Trace concretely: which input, which lines it passes through, and which sink call it reaches. Use the data-flow lines when they exist.
3. Use ONLY the reference definitions to name the vulnerability class. Never cite a CWE or CVE from memory.
4. If no finding is actually exploitable, say so and give a low exploitability_confidence. Overclaiming loses the debate.
5. {_INJECTION_GUARD}
6. Output one JSON object exactly matching this schema:
   {{
     "finding_ids": ["F1"],
     "vulnerability": "The vulnerability class and where it is...",
     "exploit_path": "Attacker-controlled input -> line -> line -> SAST-flagged sink...",
     "preconditions": "What the attacker needs to reach this code...",
     "exploitability_confidence": 0.0 to 1.0 (float)
   }}"""

    return f"""{duty}

{_evidence_packet(function_name, code_text, findings, context)}

Respond with the JSON object only, starting with {{:"""


def _format_evidence_status(evidence: dict | None) -> str:
    if not evidence:
        return ""
    if evidence.get("grounded") and evidence.get("location") == "context":
        span = _clip(evidence.get("matched_span"), 80)
        return (
            f"\nAutomated quote check: VERIFIED IN CONTEXT (matched span `{span}`) — the Defender's quote is in "
            "caller or callee code shown under CONTEXT, not in the function itself; check whether it guards every "
            "path that reaches the flagged operation."
        )
    if evidence.get("grounded"):
        span = _clip(evidence.get("matched_span"), 80)
        return (
            f"\nAutomated quote check: VERIFIED (matched span `{span}`) — the Defender's quote exists in the "
            "function; check whether it actually neutralizes the flagged operation on every path."
        )
    if evidence.get("reason") == "conceded":
        return "\nAutomated quote check: NONE — the Defender conceded ('none found') and cited no sanitizer in the function."
    return (
        "\nAutomated quote check: FAILED — the Defender's sanitization_evidence was NOT found verbatim in the "
        "function; disregard any claimed sanitizer not visible in the code below."
    )


def build_function_defender_prompt(
    function_name: str,
    code_text: str,
    findings: list[Finding],
    attacker: dict | None = None,
    context: str = "",
    include_rag: bool = False,
    *,
    track: str = TRACK_SAST,
) -> str:
    track = resolve_board_track(track, findings)
    claim_block = ""
    if attacker:
        claim_block = f"""
===== ATTACKER'S CLAIM =====
Findings: {attacker.get("finding_ids") or "none named"}
Vulnerability: {_clip(attacker.get("vulnerability"), ARGUMENT_CHARS)}
Exploit path: {_clip(attacker.get("exploit_path"), ARGUMENT_CHARS)}
"""
    if track == TRACK_LLM_SCREEN:
        # Track 2 — Semantic Invariant & Missing-Guard Check
        duty = f"""You are the DEFENDER on an application security review board (Blue Team).
TRACK: Semantic Invariant & Missing-Guard Check.
Argue that the function below is NOT exploitable as written.
{claim_block}
Rules:
1. Argue why the function is an internal helper (not attacker-reachable) OR why the required check is already enforced locally (or in callers shown under CONTEXT): ownership/authz checks, bounds checks, return-value handling, allowlists, early validation returns.
2. Copy the exact code that enforces the guard into sanitization_evidence, character for character, without the line-number prefix.
3. If no local (or shown caller) guard exists and the function is attacker-reachable, write "none found" and give a low safety_confidence. Never invent code that is not shown.
4. {_INJECTION_GUARD}
5. Output one JSON object exactly matching this schema:
   {{
     "sanitization_evidence": "exact code copied from the function, or 'none found'",
     "mitigating_controls": "Why this is an internal helper, or call-site / framework controls...",
     "rebuttal": "Why the missing-guard claim fails, or a concession if it is exploitable...",
     "safety_confidence": 0.0 to 1.0 (float)
   }}"""
    else:
        # Track 1 — Sink & Taint Verification
        duty = f"""You are the DEFENDER on an application security review board (Blue Team).
TRACK: Sink & Taint Verification.
Argue that the function below is NOT exploitable as written, and rebut the candidate findings.
{claim_block}
Rules:
1. Look for local parameterization, type casting (int()/float()), allowlists, early validation returns, escaping, shell=False, safe loaders, realpath/abspath+startswith, framework auto-escaping, or input that is not attacker-controlled at all (also check callers shown under CONTEXT).
2. Copy the exact code that neutralizes the input into sanitization_evidence, character for character, without the line-number prefix.
3. If nothing in the code neutralizes the flagged sink, write "none found" and give a low safety_confidence. Never invent code that is not shown, and do not assume that callers not shown under CONTEXT validate the input.
4. {_INJECTION_GUARD}
5. Output one JSON object exactly matching this schema:
   {{
     "sanitization_evidence": "exact code copied from the function, or 'none found'",
     "mitigating_controls": "Framework, configuration, or call-site controls that reduce risk...",
     "rebuttal": "Why the candidate finding is safe, or a concession if it is exploitable...",
     "safety_confidence": 0.0 to 1.0 (float)
   }}"""

    return f"""{duty}

{_evidence_packet(function_name, code_text, findings, context, include_rag=include_rag)}

Respond with the JSON object only, starting with {{:"""


def build_function_judge_prompt(
    function_name: str,
    code_text: str,
    findings: list[Finding],
    attacker: dict,
    defender: dict,
    context: str = "",
    evidence: dict | None = None,
    *,
    track: str = TRACK_SAST,
    rebuttal: dict | None = None,
) -> str:
    track = resolve_board_track(track, findings)
    rebuttal_block = ""
    if rebuttal:
        rebuttal_block = f"""
===== PROSECUTOR'S GROUNDED REBUTTAL (verification of the Defender's cited guard) =====
Raw path past the guard: {"YES" if rebuttal.get("raw_path") else "NO"}
Patch verified: {"PATCH_VERIFIED" if rebuttal.get("patch_verified") else "NO"}
Rebuttal: {_clip(rebuttal.get("rebuttal"), ARGUMENT_CHARS)}
Compare the Defender's claim against this specific verification; check both against the code.
"""
    if track == TRACK_LLM_SCREEN:
        # Track 2 — judge on missing-guard / privileged state change
        track_rule = (
            "2. This case has no SAST sink alert. Vote VULNERABLE only if the Prosecutor named a real "
            "privileged state change or sensitive resource AND the exact missing check is absent from the "
            "function (and from callers shown under CONTEXT). Vote NOT_VULNERABLE if the function is an "
            "internal helper not attacker-reachable, or the check is already enforced locally. "
            "This is the stricter track: the base rate of real vulnerabilities is lower here, so convict "
            "only if the Prosecutor cites a concrete input parameter AND a concrete state-mutating or "
            "data-exposing line that really exist in the function."
        )
        flow_rule = (
            "4. Do not require a Joern taint path; this track is about missing semantic guards, not sink taint."
        )
    else:
        # Track 1 — judge on unbroken input -> sink path
        track_rule = (
            "2. Candidate findings are frequently false alarms. Vote VULNERABLE if input an attacker can "
            "influence (a function parameter, request/CLI/file/env data, or state controlled by a caller) "
            "reaches the SAST-flagged sink without neutralization along an unbroken path."
        )
        flow_rule = (
            "4. If Joern data flow says no direct flow was found, treat that as inconclusive rather than "
            "proof of safety: static CPG taint misses flows through object attributes (self.*), dicts, "
            "callbacks, and decorators."
        )

    track2_cites = ""
    if track == TRACK_LLM_SCREEN:
        track2_cites = (
            f"\nCited input parameter: {_clip(attacker.get('input_parameter'), 80) or 'none'}"
            f"\nCited state-changing / data-exposing line: {_clip(attacker.get('state_line'), 200) or 'none'}"
        )

    return f"""You are the JUDGE on an application security review board.
Decide whether the function below, AS WRITTEN, contains an exploitable security vulnerability.
TRACK: {"Semantic Invariant & Missing-Guard Check" if track == TRACK_LLM_SCREEN else "Sink & Taint Verification"}.

===== ATTACKER (Red Team) =====
Findings: {attacker.get("finding_ids") or "none named"}
Vulnerability: {_clip(attacker.get("vulnerability"), ARGUMENT_CHARS)}
Exploit path: {_clip(attacker.get("exploit_path"), ARGUMENT_CHARS)}{track2_cites}
Self-reported exploitability: {attacker.get("exploitability_confidence", "unstated")}

===== DEFENDER (Blue Team) =====
Sanitization evidence: {_clip(defender.get("sanitization_evidence"), 400)}{_format_evidence_status(evidence)}
Mitigating controls: {_clip(defender.get("mitigating_controls"), 400)}
Rebuttal: {_clip(defender.get("rebuttal"), ARGUMENT_CHARS)}
Self-reported safety: {defender.get("safety_confidence", "unstated")}
{rebuttal_block}
Rules:
1. Decide from the code itself. The arguments are aids; neither side's rhetoric or confidence numbers decide the case.
{track_rule}
3. A defence counts only if the neutralizing / guarding code is really present in the function shown (or in a caller shown under CONTEXT) and verified by the Automated quote check above. Do NOT assume that callers not shown validate or sanitize arguments before calling this function.
{flow_rule}
5. Report calibrated confidence in your verdict: 0.5 means genuinely unsure, 0.9 means you would bet heavily. Do not inflate it.
6. Use ONLY the reference definitions for the vulnerability class. Never cite a CWE or CVE from memory.
7. {_INJECTION_GUARD}
8. Output one JSON object exactly matching this schema:
   {{
     "verdict": "VULNERABLE" or "NOT_VULNERABLE",
     "confidence": 0.0 to 1.0 (float, certainty in the verdict itself),
     "finding_ids": ["F1"],
     "reasoning": "Which lines decide it, and why..."
   }}

{_evidence_packet(function_name, code_text, findings, context)}

Respond with the JSON object only, starting with {{:"""
