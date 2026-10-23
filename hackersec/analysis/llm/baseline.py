"""
Single-prompt review of one function, with no static findings.

This is the comparison baseline for the SAST-gated board: the same model,
asked once whether the function is exploitable. A second call includes the
same context the board sees. Neither call is part of the shipped pipeline;
the evaluation records them so accuracy and tokens can be compared.
"""

from hackersec.analysis.llm.parser import _bounded_float, _extract_json
from hackersec.analysis.llm.prompter import _INJECTION_GUARD

TEMPERATURE = 0.0
MAX_TOKENS = 400


def build_prompt(function_name: str, code_text: str, context: str = "") -> str:
    context_block = (
        f"\n===== CONTEXT (callers and callees from this file and the repository; not under review) =====\n"
        f"{context}\n" if context else ""
    )
    return f"""You are a security reviewer. Decide whether the Python function below, AS WRITTEN, contains an exploitable security vulnerability.

Rules:
1. A vulnerability needs input an attacker can influence reaching a dangerous operation (a query, command, file path, deserialization, redirect, template, or permission decision) with no validation, escaping, parameterization, allowlist, or permission check on that path.
2. If the code shown already neutralizes that path, or the input is not attacker-controlled, the verdict is NOT_VULNERABLE.
3. Do not report style issues, hardening advice, or problems that only arise if a caller misuses the function.
4. confidence is your certainty in the verdict: 0.5 means genuinely unsure, 0.9 means you would bet heavily. Do not inflate it.
5. {_INJECTION_GUARD}
6. Output one JSON object exactly matching this schema:
   {{
     "verdict": "VULNERABLE" or "NOT_VULNERABLE",
     "confidence": 0.0 to 1.0,
     "reasoning": "Which lines decide it, and why..."
   }}
{context_block}
===== FUNCTION UNDER REVIEW: {function_name} =====
[UNTRUSTED_CODE_START]
{code_text}
[UNTRUSTED_CODE_END]

Respond with the JSON object only, starting with {{:"""


def parse_response(raw_text: str) -> dict:
    """Verdict plus P(vulnerable). An unreadable answer is kept as vulnerable
    at 0.5, the same fallback the board uses, so a parse failure cannot
    silently clear a function."""
    data = _extract_json(raw_text)
    raw = str((data or {}).get("verdict", "")).strip().upper().replace(" ", "_").replace("-", "_")
    if data is not None and any(k in raw for k in ("NOT", "SAFE", "FALSE", "BENIGN")):
        verdict = "NOT_VULNERABLE"
    elif data is not None and any(k in raw for k in ("VULN", "TRUE", "EXPLOIT")):
        verdict = "VULNERABLE"
    else:
        return {"status": "failed_parsing", "verdict": None, "confidence": None,
                "p_vulnerable": 0.5, "prediction": 1, "reasoning": ""}

    confidence = _bounded_float(data.get("confidence", 0.5), default=0.5)
    p_vuln = confidence if verdict == "VULNERABLE" else 1.0 - confidence
    return {
        "status": "success",
        "verdict": verdict,
        "confidence": confidence,
        "p_vulnerable": round(p_vuln, 4),
        "prediction": int(verdict == "VULNERABLE"),
        "reasoning": str(data.get("reasoning", ""))[:400],
    }


def review(client, model: str, function_name: str, code_text: str, context: str = "") -> dict:
    """One generation. Transport failures are returned as-is so the caller
    can wait for Ollama and retry."""
    res = client.generate(
        build_prompt(function_name, code_text, context),
        model=model, temperature=TEMPERATURE, seed=11, max_tokens=MAX_TOKENS,
    )
    if res.get("llm_status") != "success":
        return res
    parsed = parse_response(res.get("response") or "")
    return {
        "llm_status": "success",
        **parsed,
        "tokens": _usage(res),
    }


def _usage(res: dict) -> dict:
    return {
        "prompt": int(res.get("prompt_tokens") or 0),
        "completion": int(res.get("completion_tokens") or 0),
        "calls": 1,
    }
