import json
import re
import logging

logger = logging.getLogger(__name__)


def _extract_json(raw_text: str) -> dict | None:
    """
    Recovers a JSON object from a model response, tolerating markdown fences and
    surrounding prose. Returns None when nothing parseable is present.
    """
    if not raw_text:
        return None

    text = raw_text.strip()

    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        pass

    # Attempt regex scraping of nested markdown blocks
    match = re.search(r'```(?:json)?\n(.*?)\n```', text, re.IGNORECASE | re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1).strip())
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            pass

    # Last resort: grab the outermost brace pair from a chatty response
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            data = json.loads(text[start:end + 1])
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            pass

    return None


def _bounded_float(value, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (ValueError, TypeError):
        return default
    return min(max(parsed, 0.0), 1.0)


def parse_llm_response(raw_text: str) -> dict:
    """
    Safely captures unstructured or structured strings rendering the model's outputs
    into validated internal data structures for the pipeline.
    """
    if not raw_text:
        return {"llm_status": "failed_parsing", "explanation": "Empty LLM output returned."}

    data = _extract_json(raw_text)
    if data is None:
        return {
            "llm_status": "failed_parsing",
            "explanation": "Could not map JSON strings from LLM payload.",
            "raw_fallback": raw_text.strip()[:200]
        }

    return _validate_schema(data)


def _validate_schema(data: dict) -> dict:
    """
    Ensures typing and fields loosely correspond to the expected structure.
    """
    return {
        "llm_status": "success",
        "explanation": data.get("explanation", "No explanation mapped."),
        "root_cause": data.get("root_cause", "No root cause mapped."),
        "fix_suggestion": data.get("fix_suggestion", "No fix mapped."),
        "confidence": _bounded_float(data.get("confidence", 0.0))
    }


# ─── Board member parsers ───────────────────────────────────────────────────

def parse_attacker_response(raw_text: str) -> dict:
    """Normalizes the Red Team submission. Never raises — the board must survive."""
    data = _extract_json(raw_text)
    if data is None:
        return {
            "status": "failed_parsing",
            "exploit_path": "Attacker submission unparseable.",
            "preconditions": "unknown",
            "impact": "unknown",
            "exploitability_confidence": 0.0,
        }

    return {
        "status": "success",
        "exploit_path": str(data.get("exploit_path", "No exploit path submitted.")),
        "preconditions": str(data.get("preconditions", "None stated.")),
        "impact": str(data.get("impact", "None stated.")),
        "exploitability_confidence": _bounded_float(data.get("exploitability_confidence", 0.0)),
    }


def parse_defender_response(raw_text: str) -> dict:
    """Normalizes the Blue Team submission. Never raises — the board must survive."""
    data = _extract_json(raw_text)
    if data is None:
        return {
            "status": "failed_parsing",
            "sanitization_evidence": "none found",
            "mitigating_controls": "unknown",
            "rebuttal": "Defender submission unparseable.",
            "safety_confidence": 0.0,
        }

    return {
        "status": "success",
        "sanitization_evidence": str(data.get("sanitization_evidence", "none found")),
        "mitigating_controls": str(data.get("mitigating_controls", "None stated.")),
        "rebuttal": str(data.get("rebuttal", "No rebuttal submitted.")),
        "safety_confidence": _bounded_float(data.get("safety_confidence", 0.0)),
    }


def _finding_ids(value) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value if str(v).strip()][:10]


def parse_function_attacker_response(raw_text: str) -> dict:
    """Red Team submission for a whole function. Never raises."""
    data = _extract_json(raw_text)
    if data is None:
        return {
            "status": "failed_parsing",
            "finding_ids": [],
            "vulnerability": "Attacker submission unparseable.",
            "exploit_path": "unknown",
            "preconditions": "unknown",
            "exploitability_confidence": 0.0,
        }
    return {
        "status": "success",
        "finding_ids": _finding_ids(data.get("finding_ids")),
        "vulnerability": str(data.get("vulnerability", "None stated.")),
        "exploit_path": str(data.get("exploit_path", "No exploit path submitted.")),
        "preconditions": str(data.get("preconditions", "None stated.")),
        "exploitability_confidence": _bounded_float(data.get("exploitability_confidence", 0.0)),
        # Track 2 only: the concrete input and the concrete state-changing / data-exposing line.
        "input_parameter": str(data.get("input_parameter") or "").strip(),
        "state_line": str(data.get("state_line") or "").strip(),
    }


def _yes(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().upper().replace(" ", "_") in ("YES", "TRUE", "1", "RAW", "PATCH_VERIFIED")


def parse_prosecutor_rebuttal(raw_text: str) -> dict:
    """Grounded Prosecutor rebuttal of the Defender's cited guard. Never raises.
    An unparseable rebuttal claims nothing: no raw path, no patch verification."""
    data = _extract_json(raw_text)
    if data is None:
        return {"status": "failed_parsing", "raw_path": False, "patch_verified": False,
                "rebuttal": "Prosecutor rebuttal unparseable.", "input_parameter": "", "state_line": ""}
    return {
        "status": "success",
        "raw_path": _yes(data.get("raw_path")),
        "patch_verified": _yes(data.get("patch_verified")),
        "rebuttal": str(data.get("rebuttal", "No rebuttal submitted."))[:800],
        "input_parameter": str(data.get("input_parameter") or "").strip(),
        "state_line": str(data.get("state_line") or "").strip(),
    }


def parse_vote_response(raw_text: str) -> dict:
    """
    One Judge vote on a whole function.

    `p_vulnerable` converts the Judge's certainty in its own verdict into a
    probability that the function is vulnerable. An unparseable vote is
    returned with status failed_parsing and no probability, so it can be
    excluded from the tally instead of silently counting either way.
    """
    data = _extract_json(raw_text)
    if data is None:
        return {"status": "failed_parsing", "verdict": None, "confidence": None, "p_vulnerable": None,
                "finding_ids": [], "reasoning": ""}

    raw = str(data.get("verdict", "")).strip().upper().replace(" ", "_").replace("-", "_")
    if any(k in raw for k in ("NOT", "SAFE", "FALSE", "BENIGN")):
        verdict = "NOT_VULNERABLE"
    elif any(k in raw for k in ("VULN", "TRUE", "EXPLOIT")):
        verdict = "VULNERABLE"
    else:
        return {"status": "failed_parsing", "verdict": None, "confidence": None, "p_vulnerable": None,
                "finding_ids": [], "reasoning": str(data.get("reasoning", ""))[:400]}

    confidence = _bounded_float(data.get("confidence", 0.5), default=0.5)
    p_vuln = confidence if verdict == "VULNERABLE" else 1.0 - confidence
    return {
        "status": "success",
        "verdict": verdict,
        "confidence": confidence,
        "p_vulnerable": round(p_vuln, 4),
        "finding_ids": _finding_ids(data.get("finding_ids")),
        "reasoning": str(data.get("reasoning", ""))[:600],
    }


def parse_judge_response(raw_text: str) -> dict:
    """
    Normalizes the arbitration result.

    `confidence` from the model is certainty in its own verdict. Downstream
    consumers need P(vulnerability is real), so a confident FALSE_POSITIVE is
    inverted here rather than in the fusion layer.
    """
    data = _extract_json(raw_text)
    if data is None:
        # Unparseable arbitration must not silently dismiss a finding.
        return {
            "status": "failed_parsing",
            "verdict": "TRUE_POSITIVE",
            "verdict_confidence": 0.5,
            "confidence": 0.5,
            "explanation": "Judge output unparseable — defaulting to true positive.",
            "root_cause": "No root cause mapped.",
            "fix_suggestion": "No fix mapped.",
            "reasoning": "Arbitration failed to produce valid JSON.",
        }

    raw_verdict = str(data.get("verdict", "")).strip().upper()
    verdict = "FALSE_POSITIVE" if "FALSE" in raw_verdict else "TRUE_POSITIVE"

    verdict_confidence = _bounded_float(data.get("confidence", 0.5), default=0.5)
    prob_real = verdict_confidence if verdict == "TRUE_POSITIVE" else 1.0 - verdict_confidence

    return {
        "status": "success",
        "verdict": verdict,
        "verdict_confidence": verdict_confidence,
        "confidence": round(prob_real, 4),
        "explanation": str(data.get("explanation", "No explanation mapped.")),
        "root_cause": str(data.get("root_cause", "No root cause mapped.")),
        "fix_suggestion": str(data.get("fix_suggestion", "No fix mapped.")),
        "reasoning": str(data.get("reasoning", "No reasoning mapped.")),
    }
