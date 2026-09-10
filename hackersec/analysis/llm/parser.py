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
