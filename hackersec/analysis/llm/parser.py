import json
import re
import logging

logger = logging.getLogger(__name__)

def parse_llm_response(raw_text: str) -> dict:
    """
    Safely captures unstructured or structured strings rendering DeepSeek's outputs
    into validated internal data structures for the pipeline.
    """
    if not raw_text:
         return {"llm_status": "failed_parsing", "explanation": "Empty LLM output returned."}
         
    text = raw_text.strip()
    
    # Attempt straightforward decode
    try:
        data = json.loads(text)
        return _validate_schema(data)
    except json.JSONDecodeError:
        pass
        
    # Attempt regex scraping of nested markdown blocks
    match = re.search(r'```(?:json)?\n(.*?)\n```', text, re.IGNORECASE | re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1).strip())
            return _validate_schema(data)
        except json.JSONDecodeError:
            pass

    return {
        "llm_status": "failed_parsing", 
        "explanation": "Could not map JSON strings from LLM payload.",
        "raw_fallback": text[:200]
    }

def _validate_schema(data: dict) -> dict:
    """
    Ensures typing and fields loosely correspond to the expected structure.
    """
    # Enforce float conversion
    confidence = data.get("confidence", 0.0)
    try:
        confidence = float(confidence)
    except (ValueError, TypeError):
        confidence = 0.0
        
    return {
        "llm_status": "success",
        "explanation": data.get("explanation", "No explanation mapped."),
        "root_cause": data.get("root_cause", "No root cause mapped."),
        "fix_suggestion": data.get("fix_suggestion", "No fix mapped."),
        "confidence": min(max(confidence, 0.0), 1.0) # bound 0->1
    }
