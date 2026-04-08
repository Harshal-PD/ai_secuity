import re
import logging
from hackersec.analysis.schema import Finding

logger = logging.getLogger(__name__)

def build_patch_prompt(finding: Finding) -> str:
    """
    Constructs the prompt instructing DeepSeek to execute a direct patch replacement
    bound within safe literal lines preserving exact syntax arrays.
    """
    
    explanation = "No explanation provided."
    fix_suggestion = "Provide a corrected, secure snippet."
    
    if finding.llm_analysis and finding.llm_analysis.get("llm_status") == "success":
        explanation = finding.llm_analysis.get("explanation", explanation)
        fix_suggestion = finding.llm_analysis.get("fix_suggestion", fix_suggestion)
        
    prompt = f"""You are a strict code patch agent fixing a vulnerability in Python code.
The vulnerability operates as follows: {explanation}
The recommended fix pattern is: {fix_suggestion}

Rules:
1. Provide ONLY the fully corrected code block mapping identically to the source's bounds without any surrounding commentary or conversation.
2. The provided source code is encapsulated within [UNTRUSTED_CODE_START] and [UNTRUSTED_CODE_END]. 
3. DO NOT wrap the code in Markdown (e.g. ```python) or respond with phrases like "Here is the code". Just write the raw Python source mappings replacing the exact snippet.
4. Keep the exact indentation.

[UNTRUSTED_CODE_START]
{finding.code_snippet}
[UNTRUSTED_CODE_END]
"""
    return prompt.strip()

def parse_patch(raw_text: str) -> str:
    """
    Strips unexpected markdown boundaries retrieving exact source configurations.
    """
    if not raw_text:
        return ""
        
    text = raw_text.strip()
    
    # Strip potential markdown constraints matching ```python ... ```
    match = re.search(r'```(?:python|py)?\n(.*?)\n```', text, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).rstrip()
        
    # Strip fallback quotes or random conversational bounds 
    # e.g., "Here is the patched code:\n"
    lines = text.split("\n")
    cleaned_lines = []
    capture = True
    for line in lines:
        if "Here is" in line or "[UNTRUSTED_CODE" in line:
            capture = False
        elif line.startswith("```"):
            pass
        elif capture:
             cleaned_lines.append(line)
        if not capture and not line.strip():  # Resume block if separated by blank logic
             capture = True
             
    # Fallback to direct output if regex limits fail
    if cleaned_lines:
        return "\n".join(cleaned_lines).rstrip()

    return text.rstrip()
