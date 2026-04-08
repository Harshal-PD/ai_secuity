import tempfile
import subprocess
import json
import logging
import os
from hackersec.analysis.schema import Finding

logger = logging.getLogger(__name__)

def validate_patch(finding: Finding, patch_text: str) -> str:
    """
    Submits a mock validation string mapping exclusively against the local 
    rule configuration proving standard regression offsets.
    """
    if not patch_text or not finding.rule_id:
        return "unverified"
        
    try:
        # Create a temporary file safely mocking standard string writes
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tmp:
            tmp.write(patch_text)
            tmp_path = tmp.name
            
        try:
            # We assume finding.rule_id matches standard configuration strings.
            # Example rule: "python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5"
            # It's better to run Semgrep targeting p/ci since local configs vary dynamically
            cmd = ["semgrep", "--config", "p/ci", "--json", tmp_path]
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            
            # Scrape validation loops masking stdout 
            out = json.loads(result.stdout)
            results = out.get("results", [])
            
            # Assert vulnerability boundaries
            # Check if any result hits the same exact rule
            hits = [r for r in results if r.get("check_id") == finding.rule_id]
            
            if len(hits) == 0:
                 return "fixed"
            else:
                 return "still_vulnerable"
                 
        finally:
            os.remove(tmp_path)
            
    except Exception as e:
        logger.warning(f"Semgrep patch validation safely bounded exceptions: {e}")
        return "unverified"
