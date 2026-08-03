import tempfile
import subprocess
import json
import logging
import os
from pathlib import Path
from hackersec.analysis.schema import Finding

logger = logging.getLogger(__name__)


def validate_patch(finding: Finding, patch_text: str) -> str:
    """
    Re-run Semgrep on the patched code with the SAME rule packs the scan used
    (language-aware), not a fixed p/ci. A patch is 'fixed' only if the exact
    rule that flagged the finding no longer hits — otherwise the validator can
    declare 'fixed' just because p/ci never ran that rule.
    """
    if not patch_text or not finding.rule_id:
        return "unverified"

    # Preserve the finding's language so the right packs + parser apply.
    suffix = Path(finding.file_path).suffix or ".py"

    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False, encoding="utf-8") as tmp:
            tmp.write(patch_text)
            tmp_path = tmp.name

        try:
            from hackersec.analysis.static import select_semgrep_configs
            cmd = ["semgrep", "--json", "--metrics=off"]
            for cfg in select_semgrep_configs(Path(tmp_path)):
                cmd += ["--config", cfg]
            cmd.append(tmp_path)
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
