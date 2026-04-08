import json
import os
from pathlib import Path

def generate_test_suite(out_dir: str = "data/eval_set"):
    """
    Generates a localized mock subset representing Juliet/Big-Vul offline tests 
    preventing massive gigabyte downloads stalling pipelines.
    """
    # Create the matrix limits securely simulating real python boundaries
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    
    mock_files = [
        {
            "name": "vuln_md5.py",
            "code": "import hashlib\ndef hash_password(p):\n    return hashlib.md5(p.encode()).hexdigest()\n",
            "label": 1, # True Positive Vuln
            "cwe": "CWE-328"
        },
        {
            "name": "vuln_eval.py",
            "code": "def process_user(input_str):\n    return eval(input_str)\n",
            "label": 1,
            "cwe": "CWE-95"
        },
        {
            "name": "safe_sha256.py",
            "code": "import hashlib\ndef hash_password(p):\n    return hashlib.sha256(p.encode()).hexdigest()\n",
            "label": 0, # Secure code mapping False Positive targets
            "cwe": "CWE-328"
        }
    ]
    
    metadata = {}
    
    for f in mock_files:
        path = base / f["name"]
        path.write_text(f["code"])
        metadata[str(path)] = {
            "label": f["label"],
            "cwe": f["cwe"]
        }
        
    meta_path = base / "metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2))
    
    return str(meta_path)

def load_dataset(meta_path: str) -> dict:
    with open(meta_path, 'r') as f:
        return json.load(f)
