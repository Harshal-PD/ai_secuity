import difflib

def compute_diff(original: str, patched: str) -> str:
    """
    Computes unified diff representation securely mapping modifications 
    across pure python arrays separating additions (+).
    """
    if not patched:
        return "No patch mapped."
    
    # Split mapping line boundaries
    org_lines = original.splitlines(keepends=True) if original else []
    pat_lines = patched.splitlines(keepends=True)
    
    diff_gen = difflib.unified_diff(
        org_lines, pat_lines, 
        fromfile="vulnerable_code.py", 
        tofile="patched_code.py"
    )
    
    return "".join(diff_gen)
