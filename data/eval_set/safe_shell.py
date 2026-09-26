import os
import subprocess

def list_dir(user_dir):
    safe_name = os.path.basename(user_dir)
    return subprocess.run(["ls", "-la", safe_name], shell=False, capture_output=True)
