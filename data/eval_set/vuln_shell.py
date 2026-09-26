import subprocess

def list_dir(user_dir):
    return subprocess.run("ls -la " + user_dir, shell=True, capture_output=True)
