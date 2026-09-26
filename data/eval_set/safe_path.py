import os

BASE_DIR = "/var/app/uploads"

def read_upload(name):
    # basename strips every ../ traversal sequence
    with open(os.path.join(BASE_DIR, os.path.basename(name))) as handle:
        return handle.read()
