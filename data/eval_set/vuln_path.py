import os

BASE_DIR = "/var/app/uploads"

def read_upload(name):
    with open(os.path.join(BASE_DIR, name)) as handle:
        return handle.read()
