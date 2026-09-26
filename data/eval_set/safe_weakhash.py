import hashlib

def cache_key(payload):
    # non-security use: this digest is only a cache bucket
    return hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()
