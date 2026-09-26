import hashlib
import hmac
import pickle

SIGNING_KEY = b"rotated-out-of-band"

def load_session(blob, signature):
    expected = hmac.new(SIGNING_KEY, blob, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("untrusted payload rejected")
    return pickle.loads(blob)
