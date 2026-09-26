from urllib.parse import urlparse

import requests

ALLOWED_HOSTS = {"api.internal.example.com"}

def fetch(user_url):
    host = urlparse(user_url).hostname
    if host not in ALLOWED_HOSTS:
        raise ValueError("destination not on the allow list")
    return requests.get(user_url, timeout=5)
