"""
Local labeled evaluation set.

The set is built as matched pairs. Each `vulnerable` file has a `neutralized`
counterpart that KEEPS the same dangerous sink but adds an explicit, quotable
sanitizer on the tainted path. Semgrep and Bandit therefore flag both members
of most pairs, and the neutralized member is precisely the false positive the
adversarial board is supposed to dismiss.

This makes FPR meaningful: a system that simply trusts the static tool scores
~50% precision on this set, while a system that reads the sanitizer can do
better. `expected_sanitizer` records the span a correct Defender should quote,
which is what the citation-required rule is checked against.
"""

import json
from pathlib import Path
from textwrap import dedent

# ── Matched pairs: (cwe, vulnerable source, neutralized source, sanitizer) ──

PAIRS = [
    {
        "pair_id": "sqli",
        "cwe": "CWE-89",
        "vuln_name": "vuln_sqli.py",
        "safe_name": "safe_sqli.py",
        "expected_sanitizer": "int(user_id)",
        "vuln": """
            import sqlite3

            def find_user(conn, name):
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
                return cursor.fetchall()
        """,
        "safe": """
            import sqlite3

            def find_user_by_id(conn, user_id):
                cursor = conn.cursor()
                # user_id is cast to an integer before it reaches the query
                cursor.execute("SELECT * FROM users WHERE id = %d" % int(user_id))
                return cursor.fetchall()
        """,
    },
    {
        "pair_id": "oscmd",
        "cwe": "CWE-78",
        "vuln_name": "vuln_oscmd.py",
        "safe_name": "safe_oscmd.py",
        "expected_sanitizer": "int(pid)",
        "vuln": """
            import os

            def stop_process(user_pid):
                os.system("kill -9 " + user_pid)
        """,
        "safe": """
            import os

            def stop_process(pid):
                # integer cast removes every shell metacharacter
                os.system("kill -9 " + str(int(pid)))
        """,
    },
    {
        "pair_id": "shell",
        "cwe": "CWE-77",
        "vuln_name": "vuln_shell.py",
        "safe_name": "safe_shell.py",
        "expected_sanitizer": "shell=False",
        "vuln": """
            import subprocess

            def list_dir(user_dir):
                return subprocess.run("ls -la " + user_dir, shell=True, capture_output=True)
        """,
        "safe": """
            import os
            import subprocess

            def list_dir(user_dir):
                safe_name = os.path.basename(user_dir)
                return subprocess.run(["ls", "-la", safe_name], shell=False, capture_output=True)
        """,
    },
    {
        "pair_id": "eval",
        "cwe": "CWE-94",
        "vuln_name": "vuln_eval.py",
        "safe_name": "safe_eval.py",
        "expected_sanitizer": "int(raw_value)",
        "vuln": """
            def compute(user_expression):
                return eval(user_expression)
        """,
        "safe": """
            def compute(raw_value):
                # only an integer literal can ever reach the interpreter
                return eval(str(int(raw_value)))
        """,
    },
    {
        "pair_id": "path",
        "cwe": "CWE-22",
        "vuln_name": "vuln_path.py",
        "safe_name": "safe_path.py",
        "expected_sanitizer": "os.path.basename(name)",
        "vuln": """
            import os

            BASE_DIR = "/var/app/uploads"

            def read_upload(name):
                with open(os.path.join(BASE_DIR, name)) as handle:
                    return handle.read()
        """,
        "safe": """
            import os

            BASE_DIR = "/var/app/uploads"

            def read_upload(name):
                # basename strips every ../ traversal sequence
                with open(os.path.join(BASE_DIR, os.path.basename(name))) as handle:
                    return handle.read()
        """,
    },
    {
        "pair_id": "pickle",
        "cwe": "CWE-502",
        "vuln_name": "vuln_pickle.py",
        "safe_name": "safe_pickle.py",
        "expected_sanitizer": "hmac.compare_digest(expected, signature)",
        "vuln": """
            import pickle

            def load_session(blob):
                return pickle.loads(blob)
        """,
        "safe": """
            import hashlib
            import hmac
            import pickle

            SIGNING_KEY = b"rotated-out-of-band"

            def load_session(blob, signature):
                expected = hmac.new(SIGNING_KEY, blob, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, signature):
                    raise ValueError("untrusted payload rejected")
                return pickle.loads(blob)
        """,
    },
    {
        "pair_id": "weakhash",
        "cwe": "CWE-327",
        "vuln_name": "vuln_weakhash.py",
        "safe_name": "safe_weakhash.py",
        "expected_sanitizer": "usedforsecurity=False",
        "vuln": """
            import hashlib

            def store_password(password):
                return hashlib.md5(password.encode()).hexdigest()
        """,
        "safe": """
            import hashlib

            def cache_key(payload):
                # non-security use: this digest is only a cache bucket
                return hashlib.md5(payload.encode(), usedforsecurity=False).hexdigest()
        """,
    },
    {
        "pair_id": "secret",
        "cwe": "CWE-798",
        "vuln_name": "vuln_secret.py",
        "safe_name": "safe_secret.py",
        "expected_sanitizer": 'os.environ["DB_PASSWORD"]',
        "vuln": """
            DB_PASSWORD = "Pr0d-Admin-2024!"

            def connect(driver):
                return driver.connect(user="admin", password=DB_PASSWORD)
        """,
        "safe": """
            import os

            def connect(driver):
                return driver.connect(user="admin", password=os.environ["DB_PASSWORD"])
        """,
    },
    {
        "pair_id": "xxe",
        "cwe": "CWE-611",
        "vuln_name": "vuln_xxe.py",
        "safe_name": "safe_xxe.py",
        "expected_sanitizer": "STATIC_CONFIG",
        "vuln": """
            import xml.etree.ElementTree as ET

            def parse_profile(user_xml):
                return ET.fromstring(user_xml)
        """,
        "safe": """
            import xml.etree.ElementTree as ET

            STATIC_CONFIG = "<config><debug>false</debug></config>"

            def load_default_config():
                # parses a compile-time constant, never external input
                return ET.fromstring(STATIC_CONFIG)
        """,
    },
    {
        "pair_id": "ssrf",
        "cwe": "CWE-918",
        "vuln_name": "vuln_ssrf.py",
        "safe_name": "safe_ssrf.py",
        "expected_sanitizer": "if host not in ALLOWED_HOSTS",
        "vuln": """
            import requests

            def fetch(user_url):
                return requests.get(user_url, timeout=5)
        """,
        "safe": """
            from urllib.parse import urlparse

            import requests

            ALLOWED_HOSTS = {"api.internal.example.com"}

            def fetch(user_url):
                host = urlparse(user_url).hostname
                if host not in ALLOWED_HOSTS:
                    raise ValueError("destination not on the allow list")
                return requests.get(user_url, timeout=5)
        """,
    },
    {
        "pair_id": "xss",
        "cwe": "CWE-79",
        "vuln_name": "vuln_xss.py",
        "safe_name": "safe_xss.py",
        "expected_sanitizer": "html.escape(name)",
        "vuln": """
            def render_greeting(name):
                return "<b>Hello " + name + "</b>"
        """,
        "safe": """
            import html

            def render_greeting(name):
                return "<b>Hello " + html.escape(name) + "</b>"
        """,
    },
    {
        "pair_id": "random",
        "cwe": "CWE-330",
        "vuln_name": "vuln_random.py",
        "safe_name": "safe_random.py",
        "expected_sanitizer": "secrets.token_hex(32)",
        "vuln": """
            import random

            def new_reset_token():
                return str(random.random())
        """,
        "safe": """
            import secrets

            def new_reset_token():
                return secrets.token_hex(32)
        """,
    },
]


def generate_test_suite(out_dir: str = "data/eval_set") -> str:
    """
    Write the paired evaluation set to disk and return the metadata path.

    Metadata per file:
        label               1 = real vulnerability, 0 = neutralized / safe
        cwe                 ground-truth weakness class
        pair_id             links a vulnerable file to its neutralized twin
        kind                vulnerable | neutralized
        expected_sanitizer  span a correct Defender should quote (safe files)
    """
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)

    metadata = {}

    for pair in PAIRS:
        vuln_path = base / pair["vuln_name"]
        vuln_path.write_text(dedent(pair["vuln"]).strip() + "\n", encoding="utf-8")
        metadata[str(vuln_path)] = {
            "label": 1,
            "cwe": pair["cwe"],
            "pair_id": pair["pair_id"],
            "kind": "vulnerable",
            "expected_sanitizer": None,
        }

        safe_path = base / pair["safe_name"]
        safe_path.write_text(dedent(pair["safe"]).strip() + "\n", encoding="utf-8")
        metadata[str(safe_path)] = {
            "label": 0,
            "cwe": pair["cwe"],
            "pair_id": pair["pair_id"],
            "kind": "neutralized",
            "expected_sanitizer": pair["expected_sanitizer"],
        }

    meta_path = base / "metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    return str(meta_path)


def load_dataset(meta_path: str) -> dict:
    with open(meta_path, "r", encoding="utf-8") as f:
        return json.load(f)
