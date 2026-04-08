"""
Deliberately vulnerable Python file for HackerSec testing.
Each vulnerability is labeled with its expected CWE.
DO NOT use in production.
"""
import sqlite3
import os
import subprocess
import hashlib

# CWE-89: SQL Injection
def get_user_by_name(username: str):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()


# CWE-78: OS Command Injection
def run_shell_command(user_input: str):
    os.system(f"echo {user_input}")
    subprocess.call(f"ls {user_input}", shell=True)


# CWE-327: Use of Broken Cryptographic Algorithm
def hash_password_weak(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# CWE-259: Hardcoded Password
DB_PASSWORD = "supersecret123"  # noqa
API_KEY = "sk-abc123hardcoded"  # noqa


# CWE-22: Path Traversal
def read_file(filename: str) -> str:
    with open(f"/var/data/{filename}", "r") as f:
        return f.read()
