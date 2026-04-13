import sqlite3
import subprocess

def search_user(username):
    # SQL Injection Vulnerability
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

def ping_server(ip_address):
    # Command Injection Vulnerability
    command = "ping -c 1 " + ip_address
    subprocess.call(command, shell=True)

def exec_code(user_input):
    # Arbitrary Code Execution Vulnerability
    eval(user_input)

# Hardcoded credentials
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
