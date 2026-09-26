import sqlite3

def find_user(conn, name):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    return cursor.fetchall()
