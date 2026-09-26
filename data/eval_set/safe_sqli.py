import sqlite3

def find_user_by_id(conn, user_id):
    cursor = conn.cursor()
    # user_id is cast to an integer before it reaches the query
    cursor.execute("SELECT * FROM users WHERE id = %d" % int(user_id))
    return cursor.fetchall()
