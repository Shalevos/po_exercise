import sqlite3

DB_STRING = "my.db"


def setup_database():
    """
    Create the `users` table in the database
    when setting up the host machine
    """
    with sqlite3.connect(DB_STRING) as con:
        con.execute("CREATE TABLE users (user, password, ip)")

if __name__ == "__main__":
    setup_database()