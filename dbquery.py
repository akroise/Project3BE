import sqlite3
import bcrypt
from datetime import datetime

def init_db():
    conn = sqlite3.connect("expense_tracker.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,       
        plain_password TEXT,        
        created_at TIMESTAMP
    )
    """)
    # password TEXT,             -- hashed password
    # plain_password TEXT,        -- plain text (⚠️ not recommended for prod!)
    conn.commit()
    conn.close()


# --- during user signup / insertion ---
def add_user(username: str, password: str) -> None:
    """
    Adds a new user to the SQLite database with hashed password.
    Compatible with Python 3.10+ and safe DB handling.
    """

    # Generate password hash using bcrypt
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    created_at = datetime.now().isoformat()

    # Use context manager to ensure DB is closed automatically
    with sqlite3.connect("expense_tracker.db") as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password, plain_password, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (username, hashed_pw, password, created_at),
        )
        conn.commit()


# Create table command

# try:
#     print("Initating DB....")
#     init_db()
#     print("Intitating Done....")
# except Exception as error:
#     print(error)


# add user command

# try:
#     print("Inserting User....")
#     add_user("user","abcd1234")
#     print("Insertion Done....")
# except Exception as error:
#     print(error)