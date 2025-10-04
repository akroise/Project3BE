import sqlite3
from passlib.hash import bcrypt
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
def add_user(username: str, password: str):
    conn = sqlite3.connect("expense_tracker.db")
    cursor = conn.cursor()

    hashed_pw = bcrypt.hash(password)
    created_at = datetime.now().isoformat()

    cursor.execute("""
    INSERT INTO users (username, password, plain_password, created_at) 
    VALUES (?, ?, ?, ?)
    """, (username, hashed_pw, password, created_at))

    conn.commit()
    conn.close()


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
#     add_user("user","1234")
#     print("Insertion Done....")
# except Exception as error:
#     print(error)