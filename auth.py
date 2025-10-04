import sqlite3
from datetime import datetime
from fastapi import Header, HTTPException
from config import SESSION_EXPIRE_MINUTES

def get_current_user(authorization: str = Header(None)) -> int:
    """
    Validates session token from headers.
    Returns user_id if valid, otherwise raises HTTPException(401).
    """

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid session token")

    session_token = authorization.split(" ")[1]
    now = datetime.now()

    conn = sqlite3.connect("expense_tracker.db")
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, last_active_at FROM sessions WHERE session_token=?", (session_token,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid session token")

    user_id, last_active_at = row
    try:
        last_active_at = datetime.strptime(last_active_at, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        last_active_at = datetime.strptime(last_active_at, "%Y-%m-%dT%H:%M:%S")


    # Check inactivity
    if (now - last_active_at).total_seconds() > SESSION_EXPIRE_MINUTES * 60:
        conn.close()
        raise HTTPException(status_code=401, detail="Session expired. Please login again.")

    # Update last_active_at (sliding expiry)
    cursor.execute("UPDATE sessions SET last_active_at=? WHERE session_token=?", (now.isoformat(), session_token))
    conn.commit()
    conn.close()

    return user_id
