# To run the backend server - uvicorn main:app --reload
# uvicorn main:app --host 0.0.0.0 --port 8000
# To run the frontend - npx expo start

from fastapi import FastAPI, UploadFile, Form, Depends, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi_utils.tasks import repeat_every  # auto background scheduler

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from auth import get_current_user
import pdfplumber
import os, json, asyncio, time
from pydantic import BaseModel
import sqlite3
import secrets
from passlib.hash import bcrypt
from datetime import datetime
from config import SESSION_EXPIRE_MINUTES

app = FastAPI()

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Rate limiter setup ---
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"status": "error", "message": "Too many login attempts. Please try again later."}
    )

# --- Models ---
class LoginRequest(BaseModel):
    username: str
    password: str

# --- Apply rate limit to login route ---
@app.post("/login")
@limiter.limit("5/minute")   # max 5 requests per minute per IP
async def login(req: LoginRequest, request: Request):
    conn = sqlite3.connect("expense_tracker.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, password FROM users WHERE username=?", (req.username,))
    row = cursor.fetchone()

    if row and bcrypt.verify(req.password, row[1]):
        user_id = row[0]
        session_token = secrets.token_hex(32)
        now = datetime.now().isoformat()

        cursor.execute("""
        INSERT INTO sessions (user_id, session_token, created_at, last_active_at)
        VALUES (?, ?, ?, ?)
        """, (user_id, session_token, now, now))

        conn.commit()
        conn.close()

        return {"status": "success", "message": "Login successful","session_token":session_token}
    
    conn.close()    
    return {"status": "error", "message": "Invalid credentials"}


# Upload + parse PDF endpoint
@app.post("/upload")
async def upload_file(file: UploadFile, user_id: int = Depends(get_current_user)):
    # ✅ If we reach here, session is valid and user_id is injected

    # Save uploaded file
    file_path = file.filename
    with open(file_path, "wb") as f:
        f.write(await file.read())

    # Extract text from PDF
    transactions = []
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            text = page.extract_text()
            if text:
                # Simple mock parser → will improve later
                for line in text.split("\n"):
                    if "Rs" in line:  # crude check for transaction line
                        transactions.append({"raw_line": line})

    # Clean up saved file
    os.remove(file_path)

    return {"status": "success", "user_id": user_id, "transactions": transactions}


# profile page details
@app.get("/profile")
async def get_profile(user_id: int = Depends(get_current_user)):
    return {"status": "success", "user_id": user_id, "profile": "User profile data here"}

# logout call
@app.post("/logout")
async def logout(user_id: int = Depends(get_current_user), authorization: str = Header(None)):
    """
    Logout by deleting the current session token from DB.
    Requires valid session token.
    """

    session_token = authorization.split(" ")[1]

    conn = sqlite3.connect("expense_tracker.db")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE user_id=? AND session_token=?", (user_id, session_token))
    conn.commit()
    conn.close()

    return {"status": "success", "message": "Logged out successfully"}


# validate-session call
@app.post("/validate-session")
async def validate_session(current=Depends(get_current_user), authorization: str = Header(None)):
    """
    Validates if the session token is active.
    Returns user details if valid, else raises 401.
    """
    user_id = current if isinstance(current, int) else current["user_id"]

    # Fetch username or any user info
    conn = sqlite3.connect("expense_tracker.db")
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id=?", (user_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get token from header
    session_token = authorization.split(" ")[1] if authorization else None

    return {
        "status": "success",
        "user": row[0],
        "token": session_token
    }

# Caching of CXE file (Config)

CONTENT_FILE_PATH = "content/content.json"
ACCESS_KEY = "testCXE"
CACHE_REFRESH_INTERVAL = 600  # 10 minutes

# Cache state
content_cache = {"data": None, "last_loaded": None}

# Load content from file
def load_content_file():
    try:
        with open(CONTENT_FILE_PATH, "r", encoding="utf-8") as f:
            content = json.load(f)
            return content
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Content file not found")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid JSON in content file")

# Background auto-refresh task
@app.on_event("startup")
@repeat_every(seconds=CACHE_REFRESH_INTERVAL)
def refresh_content_cache_task() -> None:
    try:
        new_data = load_content_file()
        content_cache["data"] = new_data
        content_cache["last_loaded"] = datetime.now().isoformat()
        print(f"[CACHE] Refreshed content cache at {content_cache['last_loaded']}")
    except Exception as e:
        print(f"[CACHE ERROR] Failed to refresh content cache: {e}")

# Manual refresh (optional admin endpoint)
@app.post("/content/reload")
async def reload_content(access: str = Query(None)):
    if access != ACCESS_KEY:
        raise HTTPException(status_code=403, detail="Invalid access key")

    new_data = load_content_file()
    content_cache["data"] = new_data
    content_cache["last_loaded"] = datetime.now().isoformat()
    return {"status": "success", "message": "Content cache manually reloaded"}

# Public content endpoint
@app.get("/content")
async def get_content(access: str = Query(None)):
    if access != ACCESS_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing access key")

    # Load cache on first request if not done yet
    if not content_cache["data"]:
        content_cache["data"] = load_content_file()
        content_cache["last_loaded"] = datetime.now().isoformat()

    return {
        "status": "success",
        "cache_time": content_cache["last_loaded"],
        "data": content_cache["data"]
    }