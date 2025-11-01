# To run the backend server - uvicorn main:app --reload
# uvicorn main:app --host 0.0.0.0 --port 8000
# To run the frontend - npx expo start

from fastapi import FastAPI, UploadFile, Form, Depends, Header, HTTPException, Query, status, File, APIRouter, Response
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi_utils.tasks import repeat_every  # auto background scheduler

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from auth import get_current_user
from dateutil import parser  # add at top of file
import json
from pydantic import BaseModel, Field
import sqlite3
import secrets
from passlib.hash import bcrypt, bcrypt_sha256
from datetime import datetime, timedelta
from config import SESSION_EXPIRE_MINUTES

from utils.response import success_response, error_response

from calendar import month_abbr
from typing import Optional
import os
from fastapi import Request
import shutil

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

# Request body model for expense
class ExpenseRequest(BaseModel):
    date_time: str = Field(alias="DateTime")
    expense_type: str = Field(alias="expenseType")
    additional_comments: str = Field(alias="description")
    amount: float

# --- Apply rate limit to login route ---
@app.post("/login")
@limiter.limit("5/minute")
async def login(req: LoginRequest, request: Request):
    conn = sqlite3.connect("expense_tracker.db")
    cursor = conn.cursor()

    cursor.execute("SELECT id, password FROM users WHERE username=?", (req.username,))
    row = cursor.fetchone()

    if row:
        stored_hash = row[1]
        user_id = row[0]
        password = req.password

        is_valid = False
        try:
            is_valid = bcrypt_sha256.verify(password, stored_hash)
        except ValueError:
            try:
                # truncate long passwords for old bcrypt hashes
                short_pw = password[:72]
                is_valid = bcrypt.verify(short_pw, stored_hash)
                if is_valid:
                    # upgrade to bcrypt_sha256 using the full original password
                    new_hash = bcrypt_sha256.hash(password)
                    cursor.execute("UPDATE users SET password=? WHERE id=?", (new_hash, user_id))
                    conn.commit()
                    print(f"✅ Upgraded user {user_id} to bcrypt_sha256")
            except Exception as e:
                print(f"⚠️ Password verification failed for user {user_id}: {e}")
                is_valid = False

        if is_valid:
            session_token = secrets.token_hex(32)
            now = datetime.now().isoformat()
            cursor.execute("""
            INSERT INTO sessions (user_id, session_token, created_at, last_active_at)
            VALUES (?, ?, ?, ?)
            """, (user_id, session_token, now, now))
            conn.commit()
            conn.close()
            return {"status": "success", "message": "Login successful",
                    "session_token": session_token, "user_id": user_id}

    conn.close()
    return {"status": "error", "message": "Invalid credentials"}

# profile page details
@app.get("/profile")
async def get_profile(user_id: int = Depends(get_current_user)):
    return {"status": "success", "user_id": user_id, "profile": "User profile data here"}

# Health status check
@app.api_route("/health", methods=["GET", "HEAD", "OPTIONS"])
def health_check():
    return Response(content='{"status": "ok"}', media_type="application/json")


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


@app.post("/add-expense")
async def add_expense(expense: ExpenseRequest, user_id: int = Depends(get_current_user)):
    try:
        if expense.amount <= 0:
            return error_response("Invalid amount", code="VALIDATION_ERROR", details="Amount must be greater than 0")

        conn = sqlite3.connect("expense_tracker.db")
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO expenses (user_id, date_time, expense_type, additional_comments, is_active, amount, updated)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            expense.date_time,
            expense.expense_type,
            expense.additional_comments,
            1,
            expense.amount,
            datetime.now().isoformat()
        ))

        conn.commit()
        expense_id = cursor.lastrowid
        conn.close()

        return success_response("Expense added successfully", {"expense_id": expense_id})

    except sqlite3.Error as e:
        return error_response("Database error occurred", code="DB_ERROR", details=str(e))

    except Exception as e:
        return error_response("Unexpected error occurred", code="SERVER_ERROR", details=str(e))
    

# API 1 for receipts Screen on FE 
@app.get("/api/expenses/summary")
async def get_expense_summary(
    period: str = Query("total"),
    user_id: int = Depends(get_current_user)
):
    """
    Returns total expenses for the given time period for the logged-in user.
    Supported periods:
    total, last_1_day, last_3_days, last_7_days, last_14_days, last_month, last_3_months
    """
    try:
        conn = sqlite3.connect("expense_tracker.db")
        cursor = conn.cursor()

        # Build date range filter
        now = datetime.now()
        date_filter = None

        if period == "last_1_day":
            date_filter = now - timedelta(days=1)
        elif period == "last_3_days":
            date_filter = now - timedelta(days=3)
        elif period == "last_7_days":
            date_filter = now - timedelta(days=7)
        elif period == "last_14_days":
            date_filter = now - timedelta(days=14)
        elif period == "last_month":
            date_filter = now - timedelta(days=30)
        elif period == "last_3_months":
            date_filter = now - timedelta(days=90)
        elif period == "total":
            date_filter = None
        else:
            conn.close()
            return error_response(
                message="Invalid period value",
                code="VALIDATION_ERROR",
                details=f"Unsupported period: {period}"
            )

        # SQL Query
        if date_filter:
            cursor.execute("""
                SELECT SUM(amount)
                FROM expenses
                WHERE user_id = ? AND is_active = 1 AND date_time >= ?
            """, (user_id, date_filter.isoformat()))
            # print("""
            #     SELECT SUM(amount)
            #     FROM expenses
            #     WHERE user_id = ? AND is_active = 1 AND date_time >= ?
            # """, (user_id, date_filter.isoformat()))
        else:
            cursor.execute("""
                SELECT SUM(amount)
                FROM expenses
                WHERE user_id = ? AND is_active = 1
            """, (user_id,))
            # print("""
            #     SELECT SUM(amount)
            #     FROM expenses
            #     WHERE user_id = ? AND is_active = 1
            # """, (user_id,))

        result = cursor.fetchone()
        conn.close()

        total_expense = result[0] if result and result[0] is not None else 0.0

        return {
            "status": "success",
            "data": {
                "period": period,
                "totalExpense": round(total_expense, 2),
                "currency": "INR"
            }
        }

    except Exception as e:
        return error_response(
            message="Error while calculating expense summary",
            code="SERVER_ERROR",
            details=str(e)
        )

# API 2 for monthly expense 
@app.get("/api/expenses/monthly-summary")
async def get_monthly_summary(
    year: Optional[int] = Query(None, description="Year to fetch monthly totals for"),
    user_id: int = Depends(get_current_user)
):
    """
    Returns monthly total expenses and transaction count for a given year (default = current year).
    Always includes all 12 months, even if totals are zero.
    """
    try:
        # ✅ Validate year
        if year is None:
            year = datetime.now().year
        elif not isinstance(year, int) or year < 1900 or year > 2100:
            return error_response(
                "Invalid year format",
                code="VALIDATION_ERROR",
                details="Year must be a valid integer between 1900 and 2100"
            )

        conn = sqlite3.connect("expense_tracker.db")
        cursor = conn.cursor()

        # ✅ Initialize all 12 months with default values
        monthly_data = {m: {"totalExpense": 0.0, "transactionCount": 0} for m in range(1, 13)}

        # ✅ Fetch all user expenses
        cursor.execute("""
            SELECT date_time, amount
            FROM expenses
            WHERE user_id = ? AND is_active = 1
        """, (user_id,))

        rows = cursor.fetchall()
        conn.close()

        for dt_str, amount in rows:
            if not dt_str or amount is None:
                continue
            try:
                dt_obj = datetime.fromisoformat(dt_str)
            except Exception:
                try:
                    dt_obj = datetime.strptime(dt_str[:10], "%Y-%m-%d")
                except:
                    continue

            if dt_obj.year == year:
                month = dt_obj.month
                monthly_data[month]["totalExpense"] += float(amount)
                monthly_data[month]["transactionCount"] += 1

        # ✅ Build ordered response (Jan–Dec)
        result = [
            {
                "month": month_abbr[m],
                "totalExpense": round(monthly_data[m]["totalExpense"], 2),
                "transactionCount": monthly_data[m]["transactionCount"]
            }
            for m in range(1, 13)
        ]
        
        # print(result)

        return {
            "status": "success",
            "data": result,
            "currency": "INR"
        }

    except Exception as e:
        return error_response(
            "Error while generating monthly summary",
            code="SERVER_ERROR",
            details=str(e)
        )

# API 3 for feed
@app.get("/api/expenses/feed")
async def get_expense_feed(
    page: Optional[int] = Query(1, description="Page number for pagination (default=1)"),
    limit: Optional[int] = Query(20, description="Number of transactions per page (default=20)"),
    sort: Optional[str] = Query("desc", description='Sort order — "desc" or "asc"'),
    month: Optional[str] = Query(None, description="Optional month filter (Jan–Dec)"),
    period: Optional[str] = Query(None, description="Optional quick filter (last_7_days, last_month, etc.)"),
    user_id: int = Depends(get_current_user)
):
    """
    Returns paginated list of user's expenses with optional filters.
    Matches FE contract:
    {
        "status": "success",
        "data": {
            "page": 1,
            "limit": 10,
            "totalPages": 5,
            "hasMore": true,
            "currency": "INR",
            "expenses": [...]
        }
    }
    """
    # print(page, limit, sort, month, period, user_id)
    try:
        # ✅ Validation
        if not isinstance(page, int) or not isinstance(limit, int) or page <= 0 or limit <= 0:
            return error_response(
                "Invalid page number or month filter",
                code="VALIDATION_ERROR",
                details="Page and limit must be positive integers"
            )

        if sort.lower() not in ("asc", "desc"):
            return error_response(
                "Invalid sort order",
                code="VALIDATION_ERROR",
                details="Sort must be either 'asc' or 'desc'"
            )

        conn = sqlite3.connect("expense_tracker.db")
        cursor = conn.cursor()

        # ✅ Build SQL conditions
        conditions = ["user_id = ?", "is_active = 1"]
        params = [user_id]

        now = datetime.now()
        date_filter = None

        # ✅ Period filter
        if period == "last_7_days":
            date_filter = now - timedelta(days=7)
        elif period == "last_14_days":
            date_filter = now - timedelta(days=14)
        elif period == "last_month":
            date_filter = now - timedelta(days=30)
        elif period == "last_3_months":
            date_filter = now - timedelta(days=90)

        if date_filter:
            conditions.append("date_time >= ?")
            params.append(date_filter.isoformat())

        # ✅ Month filter
        month_map = {abbr: i for i, abbr in enumerate(month_abbr) if abbr}
        if month:
            month = month.capitalize()
            if month not in month_map:
                return error_response(
                    "Invalid page number or month filter",
                    code="VALIDATION_ERROR",
                    details="Month must be one of Jan–Dec"
                )
            month_num = month_map[month]
            conditions.append("strftime('%m', date_time) = ?")
            params.append(f"{month_num:02d}")

        where_clause = " AND ".join(conditions)

        # ✅ Total records
        cursor.execute(f"SELECT COUNT(*) FROM expenses WHERE {where_clause}", tuple(params))
        total_records = cursor.fetchone()[0] or 0
        total_pages = (total_records + limit - 1) // limit
        print(total_records,total_pages)

        # ✅ Pagination logic
        offset = (page - 1) * limit
        order = "DESC" if sort.lower() == "desc" else "ASC"

        cursor.execute(f"""
            SELECT id, date_time, expense_type, additional_comments, amount
            FROM expenses
            WHERE {where_clause}
            ORDER BY date_time {order}
            LIMIT ? OFFSET ?
        """, (*params, limit, offset))

        rows = cursor.fetchall()
        conn.close()
        
        print("Rows",rows)

        # ✅ Format expense list
        expenses = []
        for row in rows:
            exp_id, date_time, exp_type, desc, amount = row
            try:
                dt = parser.isoparse(date_time)
            except Exception as e:
                print(f"DEBUG: Failed to parse date_time '{date_time}': {e}")
                continue
            month_abbrv = month_abbr[dt.month]
            day_str = dt.strftime("%d %b %Y")
            expenses.append({
                "id": exp_id,
                "dateTime": dt.isoformat(),
                "expenseType": exp_type,
                "description": desc,
                "amount": round(float(amount), 2),
                "month": month_abbrv,
                "day": day_str
            })
            print("Expenses",expenses)

        # ✅ Pagination: hasMore logic
        has_more = page < total_pages
        print(has_more)
        
        print({
            "status": "success",
            "data": {
                "page": page,
                "limit": limit,
                "totalPages": total_pages,
                "hasMore": has_more,
                "currency": "INR",
                "expenses": expenses
            }
        })

        # ✅ Final success response
        return {
            "status": "success",
            "data": {
                "page": page,
                "limit": limit,
                "totalPages": total_pages,
                "hasMore": has_more,
                "currency": "INR",
                "expenses": expenses
            }
        }

    except Exception as e:
        return error_response(
            "Error fetching expenses feed",
            code="SERVER_ERROR",
            details=str(e)
        )

# Download Db call
@app.get("/download-db", tags=["Admin"])
def download_db(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Secure endpoint to download the current SQLite database file.
    Only authenticated users (admins or valid users) can access.
    """
    # 🔍 Debug incoming request headers
    # print("===== REQUEST DEBUG =====")
    # print("Headers:", dict(request.headers))
    # print("=========================")
    
    # ✅ (Optional) Role-based restriction — uncomment if you have user roles
    # if not current_user.get("is_admin", False):
    #     raise HTTPException(
    #         status_code=status.HTTP_403_FORBIDDEN,
    #         detail="You are not authorized to access this resource"
    #     )

    db_path = os.path.join(os.getcwd(), "expense_tracker.db")

    if not os.path.exists(db_path):
        raise HTTPException(status_code=404, detail="Database file not found")

    return FileResponse(
        path=db_path,
        filename="expense_tracker.db",
        media_type="application/octet-stream"
    )

# Upload file (Don't touch)
# @app.post("/upload-db", tags=["Admin"])
# async def upload_db(
#     request: Request,
#     file: UploadFile = File(...),
#     current_user: dict = Depends(get_current_user)
# ):
#     """
#     Secure endpoint to upload a new SQLite database file.
#     Replaces the existing expense_tracker.db.
#     """
#     # 🔍 Debug incoming headers
#     # print("===== REQUEST DEBUG =====")
#     # print("Headers:", dict(request.headers))
#     # print("=========================")

#     # (Optional) Restrict to admin users only
#     # if not current_user.get("is_admin", False):
#     #     raise HTTPException(status_code=403, detail="You are not authorized to upload the DB")

#     # Validate file type
#     if not file.filename.endswith(".db"):
#         raise HTTPException(status_code=400, detail="Only .db files are allowed")

#     # Define destination
#     db_dir = os.getcwd()
#     os.makedirs(db_dir, exist_ok=True)
#     db_path = os.path.join(db_dir, "expense_tracker.db")

#     try:
#         # Save uploaded file temporarily
#         temp_path = db_path + ".tmp"
#         with open(temp_path, "wb") as buffer:
#             shutil.copyfileobj(file.file, buffer)

#         # Replace old DB atomically
#         os.replace(temp_path, db_path)

#         print(f"✅ Database replaced successfully at {db_path}")

#         return JSONResponse(
#             content={
#                 "status": "success",
#                 "message": f"Database uploaded and replaced successfully.",
#                 "filename": file.filename
#             },
#             status_code=200
#         )
#     except Exception as e:
#         print(f"❌ Upload failed: {e}")
#         raise HTTPException(status_code=500, detail=f"Failed to upload DB: {e}")
