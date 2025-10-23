from typing import Optional, Dict

def success_response(message: str, data: Optional[Dict] = None):
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None
    }

def error_response(message: str, code: str = "UNKNOWN_ERROR", details: Optional[str] = None):
    return {
        "success": False,
        "message": message,
        "data": None,
        "error": {
            "code": code,
            "details": details
        }
    }
