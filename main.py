"""
FastAPI backend for email log search. Uses parser.py to search Log-CG (FES*, VIP*, GP*, ML*)
via ripgrep/grep and return trace results for the React frontend.

Production requirements:
- Required: Date, Start time, End time (max configurable hours) — validated before any file access
- Optional: Sender and/or Recipient (at least one required)
- Auth: Signup/Login with PostgreSQL; JWT required for /api/search

Multi-user: Stateless JWT auth and a DB connection pool allow many users online at once;
each request is independent and results are not shared between users.
"""
import logging
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

from parser import search_logs
from database import init_db
from auth import signup as auth_signup, login as auth_login, decode_token

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)


def _log_enter(fname: str, **kwargs):
    """Log function entry with input args (passwords/credentials redacted)."""
    safe = {k: ("<redacted>" if "pass" in k.lower() or "token" in k.lower() or "secret" in k.lower() else v) for k, v in kwargs.items()}
    log.info("[ENTER] %s input=%s", fname, safe)


def _log_exit(fname: str, output, redact=False):
    """Log function exit with output (optionally redact sensitive data)."""
    out = "<redacted>" if redact else output
    log.info("[EXIT] %s output=%s", fname, out)

app = FastAPI(title="Email Log Search API", version="2.0.0")
security = HTTPBearer(auto_error=False)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup():
    _log_enter("startup")
    try:
        init_db()
        _log_exit("startup", "ok")
    except Exception as e:
        log.warning("Database init failed (auth disabled until DB available): %s", e)
        _log_exit("startup", f"error: {e}")


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(security)):
    """Require valid JWT for protected routes."""
    _log_enter("get_current_user", has_credentials=credentials is not None and bool(credentials.credentials if credentials else False))
    if not credentials or not credentials.credentials:
        _log_exit("get_current_user", "401 Not authenticated")
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    if not payload or not payload.get("sub"):
        _log_exit("get_current_user", "401 Invalid or expired token")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    _log_exit("get_current_user", {"sub": payload.get("sub"), "email": payload.get("email")})
    return payload


class SignupBody(BaseModel):
    email: str
    password: str


class LoginBody(BaseModel):
    email: str
    password: str

# Single variable to control time range; change here to affect validation and error messages
MAX_TIME_RANGE_HOURS = 24
MAX_TIME_RANGE_MINUTES = MAX_TIME_RANGE_HOURS * 60


def _parse_time_minutes(t: str | None) -> int | None:
    """Parse H, HH, HH:MM or HH:MM:SS to minutes since midnight. Hour-only → minutes default to 00 (e.g. 9 → 09:00)."""
    _log_enter("_parse_time_minutes", t=t)
    if not t or not str(t).strip():
        _log_exit("_parse_time_minutes", None)
        return None
    parts = str(t).strip().split(":")
    try:
        h = int(parts[0])
        m = int(parts[1]) if (len(parts) >= 2 and parts[1].strip()) else 0
        s = int(parts[2]) if (len(parts) >= 3 and parts[2].strip()) else 0
        if 0 <= h <= 23 and 0 <= m <= 59 and 0 <= s <= 59:
            out = h * 60 + m
            _log_exit("_parse_time_minutes", out)
            return out
    except (ValueError, IndexError):
        pass
    _log_exit("_parse_time_minutes", None)
    return None


def _validate_search(
    date: str | None, start_time: str | None, end_time: str | None, sender: str | None, recipient: str | None
) -> str | None:
    """Returns error message if invalid, else None."""
    _log_enter("_validate_search", date=date, start_time=start_time, end_time=end_time, sender=sender, recipient=recipient)
    if not date or not str(date).strip():
        _log_exit("_validate_search", "Date is required (e.g. 2026-01-29 or 29/01)")
        return "Date is required (e.g. 2026-01-29 or 29/01)"
    if not start_time or not str(start_time).strip():
        _log_exit("_validate_search", "Start time is required (e.g. 11:00 or 11:00:00)")
        return "Start time is required (e.g. 11:00 or 11:00:00)"
    if not end_time or not str(end_time).strip():
        _log_exit("_validate_search", "End time is required (e.g. 14:00 or 14:00:00)")
        return "End time is required (e.g. 14:00 or 14:00:00)"
    if not sender and not recipient:
        _log_exit("_validate_search", "Provide sender and/or recipient")
        return "Provide sender and/or recipient"
    start_min = _parse_time_minutes(start_time)
    end_min = _parse_time_minutes(end_time)
    if start_min is None:
        _log_exit("_validate_search", "Invalid start time. Use HH:MM or HH:MM:SS (e.g. 11:00 or 11:00:00)")
        return "Invalid start time. Use HH:MM or HH:MM:SS (e.g. 11:00 or 11:00:00)"
    if end_min is None:
        _log_exit("_validate_search", "Invalid end time. Use HH:MM or HH:MM:SS (e.g. 14:00 or 14:00:00)")
        return "Invalid end time. Use HH:MM or HH:MM:SS (e.g. 14:00 or 14:00:00)"
    if start_min > end_min:
        _log_exit("_validate_search", "Start time must be before end time")
        return "Start time must be before end time"
    diff = end_min - start_min
    if diff > MAX_TIME_RANGE_MINUTES:
        err = f"Time range cannot exceed {MAX_TIME_RANGE_HOURS} hours. Yours is {diff // 60}h {diff % 60}m."
        _log_exit("_validate_search", err)
        return err
    _log_exit("_validate_search", None)
    return None


def get_log_root() -> Path:
    _log_enter("get_log_root")
    if os.environ.get("LOG_ROOT"):
        out = Path(os.environ["LOG_ROOT"]).resolve()
        _log_exit("get_log_root", str(out))
        return out
    out = (Path(__file__).resolve().parent.parent / "Log-CG").resolve()
    _log_exit("get_log_root", str(out))
    return out


@app.post("/api/signup")
def api_signup(body: SignupBody):
    """Register a new user. Returns token on success."""
    _log_enter("api_signup", email=body.email, password="<redacted>")
    ok, msg = auth_signup(body.email, body.password)
    if not ok:
        _log_exit("api_signup", {"ok": False, "error": msg})
        return {"ok": False, "error": msg}
    ok2, token = auth_login(body.email, body.password)
    if not ok2 or not token:
        _log_exit("api_signup", {"ok": False, "error": "Account created but login failed. Please try logging in."})
        return {"ok": False, "error": "Account created but login failed. Please try logging in."}
    out = {"ok": True, "token": "<redacted>", "email": body.email.strip().lower()}
    _log_exit("api_signup", out, redact=True)
    return {"ok": True, "token": token, "email": body.email.strip().lower()}


@app.post("/api/login")
def api_login(body: LoginBody):
    """Authenticate and return JWT token."""
    _log_enter("api_login", email=body.email, password="<redacted>")
    ok, result = auth_login(body.email, body.password)
    if not ok:
        _log_exit("api_login", {"ok": False, "error": result})
        return {"ok": False, "error": result}
    _log_exit("api_login", {"ok": True, "token": "<redacted>", "email": body.email.strip().lower()}, redact=True)
    return {"ok": True, "token": result, "email": body.email.strip().lower()}


@app.get("/api/search")
def api_search(
    sender: str | None = Query(None, description="Sender email (optional if recipient provided)"),
    recipient: str | None = Query(None, description="Recipient email (optional if sender provided)"),
    date: str | None = Query(None, description="Date YYYY-MM-DD or DD/MM"),
    start_time: str | None = Query(None, description="Start time HH:MM or HH:MM:SS (required)"),
    end_time: str | None = Query(None, description="End time HH:MM or HH:MM:SS (required, max 5h range)"),
    _user: dict = Depends(get_current_user),
):
    """
    Search email logs. Requires JWT. Required: date, start_time, end_time (≤5h). Optional: sender, recipient (at least one).
    Returns: results, stages (FES filtering, Server mapping, Delivery confirmation), count.
    """
    _log_enter("api_search", sender=sender, recipient=recipient, date=date, start_time=start_time, end_time=end_time, user_email=_user.get("email"))
    err = _validate_search(date, start_time, end_time, sender, recipient)
    if err:
        out = {"results": [], "error": err, "count": 0, "stages": []}
        _log_exit("api_search", out)
        return out
    log_root = get_log_root()
    if not log_root.exists():
        out = {"results": [], "error": "Log directory not found", "count": 0, "stages": []}
        _log_exit("api_search", out)
        return out
    try:
        results, stages = search_logs(
            log_root=log_root,
            sender=sender.strip() if sender else None,
            recipient=recipient.strip() if recipient else None,
            date_str=date.strip(),
            start_time=start_time.strip(),
            end_time=end_time.strip(),
        )
        out = {"results": results, "count": len(results), "stages": stages}
        _log_exit("api_search", {"count": len(results), "stages": stages})
        return out
    except Exception as e:
        log.exception("Search failed: %s", e)
        out = {"results": [], "error": str(e), "count": 0, "stages": []}
        _log_exit("api_search", out)
        return out


@app.get("/api/health")
def health():
    _log_enter("health")
    out = {"status": "ok"}
    _log_exit("health", out)
    return out
