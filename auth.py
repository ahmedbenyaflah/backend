"""
User authentication: signup, login, JWT tokens.
Passwords are hashed with bcrypt. Returns JWT access token.
"""
import logging
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from datetime import datetime, timedelta

import bcrypt
from jose import JWTError, jwt

from database import get_connection

log = logging.getLogger(__name__)

# bcrypt only accepts passwords up to 72 bytes
BCRYPT_MAX_PASSWORD_BYTES = 72


def _truncate_password_for_bcrypt(password: str) -> bytes:
    """Ensure password is at most 72 bytes (bcrypt limit)."""
    encoded = password.encode("utf-8")
    if len(encoded) > BCRYPT_MAX_PASSWORD_BYTES:
        return encoded[:BCRYPT_MAX_PASSWORD_BYTES]
    return encoded

SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "change-me-in-production-use-long-random-string")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours


def hash_password(password: str) -> str:
    log.info("[ENTER] hash_password input=password_len=%d", len(password) if password else 0)
    pwd_bytes = _truncate_password_for_bcrypt(password)
    salt = bcrypt.gensalt()
    out = bcrypt.hashpw(pwd_bytes, salt).decode("ascii")
    log.info("[EXIT] hash_password output=hash_len=%d", len(out))
    return out


def verify_password(plain: str, hashed: str) -> bool:
    log.info("[ENTER] verify_password input=plain_len=%d hashed_len=%d", len(plain) if plain else 0, len(hashed) if hashed else 0)
    pwd_bytes = _truncate_password_for_bcrypt(plain)
    out = bcrypt.checkpw(pwd_bytes, hashed.encode("ascii"))
    log.info("[EXIT] verify_password output=%s", out)
    return out


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    log.info("[ENTER] create_access_token input=keys=%s", list(data.keys()) if data else [])
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode["exp"] = expire
    out = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    log.info("[EXIT] create_access_token output=token_len=%d", len(out) if out else 0)
    return out


def decode_token(token: str) -> dict | None:
    log.info("[ENTER] decode_token input=token_len=%d", len(token) if token else 0)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        log.info("[EXIT] decode_token output=sub=%s email=%s", payload.get("sub"), payload.get("email"))
        return payload
    except JWTError as e:
        log.info("[EXIT] decode_token output=None (JWTError: %s)", e)
        return None


def signup(email: str, password: str) -> tuple[bool, str]:
    """Register a new user. Returns (success, message)."""
    log.info("[ENTER] signup input=email=%s password_len=%d", email, len(password) if password else 0)
    if not email or not email.strip():
        log.info("[EXIT] signup output=(False, 'Email is required')")
        return False, "Email is required"
    if not password or len(password) < 6:
        log.info("[EXIT] signup output=(False, 'Password must be at least 6 characters')")
        return False, "Password must be at least 6 characters"
    email = email.strip().lower()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                log.info("[EXIT] signup output=(False, 'Email already registered')")
                return False, "Email already registered"
            ph = hash_password(password)
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
                (email, ph),
            )
            conn.commit()
        log.info("[EXIT] signup output=(True, 'Account created')")
        return True, "Account created"
    except Exception as e:
        conn.rollback()
        log.exception("Signup failed: %s", e)
        log.info("[EXIT] signup output=(False, 'Registration failed')")
        return False, "Registration failed"
    finally:
        conn.close()


def login(email: str, password: str) -> tuple[bool, str | None]:
    """Authenticate user. Returns (success, token_or_error_message)."""
    log.info("[ENTER] login input=email=%s password_len=%d", email, len(password) if password else 0)
    if not email or not password:
        log.info("[EXIT] login output=(False, 'Email and password required')")
        return False, "Email and password required"
    email = email.strip().lower()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, password_hash FROM users WHERE email = %s", (email,))
            row = cur.fetchone()
        if not row:
            log.info("[EXIT] login output=(False, 'Invalid email or password')")
            return False, "Invalid email or password"
        uid, ph = row
        if not verify_password(password, ph):
            log.info("[EXIT] login output=(False, 'Invalid email or password')")
            return False, "Invalid email or password"
        token = create_access_token({"sub": str(uid), "email": email})
        log.info("[EXIT] login output=(True, token_len=%d)", len(token) if token else 0)
        return True, token
    finally:
        conn.close()
