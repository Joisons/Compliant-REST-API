"""
Password hashing and JWT issuance/validation.

Uses the `bcrypt` library directly rather than passlib's bcrypt wrapper,
which has a known incompatibility with bcrypt>=4.0 (passlib inspects an
internal `__about__.__version__` attribute that recent bcrypt releases no
longer expose). Calling bcrypt directly is simpler and avoids the issue
entirely.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from jose import jwt, JWTError

from app.config import get_settings

settings = get_settings()

BCRYPT_MAX_BYTES = 72  # bcrypt silently ignores bytes beyond this; enforce explicitly


def hash_password(plain_password: str) -> str:
    pw_bytes = plain_password.encode("utf-8")[:BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pw_bytes = plain_password.encode("utf-8")[:BCRYPT_MAX_BYTES]
    try:
        return bcrypt.checkpw(pw_bytes, hashed_password.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(subject: str, role: str, expires_minutes: Optional[int] = None) -> str:
    expire_minutes = expires_minutes or settings.access_token_expire_minutes
    expire = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    payload = {"sub": subject, "role": role, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Raises jose.JWTError on invalid/expired token; caller is responsible for translating
    that into an HTTP 401."""
    return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
