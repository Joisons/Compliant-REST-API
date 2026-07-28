"""
Audit logging middleware.

Every single request -- successful, denied, rate-limited, or errored -- is
recorded, because a compliance-grade audit trail must capture *attempted*
access, not only completed access (a pattern of repeated 403s from one
account is itself a signal worth being able to query for later).

Each log row is hash-chained: `entry_hash = SHA256(canonical_fields || prev_hash)`.
This makes the log tamper-evident rather than merely append-only -- if any
historical row's content is altered after the fact, recomputing the chain
from that point forward will no longer match the stored hashes, and
`AuditService.verify_chain()` (used by `GET /api/v1/audit-logs/verify`) will
report exactly which entry first breaks. This is the same integrity pattern
used by write-once ledgers and is a materially stronger control than a plain
log file, which can be edited with no detectable trace.
"""
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import get_settings
from app.database import SessionLocal
from app.models.db_models import AuditLogEntry
from app.core.security import decode_access_token
from jose import JWTError

settings = get_settings()


def _canonical_string(fields: dict) -> str:
    return json.dumps(fields, sort_keys=True, default=str)


def canonical_timestamp(dt: datetime) -> str:
    """
    Normalize a datetime to a fixed, hash-stable string representation.

    SQLite (via SQLAlchemy's default DateTime type) stores and returns naive
    datetimes, silently dropping tzinfo on read-back even when a
    timezone-aware value was written. If the hash were computed from
    `dt.isoformat()` directly, a value hashed as aware
    ("...+00:00") at write time would read back naive ("...", no offset) at
    verify time -- producing a hash mismatch on every single entry and a
    false "tampering detected" result. Normalizing to naive UTC, truncated
    to millisecond precision, before every hash computation (both at write
    time and at verify time) makes the chain robust to that round-trip
    regardless of what the underlying database driver does.
    """
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    dt = dt.replace(microsecond=(dt.microsecond // 1000) * 1000)
    return dt.isoformat()


def compute_entry_hash(fields: dict, prev_hash: str) -> str:
    payload = _canonical_string(fields) + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _best_effort_identity(request: Request):
    """Try to read the bearer token even though this runs before FastAPI's
    dependency injection has validated it -- purely for logging purposes.
    An invalid/expired token here simply logs as anonymous; the RBAC
    dependency downstream is the actual authorization control."""
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None, None
    token = auth_header.split(" ", 1)[1]
    try:
        payload = decode_access_token(token)
        return payload.get("sub"), payload.get("role")
    except JWTError:
        return None, None


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        response = await call_next(request)

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        username, role = _best_effort_identity(request)

        # A downstream handler/dependency may attach a more specific identity
        # or outcome detail (e.g. rate limiter attaches the limited username).
        username = getattr(request.state, "audit_username", username)
        role = getattr(request.state, "audit_role", role)
        detail = getattr(request.state, "audit_detail", None)

        if response.status_code == 429:
            outcome = "RATE_LIMITED"
        elif response.status_code in (401, 403):
            outcome = "DENIED"
        elif response.status_code >= 500:
            outcome = "ERROR"
        elif response.status_code >= 400:
            outcome = "CLIENT_ERROR"
        else:
            outcome = "SUCCESS"

        client_ip = request.client.host if request.client else "unknown"

        db = SessionLocal()
        try:
            last = db.query(AuditLogEntry).order_by(AuditLogEntry.id.desc()).first()
            prev_hash = last.entry_hash if last else settings.audit_log_genesis_hash

            now = datetime.now(timezone.utc)
            fields = {
                "request_id": request_id,
                "timestamp": canonical_timestamp(now),
                "username": username,
                "role": role,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "client_ip": client_ip,
                "duration_ms": duration_ms,
                "outcome": outcome,
                "detail": detail,
            }
            entry_hash = compute_entry_hash(fields, prev_hash)

            db_fields = dict(fields)
            db_fields["timestamp"] = now  # store as a real datetime for querying/sorting
            entry = AuditLogEntry(**db_fields, entry_hash=entry_hash, prev_hash=prev_hash)
            db.add(entry)
            db.commit()
        finally:
            db.close()

        response.headers["X-Request-ID"] = request_id
        return response
