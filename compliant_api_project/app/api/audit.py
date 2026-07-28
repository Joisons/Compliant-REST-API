"""
Audit log resource -- read access restricted to AUDITOR and ADMIN, who are
the only roles with a legitimate need to review who-did-what across the
system. Nobody, including ADMIN, is given an update or delete endpoint for
this resource: the table is designed to be application-level append-only.

GET /verify recomputes the hash chain from the genesis hash forward and
reports whether it is intact, and if not, the id of the first entry where it
breaks -- turning "is this log trustworthy" from an assumption into
something that can be checked on demand.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.core.rbac import require_roles
from app.middleware.audit_logging import compute_entry_hash, canonical_timestamp
from app.models.db_models import AuditLogEntry, User, Role
from app.models.schemas import AuditLogOut, AuditIntegrityReport

router = APIRouter(prefix="/api/v1/audit-logs", tags=["Audit"])
settings = get_settings()

READ_ROLES = (Role.AUDITOR, Role.ADMIN)


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    limit: int = Query(default=100, le=1000),
    outcome: str | None = None,
    username: str | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(require_roles(*READ_ROLES)),
):
    q = db.query(AuditLogEntry)
    if outcome:
        q = q.filter(AuditLogEntry.outcome == outcome)
    if username:
        q = q.filter(AuditLogEntry.username == username)
    return q.order_by(AuditLogEntry.id.desc()).limit(limit).all()


@router.get("/verify", response_model=AuditIntegrityReport)
def verify_audit_log(db: Session = Depends(get_db), _user: User = Depends(require_roles(*READ_ROLES))):
    entries = db.query(AuditLogEntry).order_by(AuditLogEntry.id.asc()).all()
    prev_hash = settings.audit_log_genesis_hash
    for entry in entries:
        fields = {
            "request_id": entry.request_id,
            "timestamp": canonical_timestamp(entry.timestamp),
            "username": entry.username,
            "role": entry.role,
            "method": entry.method,
            "path": entry.path,
            "status_code": entry.status_code,
            "client_ip": entry.client_ip,
            "duration_ms": entry.duration_ms,
            "outcome": entry.outcome,
            "detail": entry.detail,
        }
        expected_hash = compute_entry_hash(fields, prev_hash)
        if expected_hash != entry.entry_hash or entry.prev_hash != prev_hash:
            return AuditIntegrityReport(total_entries=len(entries), verified=False,
                                         first_break_at_id=entry.id,
                                         checked_at=datetime.now(timezone.utc))
        prev_hash = entry.entry_hash

    return AuditIntegrityReport(total_entries=len(entries), verified=True,
                                 first_break_at_id=None, checked_at=datetime.now(timezone.utc))
