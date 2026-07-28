"""
Database models.

AuditLogEntry is intentionally append-only and hash-chained (each row stores
a SHA-256 hash of its own canonical content plus the previous row's hash --
the same tamper-evidence pattern used by write-once ledgers). Any retroactive
edit to a historical row breaks the chain from that point forward, which is
exactly what /api/v1/audit-logs/verify checks for. This is the core
"auditability by construction" control the project demonstrates: the log is
not just *collected*, it is *verifiable*.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import (Column, Integer, String, DateTime, Boolean, Float,
                         ForeignKey, Enum as SAEnum, Text)
from sqlalchemy.orm import relationship

from app.database import Base


class Role(str, enum.Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    AUDITOR = "AUDITOR"
    ADMIN = "ADMIN"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    full_name = Column(String(128), nullable=False)
    hashed_password = Column(String(128), nullable=False)
    role = Column(SAEnum(Role), nullable=False, default=Role.VIEWER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Account(Base):
    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True, index=True)
    account_number = Column(String(20), unique=True, index=True, nullable=False)
    holder_name = Column(String(128), nullable=False)
    account_type = Column(String(32), nullable=False)
    balance = Column(Float, nullable=False, default=0.0)
    risk_rating = Column(String(16), nullable=False, default="Low")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    account_id = Column(Integer, ForeignKey("accounts.id"), nullable=False)
    amount = Column(Float, nullable=False)
    transaction_type = Column(String(32), nullable=False)
    description = Column(String(256), nullable=True)
    created_by = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    account = relationship("Account")


class AuditLogEntry(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    request_id = Column(String(36), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    username = Column(String(64), nullable=True, index=True)
    role = Column(String(16), nullable=True)
    method = Column(String(8), nullable=False)
    path = Column(String(256), nullable=False, index=True)
    status_code = Column(Integer, nullable=False)
    client_ip = Column(String(64), nullable=False)
    duration_ms = Column(Float, nullable=False)
    outcome = Column(String(16), nullable=False)  # SUCCESS | DENIED | RATE_LIMITED | ERROR
    detail = Column(Text, nullable=True)

    # Tamper-evidence: hash chain
    entry_hash = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
