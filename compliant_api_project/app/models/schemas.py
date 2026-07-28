"""Pydantic schemas for request/response validation and OpenAPI documentation."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict

from app.models.db_models import Role


# --- Auth ---
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: Role
    expires_in_minutes: int


class LoginRequest(BaseModel):
    username: str
    password: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    full_name: str
    password: str = Field(min_length=8, max_length=72)
    role: Role = Role.VIEWER


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    full_name: str
    role: Role
    is_active: bool
    created_at: datetime


# --- Accounts ---
class AccountCreate(BaseModel):
    account_number: str = Field(min_length=4, max_length=20)
    holder_name: str
    account_type: str
    balance: float = 0.0
    risk_rating: str = "Low"


class AccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    account_number: str
    holder_name: str
    account_type: str
    balance: float
    risk_rating: str
    created_at: datetime


# --- Transactions ---
class TransactionCreate(BaseModel):
    account_id: int
    amount: float
    transaction_type: str
    description: Optional[str] = None


class TransactionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    account_id: int
    amount: float
    transaction_type: str
    description: Optional[str]
    created_by: str
    created_at: datetime


# --- Reports ---
class ReportRequest(BaseModel):
    report_type: str = Field(description="One of: risk_summary, transaction_volume, account_overview")
    account_id: Optional[int] = None


class ReportOut(BaseModel):
    report_type: str
    generated_by: str
    generated_at: datetime
    data: dict


# --- Audit ---
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    request_id: str
    timestamp: datetime
    username: Optional[str]
    role: Optional[str]
    method: str
    path: str
    status_code: int
    client_ip: str
    duration_ms: float
    outcome: str
    detail: Optional[str]
    entry_hash: str
    prev_hash: str


class AuditIntegrityReport(BaseModel):
    total_entries: int
    verified: bool
    first_break_at_id: Optional[int] = None
    checked_at: datetime
