"""
Reports resource -- ANALYST, AUDITOR, and ADMIN may generate reports.
VIEWER may not: reports can aggregate data across the full portfolio, which
exceeds a VIEWER's intended scope even though individual account reads are
permitted.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.rbac import require_roles
from app.models.db_models import Account, Transaction, User, Role
from app.models.schemas import ReportRequest, ReportOut

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])

REPORT_ROLES = (Role.ANALYST, Role.AUDITOR, Role.ADMIN)


@router.post("/generate", response_model=ReportOut)
def generate_report(payload: ReportRequest, db: Session = Depends(get_db),
                     user: User = Depends(require_roles(*REPORT_ROLES))):
    if payload.report_type == "risk_summary":
        rows = db.query(Account.risk_rating, func.count(Account.id)).group_by(Account.risk_rating).all()
        data = {rating: count for rating, count in rows}

    elif payload.report_type == "transaction_volume":
        q = db.query(func.count(Transaction.id), func.coalesce(func.sum(Transaction.amount), 0.0))
        if payload.account_id is not None:
            q = q.filter(Transaction.account_id == payload.account_id)
        count, total = q.first()
        data = {"transaction_count": count, "total_amount": round(total, 2)}

    elif payload.report_type == "account_overview":
        if payload.account_id is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                 detail="account_id is required for account_overview")
        account = db.query(Account).filter(Account.id == payload.account_id).first()
        if not account:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
        txn_count = db.query(func.count(Transaction.id)).filter(
            Transaction.account_id == payload.account_id).scalar()
        data = {"account_number": account.account_number, "holder_name": account.holder_name,
                "balance": account.balance, "risk_rating": account.risk_rating,
                "transaction_count": txn_count}

    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                             detail="report_type must be one of: risk_summary, transaction_volume, account_overview")

    return ReportOut(report_type=payload.report_type, generated_by=user.username,
                      generated_at=datetime.now(timezone.utc), data=data)
