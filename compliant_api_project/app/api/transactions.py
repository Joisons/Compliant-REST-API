"""
Transactions resource.

RBAC policy:
  - AUDITOR, ANALYST, ADMIN can read.
  - VIEWER is deliberately excluded from transaction-level detail (can see
    account summaries but not the underlying transaction ledger) -- a
    narrower need-to-know than the Accounts resource.
  - Only ANALYST and ADMIN can post new transactions.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.rbac import require_roles
from app.models.db_models import Transaction, Account, User, Role
from app.models.schemas import TransactionCreate, TransactionOut

router = APIRouter(prefix="/api/v1/transactions", tags=["Transactions"])

READ_ROLES = (Role.ANALYST, Role.AUDITOR, Role.ADMIN)
WRITE_ROLES = (Role.ANALYST, Role.ADMIN)


@router.get("", response_model=list[TransactionOut])
def list_transactions(account_id: int | None = None, db: Session = Depends(get_db),
                       _user: User = Depends(require_roles(*READ_ROLES))):
    q = db.query(Transaction)
    if account_id is not None:
        q = q.filter(Transaction.account_id == account_id)
    return q.order_by(Transaction.created_at.desc()).all()


@router.post("", response_model=TransactionOut, status_code=status.HTTP_201_CREATED)
def create_transaction(payload: TransactionCreate, db: Session = Depends(get_db),
                        user: User = Depends(require_roles(*WRITE_ROLES))):
    account = db.query(Account).filter(Account.id == payload.account_id).first()
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")

    txn = Transaction(**payload.model_dump(), created_by=user.username)
    account.balance += payload.amount
    db.add(txn)
    db.commit()
    db.refresh(txn)
    return txn
