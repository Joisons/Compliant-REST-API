"""
Accounts resource.

RBAC policy for this resource:
  - VIEWER, ANALYST, AUDITOR, ADMIN can all *read*.
  - Only ANALYST and ADMIN can *create*.
  - Only ADMIN can *delete*.
This mirrors a real segregation-of-duties control: the people who can see
account data (broad) are not the same set of people who can create or
remove accounts (narrow), and an AUDITOR -- who must be able to review
everything -- is deliberately given no write access at all, preserving their
independence.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.core.rbac import require_roles
from app.models.db_models import Account, User, Role
from app.models.schemas import AccountCreate, AccountOut

router = APIRouter(prefix="/api/v1/accounts", tags=["Accounts"])

ALL_ROLES = (Role.VIEWER, Role.ANALYST, Role.AUDITOR, Role.ADMIN)
WRITE_ROLES = (Role.ANALYST, Role.ADMIN)


@router.get("", response_model=list[AccountOut])
def list_accounts(db: Session = Depends(get_db), _user: User = Depends(require_roles(*ALL_ROLES))):
    return db.query(Account).all()


@router.get("/{account_id}", response_model=AccountOut)
def get_account(account_id: int, db: Session = Depends(get_db),
                 _user: User = Depends(require_roles(*ALL_ROLES))):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    return account


@router.post("", response_model=AccountOut, status_code=status.HTTP_201_CREATED)
def create_account(payload: AccountCreate, db: Session = Depends(get_db),
                    _user: User = Depends(require_roles(*WRITE_ROLES))):
    if db.query(Account).filter(Account.account_number == payload.account_number).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account number already exists")
    account = Account(**payload.model_dump())
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_account(account_id: int, db: Session = Depends(get_db),
                    _user: User = Depends(require_roles(Role.ADMIN))):
    account = db.query(Account).filter(Account.id == account_id).first()
    if not account:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Account not found")
    db.delete(account)
    db.commit()
