"""Authentication endpoints."""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.core.security import verify_password, hash_password, create_access_token
from app.core.rbac import require_roles
from app.models.db_models import User, Role
from app.models.schemas import Token, UserCreate, UserOut

router = APIRouter(prefix="/auth", tags=["Authentication"])
settings = get_settings()


@router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    OAuth2-compatible password login. Issues a short-lived JWT carrying the
    user's role as a claim, which downstream RBAC and rate-limiting both
    read directly from the token (no extra database round-trip needed on
    every subsequent request purely to determine the role).
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is deactivated")

    token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=token, role=user.role, expires_in_minutes=settings.access_token_expire_minutes)


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, db: Session = Depends(get_db),
                 _admin: User = Depends(require_roles(Role.ADMIN))):
    """Admin-only: provision a new user with an explicit role. There is no
    public self-registration endpoint -- role assignment in a system handling
    regulated financial data should always be an administrative act, not a
    self-service one."""
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    user = User(username=payload.username, full_name=payload.full_name,
                hashed_password=hash_password(payload.password), role=payload.role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db), _admin: User = Depends(require_roles(Role.ADMIN))):
    return db.query(User).all()
