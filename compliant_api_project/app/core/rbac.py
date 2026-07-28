"""
Role-Based Access Control (RBAC).

`get_current_user` validates the bearer JWT AND re-checks the user's active
status against the database on every request (not just at login) -- this is
a deliberate compliance choice: a JWT with a 30-minute lifetime should not
remain valid for a user who was deactivated mid-session. It costs one indexed
lookup per request in exchange for near-real-time access revocation, which
is the right trade-off for a system handling regulated financial data.

`require_roles(...)` is a dependency factory used to declare, at the route
level, exactly which roles may call an endpoint -- e.g.
`Depends(require_roles(Role.AUDITOR, Role.ADMIN))`. Authorization logic lives
in one place and is visible directly in each route's signature, rather than
being scattered through handler bodies.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.database import get_db
from app.models.db_models import User, Role

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is deactivated")
    return user


def require_roles(*allowed_roles: Role):
    def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(f"Role '{current_user.role.value}' is not permitted to perform this action. "
                        f"Required: {', '.join(r.value for r in allowed_roles)}."),
            )
        return current_user
    return dependency
