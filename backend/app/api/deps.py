from collections.abc import Callable, Generator
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError
from sqlmodel import Session

from app.core import security
from app.core.config import settings
from app.core.db import engine
from app.core.permissions import resolve_permissions
from app.models import TokenPayload, User

reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/login/access-token"
)


def get_db() -> Generator[Session]:
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_db)]
TokenDep = Annotated[str, Depends(reusable_oauth2)]


def get_current_user(session: SessionDep, token: TokenDep) -> User:
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except InvalidTokenError, ValidationError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )
    user = session.get(User, token_data.sub)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_permissions(session: SessionDep, current_user: CurrentUser) -> set[str]:
    """The effective permission names of the current user (cached)."""
    return resolve_permissions(session, current_user)


CurrentPermissions = Annotated[set[str], Depends(get_current_permissions)]


def require_permission(permission: str) -> Callable[..., User]:
    """Dependency factory: 403 unless the user holds ``permission`` or ``super``."""

    def dependency(current_user: CurrentUser, perms: CurrentPermissions) -> User:
        if "super" in perms or permission in perms:
            return current_user
        raise HTTPException(
            status_code=403, detail="The user doesn't have enough privileges"
        )

    return dependency


def get_current_active_superuser(
    current_user: CurrentUser, perms: CurrentPermissions
) -> User:
    # Kept for back-compat: equivalent to require_permission("super").
    if "super" not in perms:
        raise HTTPException(
            status_code=403, detail="The user doesn't have enough privileges"
        )
    return current_user
