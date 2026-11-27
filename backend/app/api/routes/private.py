from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app import crud
from app.api.deps import SessionDep
from app.models import UserCreate, UserPublic

router = APIRouter(tags=["private"], prefix="/private")


class PrivateUserCreate(BaseModel):
    email: str
    password: str
    full_name: str
    is_verified: bool = False


@router.post("/users/", response_model=UserPublic)
def create_user(user_in: PrivateUserCreate, session: SessionDep) -> Any:
    """
    Create a new user.

    Dev/test-only endpoint (only mounted when FASTAPI_ENV=development). Routed
    through ``crud.create_user`` so the account receives the baseline ``member``
    role instead of being a role-less orphan, and the permission cache is
    invalidated -- keeping it consistent with the RBAC model.
    """
    user_create = UserCreate(
        email=user_in.email,
        password=user_in.password,
        full_name=user_in.full_name,
    )
    return crud.create_user(session=session, user_create=user_create)
