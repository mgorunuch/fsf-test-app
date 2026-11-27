from typing import Any

from fastapi import APIRouter, Depends
from sqlmodel import select

from app.api.deps import SessionDep, require_permission
from app.models import Role, RolePublic, RolesPublic

router = APIRouter(prefix="/roles", tags=["roles"])


@router.get(
    "/",
    dependencies=[Depends(require_permission("users:read"))],
    response_model=RolesPublic,
)
def read_roles(session: SessionDep) -> Any:
    """
    List roles (and their resolved permissions) for the admin role selector.
    """
    roles = session.exec(select(Role).order_by(Role.name)).all()
    data = [RolePublic.model_validate(role) for role in roles]
    return RolesPublic(data=data, count=len(data))
