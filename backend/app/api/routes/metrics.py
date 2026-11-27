from typing import Any

from fastapi import APIRouter, Depends
from sqlmodel import col, func, select

from app.api.deps import SessionDep, require_permission
from app.models import MetricsPublic, Role, User

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get(
    "/",
    dependencies=[Depends(require_permission("metrics:read"))],
    response_model=MetricsPublic,
)
def read_metrics(session: SessionDep) -> Any:
    """
    Simple metrics stub: total users, active users, and users per role.
    """
    total_users = session.exec(select(func.count()).select_from(User)).one()
    active_users = session.exec(
        select(func.count()).select_from(User).where(col(User.is_active).is_(True))
    ).one()
    roles = session.exec(select(Role)).all()
    users_per_role = {role.name: len(role.users) for role in roles}
    return MetricsPublic(
        total_users=total_users,
        active_users=active_users,
        users_per_role=users_per_role,
    )
