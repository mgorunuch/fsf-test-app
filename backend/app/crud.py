import uuid
from typing import Any

from sqlmodel import Session, select

from app.core.permissions import invalidate_user
from app.core.security import get_password_hash, verify_password
from app.models import (
    Item,
    ItemCreate,
    Role,
    User,
    UserCreate,
    UserUpdate,
)


def get_role_by_name(*, session: Session, name: str) -> Role | None:
    return session.exec(select(Role).where(Role.name == name)).first()


def _roles_from_ids(*, session: Session, role_ids: list[uuid.UUID]) -> list[Role]:
    roles: list[Role] = []
    for role_id in role_ids:
        role = session.get(Role, role_id)
        if role is not None and role not in roles:
            roles.append(role)
    return roles


def _resolve_create_roles(
    *, session: Session, is_superuser: bool, role_ids: list[uuid.UUID] | None
) -> list[Role]:
    """Decide which roles a newly created user receives.

    Precedence: explicit role_ids, plus the admin role when is_superuser is set.
    Falls back to the baseline ``member`` role so every user has at least the
    self-service level (mirrors the migration's is_superuser=False -> member).
    """
    roles: list[Role] = []
    if role_ids:
        roles = _roles_from_ids(session=session, role_ids=role_ids)
    if is_superuser:
        admin = get_role_by_name(session=session, name="admin")
        if admin is not None and admin not in roles:
            roles.append(admin)
    if not roles:
        member = get_role_by_name(session=session, name="member")
        if member is not None:
            roles = [member]
    return roles


def create_user(*, session: Session, user_create: UserCreate) -> User:
    db_obj = User.model_validate(
        user_create, update={"hashed_password": get_password_hash(user_create.password)}
    )
    db_obj.roles = _resolve_create_roles(
        session=session,
        is_superuser=user_create.is_superuser,
        role_ids=user_create.role_ids,
    )
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    invalidate_user(db_obj.id)
    return db_obj


def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}
    if "password" in user_data:
        password = user_data["password"]
        hashed_password = get_password_hash(password)
        extra_data["hashed_password"] = hashed_password

    # Role-related fields are not columns on User; apply them separately so
    # sqlmodel_update never tries to set the computed is_superuser property.
    role_ids = user_data.pop("role_ids", None)
    is_superuser = user_data.pop("is_superuser", None)

    db_user.sqlmodel_update(user_data, update=extra_data)

    if role_ids is not None:
        db_user.roles = _roles_from_ids(session=session, role_ids=role_ids)
    if is_superuser is not None:
        admin = get_role_by_name(session=session, name="admin")
        if is_superuser:
            if admin is not None and admin not in db_user.roles:
                db_user.roles.append(admin)
        else:
            # Drop any super-bearing role(s).
            db_user.roles = [
                role
                for role in db_user.roles
                if "super" not in {p.name for p in role.permissions}
            ]

    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    invalidate_user(db_user.id)
    return db_user


def get_user_by_email(*, session: Session, email: str) -> User | None:
    statement = select(User).where(User.email == email)
    session_user = session.exec(statement).first()
    return session_user


# Dummy hash to use for timing attack prevention when user is not found
# This is an Argon2 hash of a random password, used to ensure constant-time comparison
DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$MjQyZWE1MzBjYjJlZTI0Yw$YTU4NGM5ZTZmYjE2NzZlZjY0ZWY3ZGRkY2U2OWFjNjk"


def authenticate(*, session: Session, email: str, password: str) -> User | None:
    db_user = get_user_by_email(session=session, email=email)
    if not db_user:
        # Prevent timing attacks by running password verification even when user doesn't exist
        # This ensures the response time is similar whether or not the email exists
        verify_password(password, DUMMY_HASH)
        return None
    verified, updated_password_hash = verify_password(password, db_user.hashed_password)
    if not verified:
        return None
    if updated_password_hash:
        db_user.hashed_password = updated_password_hash
        session.add(db_user)
        session.commit()
        session.refresh(db_user)
    return db_user


def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
    db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item
