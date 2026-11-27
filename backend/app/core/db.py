from sqlmodel import Session, create_engine, select

from app import crud
from app.core.config import settings
from app.core.permissions import invalidate_all
from app.models import Permission, Role, User, UserCreate

engine = create_engine(str(settings.DATABASE_URL), pool_pre_ping=True)


# make sure all SQLModel models are imported (app.models) before initializing DB
# otherwise, SQLModel might fail to initialize relationships properly
# for more details: https://github.com/fastapi/full-stack-fastapi-template/issues/28


# Canonical RBAC seed data (mirrors the LOCKED ARCHITECTURE and the migration).
PERMISSION_DESCRIPTIONS: dict[str, str] = {
    "super": "Unrestricted access; passes every permission check.",
    "users:read": "List/view any user and view the roles list.",
    "users:manage": "Create/update/delete users and change role assignments.",
    "metrics:read": "View the metrics page/endpoint.",
}

ROLE_DEFINITIONS: dict[str, set[str]] = {
    "admin": {"super", "users:read", "users:manage", "metrics:read"},
    "manager": {"users:read", "metrics:read"},
    "member": set(),
}


def seed_rbac(session: Session) -> None:
    """Idempotently seed the permissions, roles, and their links."""
    permissions: dict[str, Permission] = {}
    for name, description in PERMISSION_DESCRIPTIONS.items():
        perm = session.exec(select(Permission).where(Permission.name == name)).first()
        if perm is None:
            perm = Permission(name=name, description=description)
            session.add(perm)
        permissions[name] = perm
    session.commit()
    for perm in permissions.values():
        session.refresh(perm)

    for role_name, perm_names in ROLE_DEFINITIONS.items():
        role = session.exec(select(Role).where(Role.name == role_name)).first()
        if role is None:
            role = Role(name=role_name)
            session.add(role)
        role.permissions = [permissions[p] for p in perm_names]
        session.add(role)
    session.commit()
    # Role -> permission mapping may have changed; flush the whole cache.
    invalidate_all()


def _ensure_demo_user(session: Session, *, email: str, role_name: str) -> None:
    """Dev-only idempotent demo user with the given role (password 'changethis')."""
    existing = session.exec(select(User).where(User.email == email)).first()
    if existing is not None:
        return
    role = session.exec(select(Role).where(Role.name == role_name)).first()
    role_ids = [role.id] if role is not None else None
    crud.create_user(
        session=session,
        user_create=UserCreate(email=email, password="changethis", role_ids=role_ids),
    )


def init_db(session: Session) -> None:
    # Tables should be created with Alembic migrations
    # But if you don't want to use migrations, create
    # the tables un-commenting the next lines
    # from sqlmodel import SQLModel

    # This works because the models are already imported and registered from app.models
    # SQLModel.metadata.create_all(engine)

    # Permissions/roles must exist before any user (every user gets at least member).
    seed_rbac(session)

    user = session.exec(
        select(User).where(User.email == settings.FIRST_SUPERUSER)
    ).first()
    if not user:
        user_in = UserCreate(
            email=settings.FIRST_SUPERUSER,
            password=settings.FIRST_SUPERUSER_PASSWORD,
            is_superuser=True,
        )
        user = crud.create_user(session=session, user_create=user_in)

    # Reviewer local exercise: dev-only demo users for manager/member logins.
    if settings.FASTAPI_ENV == "development":
        _ensure_demo_user(session, email="manager@example.com", role_name="manager")
        _ensure_demo_user(session, email="member@example.com", role_name="member")
