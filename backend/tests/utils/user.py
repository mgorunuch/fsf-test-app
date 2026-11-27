from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app import crud
from app.core.config import settings
from app.models import Role, User, UserCreate, UserUpdate
from tests.utils.utils import random_email, random_lower_string


def user_authentication_headers(
    *, client: TestClient, email: str, password: str
) -> dict[str, str]:
    data = {"username": email, "password": password}

    r = client.post(f"{settings.API_V1_STR}/login/access-token", data=data)
    response = r.json()
    auth_token = response["access_token"]
    headers = {"Authorization": f"Bearer {auth_token}"}
    return headers


def create_random_user(db: Session) -> User:
    email = random_email()
    password = random_lower_string()
    user_in = UserCreate(email=email, password=password)
    user = crud.create_user(session=db, user_create=user_in)
    return user


def get_role_by_name(*, session: Session, name: str) -> Role | None:
    """Look up a seeded role by its name."""
    return session.exec(select(Role).where(Role.name == name)).first()


def create_user_with_roles(
    *,
    session: Session,
    role_names: list[str],
    email: str | None = None,
    password: str | None = None,
    is_active: bool = True,
) -> tuple[User, str]:
    """Create a user assigned exactly the given (already seeded) roles.

    Returns the created ``User`` together with its plaintext password so the
    caller can log in and fetch auth headers.
    """
    email = email or random_email()
    password = password or random_lower_string()
    role_ids = []
    for name in role_names:
        role = get_role_by_name(session=session, name=name)
        assert role is not None, f"Role {name!r} is not seeded"
        role_ids.append(role.id)
    user_in = UserCreate(
        email=email, password=password, is_active=is_active, role_ids=role_ids
    )
    user = crud.create_user(session=session, user_create=user_in)
    return user, password


def auth_headers_for_user(
    *, client: TestClient, email: str, password: str
) -> dict[str, str]:
    """Thin alias around :func:`user_authentication_headers`."""
    return user_authentication_headers(client=client, email=email, password=password)


def role_headers(
    *, client: TestClient, session: Session, role_names: list[str]
) -> tuple[User, dict[str, str]]:
    """Create a user with the given roles and return (user, auth headers)."""
    user, password = create_user_with_roles(session=session, role_names=role_names)
    headers = auth_headers_for_user(client=client, email=user.email, password=password)
    return user, headers


def authentication_token_from_email(
    *, client: TestClient, email: str, db: Session
) -> dict[str, str]:
    """
    Return a valid token for the user with given email.

    If the user doesn't exist it is created first.
    """
    password = random_lower_string()
    user = crud.get_user_by_email(session=db, email=email)
    if not user:
        user_in_create = UserCreate(email=email, password=password)
        user = crud.create_user(session=db, user_create=user_in_create)
    else:
        user_in_update = UserUpdate(password=password)
        if not user.id:
            raise Exception("User id not set")
        user = crud.update_user(session=db, db_user=user, user_in=user_in_update)

    return user_authentication_headers(client=client, email=email, password=password)
