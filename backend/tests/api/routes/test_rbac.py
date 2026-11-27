"""RBAC contract test suite.

This is the strict checklist for the role <-> permission access-control feature
described in the parent task's LOCKED ARCHITECTURE. Each test maps to a numbered
checklist item.

Roles / permission sets under test:
  admin   -> {super, users:read, users:manage, metrics:read}
  manager -> {users:read, metrics:read}
  member  -> {}   (self-service only)
"""

import uuid

from fastapi.testclient import TestClient
from sqlmodel import Session

from app.core.config import settings
from tests.utils.user import (
    create_user_with_roles,
    get_role_by_name,
    role_headers,
)
from tests.utils.utils import random_email, random_lower_string

API = settings.API_V1_STR

EXPECTED_ROLE_PERMS = {
    "admin": {"super", "users:read", "users:manage", "metrics:read"},
    "manager": {"users:read", "metrics:read"},
    "member": set(),
}


# ---------------------------------------------------------------------------
# 1. Seed integrity
# ---------------------------------------------------------------------------
def test_seed_roles_and_permissions(db: Session) -> None:
    for role_name, expected in EXPECTED_ROLE_PERMS.items():
        role = get_role_by_name(session=db, name=role_name)
        assert role is not None, f"role {role_name} missing"
        actual = {p.name for p in role.permissions}
        assert actual == expected, f"{role_name}: {actual} != {expected}"


# ---------------------------------------------------------------------------
# 2. /users/me exposes roles + permissions + computed is_superuser
# ---------------------------------------------------------------------------
def test_users_me_exposes_roles_permissions(client: TestClient, db: Session) -> None:
    for role_name, expected_perms in EXPECTED_ROLE_PERMS.items():
        _, headers = role_headers(client=client, session=db, role_names=[role_name])
        r = client.get(f"{API}/users/me", headers=headers)
        assert r.status_code == 200
        body = r.json()
        assert body["roles"] == [role_name]
        assert set(body["permissions"]) == expected_perms
        assert body["is_superuser"] is (role_name == "admin")


# ---------------------------------------------------------------------------
# 3. GET /users/ : admin 200, manager 200, member 403, anon 401
# ---------------------------------------------------------------------------
def test_list_users_authorization(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    _, manager = role_headers(client=client, session=db, role_names=["manager"])
    _, member = role_headers(client=client, session=db, role_names=["member"])

    assert (
        client.get(f"{API}/users/", headers=superuser_token_headers).status_code == 200
    )
    assert client.get(f"{API}/users/", headers=manager).status_code == 200
    assert client.get(f"{API}/users/", headers=member).status_code == 403
    assert client.get(f"{API}/users/").status_code == 401


# ---------------------------------------------------------------------------
# 4. POST /users/ : admin ok, manager 403, member 403
# ---------------------------------------------------------------------------
def test_create_user_authorization(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    _, manager = role_headers(client=client, session=db, role_names=["manager"])
    _, member = role_headers(client=client, session=db, role_names=["member"])

    payload = {"email": random_email(), "password": random_lower_string()}
    r = client.post(f"{API}/users/", headers=superuser_token_headers, json=payload)
    assert 200 <= r.status_code < 300

    assert (
        client.post(
            f"{API}/users/",
            headers=manager,
            json={"email": random_email(), "password": random_lower_string()},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"{API}/users/",
            headers=member,
            json={"email": random_email(), "password": random_lower_string()},
        ).status_code
        == 403
    )


# ---------------------------------------------------------------------------
# 5. PATCH /users/{id} : admin ok, manager 403, member 403
# ---------------------------------------------------------------------------
def test_patch_user_authorization(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    target, _ = create_user_with_roles(session=db, role_names=["member"])
    _, manager = role_headers(client=client, session=db, role_names=["manager"])
    _, member = role_headers(client=client, session=db, role_names=["member"])

    r = client.patch(
        f"{API}/users/{target.id}",
        headers=superuser_token_headers,
        json={"full_name": "Renamed"},
    )
    assert r.status_code == 200
    assert (
        client.patch(
            f"{API}/users/{target.id}", headers=manager, json={"full_name": "x"}
        ).status_code
        == 403
    )
    assert (
        client.patch(
            f"{API}/users/{target.id}", headers=member, json={"full_name": "x"}
        ).status_code
        == 403
    )


# ---------------------------------------------------------------------------
# 6. DELETE /users/{id} : admin ok, manager 403, member 403
# ---------------------------------------------------------------------------
def test_delete_user_authorization(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    _, manager = role_headers(client=client, session=db, role_names=["manager"])
    _, member = role_headers(client=client, session=db, role_names=["member"])

    victim, _ = create_user_with_roles(session=db, role_names=["member"])
    assert client.delete(f"{API}/users/{victim.id}", headers=manager).status_code == 403
    assert client.delete(f"{API}/users/{victim.id}", headers=member).status_code == 403

    r = client.delete(f"{API}/users/{victim.id}", headers=superuser_token_headers)
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# 7. GET /users/{id} : self 200 for all; other-user admin/manager 200, member 403
# ---------------------------------------------------------------------------
def test_get_user_by_id_authorization(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    admin_me = client.get(f"{API}/users/me", headers=superuser_token_headers).json()
    admin_id = admin_me["id"]

    manager_user, manager = role_headers(
        client=client, session=db, role_names=["manager"]
    )
    member_user, member = role_headers(client=client, session=db, role_names=["member"])
    other, _ = create_user_with_roles(session=db, role_names=["member"])

    # self always OK
    assert (
        client.get(
            f"{API}/users/{admin_id}", headers=superuser_token_headers
        ).status_code
        == 200
    )
    assert (
        client.get(f"{API}/users/{manager_user.id}", headers=manager).status_code == 200
    )
    assert (
        client.get(f"{API}/users/{member_user.id}", headers=member).status_code == 200
    )

    # other-user
    assert (
        client.get(
            f"{API}/users/{other.id}", headers=superuser_token_headers
        ).status_code
        == 200
    )
    assert client.get(f"{API}/users/{other.id}", headers=manager).status_code == 200
    assert client.get(f"{API}/users/{other.id}", headers=member).status_code == 403


# ---------------------------------------------------------------------------
# 8. Role assignment via role_ids (users:manage) + no self-escalation
# ---------------------------------------------------------------------------
def test_admin_assigns_roles_via_role_ids(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    target, _ = create_user_with_roles(session=db, role_names=["member"])
    manager_role = get_role_by_name(session=db, name="manager")
    r = client.patch(
        f"{API}/users/{target.id}",
        headers=superuser_token_headers,
        json={"role_ids": [str(manager_role.id)]},
    )
    assert r.status_code == 200
    assert r.json()["roles"] == ["manager"]


def test_manager_cannot_escalate_self_to_admin(client: TestClient, db: Session) -> None:
    manager_user, manager = role_headers(
        client=client, session=db, role_names=["manager"]
    )
    admin_role = get_role_by_name(session=db, name="admin")
    r = client.patch(
        f"{API}/users/{manager_user.id}",
        headers=manager,
        json={"role_ids": [str(admin_role.id)]},
    )
    assert r.status_code == 403
    # still not a superuser
    me = client.get(f"{API}/users/me", headers=manager).json()
    assert me["is_superuser"] is False
    assert "super" not in me["permissions"]


# ---------------------------------------------------------------------------
# 9. GET /metrics/ : admin 200, manager 200, member 403, anon 401
# ---------------------------------------------------------------------------
def test_metrics_authorization(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    _, manager = role_headers(client=client, session=db, role_names=["manager"])
    _, member = role_headers(client=client, session=db, role_names=["member"])

    r = client.get(f"{API}/metrics/", headers=superuser_token_headers)
    assert r.status_code == 200
    body = r.json()
    assert "total_users" in body
    assert "active_users" in body
    assert "users_per_role" in body

    assert client.get(f"{API}/metrics/", headers=manager).status_code == 200
    assert client.get(f"{API}/metrics/", headers=member).status_code == 403
    assert client.get(f"{API}/metrics/").status_code == 401


# ---------------------------------------------------------------------------
#  GET /roles/ : users:read (admin + manager); member 403; anon 401
# ---------------------------------------------------------------------------
def test_roles_endpoint_authorization(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    _, manager = role_headers(client=client, session=db, role_names=["manager"])
    _, member = role_headers(client=client, session=db, role_names=["member"])

    r = client.get(f"{API}/roles/", headers=superuser_token_headers)
    assert r.status_code == 200
    names = {row["name"] for row in r.json()["data"]}
    assert {"admin", "manager", "member"} <= names

    assert client.get(f"{API}/roles/", headers=manager).status_code == 200
    assert client.get(f"{API}/roles/", headers=member).status_code == 403
    assert client.get(f"{API}/roles/").status_code == 401


# ---------------------------------------------------------------------------
# 10. Member self-service is preserved
# ---------------------------------------------------------------------------
def test_member_self_service(client: TestClient, db: Session) -> None:
    user, password = create_user_with_roles(session=db, role_names=["member"])
    from tests.utils.user import auth_headers_for_user

    headers = auth_headers_for_user(client=client, email=user.email, password=password)

    # GET /users/me
    assert client.get(f"{API}/users/me", headers=headers).status_code == 200

    # PATCH /users/me
    r = client.patch(
        f"{API}/users/me", headers=headers, json={"full_name": "Member Name"}
    )
    assert r.status_code == 200
    assert r.json()["full_name"] == "Member Name"

    # change own password
    new_password = random_lower_string()
    r = client.patch(
        f"{API}/users/me/password",
        headers=headers,
        json={"current_password": password, "new_password": new_password},
    )
    assert r.status_code == 200
    headers = auth_headers_for_user(
        client=client, email=user.email, password=new_password
    )

    # own items CRUD
    r = client.post(f"{API}/items/", headers=headers, json={"title": "mine"})
    assert r.status_code == 200
    item_id = r.json()["id"]
    assert client.get(f"{API}/items/{item_id}", headers=headers).status_code == 200
    assert (
        client.put(
            f"{API}/items/{item_id}", headers=headers, json={"title": "mine2"}
        ).status_code
        == 200
    )
    assert client.delete(f"{API}/items/{item_id}", headers=headers).status_code == 200


# ---------------------------------------------------------------------------
# 11. PATCH /users/me cannot change role / permission / is_superuser
# ---------------------------------------------------------------------------
def test_patch_users_me_cannot_change_privileges(
    client: TestClient, db: Session
) -> None:
    user, headers = role_headers(client=client, session=db, role_names=["member"])
    manager_role = get_role_by_name(session=db, name="manager")

    r = client.patch(
        f"{API}/users/me",
        headers=headers,
        json={
            "full_name": "Still Member",
            "is_superuser": True,
            "role_ids": [str(manager_role.id)],
            "permissions": ["super"],
            "roles": ["admin"],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["full_name"] == "Still Member"
    assert body["is_superuser"] is False
    assert body["roles"] == ["member"]
    assert body["permissions"] == []


# ---------------------------------------------------------------------------
# 12. Session / access invalidation (most security-critical)
# ---------------------------------------------------------------------------
def test_deactivation_invalidates_existing_token(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    user, headers = role_headers(client=client, session=db, role_names=["member"])
    # token works
    assert client.get(f"{API}/users/me", headers=headers).status_code == 200
    # admin deactivates
    r = client.patch(
        f"{API}/users/{user.id}",
        headers=superuser_token_headers,
        json={"is_active": False},
    )
    assert r.status_code == 200
    # existing token now rejected (inactive user)
    assert client.get(f"{API}/users/me", headers=headers).status_code == 400


def test_demote_manager_reflects_immediately(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    user, headers = role_headers(client=client, session=db, role_names=["manager"])
    member_role = get_role_by_name(session=db, name="member")
    # manager can list users -> populates cache
    assert client.get(f"{API}/users/", headers=headers).status_code == 200
    # admin demotes to member
    r = client.patch(
        f"{API}/users/{user.id}",
        headers=superuser_token_headers,
        json={"role_ids": [str(member_role.id)]},
    )
    assert r.status_code == 200
    # next request reflects demotion immediately (cache invalidated on change)
    assert client.get(f"{API}/users/", headers=headers).status_code == 403


def test_promote_member_reflects_immediately(
    client: TestClient, db: Session, superuser_token_headers: dict[str, str]
) -> None:
    user, headers = role_headers(client=client, session=db, role_names=["member"])
    manager_role = get_role_by_name(session=db, name="manager")
    # member cannot list users -> populates cache (empty perms)
    assert client.get(f"{API}/users/", headers=headers).status_code == 403
    # admin promotes to manager
    r = client.patch(
        f"{API}/users/{user.id}",
        headers=superuser_token_headers,
        json={"role_ids": [str(manager_role.id)]},
    )
    assert r.status_code == 200
    # next request now allowed
    assert client.get(f"{API}/users/", headers=headers).status_code == 200


# ---------------------------------------------------------------------------
# 13. is_superuser back-compat
# ---------------------------------------------------------------------------
def test_is_superuser_backcompat_create(
    client: TestClient, superuser_token_headers: dict[str, str]
) -> None:
    # created with is_superuser=True -> super perm + admin role + computed True
    r = client.post(
        f"{API}/users/",
        headers=superuser_token_headers,
        json={
            "email": random_email(),
            "password": random_lower_string(),
            "is_superuser": True,
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["is_superuser"] is True
    assert "admin" in body["roles"]
    assert "super" in body["permissions"]

    # plain user -> is_superuser False
    r = client.post(
        f"{API}/users/",
        headers=superuser_token_headers,
        json={"email": random_email(), "password": random_lower_string()},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["is_superuser"] is False
    assert "super" not in body["permissions"]


def test_unknown_user_id_type(client: TestClient) -> None:
    # guard: a bad uuid in path is a 422, not a 500 (sanity for route wiring)
    r = client.get(f"{API}/users/{uuid.uuid4()}")
    assert r.status_code == 401
