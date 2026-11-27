"""Unit tests for the short-lived, two-layer in-process permission cache."""

from sqlmodel import Session, select

from app.core.config import settings
from app.core.permissions import (
    invalidate_all,
    invalidate_role,
    invalidate_user,
    resolve_permissions,
)
from app.models import Permission, Role
from tests.utils.user import create_user_with_roles, get_role_by_name


def test_resolve_permissions_caches_and_invalidate_forces_refresh(
    db: Session,
) -> None:
    user, _ = create_user_with_roles(session=db, role_names=["manager"])
    # start from a clean cache entry for this user
    invalidate_user(user.id)

    perms1 = resolve_permissions(db, user)
    assert "users:read" in perms1
    assert "super" not in perms1

    # mutate roles in the DB WITHOUT invalidating the cache
    admin_role = get_role_by_name(session=db, name="admin")
    assert admin_role is not None
    user.roles = [admin_role]
    db.add(user)
    db.commit()
    db.refresh(user)

    # still served from cache -> stale (no super yet)
    perms_cached = resolve_permissions(db, user)
    assert perms_cached == perms1
    assert "super" not in perms_cached

    # explicit invalidation forces a fresh resolve
    invalidate_user(user.id)
    perms2 = resolve_permissions(db, user)
    assert "super" in perms2


def _get_or_create_role(db: Session, name: str) -> Role:
    # Roles persist across test sessions (teardown wipes only users/items), so
    # this helper must be idempotent for re-runs.
    role = get_role_by_name(session=db, name=name)
    if role is None:
        role = Role(name=name)
        db.add(role)
        db.commit()
        db.refresh(role)
    return role


def test_role_permission_change_propagates_to_all_holders_via_invalidate_role(
    db: Session,
) -> None:
    """A role's permission change reaches every holder with ONE invalidation.

    This is the point of caching ``role -> permissions`` separately from
    ``user -> roles``: the shared role entry is invalidated once and every user
    holding that role re-composes fresh on their next resolve, without touching
    any per-user entry.
    """
    metrics = db.exec(
        select(Permission).where(Permission.name == "metrics:read")
    ).one()
    users_read = db.exec(
        select(Permission).where(Permission.name == "users:read")
    ).one()

    role = _get_or_create_role(db, "cache_test_role")
    role.permissions = [metrics]
    db.add(role)
    db.commit()
    db.refresh(role)
    invalidate_role(role.id)

    u1, _ = create_user_with_roles(session=db, role_names=["cache_test_role"])
    u2, _ = create_user_with_roles(session=db, role_names=["cache_test_role"])

    assert resolve_permissions(db, u1) == {"metrics:read"}
    assert resolve_permissions(db, u2) == {"metrics:read"}

    # change the ROLE's permission set (shared by both users); no user invalidation
    role.permissions = [metrics, users_read]
    db.add(role)
    db.commit()
    db.refresh(role)

    # still stale for both: served from the shared role-permissions cache
    assert "users:read" not in resolve_permissions(db, u1)

    # a single role-level invalidation updates EVERY holder on next resolve
    invalidate_role(role.id)
    assert resolve_permissions(db, u1) == {"metrics:read", "users:read"}
    assert resolve_permissions(db, u2) == {"metrics:read", "users:read"}

    # leave the throwaway role clean for re-runs
    role.permissions = [metrics]
    db.add(role)
    db.commit()
    invalidate_role(role.id)


def test_invalidate_all_clears_every_entry(db: Session) -> None:
    user, _ = create_user_with_roles(session=db, role_names=["manager"])
    resolve_permissions(db, user)
    invalidate_all()
    # after a global flush a fresh resolve still returns the correct set
    perms = resolve_permissions(db, user)
    assert perms == {"users:read", "metrics:read"}


def test_cache_ttl_default_under_five_minutes() -> None:
    # requirement: short-lived, well under the 5-minute (300s) ceiling
    assert settings.PERMISSIONS_CACHE_TTL_SECONDS < 300
