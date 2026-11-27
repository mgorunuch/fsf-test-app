"""Unit tests for the short-lived in-process permission cache."""

from sqlmodel import Session

from app.core.config import settings
from app.core.permissions import (
    invalidate_all,
    invalidate_user,
    resolve_permissions,
)
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
