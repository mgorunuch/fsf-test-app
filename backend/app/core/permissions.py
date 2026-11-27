"""Short-lived, in-process permission cache.

Permissions are resolved in two cached layers that mirror the two relations,
rather than caching the flattened ``user -> permission`` set directly:

  * ``user -> role ids``    -- per user; small; changes only when that user's
    role assignment changes.
  * ``role -> permissions`` -- SHARED across every user that holds the role;
    changes only when a role's permission set is edited, which is rare.

A user's effective permissions are composed in memory by unioning the (cached)
permission sets of their (cached) roles. The expensive, rarely-changing
``role -> permission`` resolution is therefore cached ONCE and reused by every
user holding the role, instead of re-walking the full
``user -> role -> permission`` join and caching a separate flattened result per
user. With few roles and many users this is substantially less work and memory.

There is deliberately NO direct ``user -> permission`` relation: every
permission is granted through a role.

Invalidation is explicit and granular:
  * :func:`invalidate_user` -- a user's role assignment changed (or the user was
    deactivated / deleted / updated). Drops only that user's role-id entry.
  * :func:`invalidate_role` -- a role's permission set changed; every user that
    holds the role picks it up on their next request, via a single re-read of
    that one role (no need to touch any per-user entry).
  * :func:`invalidate_all` -- drop everything (e.g. after re-seeding).

LIMITATION: the cache is per-process. Under a multi-worker / multi-process
deployment each worker keeps its own copy, so an invalidation in one worker is
not seen by the others; stale entries would still expire within the TTL. A
cross-process deployment would need a shared store (e.g. Redis) and a pub/sub
invalidation channel. That is intentionally out of scope here.
"""

import threading
import time
import uuid

from sqlmodel import Session, col, select

from app.core.config import settings
from app.models import Permission, RolePermission, User, UserRole

# user_id -> (tuple of role ids, monotonic expiry)
_user_roles: dict[uuid.UUID, tuple[tuple[uuid.UUID, ...], float]] = {}
# role_id -> (frozenset of permission names, monotonic expiry)
_role_perms: dict[uuid.UUID, tuple[frozenset[str], float]] = {}
_lock = threading.Lock()


def _ttl() -> float:
    return settings.PERMISSIONS_CACHE_TTL_SECONDS


def _role_ids_for_user(session: Session, user_id: uuid.UUID) -> tuple[uuid.UUID, ...]:
    """Cached ``user -> role ids`` lookup (one small query per user)."""
    now = time.monotonic()
    with _lock:
        entry = _user_roles.get(user_id)
        if entry is not None and entry[1] > now:
            return entry[0]

    role_ids = tuple(
        session.exec(
            select(UserRole.role_id).where(col(UserRole.user_id) == user_id)
        ).all()
    )
    with _lock:
        _user_roles[user_id] = (role_ids, time.monotonic() + _ttl())
    return role_ids


def _permission_names_for_role(session: Session, role_id: uuid.UUID) -> frozenset[str]:
    """Cached ``role -> permission names`` lookup, shared across all users."""
    now = time.monotonic()
    with _lock:
        entry = _role_perms.get(role_id)
        if entry is not None and entry[1] > now:
            return entry[0]

    names = frozenset(
        session.exec(
            select(Permission.name)
            .select_from(RolePermission)
            .join(
                Permission,
                col(Permission.id) == col(RolePermission.permission_id),
            )
            .where(col(RolePermission.role_id) == role_id)
        ).all()
    )
    with _lock:
        _role_perms[role_id] = (names, time.monotonic() + _ttl())
    return names


def resolve_permissions(session: Session, user: User) -> set[str]:
    """Return the user's effective permission names, composed from both layers."""
    perms: set[str] = set()
    for role_id in _role_ids_for_user(session, user.id):
        perms |= _permission_names_for_role(session, role_id)
    return perms


def invalidate_user(user_id: uuid.UUID) -> None:
    """Drop one user's cached role ids (role assignment changed, deactivation...)."""
    with _lock:
        _user_roles.pop(user_id, None)


def invalidate_role(role_id: uuid.UUID) -> None:
    """Drop one role's cached permissions (its permission set changed).

    Every user holding the role sees the change on their next request, with a
    single re-read of this role -- no per-user invalidation needed.
    """
    with _lock:
        _role_perms.pop(role_id, None)


def invalidate_all() -> None:
    """Drop every cached entry (e.g. after re-seeding roles/permissions)."""
    with _lock:
        _user_roles.clear()
        _role_perms.clear()
