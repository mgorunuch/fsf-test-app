"""Short-lived, in-process permission cache.

Resolves the set of permission names granted to a user (via their roles) and
caches it for a short TTL so that repeated authorization checks within the same
request burst do not re-walk the role/permission relationships every time.

Invalidation is explicit: any change that can affect a user's effective
permissions (role assignment change, deactivation, deletion, update) calls
:func:`invalidate_user`; role->permission changes call :func:`invalidate_all`.

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

# user_id -> (frozenset of permission names, monotonic expiry timestamp)
_cache: dict[uuid.UUID, tuple[frozenset[str], float]] = {}
_lock = threading.Lock()


def _resolve_from_db(session: Session, user: User) -> frozenset[str]:
    """Resolve the user's permission names via user -> role -> permission joins."""
    statement = (
        select(Permission.name)
        .select_from(UserRole)
        .join(
            RolePermission,
            col(RolePermission.role_id) == col(UserRole.role_id),
        )
        .join(
            Permission,
            col(Permission.id) == col(RolePermission.permission_id),
        )
        .where(col(UserRole.user_id) == user.id)
        .distinct()
    )
    return frozenset(session.exec(statement).all())


def resolve_permissions(session: Session, user: User) -> set[str]:
    """Return the user's effective permission names, served through the cache."""
    now = time.monotonic()
    user_id = user.id
    with _lock:
        entry = _cache.get(user_id)
        if entry is not None and entry[1] > now:
            return set(entry[0])

    perms = _resolve_from_db(session, user)
    expires_at = time.monotonic() + settings.PERMISSIONS_CACHE_TTL_SECONDS
    with _lock:
        _cache[user_id] = (perms, expires_at)
    return set(perms)


def invalidate_user(user_id: uuid.UUID) -> None:
    """Drop one user's cached permission set (role change, deactivation, ...)."""
    with _lock:
        _cache.pop(user_id, None)


def invalidate_all() -> None:
    """Drop every cached entry (role->permission mapping changed)."""
    with _lock:
        _cache.clear()
