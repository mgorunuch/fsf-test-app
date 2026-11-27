import uuid
from datetime import UTC, datetime

from pydantic import EmailStr, model_validator
from sqlmodel import Field, Relationship, SQLModel


def get_datetime_utc() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# RBAC link tables (many-to-many association tables)
# ---------------------------------------------------------------------------
class UserRole(SQLModel, table=True):
    user_id: uuid.UUID = Field(
        foreign_key="user.id", primary_key=True, ondelete="CASCADE"
    )
    role_id: uuid.UUID = Field(
        foreign_key="role.id", primary_key=True, ondelete="CASCADE"
    )


class RolePermission(SQLModel, table=True):
    role_id: uuid.UUID = Field(
        foreign_key="role.id", primary_key=True, ondelete="CASCADE"
    )
    permission_id: uuid.UUID = Field(
        foreign_key="permission.id", primary_key=True, ondelete="CASCADE"
    )


# ---------------------------------------------------------------------------
# RBAC core tables
# ---------------------------------------------------------------------------
class Permission(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    roles: list[Role] = Relationship(
        back_populates="permissions", link_model=RolePermission
    )


class Role(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    name: str = Field(unique=True, index=True, max_length=255)
    description: str | None = Field(default=None, max_length=255)
    permissions: list[Permission] = Relationship(
        back_populates="roles", link_model=RolePermission
    )
    users: list[User] = Relationship(back_populates="roles", link_model=UserRole)


# Shared properties
class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, index=True, max_length=255)
    is_active: bool = True
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str = Field(min_length=8, max_length=128)
    # Back-compat input: True assigns the admin (super-bearing) role on create.
    is_superuser: bool = False
    # Explicit role assignment (admin-only path).
    role_ids: list[uuid.UUID] | None = None


class UserRegister(SQLModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=255)


# Properties to receive via API on update, all are optional
class UserUpdate(SQLModel):
    email: EmailStr | None = Field(default=None, max_length=255)
    is_active: bool | None = None
    # Back-compat input: True adds admin role, False removes super-bearing role(s).
    is_superuser: bool | None = None
    full_name: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=8, max_length=128)
    # Explicit role assignment (admin-only path).
    role_ids: list[uuid.UUID] | None = None


class UserUpdateMe(SQLModel):
    full_name: str | None = Field(default=None, max_length=255)
    email: EmailStr | None = Field(default=None, max_length=255)


class UpdatePassword(SQLModel):
    current_password: str = Field(min_length=8, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


# Database model, database table inferred from class name
class User(UserBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    hashed_password: str
    created_at: datetime | None = Field(default_factory=get_datetime_utc)
    items: list[Item] = Relationship(back_populates="owner", cascade_delete=True)
    roles: list[Role] = Relationship(back_populates="users", link_model=UserRole)

    @property
    def permission_names(self) -> set[str]:
        """Resolve the union of permission names granted by this user's roles."""
        return {
            permission.name for role in self.roles for permission in role.permissions
        }

    @property
    def is_superuser(self) -> bool:
        """Back-compat flag: holds the unrestricted ``super`` permission."""
        return "super" in self.permission_names


# Properties to return via API, id is always required
class UserPublic(UserBase):
    id: uuid.UUID
    created_at: datetime | None = None
    # Computed from the resolved permission set.
    is_superuser: bool = False
    roles: list[str] = []
    permissions: list[str] = []

    @model_validator(mode="before")
    @classmethod
    def _resolve_from_user(cls, data: object) -> object:
        # When validating a ``User`` ORM instance, flatten its roles/permissions.
        if isinstance(data, User):
            perms = data.permission_names
            return {
                "id": data.id,
                "email": data.email,
                "is_active": data.is_active,
                "full_name": data.full_name,
                "created_at": data.created_at,
                "is_superuser": "super" in perms,
                "roles": sorted(role.name for role in data.roles),
                "permissions": sorted(perms),
            }
        return data


class UsersPublic(SQLModel):
    data: list[UserPublic]
    count: int


# Role representation returned via API
class RolePublic(SQLModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    permissions: list[str] = []

    @model_validator(mode="before")
    @classmethod
    def _resolve_from_role(cls, data: object) -> object:
        if isinstance(data, Role):
            return {
                "id": data.id,
                "name": data.name,
                "description": data.description,
                "permissions": sorted(p.name for p in data.permissions),
            }
        return data


class RolesPublic(SQLModel):
    data: list[RolePublic]
    count: int


# Metrics stub payload
class MetricsPublic(SQLModel):
    total_users: int
    active_users: int
    users_per_role: dict[str, int]


# Shared properties
class ItemBase(SQLModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)


# Properties to receive on item creation
class ItemCreate(ItemBase):
    pass


# Properties to receive on item update
class ItemUpdate(SQLModel):
    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=255)


# Database model, database table inferred from class name
class Item(ItemBase, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime | None = Field(default_factory=get_datetime_utc)
    owner_id: uuid.UUID = Field(
        foreign_key="user.id", nullable=False, ondelete="CASCADE"
    )
    owner: User | None = Relationship(back_populates="items")


# Properties to return via API, id is always required
class ItemPublic(ItemBase):
    id: uuid.UUID
    owner_id: uuid.UUID
    created_at: datetime | None = None


class ItemsPublic(SQLModel):
    data: list[ItemPublic]
    count: int


# Generic message
class Message(SQLModel):
    message: str


# JSON payload containing access token
class Token(SQLModel):
    access_token: str
    token_type: str = "bearer"


# Contents of JWT token
class TokenPayload(SQLModel):
    sub: str | None = None


class NewPassword(SQLModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)
