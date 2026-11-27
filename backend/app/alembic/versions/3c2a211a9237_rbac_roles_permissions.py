"""rbac roles permissions

Revision ID: 3c2a211a9237
Revises: fe56fa70289e
Create Date: 2026-11-27 13:33:59.708530

Adds the RBAC schema (permission/role/rolepermission/userrole), seeds the three
roles and four permissions with their links, backfills user->role from the
existing ``user.is_superuser`` flag (True -> admin, False -> member), and then
drops the stored ``is_superuser`` column. Safe against a populated database.
"""
import uuid

import sqlalchemy as sa
import sqlmodel.sql.sqltypes
from alembic import op

# revision identifiers, used by Alembic.
revision = '3c2a211a9237'
down_revision = 'fe56fa70289e'
branch_labels = None
depends_on = None


# Canonical seed data (mirrors app.core.db and the LOCKED ARCHITECTURE).
PERMISSION_DESCRIPTIONS = {
    "super": "Unrestricted access; passes every permission check.",
    "users:read": "List/view any user and view the roles list.",
    "users:manage": "Create/update/delete users and change role assignments.",
    "metrics:read": "View the metrics page/endpoint.",
}
ROLE_DEFINITIONS = {
    "admin": {"super", "users:read", "users:manage", "metrics:read"},
    "manager": {"users:read", "metrics:read"},
    "member": set(),
}


def _tables():
    permission = sa.table(
        "permission",
        sa.column("id", sa.Uuid()),
        sa.column("name", sqlmodel.sql.sqltypes.AutoString()),
        sa.column("description", sqlmodel.sql.sqltypes.AutoString()),
    )
    role = sa.table(
        "role",
        sa.column("id", sa.Uuid()),
        sa.column("name", sqlmodel.sql.sqltypes.AutoString()),
        sa.column("description", sqlmodel.sql.sqltypes.AutoString()),
    )
    rolepermission = sa.table(
        "rolepermission",
        sa.column("role_id", sa.Uuid()),
        sa.column("permission_id", sa.Uuid()),
    )
    return permission, role, rolepermission


def _seed(bind):
    permission, role, rolepermission = _tables()

    perm_ids = {name: uuid.uuid4() for name in PERMISSION_DESCRIPTIONS}
    op.bulk_insert(
        permission,
        [
            {"id": perm_ids[name], "name": name, "description": desc}
            for name, desc in PERMISSION_DESCRIPTIONS.items()
        ],
    )

    role_ids = {name: uuid.uuid4() for name in ROLE_DEFINITIONS}
    op.bulk_insert(
        role,
        [
            {"id": role_ids[name], "name": name, "description": None}
            for name in ROLE_DEFINITIONS
        ],
    )

    links = []
    for role_name, perm_names in ROLE_DEFINITIONS.items():
        for perm_name in perm_names:
            links.append(
                {
                    "role_id": role_ids[role_name],
                    "permission_id": perm_ids[perm_name],
                }
            )
    if links:
        op.bulk_insert(rolepermission, links)


def upgrade():
    op.create_table(
        "permission",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column("description", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_permission_name"), "permission", ["name"], unique=True)
    op.create_table(
        "role",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=False),
        sa.Column("description", sqlmodel.sql.sqltypes.AutoString(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_role_name"), "role", ["name"], unique=True)
    op.create_table(
        "rolepermission",
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("permission_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["permission_id"], ["permission.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["role_id"], ["role.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("role_id", "permission_id"),
    )
    op.create_table(
        "userrole",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["role.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
    )

    # Seed roles/permissions/links.
    bind = op.get_bind()
    _seed(bind)

    # Backfill user -> role from the existing is_superuser flag.
    op.execute(
        '''
        INSERT INTO userrole (user_id, role_id)
        SELECT u.id, r.id FROM "user" u CROSS JOIN role r
        WHERE r.name = \'admin\' AND u.is_superuser = true
        '''
    )
    op.execute(
        '''
        INSERT INTO userrole (user_id, role_id)
        SELECT u.id, r.id FROM "user" u CROSS JOIN role r
        WHERE r.name = \'member\' AND u.is_superuser = false
        '''
    )

    # Finally drop the now-redundant stored column.
    op.drop_column("user", "is_superuser")


def downgrade():
    # Re-add the column (server_default makes it safe on a populated table).
    op.add_column(
        "user",
        sa.Column(
            "is_superuser",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    # Backfill True for any user whose role grants the super permission.
    op.execute(
        '''
        UPDATE "user" SET is_superuser = true
        WHERE id IN (
            SELECT ur.user_id
            FROM userrole ur
            JOIN rolepermission rp ON rp.role_id = ur.role_id
            JOIN permission p ON p.id = rp.permission_id
            WHERE p.name = \'super\'
        )
        '''
    )
    # Drop the DB-level default so the column matches the app-managed default.
    op.alter_column("user", "is_superuser", server_default=None)

    op.drop_table("userrole")
    op.drop_table("rolepermission")
    op.drop_index(op.f("ix_role_name"), table_name="role")
    op.drop_table("role")
    op.drop_index(op.f("ix_permission_name"), table_name="permission")
    op.drop_table("permission")
