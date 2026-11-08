"""SCIM 2.0 provisioning storage (area IDAM, REQ-IDAM-007).

SCIM is how an enterprise *provisions* people, and the design note that has been in the tree
since S17 (``docs/scim-ldap-interface.md``) fixes the shape: a directory mirror, not a second
authorisation source. Two additive tables are what that takes:

``provisioned_principals``
    One row per IdP ``sub`` — ``user_name``, ``display_name``, ``emails_json``, the
    ``active`` deprovisioning flag, the ``groups_json`` the IdP last asserted, the IdP's
    ``external_id`` and a ``version`` for optimistic concurrency. There is deliberately no
    ``project`` column: provisioning a person does not bind them to a tenant, so tenancy
    stays an attribute of the key that acts (``docs/scim-ldap-interface.md`` §7).

``provisioned_groups``
    One row per SCIM group: the ``group_id`` the IdP addresses it by, the ``display_name``
    that ``SsoSettings.group_roles`` maps to a role, and ``members_json`` (subject values).
    Deployment-wide, because the role vocabulary is global.

Both tables are new and empty, so the migration is safe by construction: nothing is rewritten
and nothing is backfilled. ``downgrade`` drops them, and the data they hold is a mirror of
something the IdP still has.

reversible: true
Revision ID: 0018
Revises: 0017
Create Date: 2026-11-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "provisioned_principals",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("user_name", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("emails_json", sa.JSON(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("groups_json", sa.JSON(), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    # ``unique=True`` on an indexed column is a *unique index* in SQLAlchemy's model, so the
    # migration has to create one too — a separate UniqueConstraint would show up as drift.
    op.create_index(
        "ix_provisioned_principals_subject",
        "provisioned_principals",
        ["subject"],
        unique=True,
    )
    op.create_index(
        "ix_provisioned_principals_user_name", "provisioned_principals", ["user_name"]
    )
    op.create_index("ix_provisioned_principals_active", "provisioned_principals", ["active"])

    op.create_table(
        "provisioned_groups",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("group_id", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("members_json", sa.JSON(), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_provisioned_groups_group_id", "provisioned_groups", ["group_id"], unique=True
    )
    op.create_index("ix_provisioned_groups_display_name", "provisioned_groups", ["display_name"])


def downgrade() -> None:
    op.drop_index("ix_provisioned_groups_display_name", table_name="provisioned_groups")
    op.drop_index("ix_provisioned_groups_group_id", table_name="provisioned_groups")
    op.drop_table("provisioned_groups")
    op.drop_index("ix_provisioned_principals_active", table_name="provisioned_principals")
    op.drop_index("ix_provisioned_principals_user_name", table_name="provisioned_principals")
    op.drop_index("ix_provisioned_principals_subject", table_name="provisioned_principals")
    op.drop_table("provisioned_principals")
