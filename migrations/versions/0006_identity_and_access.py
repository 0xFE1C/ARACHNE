"""enterprise identity & access — area IDAM (S17)

reversible: true
Revision ID: 0006
Revises: 0005
Create Date: 2026-10-30

Stage S17 adds three tables to the extension set, all of them interface-layer identity
state (never scanned content):

``service_accounts``
    API keys as first-class service accounts (REQ-IDAM-003): the SHA-256 digest of the
    secret (storage unchanged — hashed, verified with ``hmac.compare_digest``), an
    optional expiry, last-used tracking, and the rotation lineage (a rotated key is
    revoked, never deleted, so the rotation is visible).
``sso_flows``
    Pending OIDC authorization-code flows (REQ-IDAM-001). The ``state`` is the primary
    key and single-use nonce; the PKCE verifier and OIDC nonce live server-side, off the
    client, and a login can complete on any node of a distributed deployment.
``auth_sessions``
    Minted browser sessions after an OIDC login: only the token's SHA-256 hash is stored,
    and the row carries the per-user principal (subject/email/name/role/groups) that the
    audit trail attributes actions to.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "service_accounts",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("project", sa.String(length=64), nullable=True),
        sa.Column("owner", sa.String(length=255), nullable=True),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rotated_from", sa.String(length=128), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_service_accounts"),
        sa.UniqueConstraint("label", name="uq_service_accounts_label"),
    )

    op.create_table(
        "sso_flows",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("state", sa.String(length=128), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column("code_verifier", sa.String(length=128), nullable=False),
        sa.Column("redirect_uri", sa.String(length=1024), nullable=False),
        sa.Column("next_path", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_sso_flows"),
    )
    op.create_index("ix_sso_flows_state", "sso_flows", ["state"], unique=True)

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("project", sa.String(length=64), nullable=True),
        sa.Column("groups_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_auth_sessions"),
    )
    op.create_index("ix_auth_sessions_token_hash", "auth_sessions", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_auth_sessions_token_hash", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_sso_flows_state", table_name="sso_flows")
    op.drop_table("sso_flows")
    op.drop_table("service_accounts")
