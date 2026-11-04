"""a contract-phase migration that cannot be undone — a test fixture

This is NOT a shipped migration: it lives under ``tests/fixtures`` and exists so the
upgrade gate can be shown refusing something. It declares itself non-reversible, which is
what a migration that drops a column and cannot restore its data must declare.

reversible: false
Revision ID: 9001
Revises:
Create Date: 2026-11-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fixture_contract",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_fixture_contract"),
    )


def downgrade() -> None:
    op.drop_table("fixture_contract")
