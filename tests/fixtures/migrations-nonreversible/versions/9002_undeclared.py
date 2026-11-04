"""a migration that declares nothing at all — a test fixture

This is NOT a shipped migration. It exists so the gate can be shown treating an *absent*
declaration as non-reversible: the safe default is to demand an acknowledgement rather than
to assume the best of a downgrade nobody has described.

Revision ID: 9002
Revises: 9001
Create Date: 2026-11-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9002"
down_revision: str | None = "9001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fixture_undeclared",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_fixture_undeclared"),
    )


def downgrade() -> None:
    op.drop_table("fixture_undeclared")
