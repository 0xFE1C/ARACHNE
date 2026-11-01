"""add fp_feedback: operator false-positive feedback for the confidence tuner (F-05-07)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-28

Stage S5 adds the second extension table. docs/spec/04- §2.6's FP tuner "learns per (check,
asset-type, signature) and adjusts rule confidence thresholds", and learning that survives a
restart has to be stored: one row is one operator decision, and the tuner reads the aggregate
over a key rather than any individual row (which is what makes it re-tunable without
rewriting history). ``finding_id`` is nullable and ``SET NULL`` on delete, so deleting a
finding never loses the feedback it produced.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fp_feedback",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("is_fp", sa.Boolean(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("actor", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_fp_feedback_finding_id_findings",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_fp_feedback"),
    )
    op.create_index("ix_fp_feedback_key", "fp_feedback", ["key"])
    op.create_index("ix_fp_feedback_finding_id", "fp_feedback", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_fp_feedback_finding_id", table_name="fp_feedback")
    op.drop_index("ix_fp_feedback_key", table_name="fp_feedback")
    op.drop_table("fp_feedback")
