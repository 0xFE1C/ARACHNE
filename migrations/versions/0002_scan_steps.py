"""add scan_steps: per-step progress for resumable scans (F-01-04)

reversible: true
Revision ID: 0002
Revises: 0001
Create Date: 2026-10-28

Stage S2 adds one table to the nine of the initial schema. A scan's plan says what will
run; ``scan_steps`` records what *has* run, which is what lets a crashed scan resume from
its last completed step instead of starting over. ``UNIQUE (scan_id, step)`` makes a
progress write an upsert keyed by the step's position in the pipeline.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_steps",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("step", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("stats_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_scan_steps_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scan_steps"),
        sa.UniqueConstraint("scan_id", "step", name="uq_scan_steps_scan_id_step"),
    )
    op.create_index("ix_scan_steps_scan_id", "scan_steps", ["scan_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_steps_scan_id", table_name="scan_steps")
    op.drop_table("scan_steps")
