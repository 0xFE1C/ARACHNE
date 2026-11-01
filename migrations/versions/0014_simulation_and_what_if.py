"""Simulation & what-if modeling: the re-simulation trend table (S28, area SIM).

One table, ``simulation_points``: one row per event-driven re-simulation of the estate
model, carrying what the composer saw at that moment (path count, how many of those paths
exist only under the injected hypotheses, the exposure score and the severity mix) and, in
``provenance``, the fact that the numbers are **simulated**.

The table exists so the posture view can plot the outlook next to the exposure
(REQ-SIM-006), and it is deliberately separate from every findings table: a simulation point
is an observation of a computation, so nothing that reads findings — a report, a gate
verdict, a diff — can reach it (REQ-SIM-004).

Additive and self-contained, so an S27 database upgrades in place: a fresh table whose only
foreign key (``scans.id``) is ``ON DELETE SET NULL`` so a retention prune cannot erase the
trend, and no change to any existing table.

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-31
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "simulation_points",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("estate_key", sa.String(length=255), nullable=False),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("provenance", sa.String(length=32), nullable=False),
        sa.Column("hypotheses", sa.Integer(), nullable=False),
        sa.Column("path_count", sa.Integer(), nullable=False),
        sa.Column("introduced", sa.Integer(), nullable=False),
        sa.Column("exposure_score", sa.Integer(), nullable=False),
        sa.Column("severity_counts_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_simulation_points_estate_key", "simulation_points", ["estate_key"])
    op.create_index("ix_simulation_points_created_at", "simulation_points", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_simulation_points_created_at", table_name="simulation_points")
    op.drop_index("ix_simulation_points_estate_key", table_name="simulation_points")
    op.drop_table("simulation_points")
