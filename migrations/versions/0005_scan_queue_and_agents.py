"""scan work queue and agent fleet — area SCALE (S16)

reversible: true
Revision ID: 0005
Revises: 0004
Create Date: 2026-10-30

Stage S16 adds two extension tables and one nullable column:

``scan_queue``
    The work queue of REQ-SCALE-001: one row per admitted scan waiting for an agent,
    claimed with ``SELECT … FOR UPDATE SKIP LOCKED`` on Postgres (the database is the
    broker — no message broker becomes a default dependency). ``scan_id`` is UNIQUE, so
    a scan is enqueued exactly once and no scan can execute on two nodes at once.
``scan_agents``
    The registered fleet (REQ-SCALE-002): one row per ``arachne agent`` with its
    heartbeat, node identity and per-agent concurrency cap.
``scans.request_json``
    The admitted request document (target + options), so any node can rebuild the very
    same :class:`~arachne.core.target.ScanRequest` — the foundation of deterministic
    cross-node execution and lifecycle resume (REQ-SCALE-006, REQ-SCALE-003).

The nullable ``request_json`` column is added with ``batch_alter_table`` because SQLite
cannot ``ALTER TABLE ... ADD COLUMN`` through Alembic's default path.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "scan_agents",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("node", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("concurrency", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_scan_agents"),
        sa.UniqueConstraint("name", name="uq_scan_agents_name"),
    )

    op.create_table(
        "scan_queue",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("project_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("agent_id", sa.Integer(), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=True),
        sa.Column("schedule_id", sa.String(length=64), nullable=True),
        sa.Column("previous_scan_id", sa.Integer(), nullable=True),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_scan_queue_scan_id_scans", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_scan_queue_project_id_projects",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"],
            ["scan_agents.id"],
            name="fk_scan_queue_agent_id_scan_agents",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scan_queue"),
        sa.UniqueConstraint("scan_id", name="uq_scan_queue_scan_id"),
    )
    op.create_index("ix_scan_queue_project_id", "scan_queue", ["project_id"])
    op.create_index("ix_scan_queue_status", "scan_queue", ["status"])
    op.create_index("ix_scan_queue_agent_id", "scan_queue", ["agent_id"])

    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("request_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_column("request_json")

    op.drop_index("ix_scan_queue_agent_id", table_name="scan_queue")
    op.drop_index("ix_scan_queue_status", table_name="scan_queue")
    op.drop_index("ix_scan_queue_project_id", table_name="scan_queue")
    op.drop_table("scan_queue")
    op.drop_table("scan_agents")
