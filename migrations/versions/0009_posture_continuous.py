"""continuous exposure management: drift baselines, fix verifications, asset criticality

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-31

Stage S23 (area POSTURE) makes exposure management continuous. Three additive tables:

``posture_baselines``
    The last-seen state of one cloud resource per watched scope (REQ-POSTURE-001). The
    continuous cloud-config check diffs the snapshot it collects against these rows — the
    last baseline — emits delta findings with before/after for what changed, then replaces
    them. Unique on ``(scope_key, resource_key)``.
``posture_verifications``
    One row per fix-verification act (REQ-POSTURE-003): a targeted re-scan of only the
    affected checks either closes the original finding (``verified``), finds it still
    present (``still-open``), or — from a later scan — reopens it (``reopened``). The
    evidence each act writes is linked to the *original* finding.
``asset_criticality``
    CMDB-imported business criticality per host (REQ-POSTURE-006); feeds attack-path
    ranking and labelling, never the finding severities themselves.

Nothing is rewritten and no existing table changes: a deployment that never runs a
continuous schedule, never verifies a fix and never imports a CMDB behaves exactly as it
did at S22.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "posture_baselines",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scope_key", sa.String(length=512), nullable=False),
        sa.Column("resource_key", sa.String(length=512), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("service", sa.String(length=64), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("config_hash", sa.String(length=64), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.UniqueConstraint("scope_key", "resource_key"),
    )
    op.create_index("ix_posture_baselines_scope_key", "posture_baselines", ["scope_key"])
    op.create_index("ix_posture_baselines_resource_key", "posture_baselines", ["resource_key"])

    op.create_table(
        "posture_verifications",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column(
            "evidence_id",
            sa.Integer(),
            sa.ForeignKey("evidences.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_posture_verifications_finding_id", "posture_verifications", ["finding_id"])
    op.create_index("ix_posture_verifications_outcome", "posture_verifications", ["outcome"])

    op.create_table(
        "asset_criticality",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=True),
        sa.Column("source", sa.String(length=255), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("host"),
    )
    op.create_index("ix_asset_criticality_host", "asset_criticality", ["host"])


def downgrade() -> None:
    op.drop_table("asset_criticality")
    op.drop_table("posture_verifications")
    op.drop_table("posture_baselines")
