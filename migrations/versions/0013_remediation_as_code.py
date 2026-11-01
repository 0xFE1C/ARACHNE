"""Remediation as code: the fix-proposal table (S27, area FIX).

One table, ``fix_proposals``: the artifact ARACHNE proposed for one finding, who approved
it, what the repository's own test suite and ARACHNE's own IaC self-scan said about it, the
branch it was committed on, and the fix-verification act that closed the loop.

Additive and self-contained, so an S26 database upgrades in place: a fresh table with its
own foreign keys (``findings``/``scans``, both ``ON DELETE SET NULL`` so a retention prune
cannot erase the audit trail), and no change to any existing table.

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-31
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "fix_proposals",
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
        sa.Column("check_key", sa.String(length=128), nullable=True),
        sa.Column("asset_value", sa.String(length=1024), nullable=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("plan_id", sa.String(length=128), nullable=True),
        sa.Column("author", sa.String(length=32), nullable=False),
        sa.Column("parity", sa.String(length=16), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("flagged_reason", sa.Text(), nullable=True),
        sa.Column("targets_json", sa.JSON(), nullable=False),
        sa.Column("diff_text", sa.Text(), nullable=True),
        sa.Column("verbatim", sa.Boolean(), nullable=False),
        sa.Column("manual_apply_required", sa.Boolean(), nullable=False),
        sa.Column("safety_json", sa.JSON(), nullable=False),
        sa.Column("self_scan_json", sa.JSON(), nullable=False),
        sa.Column("repo_name", sa.String(length=128), nullable=True),
        sa.Column("repo_path", sa.String(length=1024), nullable=True),
        sa.Column("branch", sa.String(length=128), nullable=True),
        sa.Column("base_commit", sa.String(length=64), nullable=True),
        sa.Column("commit", sa.String(length=64), nullable=True),
        sa.Column("default_branch", sa.String(length=255), nullable=True),
        sa.Column("pr_artifact", sa.String(length=1024), nullable=True),
        sa.Column("test_command_json", sa.JSON(), nullable=False),
        sa.Column("test_outcome", sa.String(length=24), nullable=True),
        sa.Column("test_output", sa.Text(), nullable=True),
        sa.Column(
            "requested_by", sa.String(length=128), nullable=False
        ),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_by", sa.String(length=128), nullable=True),
        sa.Column("applied_by", sa.String(length=128), nullable=True),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verification_id", sa.Integer(), nullable=True),
        sa.Column("verification_outcome", sa.String(length=24), nullable=True),
        sa.Column("verification_scan_id", sa.Integer(), nullable=True),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_fix_proposals_finding_id", "fix_proposals", ["finding_id"])
    op.create_index("ix_fix_proposals_check_key", "fix_proposals", ["check_key"])
    op.create_index("ix_fix_proposals_status", "fix_proposals", ["status"])


def downgrade() -> None:
    op.drop_index("ix_fix_proposals_status", table_name="fix_proposals")
    op.drop_index("ix_fix_proposals_check_key", table_name="fix_proposals")
    op.drop_index("ix_fix_proposals_finding_id", table_name="fix_proposals")
    op.drop_table("fix_proposals")
