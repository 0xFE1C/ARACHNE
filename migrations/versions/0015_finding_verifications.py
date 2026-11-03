"""Verification records: one row per verification act, and the finding's current pointer.

WP-13 (area PROOF, REQ-PROOF-015/016). The proof machinery already records *how far* a
check may go and what an L2/L3/L4 act did; this migration makes the record of an act a
durable artefact on the finding rather than a payload a reader has to reconstruct.

Additive in the strict sense the work package asks for:

``findings.verification_id``
    One **nullable** column, indexed, naming the finding's current record. It is a logical
    reference, not a database-level foreign key: the reverse edge below already carries the
    cascade, and a mutual constraint would force SQLite to rebuild ``findings`` for what is
    otherwise a single ``ALTER TABLE ADD COLUMN``. A pre-WP-13 finding simply has ``NULL``,
    which the report reads as ``unverified``.
``finding_verifications``
    A new table holding the record type (level, method, observations, reproducibility token,
    verified-at, check version) plus the re-verification fields (``status``, ``outcome``,
    ``parent_id``). ``parent_id`` is the parent reference REQ-PROOF-016 asks for: a
    re-verification appends a row linked to the record it re-checked, so the history is a
    chain and nothing already written is rewritten.

Nothing about an existing table changes except the one column, so an S28 database upgrades
in place and downgrades cleanly.

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # A plain ADD COLUMN: the column is nullable and carries no constraint, so SQLite adds it
    # in place (no copy-and-move batch) and every existing row keeps its data.
    op.add_column("findings", sa.Column("verification_id", sa.Integer(), nullable=True))
    op.create_index("ix_findings_verification_id", "findings", ["verification_id"])

    op.create_table(
        "finding_verifications",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "parent_id",
            sa.Integer(),
            sa.ForeignKey("finding_verifications.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("level", sa.String(length=4), nullable=False),
        sa.Column("method", sa.String(length=255), nullable=False),
        sa.Column("observations_json", sa.JSON(), nullable=False),
        sa.Column("reproducibility_token", sa.String(length=160), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("check_version", sa.String(length=32), nullable=True),
        sa.Column("outcome", sa.String(length=24), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_finding_verifications_finding_id", "finding_verifications", ["finding_id"])
    op.create_index("ix_finding_verifications_parent_id", "finding_verifications", ["parent_id"])
    op.create_index(
        "ix_finding_verifications_verified_at", "finding_verifications", ["verified_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_finding_verifications_verified_at", table_name="finding_verifications")
    op.drop_index("ix_finding_verifications_parent_id", table_name="finding_verifications")
    op.drop_index("ix_finding_verifications_finding_id", table_name="finding_verifications")
    op.drop_table("finding_verifications")
    op.drop_index("ix_findings_verification_id", table_name="findings")
    op.drop_column("findings", "verification_id")
