"""the quality workflow: suppression rules and risk acceptances — area QUAL (S21)

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-30

Stage S21 makes quality a *workflow*. Two new tables, both additive, carry the decisions an
operator makes about findings the scanner keeps reporting:

``suppressions``
    A versioned, attributed, commented rule that silences a finding, a check or a check on a
    set of assets (REQ-QUAL-002). ``active`` is a flag rather than a delete so a report
    rendered before a revocation still reads correctly, and ``version`` comes from one
    monotonic sequence so a report can cite "suppressions vN".
``risk_acceptances``
    A real finding, owned and justified, accepted until a date (REQ-QUAL-003).
    ``owner``/``justification``/``expires_at`` are NOT NULL, and ``reopened_at`` records the
    automatic re-open an expired acceptance causes.

Nothing is rewritten and no existing table changes: a deployment that never records a
suppression or an acceptance behaves exactly as it did at S20.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "suppressions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("check_id", sa.String(length=128), nullable=True),
        sa.Column("asset_pattern", sa.String(length=512), nullable=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_suppressions_version", "suppressions", ["version"])
    op.create_index("ix_suppressions_check_id", "suppressions", ["check_id"])
    op.create_index("ix_suppressions_finding_id", "suppressions", ["finding_id"])

    op.create_table(
        "risk_acceptances",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "finding_id",
            sa.Integer(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("check_id", sa.String(length=128), nullable=True),
        sa.Column("asset_pattern", sa.String(length=512), nullable=True),
        sa.Column("owner", sa.String(length=128), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("accepted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reopened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("actor", sa.String(length=128), nullable=False),
    )
    op.create_index("ix_risk_acceptances_finding_id", "risk_acceptances", ["finding_id"])
    op.create_index("ix_risk_acceptances_check_id", "risk_acceptances", ["check_id"])
    op.create_index("ix_risk_acceptances_expires_at", "risk_acceptances", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_risk_acceptances_expires_at", table_name="risk_acceptances")
    op.drop_index("ix_risk_acceptances_check_id", table_name="risk_acceptances")
    op.drop_index("ix_risk_acceptances_finding_id", table_name="risk_acceptances")
    op.drop_table("risk_acceptances")
    op.drop_index("ix_suppressions_finding_id", table_name="suppressions")
    op.drop_index("ix_suppressions_check_id", table_name="suppressions")
    op.drop_index("ix_suppressions_version", table_name="suppressions")
    op.drop_table("suppressions")
