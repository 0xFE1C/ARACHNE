"""detection validation (purple team): campaigns, runs and defender alerts

reversible: true
Revision ID: 0010
Revises: 0009
Create Date: 2026-10-31

Stage S24 (area VALID) validates whether the defender's controls *see* the attacks
ARACHNE can prove are possible. Three additive tables:

``purple_campaigns``
    A named, replayable set of proof actions (the ATT&CK-tagged tests) with its target and
    schedule (REQ-VALID-001/006). The campaign is the identity the coverage *trend* is
    reported over, so it is a row rather than a command-line argument.
``purple_runs``
    One executed run: the run nonce every emitted artifact carried, the coordinated window
    it ran inside, the emissions and the Sigma rule-hit/rule-miss alignment, and — once
    scored — the control-coverage report (REQ-VALID-002/004). Coverage is rewritable
    because a defender's SIEM may report after the window closes.
``purple_alerts``
    The normalized defender alerts ingested from the SIEM (webhook, pull or export) and
    matched to a run by nonce plus window (REQ-VALID-002). ``nonce`` is nullable: an alert
    without one is kept and reported as unlinked, never discarded.

Nothing is rewritten and no existing table changes: a deployment that never configures
purple-team mode behaves exactly as it did at S23.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "purple_campaigns",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("spec_json", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_purple_campaigns_name", "purple_campaigns", ["name"])

    op.create_table(
        "purple_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "campaign_id",
            sa.Integer(),
            sa.ForeignKey("purple_campaigns.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("window_json", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("emissions_json", sa.JSON(), nullable=False),
        sa.Column("sigma_json", sa.JSON(), nullable=False),
        sa.Column("coverage_json", sa.JSON(), nullable=True),
        sa.Column("gaps_json", sa.JSON(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index("ix_purple_runs_campaign_id", "purple_runs", ["campaign_id"])
    op.create_index("ix_purple_runs_scan_id", "purple_runs", ["scan_id"])
    op.create_index("ix_purple_runs_nonce", "purple_runs", ["nonce"])

    op.create_table(
        "purple_alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("alert_id", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("technique", sa.String(length=32), nullable=True),
        sa.Column("tactic", sa.String(length=64), nullable=True),
        sa.Column("nonce", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column("raw_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_purple_alerts_alert_id", "purple_alerts", ["alert_id"])
    op.create_index("ix_purple_alerts_observed_at", "purple_alerts", ["observed_at"])
    op.create_index("ix_purple_alerts_technique", "purple_alerts", ["technique"])
    op.create_index("ix_purple_alerts_nonce", "purple_alerts", ["nonce"])


def downgrade() -> None:
    op.drop_index("ix_purple_alerts_nonce", table_name="purple_alerts")
    op.drop_index("ix_purple_alerts_technique", table_name="purple_alerts")
    op.drop_index("ix_purple_alerts_observed_at", table_name="purple_alerts")
    op.drop_index("ix_purple_alerts_alert_id", table_name="purple_alerts")
    op.drop_table("purple_alerts")

    op.drop_index("ix_purple_runs_nonce", table_name="purple_runs")
    op.drop_index("ix_purple_runs_scan_id", table_name="purple_runs")
    op.drop_index("ix_purple_runs_campaign_id", table_name="purple_runs")
    op.drop_table("purple_runs")

    op.drop_index("ix_purple_campaigns_name", table_name="purple_campaigns")
    op.drop_table("purple_campaigns")
