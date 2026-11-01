"""initial evidence-store schema

Creates the nine core tables: targets, scans, assets, checks, findings, evidences,
analysis_log, audit_log, scans_diff.

Revision ID: 0001
Revises:
Create Date: 2026-10-28

"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "targets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("scope_json", sa.JSON(), nullable=False),
        sa.Column("auth_attestation", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_targets"),
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("plan_json", sa.JSON(), nullable=False),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("stats_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["target_id"],
            ["targets.id"],
            name="fk_scans_target_id_targets",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans"),
    )
    op.create_index("ix_scans_target_id", "scans", ["target_id"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("value", sa.String(length=2048), nullable=False),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_assets_scan_id_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_assets"),
    )
    op.create_index("ix_assets_scan_id", "assets", ["scan_id"])

    op.create_table(
        "checks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("module", sa.String(length=32), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cwe", sa.String(length=32), nullable=True),
        sa.Column("research_ref", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_checks"),
        sa.UniqueConstraint("module", "name", "version", name="uq_checks_module_name_version"),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("check_id", sa.Integer(), nullable=True),
        sa.Column("asset_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("evidence_refs_json", sa.JSON(), nullable=False),
        sa.Column("remediation_id", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_findings_scan_id_scans", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["check_id"], ["checks.id"], name="fk_findings_check_id_checks", ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name="fk_findings_asset_id_assets", ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_check_id", "findings", ["check_id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])

    op.create_table(
        "evidences",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_evidences_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidences"),
    )
    op.create_index("ix_evidences_finding_id", "evidences", ["finding_id"])

    op.create_table(
        "analysis_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("finding_id", sa.Integer(), nullable=True),
        sa.Column("engine", sa.String(length=32), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=True),
        sa.Column("template_version", sa.String(length=64), nullable=True),
        sa.Column("prompt_hash", sa.String(length=64), nullable=True),
        sa.Column("output_json", sa.JSON(), nullable=False),
        sa.Column("tokens_used", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["finding_id"],
            ["findings.id"],
            name="fk_analysis_log_finding_id_findings",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_analysis_log"),
    )
    op.create_index("ix_analysis_log_finding_id", "analysis_log", ["finding_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=128), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_audit_log"),
    )
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_index("ix_audit_log_action", "audit_log", ["action"])

    op.create_table(
        "scans_diff",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("scan_id_a", sa.Integer(), nullable=False),
        sa.Column("scan_id_b", sa.Integer(), nullable=False),
        sa.Column("changes_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["scan_id_a"], ["scans.id"], name="fk_scans_diff_scan_id_a_scans", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_id_b"], ["scans.id"], name="fk_scans_diff_scan_id_b_scans", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_scans_diff"),
    )
    op.create_index("ix_scans_diff_scan_id_a", "scans_diff", ["scan_id_a"])
    op.create_index("ix_scans_diff_scan_id_b", "scans_diff", ["scan_id_b"])


def downgrade() -> None:
    op.drop_index("ix_scans_diff_scan_id_b", table_name="scans_diff")
    op.drop_index("ix_scans_diff_scan_id_a", table_name="scans_diff")
    op.drop_table("scans_diff")

    op.drop_index("ix_audit_log_action", table_name="audit_log")
    op.drop_index("ix_audit_log_ts", table_name="audit_log")
    op.drop_table("audit_log")

    op.drop_index("ix_analysis_log_finding_id", table_name="analysis_log")
    op.drop_table("analysis_log")

    op.drop_index("ix_evidences_finding_id", table_name="evidences")
    op.drop_table("evidences")

    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_index("ix_findings_check_id", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")

    op.drop_table("checks")

    op.drop_index("ix_assets_scan_id", table_name="assets")
    op.drop_table("assets")

    op.drop_index("ix_scans_target_id", table_name="scans")
    op.drop_table("scans")

    op.drop_table("targets")
