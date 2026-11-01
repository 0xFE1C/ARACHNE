"""add projects (multi-tenancy) and feeds (CVE/EPSS ingestion) — F-07-06, F-09-03

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-29

Stage S14 adds three extension tables and two nullable columns:

``projects``
    The tenant/workspace row of F-07-06: a slug, a display name, the addresses its
    operator may scan (``scope_json``) and optional report branding. ``targets.project_id``
    and ``scans.project_id`` point at it; both are nullable so every pre-S14 row reads as
    the implicit "default" workspace, and deleting a project detaches rather than deletes
    the scans it owned (``SET NULL`` — evidence is never silently destroyed).
``feeds`` / ``feed_entries``
    The offline-friendly CVE/EPSS ingestion of F-09-03: the artefact's provenance plus the
    normalised rows, so an operator can list, inspect and query what they imported.

The two foreign keys are added with ``batch_alter_table`` because SQLite cannot ``ALTER
TABLE ... ADD CONSTRAINT``; batch mode recreates the table on SQLite and emits a plain
``ALTER TABLE`` on Postgres.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scope_json", sa.JSON(), nullable=False),
        sa.Column("branding_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
        sa.UniqueConstraint("slug", name="uq_projects_slug"),
    )

    op.create_table(
        "feeds",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("source", sa.String(length=1024), nullable=True),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("imported_by", sa.String(length=128), nullable=True),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_feeds"),
    )
    op.create_index("ix_feeds_kind", "feeds", ["kind"])

    op.create_table(
        "feed_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("feed_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("data_json", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ["feed_id"],
            ["feeds.id"],
            name="fk_feed_entries_feed_id_feeds",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_feed_entries"),
        sa.UniqueConstraint("feed_id", "key", name="uq_feed_entries_feed_id_key"),
    )
    op.create_index("ix_feed_entries_feed_id", "feed_entries", ["feed_id"])
    op.create_index("ix_feed_entries_key", "feed_entries", ["key"])

    with op.batch_alter_table("targets") as batch:
        batch.add_column(sa.Column("project_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_targets_project_id_projects", "projects", ["project_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_targets_project_id", ["project_id"])

    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("project_id", sa.Integer(), nullable=True))
        batch.create_foreign_key(
            "fk_scans_project_id_projects", "projects", ["project_id"], ["id"], ondelete="SET NULL"
        )
        batch.create_index("ix_scans_project_id", ["project_id"])


def downgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.drop_index("ix_scans_project_id")
        batch.drop_constraint("fk_scans_project_id_projects", type_="foreignkey")
        batch.drop_column("project_id")

    with op.batch_alter_table("targets") as batch:
        batch.drop_index("ix_targets_project_id")
        batch.drop_constraint("fk_targets_project_id_projects", type_="foreignkey")
        batch.drop_column("project_id")

    op.drop_index("ix_feed_entries_key", table_name="feed_entries")
    op.drop_index("ix_feed_entries_feed_id", table_name="feed_entries")
    op.drop_table("feed_entries")
    op.drop_index("ix_feeds_kind", table_name="feeds")
    op.drop_table("feeds")
    op.drop_table("projects")