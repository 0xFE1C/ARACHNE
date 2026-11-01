"""ecosystem & product surface: tenant-scoped quality, per-tenant locale, pack reviews

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-31

Stage S26 (area ECOS) — the ecosystem and product-surface half of the platform ceiling.
**Expand-only by construction**, like S25's 0011 and for the same reason: a rolling upgrade
must let the *old* replica keep serving against the *new* schema. Every change below adds a
nullable column or a new table; nothing is narrowed, renamed or dropped, and the contract
phase is a future release's job.

``projects``
    ``report_locale`` (REQ-ECOS-005) — the language this tenant's reports default to. NULL
    inherits the deployment's ``ARACHNE_REPORT_LOCALE``, so a deployment that sets nothing
    renders exactly as it did before S26.
``suppressions`` / ``risk_acceptances``
    ``project_id`` (REQ-ECOS-004) — the tenant that owns a rule/acceptance, so the tenant
    self-service workflow can scope "my tenant's false positives". NULL is a deployment-wide
    row: every row written before S26 keeps NULL and therefore stays visible to every tenant,
    which is what makes the migration change no existing behaviour.
``pack_reviews``
    The marketplace review pipeline's provenance (REQ-ECOS-001): one row per reviewed pack —
    its identity, digest, signing key, decision and the full gate report — so a pack is listed
    only once a review for its exact digest says so.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --------------------------------------------------- expand: per-tenant report locale
    op.add_column("projects", sa.Column("report_locale", sa.String(length=16), nullable=True))

    # ---------------------------------------- expand: tenant-scoped quality workflow rows
    # An indexed column, **not** a foreign-key constraint. SQLite cannot ALTER a constraint
    # into an existing table (it needs a copy-and-move batch), and the shipped migrations run
    # on SQLite, so a database-level FK here would make ``alembic upgrade`` fail on the
    # default dialect. The semantics ``ON DELETE SET NULL`` would give are provided by
    # ``ProjectStore.delete``, which nulls these columns in the same transaction — pinning
    # that in the store keeps the behaviour testable, which a dialect-dependent constraint
    # would not be (the same reasoning 0011 records for the audit ``seq`` index).
    op.add_column("suppressions", sa.Column("project_id", sa.Integer(), nullable=True))
    op.create_index("ix_suppressions_project_id", "suppressions", ["project_id"])
    op.add_column("risk_acceptances", sa.Column("project_id", sa.Integer(), nullable=True))
    op.create_index("ix_risk_acceptances_project_id", "risk_acceptances", ["project_id"])

    # ------------------------------------------------- expand: the pack review provenance
    op.create_table(
        "pack_reviews",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("decision", sa.String(length=16), nullable=False),
        sa.Column("gates_json", sa.JSON(), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=True),
        sa.Column("reviewed_by", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "name", "version", "digest", name="uq_pack_reviews_name_version_digest"
        ),
    )
    op.create_index("ix_pack_reviews_name", "pack_reviews", ["name"])
    op.create_index("ix_pack_reviews_digest", "pack_reviews", ["digest"])
    op.create_index("ix_pack_reviews_decision", "pack_reviews", ["decision"])


def downgrade() -> None:
    op.drop_index("ix_pack_reviews_decision", table_name="pack_reviews")
    op.drop_index("ix_pack_reviews_digest", table_name="pack_reviews")
    op.drop_index("ix_pack_reviews_name", table_name="pack_reviews")
    op.drop_table("pack_reviews")

    op.drop_index("ix_risk_acceptances_project_id", table_name="risk_acceptances")
    op.drop_column("risk_acceptances", "project_id")

    op.drop_index("ix_suppressions_project_id", table_name="suppressions")
    op.drop_column("suppressions", "project_id")

    op.drop_column("projects", "report_locale")
