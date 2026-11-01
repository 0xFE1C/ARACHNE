"""data lifecycle, evidence storage and observability — area DATA/OPS (S20)

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-30

Stage S20 makes storage *governable*: a tenant can say how long its data may live, how much
of it it may keep, and where the large evidence payloads are written. Six columns and one
index, all additive — nothing is rewritten, and a deployment that configures nothing behaves
exactly as it did at S19.

``projects.retention_json``
    The tenant's retention policy (REQ-DATA-001). NULL means "inherit the deployment
    defaults" (``ARACHNE_RETENTION_*``), which is what every existing project means.
``projects.quota_bytes``
    The tenant's storage quota in bytes (REQ-DATA-003). NULL means no quota.
``projects.used_bytes``
    The running total the quota is checked against. NULL reads as 0, the value of rows
    written before S20 — the same convention ``scans.request_json`` uses for pre-S16 rows.
``evidences.size_bytes`` / ``evidences.storage`` / ``evidences.storage_key``
    Where a payload lives and how big it is (REQ-DATA-002/003/004). NULL ``storage`` means
    inline in ``payload_json``, i.e. every row written before S20.
``ix_evidences_created_at``
    The retention job's predicate is age, so the column it filters on is indexed.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("projects") as batch:
        batch.add_column(sa.Column("retention_json", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("quota_bytes", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("used_bytes", sa.BigInteger(), nullable=True))

    with op.batch_alter_table("evidences") as batch:
        batch.add_column(sa.Column("size_bytes", sa.BigInteger(), nullable=True))
        batch.add_column(sa.Column("storage", sa.String(length=16), nullable=True))
        batch.add_column(sa.Column("storage_key", sa.String(length=255), nullable=True))

    op.create_index("ix_evidences_created_at", "evidences", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_evidences_created_at", table_name="evidences")

    with op.batch_alter_table("evidences") as batch:
        batch.drop_column("storage_key")
        batch.drop_column("storage")
        batch.drop_column("size_bytes")

    with op.batch_alter_table("projects") as batch:
        batch.drop_column("used_bytes")
        batch.drop_column("quota_bytes")
        batch.drop_column("retention_json")
