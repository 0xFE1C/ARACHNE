"""Reference-counted, tenant-scoped evidence blobs (area DATA, REQ-DATA-006).

S20 made the evidence backend content-addressed, which deduplicated identical payloads — and
introduced two defects the requirement names. First, the dedup was *global*: two tenants that
captured the same bytes shared one object, so the store could answer "does another tenant hold
this exact byte string?" through an existence check, which is a data leak. Second, deletion was
unconditional: the retention job unlinked every key its plan had selected, even when another
finding still referenced the object, which corrupted the surviving finding's evidence.

One additive table fixes both, because both need the same missing fact — *who references this
object*:

``evidence_blobs``
    One row per ``(tenant, key)``: the backend namespace (``default`` for the implicit
    workspace, ``p<id>`` for a named project), the object's content digest, the number of
    evidence rows addressing it, and its logical and physical sizes. The tenant is the first
    path segment of the object's address too, so identical bytes in two tenants are two
    objects rather than one shared object with two names on it. ``refcount`` reaching zero is
    the only authority to unlink a blob.

The table starts empty. Existing offloaded objects keep working: the local backend still reads
an object at its pre-existing path for the default workspace, and an evidence row that no ledger
row describes simply never becomes a sweep candidate — an orphan is the safe failure, a wrong
unlink is not. An operator who wants the ledger to cover historic rows can let retention age
them out and re-ingest; nothing here rewrites or guesses a count.

reversible: true
Revision ID: 0019
Revises: 0018
Create Date: 2026-11-05
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_blobs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant", sa.String(length=64), nullable=False),
        sa.Column("key", sa.String(length=64), nullable=False),
        sa.Column("refcount", sa.Integer(), nullable=False),
        sa.Column("logical_bytes", sa.BigInteger(), nullable=False),
        sa.Column("physical_bytes", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant", "key", name="uq_evidence_blobs_tenant_key"),
    )
    op.create_index("ix_evidence_blobs_tenant", "evidence_blobs", ["tenant"])


def downgrade() -> None:
    op.drop_index("ix_evidence_blobs_tenant", table_name="evidence_blobs")
    op.drop_table("evidence_blobs")
