"""resilience & evidence integrity: the chain, the seals, the leases, the packs

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-31

Stage S25 (areas RESIL + TRUST) — the platform ceiling's resilience half. **Expand-only
by construction**: every change below adds a nullable column or a new table, and no
existing column is narrowed, renamed or dropped. That is deliberate, because
REQ-RESIL-002's zero-downtime upgrade path requires the *old* code to keep running against
the *new* schema during a rolling restart: an old replica inserts into ``audit_log``
without the chain columns (they are nullable), and a new replica fills them in. The
matching contract phase — the migration that finally drops the pre-S25 compatibility — is
a future release's job, which is the whole point of expand/contract.

``audit_log``
    Four nullable columns: ``seq`` (position in the hash chain), ``prev_hash`` (the
    previous row's hash), ``hash`` (this row's digest over its own canonical content plus
    position) and ``signature`` (the deployment key's signature over ``hash``). Pre-S25 rows
    keep NULL and a verification starts at the first chained row.
``findings`` / ``evidences``
    ``signature`` — the deployment key's signature over the row's identity (and, for
    evidence, its payload digest). ``evidences.region`` pins a payload to the region it was
    written in (REQ-RESIL-004).
``projects``
    ``pii_json`` (the tenant's PII policy, REQ-TRUST-006) and ``residency_region`` (the
    tenant's evidence residency pin, REQ-RESIL-004).
``integrity_anchors`` / ``integrity_seals``
    The signed chain checkpoints and the per-scan row manifests (REQ-TRUST-005).
``leader_leases``
    The database-backed singleton leases (REQ-RESIL-002).
``content_packs``
    The provenance of each imported offline content pack (REQ-RESIL-001).
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ---------------------------------------------------------------- expand: audit chain
    op.add_column("audit_log", sa.Column("seq", sa.BigInteger(), nullable=True))
    op.add_column("audit_log", sa.Column("prev_hash", sa.String(length=64), nullable=True))
    op.add_column("audit_log", sa.Column("hash", sa.String(length=64), nullable=True))
    op.add_column("audit_log", sa.Column("signature", sa.String(length=128), nullable=True))
    op.create_index("ix_audit_log_seq", "audit_log", ["seq"])
    # A unique *index*, not a table constraint: the column is being added to an existing
    # table and SQLite cannot ALTER a constraint in (it needs a copy-and-move batch), while a
    # unique index is supported everywhere. Multiple NULLs stay legal, so a pre-S25 row never
    # collides; a chained ``seq`` is unique, which is what lets two replicas race and lose
    # safely (SqlAuditChain retries).
    op.create_index("uq_audit_log_seq", "audit_log", ["seq"], unique=True)

    # ------------------------------------------------------- expand: signed rows / region
    op.add_column("findings", sa.Column("signature", sa.String(length=128), nullable=True))
    op.add_column("evidences", sa.Column("signature", sa.String(length=128), nullable=True))
    op.add_column("evidences", sa.Column("region", sa.String(length=32), nullable=True))
    op.create_index("ix_evidences_region", "evidences", ["region"])

    # --------------------------------------------- expand: per-project policy + residency
    op.add_column("projects", sa.Column("pii_json", sa.JSON(), nullable=True))
    op.add_column("projects", sa.Column("residency_region", sa.String(length=32), nullable=True))

    # ------------------------------------------------------------- integrity: anchors
    op.create_table(
        "integrity_anchors",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("hash", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=True),
        sa.Column("reason", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_integrity_anchors_seq", "integrity_anchors", ["seq"])
    op.create_index("ix_integrity_anchors_created_at", "integrity_anchors", ["created_at"])

    # --------------------------------------------------------------- integrity: seals
    op.create_table(
        "integrity_seals",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("manifest_json", sa.JSON(), nullable=False),
        sa.Column("signature", sa.String(length=128), nullable=True),
        sa.Column("reason", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_id", name="uq_integrity_seals_scan_id"),
    )
    op.create_index("ix_integrity_seals_scan_id", "integrity_seals", ["scan_id"])

    # ------------------------------------------------------------------ HA: leader leases
    op.create_table(
        "leader_leases",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("holder", sa.String(length=255), nullable=True),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("token", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", name="uq_leader_leases_name"),
    )
    op.create_index("ix_leader_leases_name", "leader_leases", ["name"])

    # ---------------------------------------------------------------- air-gap: content packs
    op.create_table(
        "content_packs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("digest", sa.String(length=64), nullable=False),
        sa.Column("key_id", sa.String(length=64), nullable=False),
        sa.Column("contents_json", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=1024), nullable=True),
        sa.Column("imported_by", sa.String(length=128), nullable=True),
        sa.Column("meta_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("name", "version", name="uq_content_packs_name_version"),
    )
    op.create_index("ix_content_packs_name", "content_packs", ["name"])


def downgrade() -> None:
    op.drop_index("ix_content_packs_name", table_name="content_packs")
    op.drop_table("content_packs")

    op.drop_index("ix_leader_leases_name", table_name="leader_leases")
    op.drop_table("leader_leases")

    op.drop_index("ix_integrity_seals_scan_id", table_name="integrity_seals")
    op.drop_table("integrity_seals")

    op.drop_index("ix_integrity_anchors_created_at", table_name="integrity_anchors")
    op.drop_index("ix_integrity_anchors_seq", table_name="integrity_anchors")
    op.drop_table("integrity_anchors")

    op.drop_column("projects", "residency_region")
    op.drop_column("projects", "pii_json")

    op.drop_index("ix_evidences_region", table_name="evidences")
    op.drop_column("evidences", "region")
    op.drop_column("evidences", "signature")
    op.drop_column("findings", "signature")

    op.drop_index("uq_audit_log_seq", table_name="audit_log")
    op.drop_index("ix_audit_log_seq", table_name="audit_log")
    op.drop_column("audit_log", "signature")
    op.drop_column("audit_log", "hash")
    op.drop_column("audit_log", "prev_hash")
    op.drop_column("audit_log", "seq")
