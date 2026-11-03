"""The per-scan residue attestation's storage (WP-14, area PROOF, REQ-PROOF-017).

``INV-7`` restores every state change an L4 proof makes, and the scan machine writes the
restore outcome into the proof journal. What it could not do before this package was hand a
third party an artefact to check: the outcome lived inside ``scans.stats``, unsigned and
unhashed, and "did this scan put everything back?" was answerable only by trusting the
report the scanner itself wrote.

Two **nullable** columns on ``scans`` make the attestation a first-class row value:

``residue_attestation``
    The full artefact: the entries (asset, action, before-value hash, restore outcome,
    timestamp), the verdict, the statement and, when the deployment has an integrity key,
    the signature. A scan that authorized no state change still carries one — with an empty
    entry list and the statement saying exactly that.
``residue_hash``
    The digest of the attestation body. It is what the scan machine links into the audit
    chain (``proof.residue_attested``), so the artefact and the trail cannot disagree, and
    what a later verifier recomputes.

Nullability is the whole migration story: an existing database upgrades in place, every
pre-WP-14 scan keeps ``NULL``, and a missing attestation is read as "not stated" rather than
as "clean" (:func:`arachne.proof.residue.attestation_is_clean`). Nothing is rewritten and
nothing is backfilled — a backfilled attestation would be a signature over a claim nobody
made at the time.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-03
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Two plain ADD COLUMNs: both nullable, neither constrained, so SQLite adds them in
    # place (no copy-and-move batch) and every existing row keeps its data.
    op.add_column("scans", sa.Column("residue_attestation", sa.JSON(), nullable=True))
    op.add_column("scans", sa.Column("residue_hash", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "residue_hash")
    op.drop_column("scans", "residue_attestation")
