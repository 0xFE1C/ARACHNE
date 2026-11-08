"""The AI provenance record's storage (area AGENT, REQ-AGENT-008).

"The AI found it" is unfalsifiable unless the claim carries its own audit: which provider and
model answered, what prompt template and rendered-prompt hash asked the question, what it cost in
tokens, which evidence the answer cited, and what it changed about the analysis. Before this
package that was spread across four columns of ``analysis_log``, an ``ai`` blob inside
``output_json`` and the audit trail — answerable, but only by joining things and reading logs.

One **nullable** JSON column makes it one row value:

``analysis_log.provenance``
    The record itself: ``origin`` (``ai`` or ``heuristic``), ``provider``, ``model``,
    ``template_version``, ``prompt_template``, ``prompt_hash``, the prompt and completion token
    counts, ``evidence_ids``, ``stages``, the ``change`` the AI half made and the ``fallback``
    marker. A scan emits one per analysis row, whether or not AI ran.

Nullability is the whole migration story: an existing database upgrades in place, every pre-existing
row keeps ``NULL``, and a missing record reads as "not stated" rather than as "heuristic". Nothing
is rewritten and nothing is backfilled — a provenance record backfilled after the fact would be a
statement about a call nobody made at the time.

The column is written from the analysis payload's ``ai.provenance`` block, and this module is the
one place that decides whether a row may call itself AI-authored: a row whose payload claims
``ai`` without a cited evidence id is persisted as heuristic-origin with
``fallback="provenance_invalid"`` and a warning. The invariant is enforced structurally by
:class:`~arachne.ai.provenance.ProvenanceRecord`, so reaching that branch means some other code
wrote the payload — and a scan must not fail over it.

reversible: true
Revision ID: 0017
Revises: 0016
Create Date: 2026-11-04
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # One plain ADD COLUMN: nullable and unconstrained, so SQLite adds it in place (no
    # copy-and-move batch) and every existing row keeps its data and its NULL.
    op.add_column("analysis_log", sa.Column("provenance", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("analysis_log", "provenance")
