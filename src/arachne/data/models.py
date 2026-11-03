"""SQLAlchemy models for the evidence store (```` §2.4, F-09-02).

Nine tables, one per row of the spec's data-model table. Design rules from ADR-03:

* SQLite is the default backend and Postgres must work unchanged, so every column uses a
  portable SQLAlchemy type (``Integer``, ``String``, ``Float``, ``JSON``, ``DateTime``)
  and no engine-specific SQL appears here.
* Timestamps are timezone-aware UTC values written by Python, not by a database
  function, so behaviour is identical on both backends.
* The schema is created by Alembic, never by ``create_all`` in production paths;
  ``create_all`` exists only for tests (:mod:`arachne.data.db`).
* ``*_json`` columns hold the serialized forms of the pydantic/dataclass DTOs defined in
  the core and module layers. The store deliberately stays schema-agnostic about them so
  a DTO can gain fields without a migration; the *keys* listed in the spec stay stable.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__all__ = [
    "AnalysisLog",
    "Asset",
    "AssetCriticality",
    "AuditLog",
    "AuthSession",
    "Base",
    "Check",
    "ContentPack",
    "Evidence",
    "Feed",
    "FeedEntry",
    "Finding",
    "FixProposal",
    "FpFeedback",
    "IntegrityAnchor",
    "IntegritySeal",
    "LeaderLease",
    "PostureBaseline",
    "PostureVerification",
    "Project",
    "PurpleAlert",
    "PurpleCampaign",
    "PurpleRun",
    "Scan",
    "ScanAgent",
    "ScanDiff",
    "ScanQueue",
    "ScanStepRecord",
    "ServiceAccount",
    "SimulationPointRecord",
    "SsoFlow",
    "Target",
]

#: Deterministic constraint names keep Alembic diffs stable across backends.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    """Timezone-aware UTC now; the single clock used by every default."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Declarative base with the shared naming convention."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class TimestampMixin:
    """Adds a creation timestamp (UTC)."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class Target(Base, TimestampMixin):
    """A declared, authorized scanning target (F-01-01, F-08-05).

    ``scope_json`` holds the scope definition (hosts, domains, exclusions);
    ``auth_attestation`` records who attested authorization, to what scope, and when —
    it is copied into reports and the audit log (F-08-05).

    ``project_id`` is the tenant the target belongs to (F-07-06). ``NULL`` is the implicit
    default workspace, which is what every row written before S14 is; a deployment that
    never creates a project therefore behaves exactly as it did before multi-tenancy.
    """

    __tablename__ = "targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    auth_attestation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class Scan(Base):
    """One scan run of a target (F-01-03, F-01-04).

    ``project_id`` mirrors the target's tenant so report lists and dashboards can be
    filtered without joining through ``targets`` (F-07-06).
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target_id: Mapped[int] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(32), default="pending", nullable=False)
    plan_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    engine: Mapped[str] = mapped_column(String(32), default="heuristic", nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    stats_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    #: The admitted request document (S16, area SCALE): target + options exactly as the
    #: producer admitted them. Any node can rebuild the very same
    #: :class:`~arachne.core.target.ScanRequest` from it, so an agent executes (or
    #: resumes) a scan without the original fixture file — the foundation of
    #: deterministic cross-node execution (REQ-SCALE-006). Nullable: rows written
    #: before S16 have none, and the executing node then rebuilds the definition from
    #: the stored target row.
    request_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    #: The scan's residue attestation (WP-14, REQ-PROOF-017): one signed (or explicitly
    #: unsigned) artefact enumerating every state change the scan authorized — asset,
    #: action, before-value hash, restore outcome, timestamp — with the verdict ("zero
    #: residue", or the list of what was not restored). ``residue_hash`` is the digest the
    #: audit chain links, and ``residue_attestation["clean"]`` is false whenever the count
    #: is non-zero. Nullable: rows written before WP-14 have none, and a missing
    #: attestation is deliberately *not* read as "clean".
    residue_attestation: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    residue_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Asset(Base):
    """A discovered asset: host, domain, URL or cloud resource (F-02-02..07)."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class Check(Base):
    """The check catalogue: one row per implemented check (F-02-10, F-09-01).

    ``research_ref`` carries the traceability link to the research corpus
    (e.g. ``ch04#1``), and ``version`` feeds "version everything" .
    """

    __tablename__ = "checks"
    __table_args__ = (UniqueConstraint("module", "name", "version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    module: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(32), nullable=True)
    research_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Finding(Base, TimestampMixin):
    """A candidate/confirmed finding (F-06-01).

    ``severity``/``confidence``/``remediation_id`` are written by the analyzer, not by
    the module (ADR-02); ``status`` is one of ``open``/``verified``/``fp``.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    check_id: Mapped[int | None] = mapped_column(
        ForeignKey("checks.id", ondelete="SET NULL"), nullable=True, index=True
    )
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="open", nullable=False)
    evidence_refs_json: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    remediation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: The deployment key's signature over this finding's immutable identity (S25,
    #: REQ-TRUST-005). ``NULL`` when the deployment has no integrity key. The fields that
    #: legitimately mutate afterwards (severity/confidence/status) are covered by the
    #: scan's seal instead, not by this signature.
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: The finding's *current* verification record (WP-13, REQ-PROOF-015): the row in
    #: ``finding_verifications`` the report renders. ``NULL`` means the finding carries no
    #: record — a pre-WP-13 row, or a write path that bypassed the store — and the report
    #: then forces its severity to ``info`` and marks it ``unverified``. A logical
    #: reference rather than a database-level foreign key: the reverse edge
    #: (``finding_verifications.finding_id``) already carries the cascade, and a mutual
    #: constraint would make SQLite rebuild ``findings`` for an otherwise additive column.
    verification_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)


class FindingVerification(Base, TimestampMixin):
    """One verification record: how a finding was established (WP-13, REQ-PROOF-015/016).

    The proof ladder lives in ``core/proof.py``/``proof/``; this table is the durable
    *record* of an act. The finding's current record is named by
    ``findings.verification_id``; every re-verification appends a row whose ``parent_id``
    names the record it re-checked, so the history is a chain and the earlier records stay
    exactly as they were.

    ``status`` is ``verified`` (the check's own evidence established the claim) or
    ``unverified`` (a re-verification that no longer reproduces it). ``outcome`` is set only
    on a re-verification — ``still-verified`` / ``no-longer-verified`` / ``inconclusive`` —
    and is ``NULL`` for the original record. ``refused`` is never a row: a refusal means
    nothing was re-checked, so there is nothing to record.
    """

    __tablename__ = "finding_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: The record this one re-checked (``NULL`` for the original). ``SET NULL`` keeps the
    #: child row if its parent is ever pruned, so the history never dangles into a missing id.
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("finding_verifications.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: The scan that produced the record (the original scan, or the verification re-scan).
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    #: ``verified`` | ``unverified`` (see the class docstring).
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="verified")
    #: ``L0``..``L4`` — the rung the claim was established at (never above the parent's).
    level: Mapped[str] = mapped_column(String(4), nullable=False)
    #: The verification method, in operator-readable form.
    method: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    #: The observations that established (or refuted) it: the spec's
    #: ``{request, status, length}`` rows, bounded by ``data.verification.MAX_OBSERVATIONS``.
    observations_json: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    #: The handle a re-run reproduces: the ladder's single-use token when the proof had one,
    #: otherwise a content digest over the observation set.
    reproducibility_token: Mapped[str | None] = mapped_column(String(160), nullable=True)
    verified_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    #: The check's version at the time of the verification, so "the check changed" is
    #: answerable without consulting the ``checks`` table's present state.
    check_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: Set only by a re-verification: ``still-verified`` | ``no-longer-verified`` |
    #: ``inconclusive``.
    outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)


class Evidence(Base):
    """Reproducible evidence attached to a finding (F-02-08, F-08-04).

    ``payload_json`` is always the **redacted** capture; ``sha256`` is the integrity
    reference for it.

    S20 (area DATA) adds where the payload physically lives. A payload small enough to sit
    inline stays exactly as it always was (``storage`` NULL, ``payload_json`` the payload) —
    that is what keeps the default deployment unchanged. A larger one is written to the
    configured evidence backend (REQ-DATA-002) and ``payload_json`` becomes a *reference*
    (``{"offloaded": true, "key": ..., "sha256": ..., "size": ...}``), with ``size_bytes``
    (the logical, uncompressed size) and ``storage_key`` mirrored into columns so quota
    accounting (REQ-DATA-003), retention pruning and blob deletion never have to parse JSON.
    ``created_at`` is indexed because it is the retention job's predicate (REQ-DATA-001).
    """

    __tablename__ = "evidences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Logical size of the payload in bytes; NULL for rows written before S20.
    size_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: ``None``/``inline`` (payload in ``payload_json``), ``local`` or ``s3``.
    storage: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: The backend's key for an offloaded payload (content hash); NULL when inline.
    storage_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: The deployment key's signature over this row's identity and payload digest (S25,
    #: REQ-TRUST-005). ``NULL`` when the deployment has no integrity key.
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: The region the payload is pinned to (S25, REQ-RESIL-004). ``NULL`` means "the
    #: deployment's own region at write time, or no residency enforcement"; a deployment
    #: serving another region refuses to read a row stamped with a different one.
    region: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class AnalysisLog(Base):
    """Provenance of one analysis step (F-03-05, F-04-07).

    Records which engine produced the analysis, which model/template version was used,
    the prompt hash (never the prompt body, which can embed target secrets), the output,
    and the token spend.
    """

    __tablename__ = "analysis_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    engine: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    template_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prompt_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class AuditLog(Base):
    """Audit trail of actions and blocked requests (F-01-08).

    Mirrors :class:`arachne.core.audit.AuditEvent`; ``meta_json`` holds the detail.

    S25 (REQ-TRUST-005) makes the trail **tamper-evident**: ``seq`` is the event's position
    in the hash chain, ``prev_hash`` the hash of the event before it and ``hash`` the
    digest of the event's own canonical content plus that position. ``signature`` is the
    deployment key's signature over ``hash``. The four are nullable so pre-S25 rows keep
    their place; :func:`arachne.core.integrity.verify_audit_chain` starts at the first row
    that carries a ``seq`` and reports a gap or a dangling link as a deletion.
    """

    __tablename__ = "audit_log"
    # A *unique index* rather than a table constraint: the column is added to an existing
    # table, and SQLite cannot ALTER a constraint in (it needs a copy-and-move batch), while
    # it creates a unique index happily. Both backends then enforce the property that makes
    # a concurrent chain append safe — two writers cannot claim one ``seq``. Multiple NULLs
    # are allowed, so a pre-S25 row never collides.
    __table_args__ = (Index("uq_audit_log_seq", "seq", unique=True),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    #: Position in the hash chain (S25). ``NULL`` for rows written before S25.
    seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: ``v1:<key id>:<hex>`` — the deployment key's signature over :attr:`hash`.
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True)


class ScanDiff(Base):
    """Change detection between two scans of the same target (F-06-05)."""

    __tablename__ = "scans_diff"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id_a: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id_b: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    changes_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class ScanStepRecord(Base):
    """Per-step progress of a scan, which is what makes a scan resumable (F-01-04).

    Stage S2 adds this table to the nine of the initial schema (ADR-060.2). A step row is
    written *before* the step runs and updated when it finishes, so a hard kill leaves a
    durable record of where the scan stopped; ``UNIQUE (scan_id, step)`` makes the write an
    upsert keyed by position in the pipeline.
    """

    __tablename__ = "scan_steps"
    __table_args__ = (UniqueConstraint("scan_id", "step"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    step: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stats_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class Suppression(Base):
    """An operator decision to silence a finding, a rule or a rule-on-a-pattern (S21).

    Versioned (one monotonic sequence shared by every rule, REQ-QUAL-002 *versioned*),
    attributed (``actor``) and commented (``reason`` is NOT NULL): a suppression without a
    reason is indistinguishable from hiding a finding, so the column is required rather than
    merely validated at the API edge. ``active`` is a flag rather than a delete so a report
    rendered before the revocation still reads correctly.
    """

    __tablename__ = "suppressions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: The global rule version this row belongs to (``max(version)`` is "suppressions vN").
    version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    #: ``finding`` | ``rule`` | ``pattern``.
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    check_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    asset_pattern: Mapped[str | None] = mapped_column(String(512), nullable=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: The tenant this rule belongs to (S26, REQ-ECOS-004). ``NULL`` is a deployment-wide
    #: rule — every row written before S26, which stays visible to every tenant, so the
    #: migration changes no existing behaviour. The tenant self-service UI writes its own
    #: rows scoped, which is what makes "my tenant's false positives" a question the store
    #: can answer.
    #:
    #: Deliberately an indexed ``Integer`` and **not** a ``ForeignKey``: SQLite cannot ALTER a
    #: constraint into an existing table (see migration 0012), so a database-level FK here
    #: would make ``alembic upgrade`` fail on the shipped dialect. ``ProjectStore.delete``
    #: nulls the column explicitly instead, which is the behaviour ``ON DELETE SET NULL``
    #: would have given — the same trade-off 0011 records for the audit ``seq`` index.
    project_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)


class RiskAcceptance(Base):
    """A real finding an owner has accepted until a date (S21, REQ-QUAL-003).

    Distinct from :class:`Suppression` on purpose: this row says "the finding is real".
    ``owner``/``justification``/``expires_at`` are all NOT NULL, because an acceptance without
    an owner, a reason or an end is not a decision an organisation can defend. ``reopened_at``
    records the automatic re-open, so the history reads "accepted, then expired, then re-opened"
    rather than the finding silently changing status.
    """

    __tablename__ = "risk_acceptances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True, index=True
    )
    check_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    asset_pattern: Mapped[str | None] = mapped_column(String(512), nullable=True)
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    #: The tenant that owns the acceptance (S26, REQ-ECOS-004). ``NULL`` is deployment-wide
    #: (see :attr:`Suppression.project_id`): an acceptance is a risk *decision*, and a
    #: tenant-scoped one is the difference between "acme accepted this risk" and "somebody
    #: in the estate accepted this risk". An indexed ``Integer``, not a ``ForeignKey`` — the
    #: same SQLite constraint as :attr:`Suppression.project_id`.
    project_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)


class FpFeedback(Base):
    """Operator false-positive feedback, the FP tuner's input (F-05-07).

    Stage S5 adds this table to the spec's core set: F-05-07's tuner "learns per (check,
    asset-type, signature)", and learning that survives a restart has to be persisted. One
    row is one operator decision; the tuner reads the aggregate, never the individual row, so
    a decision can be re-taken later without rewriting history.
    """

    __tablename__ = "fp_feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: ``check/name@version|asset-kind|signature`` — the key the tuner aggregates on.
    key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    is_fp: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class Project(Base, TimestampMixin):
    """A tenant / workspace: its own scope, its own targets, scans and reports (F-07-06).

    The MSSP use case is "one deployment, several customers": each project declares the
    addresses its operator may scan (``scope_json``, same shape ``ARACHNE_SCOPE_*`` uses) and
    may carry its own report branding (``branding_json``), so a report never leaks another
    customer's name. A scan is refused when a target falls outside the project's scope, even
    if the deployment allowlist is wider.

    ``slug`` is the stable, URL-safe tenant identifier (``acme``); ``name`` is the display
    name. The row with slug ``default`` is created on demand and owns everything that existed
    before S14 (``project_id IS NULL`` reads as that project).
    """

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    slug: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Scope dimensions (hosts/domains/networks/url prefixes/refs + exclusions).
    scope_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    #: White-label settings for this tenant's reports (S14 branding).
    branding_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    #: This tenant's retention policy (S20, REQ-DATA-001). ``NULL`` (or an empty object)
    #: means "inherit the deployment defaults" — which is what every project did before S20.
    #: Keys are the four categories (``findings_days``, ``evidence_days``, ``scans_days``,
    #: ``audit_days``); ``0`` in a category means keep that category forever, which is how a
    #: statutory holding period is expressed without disabling retention everywhere.
    retention_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    #: Storage quota in bytes (S20, REQ-DATA-003); ``NULL`` means no quota.
    quota_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: Running total of this project's stored evidence bytes. ``NULL`` reads as 0 — the
    #: value of rows written before S20, which the migration leaves alone (the same
    #: convention ``scans.request_json`` uses for pre-S16 rows). Always written by the
    #: finding store, so it is never NULL for a project that has recorded evidence since.
    used_bytes: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    #: This tenant's PII policy (S25, REQ-TRUST-006): which categories to detect, what to
    #: do with them (mask/hash/drop) and the retention hook's window. ``NULL`` inherits the
    #: deployment's ``ARACHNE_PII_*`` defaults, which are off.
    pii_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    #: The region this tenant's evidence must stay in (S25, REQ-RESIL-004). ``NULL`` means
    #: no pin: the project's evidence lives wherever the deployment writes it.
    residency_region: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: The language this tenant's reports are delivered in by default (S26, REQ-ECOS-005):
    #: a BCP-47 primary subtag such as ``fr``. ``NULL`` inherits the deployment default
    #: (``ARACHNE_REPORT_LOCALE``), so a tenant that sets nothing keeps the pre-S26 path. A
    #: single report can still override it per request.
    report_locale: Mapped[str | None] = mapped_column(String(16), nullable=True)


class Feed(Base, TimestampMixin):
    """One ingested CVE/EPSS feed artefact (F-09-03).

    Ingestion is offline-friendly by design: an operator brings a FIRST EPSS CSV, a CISA KEV
    JSON or a CVE JSON export, ARACHNE validates and normalises it, stores the normalised
    file under the feeds directory, and records what it was. ``path`` points at that
    normalised file, which is exactly the shape ``ARACHNE_M6_EPSS_FEED`` /
    ``ARACHNE_M6_KEV_FEED`` consume, so ingestion and correlation share one format.
    """

    __tablename__ = "feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: ``epss`` | ``kev`` | ``cve`` — the shape of the artefact.
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: Where the operator's file came from (a path, a URL, "upload").
    source: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    #: Absolute path of the normalised artefact the checks consume.
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    record_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    imported_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class FeedEntry(Base):
    """One normalised feed row, keyed by CVE id (F-09-03).

    The row exists so ``GET /feeds/{id}`` and ``arachne feeds lookup`` can answer without
    re-reading a 200k-line CSV, and so a feed's provenance is queryable. ``data_json`` is the
    vocabulary the M6 check already understands (``epss``, ``percentile``, ``kev``, ``cvss``).
    """

    __tablename__ = "feed_entries"
    __table_args__ = (UniqueConstraint("feed_id", "key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    feed_id: Mapped[int] = mapped_column(
        ForeignKey("feeds.id", ondelete="CASCADE"), nullable=False, index=True
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    data_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ScanAgent(Base, TimestampMixin):
    """A registered worker of the scan fleet (S16, REQ-SCALE-002).

    One row per ``arachne agent``. Registration is the agent's first control-plane call;
    the heartbeat refreshes :attr:`last_heartbeat_at`, and every lease the agent holds is
    stamped with its id. ``concurrency`` is the per-agent cap the queue enforces when the
    agent claims work (default 1 — one scan at a time). ``status`` is ``active`` or
    ``retired`` (an operator-drained agent that no longer claims work); liveness is
    *computed* from the heartbeat, never stored.
    """

    __tablename__ = "scan_agents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    concurrency: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class ScanQueue(Base):
    """One row per admitted scan waiting for an agent (S16, REQ-SCALE-001).

    The work queue is a Postgres table claimed with ``SELECT … FOR UPDATE SKIP LOCKED``
    — the database is the broker, and no message broker is a default dependency. A row
    moves ``queued → leased → done``; an expired lease (its agent stopped heartbeating)
    flips back to ``queued`` with an interruption note on the scan (REQ-SCALE-003), and a
    stopped scan is ``cancelled``. ``scan_id`` is UNIQUE, so a scan is enqueued exactly
    once and no scan can execute on two nodes at once. ``attempts`` counts leases —
    2+ means the scan was interrupted and re-leased.
    """

    __tablename__ = "scan_queue"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="queued", nullable=False, index=True)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    agent_id: Mapped[int | None] = mapped_column(
        ForeignKey("scan_agents.id", ondelete="SET NULL"), nullable=True, index=True
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: The authenticated label of the key that enqueued the scan (audit continuity).
    requested_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: Producer provenance: the schedule that enqueued this scan, if any, and the
    #: previous run of the same schedule (the completion path computes the diff).
    schedule_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    previous_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class ServiceAccount(Base):
    """An API key that is a *service account* (S17, REQ-IDAM-003).

    The three fields the requirement adds to the pre-S17 static key list are all here:
    ``expires_at`` (optional expiry), ``last_used_at`` (last-used tracking) and the
    rotation lineage (``rotated_from``/``revoked_at`` — a rotated key is *revoked*, never
    deleted, so the rotation is visible in the row history). Storage is unchanged: only the
    SHA-256 ``digest`` of the secret lives here, verified with
    :func:`hmac.compare_digest` — the same discipline :class:`ApiKeyStore` has always used.

    ``owner`` is the human the key acts for (the SSO identity that created it, or an
    operator-supplied name). It is what makes an audit row read "user X via key Y"
    (REQ-IDAM-004): a service account with no owner degrades to "key Y" only.
    """

    __tablename__ = "service_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    project: Mapped[str | None] = mapped_column(String(64), nullable=True)
    #: The human this key acts for; ``None`` for a purely machine identity.
    owner: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: SHA-256 hex digest of the secret (plaintext is never stored — F-07-02, S12).
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: Optional expiry; ``None`` means the key does not expire (REQ-IDAM-003).
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Set when the key is rotated away or revoked; a revoked key never authenticates.
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: The label of the key this one superseded (rotation lineage), if any.
    rotated_from: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class SsoFlow(Base):
    """One *pending* OIDC authorization-code flow (S17, REQ-IDAM-001).

    The ``state`` parameter is the flow's primary key and its single-use nonce: the
    callback consumes the row it names, so a replayed ``code``/``state`` finds nothing.
    Storing the flow server-side (rather than in a cookie) keeps the PKCE verifier and the
    OIDC ``nonce`` off the client and lets a multi-node deployment complete a login on any
    node — the same store-is-the-truth posture the rest of the platform uses.
    """

    __tablename__ = "sso_flows"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    state: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    code_verifier: Mapped[str] = mapped_column(String(128), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(1024), nullable=False)
    #: Where to send the browser after a successful login (validated to a local path).
    next_path: Mapped[str] = mapped_column(String(512), nullable=False, default="/ui/")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuthSession(Base):
    """A logged-in browser session minted after an OIDC login (S17, REQ-IDAM-001).

    Only the SHA-256 ``token_hash`` is stored — the cookie carries the opaque token, and a
    database read cannot replay it. The row records the *per-user* principal
    (subject/email/name/role/groups) that every scan, report and audit event this session
    causes is attributed to.
    """

    __tablename__ = "auth_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    project: Mapped[str | None] = mapped_column(String(64), nullable=True)
    groups_json: Mapped[list[Any]] = mapped_column(JSON, default=list, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PostureBaseline(Base):
    """The last-seen state of one cloud resource (S23, REQ-POSTURE-001).

    One row per ``(scope_key, resource_key)``: the continuous cloud-config check diffs the
    snapshot it just collected against these rows — *the last baseline* — and emits delta
    findings for what changed, then replaces them with the snapshot it just saw. The row
    is therefore "the state the previous continuous run observed", and deleting the rows
    of a scope that vanished is correct (the delta findings and the audit trail carry the
    history). ``config_hash`` is the digest the diff compares so a changed-but-reordered
    document is not a phantom modification.
    """

    __tablename__ = "posture_baselines"
    __table_args__ = (UniqueConstraint("scope_key", "resource_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: The watched surface (the target's cloud reference or endpoint). One scope per
    #: continuous schedule target.
    scope_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    #: ``provider:service/id`` — the stable identity of one resource across runs.
    resource_key: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    service: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The resource's normalised configuration (what the policies and the diff read).
    config_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class PostureVerification(Base):
    """One fix-verification act on one finding (S23, REQ-POSTURE-003).

    The loop: a finding marked remediated is re-verified by a targeted re-scan (only the
    affected checks), closed automatically on verified absence and re-opened on
    regression. Every act writes one row here — ``outcome`` is ``verified`` (auto-close),
    ``still-open`` (the finding persisted), or ``reopened`` (regression detected by a
    later scan) — and the accompanying evidence row is linked to the *original* finding,
    so its record reads "closed by verification scan N" and later "reopened by scan M"
    without rewriting anything.
    """

    __tablename__ = "posture_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: The finding the loop acts on (never deleted with a scan: SET NULL keeps the row).
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: The scan that produced the verdict: the targeted re-scan, or the later scan whose
    #: findings caused a reopen.
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    #: ``verified`` | ``still-open`` | ``reopened``.
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: The evidence row (on the original finding) this act wrote.
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidences.id", ondelete="SET NULL"), nullable=True
    )
    actor: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class AssetCriticality(Base):
    """One asset's business criticality from a CMDB import (S23, REQ-POSTURE-006).

    ``host`` is the grouping key attack paths use (a URL asset contributes its hostname);
    ``tier`` is 1 (most critical) … 4, and the import upserts on it. The value feeds path
    *ranking and labelling* — a tier-1 host's path carries a business-impact floor — never
    the underlying finding severities, which stay what the analyzer computed.
    """

    __tablename__ = "asset_criticality"
    __table_args__ = (UniqueConstraint("host"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    #: 1 (most critical) … 4; a wildcard entry (``*.example.com``) has ``host`` starting
    #: with ``*.`` and matches any subdomain that has no exact row.
    tier: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Where the row came from (the import file, or ``manual``).
    source: Mapped[str] = mapped_column(String(255), nullable=False, default="import")
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class PurpleCampaign(Base):
    """One purple-team campaign: what to replay, and how often (S24, REQ-VALID-001/006).

    A campaign is the unit the *trend* is reported over, so it is a row rather than a CLI
    argument: "the control coverage of campaign X over the last six runs" needs a stable
    identity. ``spec_json`` holds the validated campaign spec (actions, target, cron), and
    ``enabled`` lets an operator park a campaign without losing its history.
    """

    __tablename__ = "purple_campaigns"
    __table_args__ = (UniqueConstraint("name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: The validated campaign spec (actions, target, schedule, notes).
    spec_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: When the campaign last ran (any status), for the operator's view.
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class PurpleRun(Base):
    """One executed purple-team run and what it learned (S24, REQ-VALID-002/006).

    ``emissions_json`` is the scan-time half (which actions fired, each with its technique,
    tactic and the run nonce) and ``sigma_json`` the rule-hit/rule-miss alignment against
    the M6 hunt library; both are written when the run's scan completes.
    ``coverage_json`` is the defender half — the scored report against the alerts ingested
    so far — and is *rewritable*: a defender's SIEM may report minutes after the window
    closed, so re-scoring a run as more alerts arrive must be possible without a second
    scan. That is why coverage lives here rather than in the scan's stats.
    """

    __tablename__ = "purple_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    campaign_id: Mapped[int] = mapped_column(
        ForeignKey("purple_campaigns.id", ondelete="CASCADE"), nullable=False, index=True
    )
    #: The scan the run drove (SET NULL so pruning a scan never orphans the trend).
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: The run's visible tag: every emitted artifact carried it, and matching an alert to
    #: this run requires it (REQ-VALID-003).
    nonce: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    window_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: completed | window_refused | failed
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    emissions_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    sigma_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    coverage_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    #: Techniques this run's coverage found unseen — denormalised so the trend query does
    #: not have to unpack the whole coverage document.
    gaps_json: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class PurpleAlert(Base):
    """One ingested defender alert (S24, REQ-VALID-002).

    Alerts arrive asynchronously (webhook, pull or an export) and are matched to runs by
    ``nonce`` plus the run's window, so they are stored independently of any run. ``nonce``
    is nullable on purpose: an alert that carries none is kept and reported as unlinked
    rather than discarded — discarding it would hide evidence that the defender's tooling
    fired at all.
    """

    __tablename__ = "purple_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="webhook")
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    technique: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    nonce: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class IntegrityAnchor(Base):
    """A signed checkpoint of the audit chain's head (S25, REQ-TRUST-005).

    A hash chain cannot notice its own *tail* being deleted — there is no later row to
    disagree with. An anchor records "at this moment the head was ``(seq, hash)``" and is
    itself signed with the deployment key, so :func:`~arachne.core.integrity.verify_anchors`
    can report a log that no longer reaches it. Anchors are cheap and append-only; the
    operator can also export one out of band (``arachne integrity anchor --export``) so a
    database-level rewrite cannot silently drop the evidence of the deletion.
    """

    __tablename__ = "integrity_anchors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: The chain position this anchor pins.
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: ``auto`` (the configured cadence) or ``manual`` (an operator's act).
    reason: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )


class IntegritySeal(Base):
    """The signed manifest of one completed scan's findings and evidence (S25).

    A per-row signature proves a row was not edited; it cannot prove a row still *exists*.
    The seal is the answer: when a scan completes, the deployment signs a manifest of every
    finding and evidence row it holds (each with its content digest) and stores it here.
    Verification recomputes the manifest from what is present — a line that is gone is a
    deletion, a line that appeared is an insertion, a line whose digest changed is an edit,
    and the report names the row in each case (REQ-TRUST-005's "modification **and**
    deletion").

    One row per scan (``UNIQUE (scan_id)``): re-sealing a scan replaces its manifest, which
    is what lets a deliberately re-analysed scan be sealed again. ``scan_id`` is
    ``SET NULL`` on delete so pruning a scan's rows leaves the seal as the record of what
    was pruned rather than silently removing it too.
    """

    __tablename__ = "integrity_seals"
    __table_args__ = (UniqueConstraint("scan_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: SHA-256 over the sorted manifest lines.
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: How many rows the manifest covered (findings + evidence).
    row_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    #: The manifest itself, so verification can name the row that changed.
    manifest_json: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    signature: Mapped[str | None] = mapped_column(String(128), nullable=True)
    #: ``finish`` (written when the scan completed) or ``manual`` (``arachne integrity seal``).
    reason: Mapped[str] = mapped_column(String(16), nullable=False, default="finish")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class LeaderLease(Base):
    """One named singleton-election lease (S25, REQ-RESIL-002).

    The multi-replica control plane runs N identical API pods, but the scheduler tick, the
    retention prune and the auto-anchor pass must each run **once**. Rather than a second
    coordination service, the lease lives in the database every replica already shares: a
    holder is the row whose ``holder`` matches this replica and whose ``expires_at`` is in
    the future. Acquisition is a compare-and-swap (``UPDATE ... WHERE expires_at < now``)
    guarded by the row's primary key, so two replicas racing the same lease cannot both win
    — the same "the database is the broker" posture the work queue takes (REQ-SCALE-001).

    Liveness is *computed*, never stored: a row whose lease has expired is free regardless
    of what ``holder`` says, so a replica that is killed needs no cleanup to hand the lease
    on (the failure mode that matters in a replica-kill test).
    """

    __tablename__ = "leader_leases"
    __table_args__ = (UniqueConstraint("name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: The singleton's name (``scheduler``, ``retention``, ``integrity-anchor``).
    name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: The replicas' identity that last won the lease (its host/pid label).
    holder: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Segment the holder occupies, for a human reading the table.
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: Monotonic fencing token: every successful acquisition increments it, so a stale
    #: holder that wakes up can tell its lease was superseded rather than renewed. It is
    #: also the ORM's **version counter** (``__mapper_args__`` below): every UPDATE carries
    #: ``WHERE token = <the value this session read>``, which makes an acquisition a true
    #: compare-and-swap — two replicas racing a free lease cannot both win, and the loser
    #: gets ``StaleDataError`` instead of a silent double-hold.
    token: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __mapper_args__ = {"version_id_col": token}


class ContentPack(Base):
    """One imported offline content pack (S25, REQ-RESIL-001) — its provenance.

    A pack is how checks, rules, feeds and templates reach an air-gapped estate: the
    operator exports it from a connected build, signs it, carries it in and imports it.
    This row is the *provenance* of that act — the pack's name, version, the digest of its
    manifest, which key signed it, what it contained and who imported it — so
    "which content is this deployment running, and where did it come from?" is answerable
    from the database rather than from a shell history. The bytes themselves live in the
    content directory (``ARACHNE_CONTENT_PACKS_DIR``).
    """

    __tablename__ = "content_packs"
    __table_args__ = (UniqueConstraint("name", "version"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    #: SHA-256 of the pack's canonical manifest (the value the signature covers).
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    #: The key id that signed it (a non-secret label), so a rotation is visible.
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    #: How many files the pack carried, by kind (``checks``, ``rules``, ``feeds``, ...).
    contents_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    #: Where the pack was imported from (a path or "upload").
    source: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    imported_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class PackReview(Base):
    """One content pack's trip through the marketplace review pipeline (S26, REQ-ECOS-001).

    REQ-ECOS-001 requires provenance to be *recorded* and a pack to pass the pipeline
    (signature, safety and parity gates) *before it is listed*. This row is that record: the
    pack identity, the digest and key the review ran against, the decision, and every gate's
    outcome with the reasons it gave. A pack is "listed" when its newest review for a digest
    says ``listed`` — so a pack rebuilt with different content is re-reviewed rather than
    inheriting its predecessor's verdict.

    ``gates_json`` keeps the whole gate report rather than a bool, because "why was this
    refused?" is the question an operator and an auditor both ask, and a re-run that disagrees
    with a stored verdict must be visible rather than overwritten silently.
    """

    __tablename__ = "pack_reviews"
    __table_args__ = (UniqueConstraint("name", "version", "digest"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    #: SHA-256 of the reviewed pack's canonical manifest.
    digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    #: The key id the pack was signed with (``"unsigned"`` when it carried no signature).
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, default="unsigned")
    #: ``listed`` | ``rejected`` — the pipeline's decision (never a partial state).
    decision: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    #: The full gate report: one object per gate with its outcome and reasons.
    gates_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    #: The pack's declared kind and entry-point group (parity's inputs; recorded for audit).
    kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class FixProposal(Base):
    """One remediation artifact proposed for one finding (S27, area FIX, REQ-FIX-001...005).

    The row is the whole story of one proposal, because "full audit trail from finding to
    proposal" (REQ-FIX-003) has to survive an operator reading the record months later:

    * **what** — the plan, the author (``template`` or ``ai``), the diff, the files it
      touches and the safety verdict on that diff;
    * **who** — who proposed it, who approved it, who said the fix landed. Each is a
      separate, recorded act: nothing advances the row without one, which is how "human
      approval is a hard gate" is visible in the data and not only in the code;
    * **the gate** — the repository's own test suite and ARACHNE's own IaC self-scan, with
      their outcomes, so a submission re-reads as "these tests passed on this commit";
    * **the loop** — the branch and PR artifact a submission created, and the
      fix-verification act that closed (or kept open) the original finding.

    ``status`` is one flat vocabulary rather than a state-machine table, so a reader sees in
    one column where a proposal stopped: ``proposed`` (awaiting a human), ``approved``,
    ``rejected``, ``applied`` (a human says the fix landed), ``verified``/``still-open`` (the
    loop's verdict), or one of the flagged terminal states (``unsupported``, ``ambiguous``,
    ``already-fixed``, ``refused``, ``tests-failed``, ``baseline-failing``, ``failed``).
    """

    __tablename__ = "fix_proposals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: The finding this artifact is for. ``SET NULL`` keeps the proposal readable after a
    #: retention prune removes the finding, which is what an audit trail has to survive.
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    check_key: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    asset_value: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    #: ``iac`` | ``code`` | ``none`` (no plan covered the class).
    kind: Mapped[str] = mapped_column(String(16), nullable=False, default="none")
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    plan_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    author: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    #: ``n/a`` | ``ok`` | ``failed`` | ``not-covered`` — the dual-engine parity outcome.
    parity: Mapped[str] = mapped_column(String(16), nullable=False, default="n/a")
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Why a flagged proposal stopped, in the operator's words (``tests-failed``, …).
    flagged_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: Repo-relative files the artifact changes, with the plan's skipped-target reasons.
    targets_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    #: The diff an operator would apply. Always the *emitted* diff: a secret-bearing
    #: removal is masked before it is stored (REQ-FIX-003).
    diff_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: False when a masked removal means the diff is not byte-applicable (manual apply).
    verbatim: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    manual_apply_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    safety_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    self_scan_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    #: Repository mode: the granted repo, the branch created, the base and the commit.
    repo_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    repo_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    branch: Mapped[str | None] = mapped_column(String(128), nullable=True)
    base_commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    commit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    default_branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    #: Where the reviewable PR artifact was written (a file, since nothing is pushed).
    pr_artifact: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    #: The repository's own test suite: the declared argv, both runs and their outcomes.
    test_command_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    test_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    test_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False, default="system")
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    applied_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: The fix-verification act that linked this proposal back into the loop
    #: (``posture_verifications.id``, REQ-FIX-005).
    verification_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verification_outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    verification_scan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    meta_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class SimulationPointRecord(Base):
    """One re-simulation of the estate model (S28, area SIM, REQ-SIM-006).

    Deliberately its own table, and deliberately *not* a findings table. A simulation point
    is an observation of a **computation**, not of a target: it records what the estate model
    looked like to the composer at one moment, so the posture view can plot the outlook next
    to the exposure. Nothing in the scan pipeline reads this table, no gate count is derived
    from it, and a retention policy over it can never affect a finding.

    ``provenance`` is stored rather than assumed, because it is the column a reader — and a
    test — checks to be sure a row is simulated and not observed.
    ``severity_counts_json`` counts only *simulated* paths.
    """

    __tablename__ = "simulation_points"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    #: The estate this point belongs to (an operator-chosen key: a project, a target set).
    estate_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    #: The scan whose completion triggered the re-simulation, when there was one.
    scan_id: Mapped[int | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    provenance: Mapped[str] = mapped_column(String(32), nullable=False, default="simulated")
    hypotheses: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    path_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    introduced: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exposure_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    severity_counts_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )
