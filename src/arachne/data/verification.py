"""The per-finding verification record (WP-13, area PROOF, REQ-PROOF-015/016).

The proof ladder (``core/proof.py``, ``proof/``) says *how far* a check may go; this module
is the durable record of *how far it actually went*. Every finding ARACHNE persists carries
one: the level used, the method, the observations that established it, a reproducibility
token, the timestamp and the check's version. A finding that somehow reaches a report
without one is downgraded to ``info`` and marked ``unverified`` (``report/model.py``), so an
unproven claim can never be dressed as a proven one.

Two deliberate properties, both enforced here rather than by convention:

* **One construction path.** :func:`record_for_result` is the only way a *verified* record
  is built, and it reads nothing but a check-layer :class:`~arachne.core.results.CheckResult`.
  The AI stage (:mod:`arachne.ai`, :mod:`arachne.reasoning`) cannot create or alter a record
  because there is no API that accepts its output: the store computes the record itself
  (``data/finding_store.py``), and the report builder reads it back from the store rather
  than from an analysis (PD-8, REQ-PROOF-020's sibling rule in ``05-detection-program.md``
  §3.4).
* **Levels never rise.** :func:`reverification_record` refuses a re-verification whose level
  ranks above the record it re-checks (REQ-PROOF-016, PD-7), and the store refuses to persist
  one even if a caller built the dataclass by hand.

The record is *additive*: a nullable ``findings.verification_id`` points at the row that is
current, and every re-verification appends a row whose ``parent_id`` names the record it
re-checked, so the history is intact and the migration adds a column plus an index
(``migrations/versions/0015_finding_verifications.py``).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult, Evidence, sha256_of

__all__ = [
    "MAX_OBSERVATIONS",
    "OUTCOMES",
    "OUTCOME_INCONCLUSIVE",
    "OUTCOME_NO_LONGER_VERIFIED",
    "OUTCOME_REFUSED",
    "OUTCOME_STILL_VERIFIED",
    "STATUS_UNVERIFIED",
    "STATUS_VERIFIED",
    "SqlVerificationStore",
    "VerificationRecord",
    "level_rank",
    "observation",
    "record_for_result",
    "reverification_record",
]

#: The VERIFIED status vocabulary (``05-detection-program.md`` §3.3).
STATUS_VERIFIED: Final = "verified"
STATUS_UNVERIFIED: Final = "unverified"

#: What ``arachne verify-finding`` reports (REQ-PROOF-016). ``refused`` is never persisted as
#: a record: nothing was re-checked, so there is nothing to record.
OUTCOME_STILL_VERIFIED: Final = "still-verified"
OUTCOME_NO_LONGER_VERIFIED: Final = "no-longer-verified"
OUTCOME_INCONCLUSIVE: Final = "inconclusive"
OUTCOME_REFUSED: Final = "refused"
OUTCOMES: Final[tuple[str, ...]] = (
    OUTCOME_STILL_VERIFIED,
    OUTCOME_NO_LONGER_VERIFIED,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_REFUSED,
)

#: How many observations a record carries. A record is a reviewable summary, not a second
#: copy of the evidence store (the full exchanges live there, referenced by ref).
MAX_OBSERVATIONS: Final = 12

_PROOF_KINDS: Final = frozenset({"proof"})
_EXCHANGE_KINDS: Final = frozenset({"http_request", "http_response"})


def level_rank(level: str) -> int:
    """The ladder position of ``level``; an unknown level ranks lowest (fail-closed)."""
    try:
        return ProofLevel(level).rank
    except ValueError:
        return -1


def observation(what: str, **fields: Any) -> dict[str, Any]:
    """One observation entry: a short ``what`` label plus the measured fields."""
    entry: dict[str, Any] = {"what": str(what)}
    for key, value in fields.items():
        if value is None:
            continue
        entry[str(key)] = value
    return entry


@dataclass(frozen=True, slots=True)
class VerificationRecord:
    """One persisted verification act on one finding (REQ-PROOF-015).

    ``status`` is ``verified`` for a record built from a check's own evidence and
    ``unverified`` for the placeholder a finding without a persisted record is reported with.
    ``outcome`` is set only by a re-verification (:data:`OUTCOMES`); ``parent_id`` links a
    re-verification to the record it re-checked, so the history is a chain rather than a
    rewrite.
    """

    level: str
    method: str = ""
    observations: tuple[Mapping[str, Any], ...] = ()
    reproducibility_token: str | None = None
    verified_at: datetime | None = None
    check_version: str | None = None
    status: str = STATUS_VERIFIED
    outcome: str | None = None
    parent_id: int | None = None
    id: int | None = None
    finding_id: int | None = None
    scan_id: int | None = None

    def __post_init__(self) -> None:
        if self.status not in (STATUS_VERIFIED, STATUS_UNVERIFIED):
            msg = f"invalid verification status {self.status!r}"
            raise ValueError(msg)
        if self.outcome is not None and self.outcome not in OUTCOMES:
            msg = f"invalid verification outcome {self.outcome!r}"
            raise ValueError(msg)
        if self.verified_at is not None and self.verified_at.tzinfo is None:
            msg = "verification timestamps must be timezone-aware (UTC)"
            raise ValueError(msg)
        if self.status == STATUS_VERIFIED and not self.method:
            msg = "a verified record must name the method that established it"
            raise ValueError(msg)

    @property
    def verified(self) -> bool:
        """True when this record documents a check that actually ran."""
        return self.status == STATUS_VERIFIED

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (what the report renders and what a store row carries)."""
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "parent_id": self.parent_id,
            "scan_id": self.scan_id,
            "status": self.status,
            "level": self.level,
            "method": self.method,
            "observations": [dict(item) for item in self.observations],
            "reproducibility_token": self.reproducibility_token,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "check_version": self.check_version,
            "outcome": self.outcome,
        }


def _exchange_observation(
    request: Mapping[str, Any], response: Mapping[str, Any]
) -> dict[str, Any]:
    body = response.get("body")
    method = str(request.get("method") or "GET")
    url = str(request.get("url") or request.get("path") or "")
    status_code = response.get("status_code")
    length = len(body) if isinstance(body, str) else None
    return observation(
        "exchange",
        request=f"{method} {url}".strip(),
        status=int(status_code) if isinstance(status_code, int) else None,
        length=length,
    )


def _evidence_observations(evidence: Sequence[Evidence]) -> list[dict[str, Any]]:
    """The spec's ``{request, status, length}`` rows, in capture order (bounded)."""
    out: list[dict[str, Any]] = []
    pending: Mapping[str, Any] | None = None
    for item in evidence:
        if item.kind == "http_request":
            pending = item.payload
            continue
        if item.kind == "http_response":
            out.append(_exchange_observation(pending or {}, item.payload))
            pending = None
            continue
        if item.kind in _PROOF_KINDS:
            continue
        # Any other kind (artifact, banner, file_path, tls_certificate, note, purple) is a
        # measured fact worth naming, not a payload worth copying: name it and its digest.
        out.append(
            observation(
                str(item.kind),
                source=item.source,
                sha256=item.sha256,
            )
        )
        if len(out) >= MAX_OBSERVATIONS:
            break
    return out[:MAX_OBSERVATIONS]


def _proof_observations(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    hit = payload.get("hit")
    if isinstance(hit, Mapping):
        out.append(
            observation(
                "out-of-band-callback",
                token=hit.get("token"),
                source=hit.get("source"),
                at=hit.get("at") or hit.get("received_at"),
            )
        )
    change = payload.get("change")
    if isinstance(change, Mapping):
        out.append(
            observation(
                "state-change",
                kind=change.get("kind"),
                locator=change.get("locator"),
                restored=bool(change.get("restored")),
                restore_verified=bool(change.get("restore_verified")),
            )
        )
    cleanup = payload.get("cleanup")
    if cleanup:
        out.append(observation("cleanup", result=str(cleanup)))
    return out


def _usable_token(value: Any) -> str | None:
    """``value`` as a token, or ``None`` when it is absent or a redaction placeholder."""
    text = str(value) if value else ""
    if not text or text.startswith("[REDACTED"):
        return None
    return text


def _content_token(result: CheckResult, observations: Sequence[Mapping[str, Any]]) -> str:
    """A content-addressed reproducibility token for a record with no token of its own.

    It is derived from the check, the candidate's identity and the observation set, so
    re-running the same check against the same asset reproduces it — which is exactly the
    handle a "can this be re-established?" question needs. It is *not* a secret and grants
    no capability: the L2/L3/L4 capabilities are carried by the ladder's own single-use
    tokens, which the proof payload supplies when they exist.
    """
    material = json.dumps(
        {
            "check": result.check,
            "module": result.module,
            "title": result.title,
            "cwe": result.cwe,
            "observations": [dict(item) for item in observations],
        },
        default=str,
        sort_keys=True,
        ensure_ascii=False,
    )
    return f"sha256:{sha256_of(material)}"


def record_for_result(
    result: CheckResult,
    *,
    check_version: str | None,
    verified_at: datetime,
    level_hint: str = ProofLevel.L1.value,
    finding_id: int | None = None,
    scan_id: int | None = None,
) -> VerificationRecord:
    """The verification record a stored candidate carries (the *only* verified constructor).

    It reads a :class:`~arachne.core.results.CheckResult` and nothing else. That signature is
    the AI guard: an analysis, a model completion or a hybrid engine's annotation is not a
    ``CheckResult``, so no AI contribution can reach this function (PD-8).
    """
    proof_payload: Mapping[str, Any] = {}
    for item in result.evidence:
        if item.kind in _PROOF_KINDS:
            proof_payload = item.payload
    level = str(proof_payload.get("level") or level_hint)
    if level_rank(level) < 0:
        level = level_hint
    method = str(proof_payload.get("method") or "")
    if not method:
        method = f"check-local observation ({result.check or result.module or 'check'})"
    # ``Evidence.of`` redacts a payload key that names a secret, and ``callback_token`` is
    # one — so the ladder's single-use token arrives here masked. A redaction placeholder is
    # not a handle anyone can reproduce with, so it is treated as absent and the record falls
    # back to the content digest (which *is* reproducible). A ``nonce`` key is not treated as
    # secret by the redactor and survives verbatim, which is why it is consulted too.
    token = _usable_token(
        proof_payload.get("callback_token")
        or proof_payload.get("proof_nonce")
        or proof_payload.get("nonce")
    )
    observations = [
        *_proof_observations(proof_payload),
        *_evidence_observations(result.evidence),
    ][:MAX_OBSERVATIONS]
    verified_at = verified_at if verified_at.tzinfo else verified_at.replace(tzinfo=UTC)
    return VerificationRecord(
        level=level,
        method=method,
        observations=tuple(observations),
        reproducibility_token=str(token) if token else _content_token(result, observations),
        verified_at=verified_at,
        check_version=check_version,
        status=STATUS_VERIFIED,
        finding_id=finding_id,
        scan_id=scan_id,
    )


def reverification_record(
    parent: VerificationRecord,
    *,
    level: str,
    method: str,
    observations: Iterable[Mapping[str, Any]],
    reproducibility_token: str | None,
    verified_at: datetime,
    check_version: str | None,
    outcome: str,
    scan_id: int | None = None,
) -> VerificationRecord:
    """A re-verification record linked to ``parent`` — refusing any level escalation.

    REQ-PROOF-016 and PD-7: a re-run may establish the same claim at the same level or a
    weaker one, never a stronger one. A caller that tries to escalate is refused in code,
    here and again at the store boundary.
    """
    if outcome not in (OUTCOME_STILL_VERIFIED, OUTCOME_NO_LONGER_VERIFIED, OUTCOME_INCONCLUSIVE):
        msg = f"{outcome!r} is not a persistable re-verification outcome"
        raise ValueError(msg)
    if level_rank(level) > level_rank(parent.level):
        msg = (
            f"re-verification refuses to raise the proof level from {parent.level} to {level} "
            "(PD-7: a re-run never escalates)"
        )
        raise ValueError(msg)
    if parent.id is None:
        msg = "the parent record has no stored id; re-verification needs a persisted parent"
        raise ValueError(msg)
    return VerificationRecord(
        level=level,
        method=method,
        observations=tuple(dict(item) for item in observations),
        reproducibility_token=reproducibility_token,
        verified_at=verified_at,
        check_version=check_version,
        status=STATUS_VERIFIED if outcome == OUTCOME_STILL_VERIFIED else STATUS_UNVERIFIED,
        outcome=outcome,
        parent_id=parent.id,
        finding_id=parent.finding_id,
        # The scan that *produced* the record (the verification re-scan), not the one that
        # produced the parent — so a reader can tell where the new evidence came from.
        scan_id=scan_id if scan_id is not None else parent.scan_id,
    )


# --------------------------------------------------------------------------- persistence
def append_verification(session: Session, record: VerificationRecord) -> VerificationRecord:
    """Add ``record`` to ``session`` and point its finding at the new row.

    Shared by :meth:`SqlVerificationStore.append` and
    :meth:`~arachne.data.finding_store.SqlFindingStore.record_candidate` so the write path
    (and the PD-7 level guard) exists exactly once. The caller owns the transaction.
    """
    from arachne.data.models import Finding
    from arachne.data.scan_store import as_utc

    if record.finding_id is None:
        msg = "a verification record must name the finding it belongs to"
        raise ValueError(msg)
    if record.parent_id is not None:
        parent = session.get(_row_model(), int(record.parent_id))
        if parent is not None and level_rank(record.level) > level_rank(str(parent.level)):
            # Defence in depth (PD-7): even a hand-built dataclass cannot be stored at a
            # level above the record it re-checks.
            msg = (
                f"refusing to persist a re-verification at {record.level} above its "
                f"parent {parent.level}"
            )
            raise ValueError(msg)
    row = _row_model()(
        finding_id=int(record.finding_id),
        parent_id=record.parent_id,
        scan_id=record.scan_id,
        status=record.status,
        level=record.level,
        method=record.method,
        observations_json=[dict(item) for item in record.observations],
        reproducibility_token=record.reproducibility_token,
        verified_at=as_utc(record.verified_at) or datetime.now(UTC),
        check_version=record.check_version,
        outcome=record.outcome,
    )
    session.add(row)
    session.flush()
    finding = session.get(Finding, int(record.finding_id))
    if finding is not None:
        finding.verification_id = int(row.id)
    return replace(record, id=int(row.id))


class SqlVerificationStore:
    """Read and write ``finding_verifications`` rows over one session factory."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def current(self, finding_id: int) -> VerificationRecord | None:
        """The finding's current record (the row ``findings.verification_id`` points at)."""
        from arachne.data.models import Finding

        with self._session_factory() as session:
            finding = session.get(Finding, finding_id)
            if finding is None or finding.verification_id is None:
                return None
            row = session.get(_row_model(), int(finding.verification_id))
            return None if row is None else _to_record(row)

    def history(self, finding_id: int) -> tuple[VerificationRecord, ...]:
        """Every record for the finding, oldest first (the report's per-finding history)."""
        rows = self._rows_for(finding_id)
        return tuple(_to_record(row) for row in rows)

    def append(self, record: VerificationRecord) -> VerificationRecord:
        """Persist ``record`` and point its finding at it; return it with its new id."""
        with self._session_factory() as session:
            stored = append_verification(session, record)
            session.commit()
            return stored

    def _rows_for(self, finding_id: int) -> list[Any]:
        model = _row_model()
        with self._session_factory() as session:
            return list(
                session.scalars(
                    select(model).where(model.finding_id == finding_id).order_by(model.id)
                ).all()
            )


def _row_model() -> Any:
    from arachne.data.models import FindingVerification

    return FindingVerification


def _to_record(row: Any) -> VerificationRecord:
    from arachne.data.scan_store import as_utc

    observations = row.observations_json if isinstance(row.observations_json, list) else []
    return VerificationRecord(
        id=int(row.id),
        finding_id=int(row.finding_id) if row.finding_id is not None else None,
        parent_id=int(row.parent_id) if row.parent_id is not None else None,
        scan_id=int(row.scan_id) if row.scan_id is not None else None,
        status=str(row.status),
        level=str(row.level),
        method=str(row.method),
        observations=tuple(dict(item) for item in observations if isinstance(item, Mapping)),
        reproducibility_token=(
            str(row.reproducibility_token) if row.reproducibility_token else None
        ),
        verified_at=as_utc(row.verified_at),
        check_version=str(row.check_version) if row.check_version else None,
        outcome=str(row.outcome) if row.outcome else None,
    )
