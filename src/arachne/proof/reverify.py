"""Single-finding re-verification (WP-13, area PROOF, REQ-PROOF-016).

``arachne verify-finding <finding-id>`` answers one question: *does the proof this finding
rests on still hold?* It re-runs the finding's own check against the same asset — a
targeted re-scan, exactly as the fix-verification loop does (REQ-POSTURE-003) — and records
a new verification record linked to the one it re-checked.

Four properties, in the order they are enforced:

0. **It never escalates the proof level.** The check's *declared* level is compared with the
   level the finding was recorded at *before* anything runs; a check that now declares a
   higher rung is refused rather than run, and the store refuses a re-verification record
   whose level exceeds its parent's (PD-7).
1. **Scope and attestation are re-checked before any network access.** The gates are the
   orchestrator's own (``assert_in_scope`` then ``assert_authorized``), called on the
   admitted request the original scan stored — the order ``Orchestrator.execute`` uses — so
   an expired attestation refuses the re-verification exactly as it would refuse a scan. No
   client is constructed and no socket is opened before both return.
2. **The re-run is a real, gated scan.** It goes through :meth:`Orchestrator.scan` with the
   finding's check and nothing else selected, so "still verified" means "a scan that obeyed
   every gate ran the check against the target and it reported the finding again" — never
   "we assumed it".
3. **Every outcome is one of four.** ``still-verified`` / ``no-longer-verified`` /
   ``inconclusive`` (the check could not run: a skip, a failure, or no recorded line) /
   ``refused`` (nothing was re-checked, and the CLI exits non-zero).
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import AuthorizationError, OutOfScopeError, ScanStateError
from arachne.core.target import ModuleSelection, ScanRequest, parse_scan_request
from arachne.data.services import ScanServices, build_orchestrator
from arachne.data.verification import (
    OUTCOME_INCONCLUSIVE,
    OUTCOME_NO_LONGER_VERIFIED,
    OUTCOME_REFUSED,
    OUTCOME_STILL_VERIFIED,
    VerificationRecord,
    level_rank,
    observation,
    reverification_record,
)

__all__ = [
    "STATUSES_CONSIDERED_PRESENT",
    "ReverificationResult",
    "ReverificationService",
    "normalise_check_key",
    "reverify_finding_sync",
]

#: Stored statuses that mean "the analyzer kept this finding" (the vocabulary the posture
#: loop uses too). ``fp``/``merged`` are analyzer decisions, not findings.
STATUSES_CONSIDERED_PRESENT: frozenset[str] = frozenset({"open", "verified"})


@dataclass(frozen=True, slots=True)
class ReverificationResult:
    """What one re-verification concluded (REQ-PROOF-016's four outcomes)."""

    finding_id: int
    outcome: str
    detail: str
    level: str = ""
    check_id: str | None = None
    asset: str | None = None
    original_scan_id: int | None = None
    verification_scan_id: int | None = None
    parent_record_id: int | None = None
    record: VerificationRecord | None = None

    @property
    def refused(self) -> bool:
        return self.outcome == OUTCOME_REFUSED

    @property
    def record_id(self) -> int | None:
        return self.record.id if self.record is not None else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "outcome": self.outcome,
            "detail": self.detail,
            "level": self.level or None,
            "check": self.check_id,
            "asset": self.asset,
            "original_scan_id": self.original_scan_id,
            "verification_scan_id": self.verification_scan_id,
            "parent_record_id": self.parent_record_id,
            "record_id": self.record_id,
        }


def normalise_check_key(check_key: str | None) -> str | None:
    """``M3/sqli-oracle@1.0`` → ``m3.sqli-oracle``.

    The same rule the fix-verification loop uses (``posture.verify.normalise_check_key``),
    imported rather than copied so the two cannot disagree about what a stored check key
    names — a divergence there would silently target the wrong check.
    """
    from arachne.posture.verify import normalise_check_key as _normalise

    return _normalise(check_key)


class ReverificationService:
    """Re-verify one finding against the target its scan was admitted for."""

    def __init__(self, services: ScanServices, *, auditor: Auditor | None = None) -> None:
        self.services = services
        self.auditor = auditor or services.auditor

    async def verify(
        self,
        finding_id: int,
        *,
        actor: str = "operator",
        now: datetime | None = None,
    ) -> ReverificationResult:
        """Re-run the finding's check and record the outcome (REQ-PROOF-016)."""
        finding = self.services.findings.find_candidate(finding_id)
        if finding is None:
            msg = f"finding {finding_id} does not exist"
            raise ScanStateError(msg)
        parent = finding.verification
        if parent is None:
            # Nothing to re-check, and no level to bound a re-run by: the safe answer is a
            # refusal, not a re-run from an unknown rung.
            return self._refuse(
                finding_id,
                reason=(
                    "the finding carries no verification record, so there is nothing to "
                    "re-verify (a pre-WP-13 row, or a write path that bypassed the store)"
                ),
                actor=actor,
                original_scan_id=finding.scan_id,
                asset=finding.asset_value,
                check_id=finding.check_key,
            )
        check_id = normalise_check_key(finding.check_key)
        if check_id is None:
            return self._refuse(
                finding_id,
                reason="the finding carries no check provenance to re-run",
                actor=actor,
                original_scan_id=finding.scan_id,
                asset=finding.asset_value,
            )
        declared = self._declared_level(check_id)
        if declared is None:
            return self._refuse(
                finding_id,
                reason=(
                    f"check {check_id!r} is not registered in this build, so the proof it "
                    "rests on cannot be re-run deterministically"
                ),
                actor=actor,
                original_scan_id=finding.scan_id,
                asset=finding.asset_value,
                check_id=check_id,
                level=parent.level,
                parent_record_id=parent.id,
            )
        if level_rank(declared) > level_rank(parent.level):
            # PD-7 / REQ-PROOF-016: never escalate. A check that has grown a stronger proof
            # since the finding was recorded is refused *before* the network, never run up a
            # rung to see whether it would hold.
            return self._refuse(
                finding_id,
                reason=(
                    f"re-verification would raise the proof level: {check_id} now declares "
                    f"{declared}, and the finding was recorded at {parent.level}. ARACHNE "
                    "does not escalate a re-verification (PD-7)"
                ),
                actor=actor,
                original_scan_id=finding.scan_id,
                asset=finding.asset_value,
                check_id=check_id,
                level=parent.level,
                parent_record_id=parent.id,
            )

        request = self._request_for(finding.scan_id)
        if request is None:
            return self._refuse(
                finding_id,
                reason=(
                    f"scan {finding.scan_id} carries no admitted request document, so the "
                    "same target cannot be re-run"
                ),
                actor=actor,
                original_scan_id=finding.scan_id,
                asset=finding.asset_value,
                check_id=check_id,
                level=parent.level,
                parent_record_id=parent.id,
            )

        orchestrator = build_orchestrator(self.services)
        # The gates, in the order ``Orchestrator.execute`` uses them, and *before* any client
        # is built: scope first (deny by default), then authorization (an expired or
        # non-covering attestation refuses here). Both audit their own refusal.
        try:
            orchestrator.assert_in_scope(request)
            # ``assert_authorized`` reads ``options.active_checks`` from the request itself,
            # so the attestation is judged against exactly what the re-scan will do.
            orchestrator.assert_authorized(request, now=now)
        except (OutOfScopeError, AuthorizationError) as exc:
            return self._refuse(
                finding_id,
                reason=str(exc),
                actor=actor,
                original_scan_id=finding.scan_id,
                asset=finding.asset_value,
                check_id=check_id,
                level=parent.level,
                parent_record_id=parent.id,
            )

        session = await orchestrator.scan(_only_this_check(request, check_id))
        scan_id = session.scan_id
        if scan_id is None:  # pragma: no cover - scan() always persists one
            return self._refuse(
                finding_id,
                reason="the re-verification scan produced no id",
                actor=actor,
                original_scan_id=finding.scan_id,
                asset=finding.asset_value,
                check_id=check_id,
                level=parent.level,
                parent_record_id=parent.id,
            )

        outcome, detail, fresh = self._outcome(
            scan_id=scan_id,
            check_id=check_id,
            asset=finding.asset_value,
            check_key=finding.check_key,
        )
        # The level can only be the parent's or lower (``declared`` was checked above);
        # taking the minimum is belt-and-braces for a registry that changed mid-call.
        level = parent.level if level_rank(parent.level) <= level_rank(declared) else declared
        record = reverification_record(
            parent,
            level=level,
            method=f"re-verification of {check_id} (targeted re-scan {scan_id})",
            observations=_observations(
                scan_id=scan_id,
                check_id=check_id,
                asset=finding.asset_value,
                outcome=outcome,
                fresh=fresh,
            ),
            reproducibility_token=(
                fresh.reproducibility_token if fresh is not None else parent.reproducibility_token
            ),
            verified_at=now or datetime.now(UTC),
            check_version=(fresh.check_version if fresh is not None else parent.check_version),
            outcome=outcome,
            scan_id=scan_id,
        )
        stored = self.services.findings.record_verification(record)
        self._audit_pair(
            finding_id=finding_id,
            parent=parent,
            stored=stored,
            outcome=outcome,
            detail=detail,
            check_id=check_id,
            asset=finding.asset_value,
            verification_scan_id=scan_id,
            actor=actor,
        )
        return ReverificationResult(
            finding_id=finding_id,
            outcome=outcome,
            detail=detail,
            level=stored.level,
            check_id=check_id,
            asset=finding.asset_value,
            original_scan_id=finding.scan_id,
            verification_scan_id=scan_id,
            parent_record_id=parent.id,
            record=stored,
        )

    # ------------------------------------------------------------------ helpers
    def _declared_level(self, check_id: str) -> str | None:
        check = self.services.registry.get(check_id)
        if check is None:
            return None
        return str(check.metadata.proof)

    def _request_for(self, scan_id: int) -> ScanRequest | None:
        """The admitted request document the original scan stored (S16)."""
        record = self.services.store.get_scan(scan_id)
        document = record.request_json if record is not None else None
        if not document:
            return None
        return parse_scan_request(dict(document), source=f"scan:{scan_id}")

    def _outcome(
        self, *, scan_id: int, check_id: str, asset: str | None, check_key: str | None
    ) -> tuple[str, str, VerificationRecord | None]:
        """Decide the verdict from the re-scan's stored candidates and its check audit lines.

        A reported candidate is ``still-verified``. No candidate plus a completed check line
        is ``no-longer-verified``: the check ran against the asset and stayed quiet. A skipped
        or failed check, or no line at all, is ``inconclusive`` — the honest third state,
        because "we could not re-run it" is not "it is gone".
        """
        for candidate in self.services.findings.list_candidates(scan_id):
            if candidate.check_key != check_key or candidate.asset_value != asset:
                continue
            if candidate.status not in STATUSES_CONSIDERED_PRESENT:
                continue
            return (
                OUTCOME_STILL_VERIFIED,
                (
                    f"the targeted re-scan {scan_id} reported {check_id} on {asset!r} again; "
                    "the finding still holds"
                ),
                candidate.verification,
            )
        ran, skipped = self._check_lines(scan_id=scan_id, check_id=check_id)
        if skipped:
            return (
                OUTCOME_INCONCLUSIVE,
                (
                    f"the targeted re-scan {scan_id} could not run {check_id} against "
                    f"{asset!r} (it reported itself skipped or failed); the finding is neither "
                    "confirmed nor refuted"
                ),
                None,
            )
        if ran:
            return (
                OUTCOME_NO_LONGER_VERIFIED,
                (
                    f"the targeted re-scan {scan_id} ran {check_id} against {asset!r} and "
                    "reported nothing; the proof no longer establishes the finding"
                ),
                None,
            )
        return (
            OUTCOME_INCONCLUSIVE,
            (
                f"the targeted re-scan {scan_id} left no audit line for {check_id}; the "
                "re-verification did not establish whether the finding still holds"
            ),
            None,
        )

    def _check_lines(self, *, scan_id: int, check_id: str) -> tuple[bool, bool]:
        """``(ran_cleanly, skipped_or_failed)`` from the re-scan's own audit trail."""
        from arachne.data.report_store import SqlAuditReader

        return SqlAuditReader(self.services.session_factory).check_outcomes(scan_id, check_id)

    def _audit_pair(
        self,
        *,
        finding_id: int,
        parent: VerificationRecord,
        stored: VerificationRecord,
        outcome: str,
        detail: str,
        check_id: str,
        asset: str | None,
        verification_scan_id: int,
        actor: str,
    ) -> None:
        """Audit both records: the parent that was re-checked, and the new one (REQ-PROOF-016).

        Two lines, one per record, each naming the other, so the trail reads as a link rather
        than as an isolated event. The actor is the operator who asked.
        """
        auditor = self.auditor.with_actor(actor)
        auditor.record(
            AuditAction.FINDING_VERIFICATION_RECORDED,
            outcome=AuditOutcome.ALLOWED,
            scan_id=parent.scan_id,
            target=f"finding:{finding_id}",
            reason=detail,
            meta={
                "role": "parent",
                "finding_id": finding_id,
                "record_id": parent.id,
                "rechecked_by_record_id": stored.id,
                "level": parent.level,
                "check": check_id,
                "asset": asset,
            },
        )
        auditor.record(
            AuditAction.FINDING_REVERIFIED,
            outcome=AuditOutcome.ALLOWED,
            scan_id=verification_scan_id,
            target=f"finding:{finding_id}",
            reason=detail,
            meta={
                "role": "new",
                "finding_id": finding_id,
                "record_id": stored.id,
                "parent_record_id": parent.id,
                "outcome": outcome,
                "level": stored.level,
                "check": check_id,
                "asset": asset,
            },
        )

    def _refuse(
        self,
        finding_id: int,
        *,
        reason: str,
        actor: str,
        original_scan_id: int | None = None,
        asset: str | None = None,
        check_id: str | None = None,
        level: str = "",
        parent_record_id: int | None = None,
    ) -> ReverificationResult:
        """Refuse without touching the network, and audit the refusal."""
        self.auditor.with_actor(actor).record(
            AuditAction.FINDING_REVERIFY_REFUSED,
            outcome=AuditOutcome.BLOCKED,
            scan_id=original_scan_id,
            target=f"finding:{finding_id}",
            reason=reason,
            meta={
                "finding_id": finding_id,
                "check": check_id,
                "asset": asset,
                "parent_record_id": parent_record_id,
            },
        )
        return ReverificationResult(
            finding_id=finding_id,
            outcome=OUTCOME_REFUSED,
            detail=reason,
            level=level,
            check_id=check_id,
            asset=asset,
            original_scan_id=original_scan_id,
            parent_record_id=parent_record_id,
        )


def _only_this_check(request: ScanRequest, check_id: str) -> ScanRequest:
    """The admitted request with exactly one check selected (the targeted re-scan)."""
    return request.model_copy(
        update={
            "options": request.options.model_copy(
                update={"modules": ModuleSelection(only=(check_id,))}
            )
        }
    )


def _observations(
    *,
    scan_id: int,
    check_id: str,
    asset: str | None,
    outcome: str,
    fresh: VerificationRecord | None,
) -> tuple[Mapping[str, Any], ...]:
    """The new record's observations: what was re-run, plus the fresh evidence if there is any."""
    head = observation(
        "re-verification",
        scan=scan_id,
        check=check_id,
        asset=asset,
        outcome=outcome,
    )
    if fresh is None:
        return (head,)
    return (head, *fresh.observations)


def reverify_finding_sync(
    services: ScanServices, finding_id: int, *, actor: str = "operator"
) -> ReverificationResult:
    """The synchronous entry point the CLI uses (the re-scan is async, like any scan)."""
    return asyncio.run(ReverificationService(services).verify(finding_id, actor=actor))
