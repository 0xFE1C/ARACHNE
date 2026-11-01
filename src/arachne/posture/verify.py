"""The fix-verification loop (S23, REQ-POSTURE-003).

The loop the requirement names, in order: a finding is *marked remediated* (the operator
tells ARACHNE the fix has landed), ARACHNE re-verifies it with a **targeted re-scan** —
a real scan over the same target definition, planned with only the affected checks —
**closes** the finding automatically on verified absence, and **re-opens** it on
regression when a later scan of the same target sees it again. Every act links its
evidence to the *original* finding, so its record reads "closed by verification scan N /
reopened by scan M" instead of silently changing status.

Two deliberate properties:

* **Verification is a real scan.** The re-scan goes through :meth:`Orchestrator.scan` —
  the same scope gate, the same authorization gate, the same proof gate, the same
  analysis — so "verified absent" means "a scan that obeyed every gate ran the check
  against the target and the check did not report it", never "we assumed it".
* **Reopen is identity-scoped.** A closed finding reopens only when a scan of the *same
  target* reports the *same* ``(check, asset)`` again. A scan of another target (or
  another asset) cannot resurrect a finding it does not actually contradict, and a
  verification scan cannot reopen the finding it just closed.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import ScanStateError
from arachne.core.results import sha256_of
from arachne.core.target import ModuleSelection, ScanRequest, parse_scan_request
from arachne.data.posture_store import FINDING_CLOSED, PostureStore, VerificationRecord
from arachne.data.services import ScanServices, build_orchestrator

__all__ = [
    "FixVerificationResult",
    "FixVerificationService",
    "normalise_check_key",
    "verification_evidence",
]

#: The status vocabulary this loop writes. ``open``/``verified``/``fp``/``merged`` are the
#: analyzer's; ``closed`` is the fix loop's own (see ``data/posture_store``).
REOPENED_STATUS = "open"

_OUTCOME_VERIFIED: Final = "verified"
_OUTCOME_STILL_OPEN: Final = "still-open"
_OUTCOME_REOPENED: Final = "reopened"


def normalise_check_key(check_key: str | None) -> str | None:
    """``M5/x@1.0`` → ``m5.x`` (the form ``ModuleSelection`` and the diff keys use)."""
    if not check_key:
        return None
    key = check_key.split("@", 1)[0]
    module, _, name = key.partition("/")
    if not name:
        return key.lower() or None
    return f"{module.lower()}.{name}"


def verification_evidence(
    *,
    outcome: str,
    finding_id: int,
    original_scan_id: int,
    verification_scan_id: int | None,
    detail: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The evidence payload linked to the original finding (redacted upstream by the store).

    ``sha256`` covers the payload so the link is integrity-bearing the way every other
    evidence row is.
    """
    payload = {
        "signal": "fix-verification",
        "outcome": outcome,
        "finding_id": finding_id,
        "original_scan_id": original_scan_id,
        "verification_scan_id": verification_scan_id,
        "detail": detail,
    }
    if now is not None:
        payload["verified_at"] = now.isoformat()
    return {
        "kind": "note",
        "payload": payload,
        "sha256": sha256_of(json.dumps(payload, sort_keys=True, default=str)),
    }


@dataclass(frozen=True, slots=True)
class FixVerificationResult:
    """What one verification act did."""

    finding_id: int
    check_key: str | None
    asset_value: str | None
    original_scan_id: int
    verification_scan_id: int | None
    #: ``verified`` (auto-closed) or ``still-open`` (kept open, act recorded).
    outcome: str
    detail: str
    record: VerificationRecord | None = None

    @property
    def closed(self) -> bool:
        return self.outcome == _OUTCOME_VERIFIED


@dataclass(frozen=True, slots=True)
class ReopenRecord:
    """One regression auto-reopen (``reconcile``)."""

    finding_id: int
    scan_id: int
    check_key: str | None
    asset_value: str | None
    record: VerificationRecord | None = None


class FixVerificationService:
    """The close → reopen loop over one deployment's services."""

    def __init__(self, services: ScanServices, *, auditor: Auditor | None = None) -> None:
        self.services = services
        self.auditor = auditor or services.auditor
        self.store: PostureStore = services.posture  # type: ignore[assignment]

    # ------------------------------------------------------------------ verify
    async def verify(
        self,
        finding_id: int,
        *,
        actor: str = "operator",
        now: datetime | None = None,
    ) -> FixVerificationResult:
        """Re-verify one finding with a targeted re-scan; close it on verified absence."""
        finding = self.store.finding(finding_id)
        if finding is None:
            msg = f"finding {finding_id} does not exist"
            raise ScanStateError(msg)
        if finding["status"] == FINDING_CLOSED:
            msg = f"finding {finding_id} is already closed by a previous verification"
            raise ScanStateError(msg)
        if finding["status"] in {"fp", "merged"}:
            msg = (
                f"finding {finding_id} is {finding['status']!r} (an analyzer decision); "
                "fix verification applies to open or verified findings"
            )
            raise ScanStateError(msg)
        check_key = finding.get("check_key")
        check_id = normalise_check_key(check_key)
        if check_id is None:
            msg = f"finding {finding_id} carries no check provenance to re-run"
            raise ScanStateError(msg)
        original_scan_id = int(finding["scan_id"])
        request = self._targeted_request(original_scan_id, check_id)
        orchestrator = build_orchestrator(self.services)
        session = await orchestrator.scan(request)
        verification_scan_id = session.scan_id
        if verification_scan_id is None:  # pragma: no cover - scan() always persists one
            msg = "the verification scan produced no id"
            raise ScanStateError(msg)

        still_present = any(
            candidate.check_key == check_key
            and candidate.asset_value == finding.get("asset_value")
            # The stored status vocabulary is the analyzer's (open/verified/fp/merged):
            # "still present" means the verification scan confirmed and scored it again.
            and candidate.status not in {"fp", "merged"}
            and candidate.severity is not None
            for candidate in self.services.findings.list_candidates(int(verification_scan_id))
        )
        if still_present:
            outcome = _OUTCOME_STILL_OPEN
            detail = (
                f"targeted re-scan (scan {verification_scan_id}) still reports "
                f"{check_id} on {finding.get('asset_value')!r}; the finding stays open"
            )
        else:
            outcome = _OUTCOME_VERIFIED
            detail = (
                f"targeted re-scan (scan {verification_scan_id}) ran {check_id} against "
                f"{finding.get('asset_value')!r} and reported nothing; finding closed"
            )
        evidence_id = self.store.set_finding_status(
            finding_id,
            FINDING_CLOSED if not still_present else str(finding["status"]),
            evidence=verification_evidence(
                outcome=outcome,
                finding_id=finding_id,
                original_scan_id=original_scan_id,
                verification_scan_id=verification_scan_id,
                detail=detail,
                now=now,
            ),
        )
        record = self.store.record_verification(
            finding_id=finding_id,
            scan_id=verification_scan_id,
            outcome=outcome,
            detail=detail,
            evidence_id=evidence_id,
            actor=actor,
            now=now,
        )
        self.auditor.record(
            AuditAction.POSTURE_FIX_VERIFIED
            if not still_present
            else AuditAction.POSTURE_FIX_STILL_OPEN,
            outcome=AuditOutcome.ALLOWED,
            scan_id=verification_scan_id,
            target=f"finding:{finding_id}",
            reason=detail,
            meta={
                "finding_id": finding_id,
                "check": check_id,
                "asset": finding.get("asset_value"),
                "original_scan_id": original_scan_id,
            },
        )
        return FixVerificationResult(
            finding_id=finding_id,
            check_key=check_key,
            asset_value=finding.get("asset_value"),
            original_scan_id=original_scan_id,
            verification_scan_id=verification_scan_id,
            outcome=outcome,
            detail=detail,
            record=record,
        )

    def _targeted_request(self, scan_id: int, check_id: str) -> ScanRequest:
        """Rebuild the original scan's request, bounded to the affected checks."""
        record = self.services.store.get_scan(scan_id)
        if record is None:
            msg = f"original scan {scan_id} does not exist"
            raise ScanStateError(msg)
        document = record.request_json
        if not document:
            msg = (
                f"scan {scan_id} carries no stored request document (pre-S16 scan); "
                "fix verification needs the admitted request to re-run the same target"
            )
            raise ScanStateError(msg)
        request = parse_scan_request(document, source=f"scan:{scan_id}")
        # "only the affected checks" (REQ-POSTURE-003) is the S21 exact allowlist: every
        # other catalogue check is withheld, so the verification scan cannot quietly run
        # anything the finding did not come from.
        return request.model_copy(
            update={
                "options": request.options.model_copy(
                    update={"modules": ModuleSelection(only=(check_id,))}
                )
            }
        )

    # ------------------------------------------------------------------ reconcile
    def reconcile(
        self, scan_id: int, *, actor: str = "system", now: datetime | None = None
    ) -> tuple[ReopenRecord, ...]:
        """Reopen closed findings a scan of the same target reports again (regression).

        Called after a scheduled scan's diff is computed (and available as
        ``arachne posture reconcile``): the identity is ``(check, asset)`` *and* the
        target the closed finding was raised on, so a different target's scan never
        reopens it and a verification scan never reopens what it just closed.
        """
        current = self.services.store.get_scan(scan_id)
        if current is None:
            msg = f"scan {scan_id} does not exist"
            raise ScanStateError(msg)
        target_name = current.plan.get("target_name") if isinstance(current.plan, dict) else None
        reopens: list[ReopenRecord] = []
        for candidate in self.services.findings.list_candidates(scan_id):
            # The stored status vocabulary is the analyzer's (open/verified/fp/merged):
            # a confirmed finding is one the analyzer kept and scored.
            if candidate.status in {"fp", "merged"} or candidate.severity is None:
                continue
            if not candidate.check_key:
                continue
            closed = self.store.closed_findings(
                check_key=candidate.check_key, asset_value=candidate.asset_value
            )
            for finding in closed:
                if int(finding["scan_id"]) == scan_id:
                    continue
                if not self._same_target(int(finding["scan_id"]), target_name):
                    continue
                evidence_id = self.store.set_finding_status(
                    int(finding["id"]),
                    REOPENED_STATUS,
                    evidence=verification_evidence(
                        outcome=_OUTCOME_REOPENED,
                        finding_id=int(finding["id"]),
                        original_scan_id=int(finding["scan_id"]),
                        verification_scan_id=scan_id,
                        detail=(
                            f"regression: scan {scan_id} reports "
                            f"{candidate.check_key} on {candidate.asset_value!r} again; "
                            "finding reopened with the verification evidence linked"
                        ),
                        now=now,
                    ),
                )
                record = self.store.record_verification(
                    finding_id=int(finding["id"]),
                    scan_id=scan_id,
                    outcome=_OUTCOME_REOPENED,
                    detail=f"regression detected by scan {scan_id}",
                    evidence_id=evidence_id,
                    actor=actor,
                    now=now,
                )
                self.auditor.record(
                    AuditAction.POSTURE_FIX_REGRESSED,
                    outcome=AuditOutcome.ALLOWED,
                    scan_id=scan_id,
                    target=f"finding:{finding['id']}",
                    reason=f"{candidate.check_key} on {candidate.asset_value!r} reappeared",
                    meta={"finding_id": int(finding["id"]), "reopened_by": scan_id},
                )
                reopens.append(
                    ReopenRecord(
                        finding_id=int(finding["id"]),
                        scan_id=scan_id,
                        check_key=candidate.check_key,
                        asset_value=candidate.asset_value,
                        record=record,
                    )
                )
        return tuple(reopens)

    def _same_target(self, other_scan_id: int, target_name: Any) -> bool:
        other = self.services.store.get_scan(other_scan_id)
        if other is None or target_name is None:
            return False
        return bool(other.plan.get("target_name") == target_name)


def verify_finding_sync(
    services: ScanServices, finding_id: int, *, actor: str = "operator"
) -> FixVerificationResult:
    """The synchronous entry point the CLI uses (the loop itself is async, like a scan)."""
    return asyncio.run(FixVerificationService(services).verify(finding_id, actor=actor))
