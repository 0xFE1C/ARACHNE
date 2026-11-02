"""The proof capability boundary a check sees (``ctx.proof``).

A check never imports the proof package's helpers directly and never receives a wider
grant than its metadata declares: :class:`ProofAccess` is constructed per check run with
the check's :class:`~arachne.modules.base.CheckMetadata`, and every capability method
refuses below the matching level:

======================  ==========================================================
capability method       requires
======================  ==========================================================
:attr:`level`/``marker``  any level — the calm marker format (REQ-PROOF-009)
:meth:`oob_token`         L2+ and a callback service or base (REQ-PROOF-005)
:meth:`oob_consume`       L2+ — the single-use match, as evidence
:meth:`command_proof`     L3+ — the one-shot allowlisted echo (REQ-PROOF-007)
:meth:`sql`               L4+ and a state-change-authorized scan (REQ-PROOF-008)
======================  ==========================================================

Every refusal is a :class:`~arachne.core.proof.ProofRefused` — a safety refusal at the
boundary, which is where REQ-PROOF-011's prohibitions live in code. The L4 grant
additionally re-checks the attestation flag that reached the run, so a check cannot
out-run its plan.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from arachne.core.proof import CallbackToken, ProofLevel, ProofRefused, poc_marker
from arachne.proof.commands import CommandProof
from arachne.proof.oob import CallbackService, OobHit
from arachne.proof.sql import SqlExecutor, SqlProof

if TYPE_CHECKING:  # the ledger is scan-scoped; checks only ever hold the access object
    from arachne.proof.ledger import ProofLedger

__all__ = ["OobToken", "ProofAccess"]


@dataclass(frozen=True, slots=True)
class OobToken:
    """One issued callback token plus, in standalone mode, the URL to inject."""

    token: CallbackToken
    #: ``None`` in in-process mode (the target can still hit any URL carrying the token
    #: path; the check simply has no base to advertise).
    url: str | None

    def __str__(self) -> str:
        return self.token.value


class ProofAccess:
    """What one check may do on the proof ladder — nothing more."""

    def __init__(
        self,
        *,
        level: ProofLevel,
        check_id: str,
        scan_id: str | int,
        ledger: ProofLedger,
        auditor: Any = None,
        service: CallbackService | None = None,
        callback_base: str | None = None,
        state_changes_authorized: bool = False,
        http: Any = None,
        run_nonce: str | None = None,
    ) -> None:
        self.level = level
        self.check_id = check_id
        self.scan_id = str(scan_id)
        self._ledger = ledger
        self._auditor = auditor
        self._service = service
        self._callback_base = (callback_base or "").rstrip("/") or None
        self._state_changes_authorized = state_changes_authorized
        self._http = http
        #: The purple-team run nonce (S24, REQ-VALID-003). When set, every tag this access
        #: mints — the marker text, an OOB token, the L3 payload — carries it verbatim, so
        #: every emitted artifact is visibly one run's test and a defender's alert can be
        #: matched back to it. ``None`` is the pre-S24 behaviour (a fresh random tag).
        self._run_nonce = run_nonce

    # ------------------------------------------------------------------ any level
    @property
    def run_nonce(self) -> str | None:
        """The nonce this access tags artifacts with, or ``None`` for an ordinary scan."""
        return self._run_nonce

    def marker(self, vuln_class: str, *, nonce: str | None = None) -> str:
        """The calm, self-identifying marker text (REQ-PROOF-009)."""
        return poc_marker(nonce or self._run_nonce or secrets.token_hex(12), vuln_class)

    # ------------------------------------------------------------------ L2+
    def oob_token(self) -> OobToken:
        """Issue one callback token (L2+); refused below L2 or without a service."""
        self._require(ProofLevel.L2, "out-of-band callback tokens")
        if self._service is None and self._callback_base is None:
            # REQ-PROOF-003: unavailability downgrades (the check continues in-band with a
            # note) — reaching this point means the check ignored the downgrade.
            msg = (
                "no out-of-band callback service is available; the check should report "
                "its downgraded (L1) behaviour instead of requesting a token"
            )
            raise ProofRefused(msg)
        if self._service is not None:
            token = self._service.issue(self.scan_id, self.check_id, nonce=self._run_nonce)
            url = None
        else:
            token = CallbackToken(
                self.scan_id, self.check_id, self._run_nonce or secrets.token_hex(12)
            )
            url = f"{self._callback_base}/{token.value}"
        self._ledger.record_oob_probe(token.value, check_id=self.check_id, nonce=token.nonce)
        return OobToken(token=token, url=url)

    async def oob_consume(self, token: CallbackToken | str) -> OobHit | None:
        """Match the hit for ``token`` — single use (REQ-PROOF-005)."""
        self._require(ProofLevel.L2, "out-of-band callback matching")
        value = token.value if isinstance(token, CallbackToken) else str(token)
        if self._service is not None:
            hit = self._service.consume(value)
        else:
            if self._callback_base is None or self._http is None:
                raise ProofRefused("no callback service is reachable to match this token")
            exchange = await self._http.get(f"{self._callback_base}/hits?token={value}")
            hit = _hit_from_json(getattr(exchange, "body", ""))
            if hit is None:
                return None
        if hit is not None:
            self._ledger.mark_oob_consumed(value, hit.to_dict())
        return hit

    # ------------------------------------------------------------------ L3+
    def command_proof(self) -> CommandProof:
        """The one-shot allowlisted command proof (L3+, REQ-PROOF-007)."""
        self._require(ProofLevel.L3, "the one-shot command proof")
        return CommandProof(
            check_id=self.check_id,
            scan_id=self.scan_id,
            auditor=self._auditor,
            nonce=self._run_nonce,
        )

    # ------------------------------------------------------------------ L4+
    def sql(self, executor: SqlExecutor) -> SqlProof:
        """The L4 state-change helper; refused without the state-change authorization."""
        self._require(ProofLevel.L4, "state-changing proofs (L4)")
        if not self._state_changes_authorized:
            msg = (
                "the scan's attestation does not authorize state changes "
                "(state_changes_authorized); the L4 helper is unavailable"
            )
            raise ProofRefused(msg)
        return SqlProof(
            executor=executor, ledger=self._ledger, check_id=self.check_id, auditor=self._auditor
        )

    # ------------------------------------------------------------------ internals
    def _require(self, minimum: ProofLevel, capability: str) -> None:
        if not self.level.at_least(minimum):
            msg = (
                f"check {self.check_id!r} declares proof {self.level.value}; {capability} "
                f"requires {minimum.value} — the capability boundary refuses the escalation"
            )
            raise ProofRefused(msg)


def _hit_from_json(body: str) -> OobHit | None:
    """Parse a ``/hits`` response from the standalone callback server."""
    import json
    from datetime import UTC, datetime

    if not body.strip():
        return None
    try:
        data = json.loads(body)
    except ValueError:
        return None
    if not isinstance(data, dict) or not data.get("found"):
        return None
    hit = data.get("hit") or {}
    received = hit.get("received_at")
    parsed = None
    if isinstance(received, str) and received:
        try:
            parsed = datetime.fromisoformat(received.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            parsed = None
    return OobHit(
        token=str(hit.get("token") or ""),
        received_at=parsed or datetime.now(UTC),
        method=str(hit.get("method") or "GET"),
        source=hit.get("source"),
        path=str(hit.get("path") or "/"),
        query=str(hit.get("query") or ""),
        headers=dict(hit.get("headers") or {}),
        body=str(hit.get("body") or ""),
    )
