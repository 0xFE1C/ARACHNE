"""The out-of-band callback service (REQ-PROOF-005).

A blind vulnerability (SSRF, XXE, blind SQLi) is proven when the *target* connects out
to ARACHNE's callback service. The service is deliberately minimal:

* **Tokens.** ``arachne-<scan-id>-<check-id>-<nonce>`` tokens
  (:class:`~arachne.core.proof.CallbackToken`); the nonce carries 96 bits of entropy, so
  the token itself is the authenticator — a hit can only be matched by whoever was told
  the token, and a forged token cannot land on a value a check is polling for.
* **Single use.** A token matches exactly one hit, exactly once:
  :meth:`CallbackService.consume` returns the hit and marks the token spent; a second
  consume is refused and audited as ``proof.oob_replay`` (the acceptance property:
  "tokens single-use").
* **Hits are captured, redacted, audited.** A hit records what arrived (method, source
  address, headers, body preview) through the same redaction every other capture uses
  (REQ-PROOF-012), and each step of the flow — issue, hit, replay — is an audit line.
* **It never dials out.** The service only *listens*. There is no outbound client, no
  webhook forwarding, no URL prefetch: a hit's content is stored redacted and nothing
  else happens to it. ``tests/test_proof_safety.py`` proves the no-fetch property by
  feeding hostile URLs into a hit while the socket constructor is armed to explode.
* **Rate-limited.** Token issuance is capped per scan, and hit ingestion runs through a
  sliding-window limiter, so a target cannot turn the callback service into a write
  amplifier.

Two run modes share this one class:

* **In-process** (tests, and single-node deployments that wire it into the handlers):
  checks get hits via :class:`~arachne.proof.access.ProofAccess` directly.
* **Standalone** (``arachne callback-server``, :mod:`arachne.proof.server`): the same
  class behind a tiny HTTP facade; checks consume over HTTP by token.
"""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any, Final

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.proof import (
    CallbackToken,
    parse_callback_token,
    per_scan_secret,
    token_mac,
)
from arachne.core.redaction import redact_mapping, redact_text
from arachne.core.signing import DeploymentSigner

__all__ = [
    "MAX_HITS_PER_WINDOW",
    "MAX_TOKENS_PER_SCAN",
    "REPLAY_WINDOW_SECONDS",
    "CallbackService",
    "OobHit",
    "OobProbe",
]

#: How long after its first use a token may still be *recognised* as a replay. Inside the
#: window a replayed callback is refused and counted as a replay (the original verdict
#: stands); outside it the token is dead and the callback is refused as expired. The window
#: is bounded on purpose: it is the interval in which "the same callback arrived twice" is a
#: network artifact rather than an attempt to resurrect a spent proof.
REPLAY_WINDOW_SECONDS: Final = 300.0

#: Body text kept per hit. Enough to identify the interaction (a marker, a token echo);
#: nowhere near enough to matter as exfiltration (REQ-PROOF-011: no bulk data).
MAX_HIT_BODY_CHARS = 2_000

#: Tokens one scan may have outstanding. A scan that wants more is misconfigured, and a
#: hostile check must not be able to grow the service without bound.
MAX_TOKENS_PER_SCAN = 256

#: Distinct tokens with recorded hits at once — the store is bounded (an operator reads
#: it; nothing iterates it unboundedly).
MAX_STORED_HITS = 4_096

#: Hit ingestion per sliding window: a target cannot turn the callback service into a
#: write amplifier. (A dedicated service sees one hit per callback; anything above this
#: rate is noise or an attack on ARACHNE.)
MAX_HITS_PER_WINDOW = 120
HIT_WINDOW_SECONDS = 60.0


class _HitRateLimiter:
    """Thread-safe sliding window; ``allow()`` is the only decision it makes."""

    def __init__(
        self, limit: int = MAX_HITS_PER_WINDOW, window: float = HIT_WINDOW_SECONDS
    ) -> None:
        self._limit = limit
        self._window = window
        self._events: list[float] = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            self._events = [stamp for stamp in self._events if now - stamp < self._window]
            if len(self._events) >= self._limit:
                return False
            self._events.append(now)
            return True


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class OobHit:
    """What the callback service saw when the target connected out."""

    token: str
    received_at: datetime
    method: str
    source: str | None
    path: str
    query: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Redacted, JSON-safe form (what evidence and the ledger carry)."""
        return {
            "token": self.token,
            "received_at": self.received_at.isoformat(),
            "method": self.method,
            "source": self.source,
            "path": self.path,
            "query": self.query,
            "headers": dict(self.headers),
            "body": self.body,
        }


@dataclass(frozen=True, slots=True)
class OobProbe:
    """One issued token and everything known about its interaction."""

    token: str
    scan_id: str
    check_id: str
    nonce: str
    issued_at: datetime
    consumed: bool = False
    hit: OobHit | None = None
    #: How many times a callback arrived after the token was already spent (WP-14,
    #: REQ-PROOF-019). Counted so "a replay happened" is a number an operator can alert on,
    #: while the probe's verdict stays exactly what the first callback established.
    replays: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "scan_id": self.scan_id,
            "check_id": self.check_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at.isoformat(),
            "consumed": self.consumed,
            "replays": self.replays,
            "hit": self.hit.to_dict() if self.hit is not None else None,
        }


class CallbackService:
    """Issues single-use OOB tokens and matches the hits that come back.

    Thread-safe: the standalone server answers hits on worker threads while checks
    consume on their own.
    """

    def __init__(
        self,
        *,
        auditor: Auditor | None = None,
        hit_limiter: _HitRateLimiter | None = None,
        max_tokens_per_scan: int = MAX_TOKENS_PER_SCAN,
        signer: DeploymentSigner | None = None,
        scan_gate: Callable[[str], str | None] | None = None,
        replay_window_s: float = REPLAY_WINDOW_SECONDS,
    ) -> None:
        self._auditor = auditor
        self._hit_limiter = hit_limiter or _HitRateLimiter()
        self._max_tokens_per_scan = max_tokens_per_scan
        #: The deployment key the per-scan callback secrets are derived from
        #: (REQ-PROOF-019). ``None`` means this deployment mints unauthenticated tokens —
        #: the nonce is then the only authenticator, exactly as it was before this package.
        self._signer = signer
        #: Asked whether a scan may still receive a callback: it returns a refusal reason or
        #: ``None`` for "active". The receiver asks it before anything else, so a scan that
        #: is gone, not running, or whose attestation has expired is refused *and audited*
        #: rather than matched.
        self._scan_gate = scan_gate
        self.replay_window_s = float(replay_window_s)
        self._lock = threading.Lock()
        self._probes: dict[str, OobProbe] = {}
        self._issued_per_scan: dict[str, int] = {}
        self._hits: dict[str, OobHit] = {}
        self._consumed: set[str] = set()
        #: When each token was consumed (monotonic), for the bounded replay window.
        self._consumed_at: dict[str, float] = {}
        #: Per-scan secrets minted in-process, for a deployment with no deployment key: an
        #: in-process service still authenticates its own tokens, it just cannot authenticate
        #: another process's.
        self._secrets: dict[str, str] = {}

    # ------------------------------------------------------------------ authentication
    def secret_for(self, scan_id: str | int) -> str | None:
        """The per-scan secret this receiver can authenticate ``scan_id`` with.

        Registered secrets (this process minted a token for the scan) win; otherwise the
        secret is derived from the deployment key, so a *separate* callback-server process
        authenticates the scanner's tokens without ever being told them. ``None`` means this
        receiver has no way to authenticate that scan at all.
        """
        label = str(scan_id)
        with self._lock:
            registered = self._secrets.get(label)
        if registered is not None:
            return registered
        return per_scan_secret(self._signer, label)

    def register_scan_secret(self, scan_id: str | int, secret: str) -> None:
        """Pin one scan's secret (a caller that derived it out of band can hand it over)."""
        with self._lock:
            self._secrets[str(scan_id)] = secret

    def _authenticate(self, token: CallbackToken) -> str | None:
        """``None`` when the token is authentic, else the refusal reason (REQ-PROOF-019)."""
        secret = self.secret_for(token.scan_id)
        if secret is None:
            if token.mac is not None:
                return (
                    f"callback for scan {token.scan_id} carries a per-scan secret this "
                    "receiver cannot verify (no deployment key and no registration)"
                )
            return None
        if token.mac is None:
            return (
                f"callback for scan {token.scan_id} carries no per-scan secret, but this "
                "receiver can derive one for that scan: the token is not authentic"
            )
        if not hmac.compare_digest(token.mac, token_mac(secret, token.base)):
            return f"callback for scan {token.scan_id} presented the wrong scan secret"
        return None

    # ------------------------------------------------------------------ issuance
    def issue(
        self, scan_id: str | int, check_id: str, *, nonce: str | None = None
    ) -> CallbackToken:
        """Mint one token for ``(scan, check)``; audited, and rate-limited per scan.

        ``nonce`` (S24) pins the token's visible tag to a caller-supplied value — the
        purple-team run nonce every emitted artifact must carry (REQ-VALID-003). It is
        validated against the same alphabet as a generated one, so a caller cannot smuggle
        a payload-shaped "nonce" into a token, and a purple run's artifacts share one
        readable tag.
        """
        generated = nonce or secrets.token_hex(12)
        secret = self.secret_for(scan_id)
        if secret is None:
            # No deployment key: mint a per-scan secret for *this* process, so an in-process
            # deployment still authenticates its own callbacks. What a keyless deployment
            # cannot authenticate is another process's token, and the receiver says so
            # instead of accepting it.
            with self._lock:
                secret = self._secrets.setdefault(str(scan_id), secrets.token_hex(16))
        base = CallbackToken(scan_id, check_id, generated).base
        token = CallbackToken(scan_id, check_id, generated, token_mac(secret, base))
        with self._lock:
            issued = self._issued_per_scan.get(token.scan_id, 0)
            if issued >= self._max_tokens_per_scan:
                msg = (
                    f"scan {token.scan_id} already issued {issued} OOB tokens; the "
                    f"per-scan cap is {self._max_tokens_per_scan}"
                )
                raise OverflowError(msg)
            self._issued_per_scan[token.scan_id] = issued + 1
            self._probes[token.value] = OobProbe(
                token=token.value,
                scan_id=token.scan_id,
                check_id=check_id,
                nonce=token.nonce,
                issued_at=_now(),
            )
        self._audit(AuditAction.PROOF_OOB_ISSUED, token=token.value, meta={"check": check_id})
        return token

    def issue_nonce(self, scan_id: str | int, check_id: str) -> tuple[CallbackToken, str]:
        """``(token, nonce)`` — the nonce alone is what payloads embed."""
        token = self.issue(scan_id, check_id)
        return token, token.nonce

    # ------------------------------------------------------------------ hit capture
    def record_hit(
        self,
        token_value: str,
        *,
        method: str = "GET",
        path: str | None = None,
        query: str = "",
        source: str | None = None,
        headers: dict[str, str] | None = None,
        body: str = "",
    ) -> OobHit | None:
        """Record an inbound interaction for ``token_value``; ``None`` when refused.

        Four gates, in order, each of which refuses *and audits* (REQ-PROOF-019):

        1. **Shape.** Anything that is not an ``arachne-…`` token is refused.
        2. **The scan.** ``scan_gate`` is asked whether this scan may still receive a
           callback at all — an unknown scan, one that is not active, or one whose
           attestation has expired is refused here, before anything is stored.
        3. **The per-scan secret.** When this receiver can obtain one for the scan, the token
           must carry a MAC that verifies against it; a missing or wrong authenticator is
           refused as a forgery. A deployment with no key cannot authenticate at all, and
           then the 96-bit nonce is the authenticator — as it was before this package.
        4. **Single use.** A callback that arrives after the token was spent is refused and
           counted as a replay inside the bounded replay window, and refused as expired
           outside it. Either way the first callback's verdict stands.

        The captured payload is redacted *at capture* like every other evidence path
        (REQ-PROOF-012), and ingestion is rate-limited so a target cannot flood the ledger.
        """
        try:
            token = parse_callback_token(token_value)
        except Exception:
            self._audit(
                AuditAction.PROOF_OOB_HIT,
                outcome=AuditOutcome.BLOCKED,
                token=token_value[:120],
                reason="refused: not a well-formed arachne callback token",
            )
            return None
        # REQ-PROOF-019, in the order that keeps the decision cheap and complete: is the
        # scan still allowed to receive a callback at all, is the token authentic, and has
        # it already been spent?
        refusal = self._gate_reason(token)
        if refusal is not None:
            self._audit(
                AuditAction.PROOF_OOB_REFUSED,
                outcome=AuditOutcome.BLOCKED,
                scan_id=token.scan_id,
                token=token.value[:160],
                reason=refusal,
            )
            return None
        if not self._hit_limiter.allow():
            self._audit(
                AuditAction.PROOF_OOB_HIT,
                outcome=AuditOutcome.BLOCKED,
                token=token_value,
                reason="callback hit rate limit exhausted",
            )
            return None
        # Redact first, then bound: a [REDACTED:…] placeholder is longer than the secret
        # it replaced, so the cap has to be applied to the *stored* text.
        hit = OobHit(
            token=token_value,
            received_at=_now(),
            method=method[:32],
            source=None if source is None else redact_text(source),
            path=redact_text(path or "/"),
            query=redact_text(query),
            headers=redact_mapping(dict(headers or {})),
            body=redact_text(body)[:MAX_HIT_BODY_CHARS],
        )
        with self._lock:
            if token_value in self._consumed:
                replayed = True
                age = time.monotonic() - self._consumed_at.get(token_value, 0.0)
                probe = self._probes.get(token_value)
                if probe is not None:
                    self._probes[token_value] = replace(probe, replays=probe.replays + 1)
            else:
                replayed = False
                age = 0.0
                if len(self._hits) < MAX_STORED_HITS or token_value in self._hits:
                    self._hits[token_value] = hit
                probe = self._probes.get(token_value)
                if probe is not None:
                    self._probes[token_value] = replace(probe, hit=hit)
        if replayed:
            within_window = age <= self.replay_window_s
            self._audit(
                AuditAction.PROOF_OOB_REPLAY if within_window else AuditAction.PROOF_OOB_REFUSED,
                outcome=AuditOutcome.BLOCKED,
                scan_id=token.scan_id,
                token=token_value,
                reason=(
                    "hit arrived after the token was consumed (single-use; replay counted, "
                    "the first verdict stands)"
                    if within_window
                    else "hit arrived after the token's replay window closed (expired)"
                ),
                meta={"replay_window_s": self.replay_window_s, "age_s": round(age, 3)},
            )
            return None
        self._audit(AuditAction.PROOF_OOB_HIT, token=token_value, meta={"method": method})
        return hit

    # ------------------------------------------------------------------ admission
    def _gate_reason(self, token: CallbackToken) -> str | None:
        """``None`` when the callback may proceed, else why it is refused (REQ-PROOF-019)."""
        if self._scan_gate is not None:
            try:
                reason = self._scan_gate(token.scan_id)
            except Exception as exc:  # a gate that cannot answer refuses; it never allows
                reason = f"the scan gate could not decide: {type(exc).__name__}"
            if reason:
                return f"refused: {reason}"
        return self._authenticate(token)

    # ------------------------------------------------------------------ matching
    def consume(self, token_value: str) -> OobHit | None:
        """Return the hit for ``token_value`` — once. Single use is the contract."""
        with self._lock:
            hit = self._hits.get(token_value)
            if hit is None:
                return None
            if token_value in self._consumed:
                spent = True
            else:
                spent = False
                self._consumed.add(token_value)
                self._consumed_at[token_value] = time.monotonic()
                probe = self._probes.get(token_value)
                if probe is not None:
                    self._probes[token_value] = replace(probe, consumed=True)
        if spent:
            self._audit(
                AuditAction.PROOF_OOB_REPLAY,
                outcome=AuditOutcome.BLOCKED,
                token=token_value,
                reason="token already consumed (single-use)",
            )
            return None
        return hit

    def probe(self, token_value: str) -> OobProbe | None:
        """The probe record (issued/consumed/hit) without consuming."""
        with self._lock:
            return self._probes.get(token_value)

    def probes_for(self, scan_id: str | int) -> tuple[OobProbe, ...]:
        """Every probe issued for one scan — the nonce→probe map of REQ-PROOF-012."""
        label = str(scan_id)
        with self._lock:
            return tuple(probe for probe in self._probes.values() if probe.scan_id == label)

    def outstanding(self, scan_id: str | int) -> int:
        """Tokens issued but never consumed for one scan (the cleanup-relevant count)."""
        return sum(1 for probe in self.probes_for(scan_id) if not probe.consumed)

    # ------------------------------------------------------------------ internals
    def _audit(self, action: AuditAction, *, token: str, **kwargs: Any) -> None:
        if self._auditor is None:
            return
        self._auditor.record(action, target=token, **kwargs)
