"""Error model for ARACHNE.

Errors are data (```` §4): a failing check yields
``CheckResult(status="error")`` rather than crashing the scan (F-02-08 note). Every
exception that can cross a module boundary is therefore a subclass of
:class:`ArachneError`, and :func:`error_info` turns any exception into a bounded,
redacted, JSON-serializable record.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from arachne.core.redaction import redact_text

__all__ = [
    "ArachneError",
    "AuthorizationError",
    "BackupError",
    "BudgetExhaustedError",
    "CheckExecutionError",
    "ConfigurationError",
    "ContentPackError",
    "CredentialError",
    "CredentialScopeError",
    "ErrorCategory",
    "ErrorInfo",
    "EvidenceNotFoundError",
    "EvidenceStoreError",
    "FeedIntegrityError",
    "IdentityError",
    "IntegrityError",
    "NetProbeError",
    "OsintError",
    "OutOfScopeError",
    "PlanningError",
    "ReportError",
    "RequestError",
    "ResidencyError",
    "SafetyError",
    "ScanStateError",
    "SimulationError",
    "SimulationNetworkError",
    "StorageQuotaError",
    "UnsafeUrlError",
    "VaultLockedError",
    "error_info",
]

#: Upper bound on the size of an error message kept in findings/evidence. An error
#: string is target-influenced data and must never be allowed to bloat a report.
MAX_ERROR_MESSAGE = 500


class ErrorCategory(StrEnum):
    """Coarse classification used in evidence and audit records."""

    CONFIGURATION = "configuration"
    SAFETY = "safety"
    SCOPE = "scope"
    AUTHORIZATION = "authorization"
    LIFECYCLE = "lifecycle"
    REPORTING = "reporting"
    TRANSPORT = "transport"
    TIMEOUT = "timeout"
    #: A model provider failed, refused or produced unusable structured output (S9, F-04-*).
    #: Its own category so an audit can separate "the target misbehaved" from "the provider did".
    AI = "ai"
    INTERNAL = "internal"


class ArachneError(Exception):
    """Base class for every error ARACHNE raises deliberately."""

    category: ErrorCategory = ErrorCategory.INTERNAL


class ConfigurationError(ArachneError):
    """Invalid or missing configuration (env vars, settings)."""

    category = ErrorCategory.CONFIGURATION


class SafetyError(ArachneError):
    """A request or action was refused by a safety policy."""

    category = ErrorCategory.SAFETY

    def __init__(self, message: str, *, url: str | None = None, reason: str | None = None) -> None:
        super().__init__(message)
        self.url = url
        self.reason = reason or message


class UnsafeUrlError(SafetyError):
    """Target-supplied URL failed SSRF-by-design validation (F-08-03)."""


class OutOfScopeError(SafetyError):
    """Target is not inside the declared scan scope (F-01-02, F-01-09)."""

    category = ErrorCategory.SCOPE


class RequestError(ArachneError):
    """An HTTP request failed at the transport layer or timed out."""

    category = ErrorCategory.TRANSPORT


class NetProbeError(ArachneError):
    """A raw network probe (TCP/UDP/TLS) failed at the transport layer (S4, M2).

    The non-HTTP counterpart of :class:`RequestError`: M2's probes go through
    :class:`~arachne.core.net.ScopedNetClient`, and a refused, timed-out or reset
    connection is data about the target, not a crash. A check turns this into a
    ``status="error"`` result .
    """

    category = ErrorCategory.TRANSPORT


class CheckExecutionError(ArachneError):
    """A detection check raised; the orchestrator converts it to a status="error" result."""


class OsintError(ArachneError):
    """A third-party OSINT data source could not be queried (network, policy, quota).

    Raised by the provider layer (``arachne.modules.providers``). A check turns it into a
    ``status="error"`` result, so an unreachable index degrades one check instead of the
    whole scan .
    """

    category = ErrorCategory.TRANSPORT


class BudgetExhaustedError(ArachneError):
    """A configured budget (provider requests or API tokens) is spent; the check stops.

    Budgets are what make an opt-in, token-budgeted check (M1 code search, F-02-09) bounded
    by construction rather than by good intentions.
    """

    category = ErrorCategory.CONFIGURATION


class FeedIntegrityError(ArachneError):
    """A threat-intel feed payload did not verify (REQ-INTEL-002).

    Raised by ``arachne.intel.verify`` before an import: the digest or detached signature
    did not match what the deployment pinned, or no expectation was available to check
    against. The payload is refused — never partially imported — and the refusal is audited
    (``intel.feed_rejected``), because "the mirror served something different" is a security
    event, not a parsing detail.
    """

    category = ErrorCategory.SAFETY


class AuthorizationError(SafetyError):
    """The scan is not authorized for its declared scope (F-01-09, F-08-05).

    Raised by the attestation gate: no request leaves the process unless a complete
    authorization attestation (who / what scope / when) covers every declared target.
    """

    category = ErrorCategory.AUTHORIZATION


class PlanningError(ArachneError):
    """The scan plan could not be built (F-01-10)."""

    category = ErrorCategory.CONFIGURATION


class DetectionWindowError(SafetyError):
    """A purple-team detection test was refused by the coordinated window (S24, REQ-VALID-001).

    Raised when a purple action would run outside the detection window agreed with the
    defender — before it opens, after it closes, or with no window at all. A
    :class:`~arachne.core.safety`-family error on purpose: this is a boundary, not a
    configuration detail, and it must be as unbypassable as the scope gate. Every refusal is
    audited (``purple.window_refused``).
    """

    category = ErrorCategory.AUTHORIZATION


class ScanStateError(ArachneError):
    """A lifecycle transition was refused (unknown scan, illegal resume, F-01-04)."""

    category = ErrorCategory.LIFECYCLE


class IdentityError(ArachneError):
    """An identity/SSO operation was refused (S17, area IDAM: REQ-IDAM-001/002).

    Raised when an OIDC login cannot be established or verified — no IdP configured, a
    replayed or unknown ``state``, an ID token that fails signature/issuer/audience/nonce
    validation, or a valid login whose groups map to no role. The SSO routes turn it into
    a 401/403 and audit the refusal; the deny-by-default posture is the same one a wrong
    API key meets.
    """

    category = ErrorCategory.AUTHORIZATION


class ControlPlaneError(ArachneError):
    """The agent control plane refused or failed a call (S16, area SCALE).

    Raised by the HTTP control plane when the deployment answers with an unexpected
    status: an unregistered agent, a lost lease, an unavailable API. The agent loop
    treats it as retryable — a control-plane hiccup delays the fleet, it never weakens
    a gate.
    """

    category = ErrorCategory.TRANSPORT


class ReportError(ArachneError):
    """A report could not be built or rendered (F-06-*).

    Raised for a missing scan, a schema that no longer matches the DTO, or a renderer that
    was asked for a format this build does not ship. It is deliberately separate from a
    configuration error: a report is a deliverable, and "the scan you asked about does not
    exist" is an operator-facing answer, not a deployment fault.
    """

    category = ErrorCategory.REPORTING


class VaultLockedError(ConfigurationError):
    """The credential vault cannot be used (S19, area CREDS: REQ-CREDS-002).

    Raised when a vault is asked for on a deployment that configured no key, or when the
    key does not authenticate the vault file (a wrong key and a tampered file are
    indistinguishable by design). Refusing is the only safe answer: the alternative is
    storing or serving credentials in the clear.
    """


class CredentialError(ArachneError):
    """A credential could not be released or was asked for through the wrong seam.

    Raised for an unknown or revoked label, and when a caller tries to read a
    :class:`~arachne.core.vault.CredentialHandle`'s material without the broker's
    capability. Credentials are handed to checks as opaque scoped handles; this is the
    error that says that boundary was crossed (REQ-CREDS-002).
    """

    category = ErrorCategory.SAFETY


class CredentialScopeError(OutOfScopeError):
    """A credential exists but is not scoped to the target it was offered for.

    The credential half of F-01-02/REQ-CREDS-005: a scan may hold several credentials and
    each one is bound to the hosts or URL prefixes it was stored for, so an authenticated
    request can never be made against a target the credential was not declared for.
    Subclasses :class:`OutOfScopeError` on purpose — an out-of-scope credential is a scope
    refusal, and it must compose with the existing scope gate rather than beside it.
    """


class EvidenceStoreError(ArachneError):
    """The evidence backend could not complete an operation (S20, REQ-DATA-002).

    Raised for an unreachable object store, a refused write, a container that fails its
    integrity check, or a key that is not a content hash. Deliberately *not* swallowed: an
    evidence write that did not land is a scan whose findings lost their proof, and the
    caller has to be able to say so. (Read failures are the exception — see
    :class:`EvidenceNotFoundError`.)
    """

    category = ErrorCategory.TRANSPORT


class EvidenceNotFoundError(EvidenceStoreError):
    """The requested evidence object does not exist in the backend.

    Maps to 404 at the API boundary: an operator asked for a blob that retention pruned, a
    project deleted, or a backend that has since been pointed elsewhere.
    """


class StorageQuotaError(ArachneError):
    """A project has exhausted its storage quota (S20, REQ-DATA-003).

    Raised *before* an evidence write that would cross the hard limit, so nothing is
    written and the error is the whole outcome. The checks step lets it propagate: the scan
    machine marks the step failed and the scan ``failed``, which is resumable — raising the
    quota and re-running ``arachne scan --resume`` continues from the failed step instead of
    rescanning. The message names the project, the limit and the write that was refused,
    because it is the operator's whole diagnosis.
    """

    category = ErrorCategory.LIFECYCLE


class IntegrityError(ArachneError):
    """Tamper-evidence verification failed (S25, REQ-TRUST-005).

    Distinct from a *refusal*: this is raised when ``arachne verify-chain`` finds a
    modified, reordered or deleted record, and when a signed artifact fails to verify
    before use. A caller that sees it is holding evidence it cannot trust, so it is never
    swallowed — the whole point of the requirement is that the failure is loud.
    """

    category = ErrorCategory.SAFETY


class ContentPackError(ArachneError):
    """An offline content pack was refused (S25, REQ-RESIL-001).

    Raised for a missing or invalid signature, a digest that does not match the manifest,
    a manifest that names a file outside the pack, or a pack whose format version this
    build does not understand. **Fail-closed by construction**: an import that raises this
    has installed nothing at all, which is why the loader verifies the whole pack into a
    staging directory before it moves a single file into place.
    """

    category = ErrorCategory.CONFIGURATION


class ResidencyError(OutOfScopeError):
    """Evidence residency was violated (S25, REQ-RESIL-004).

    Raised when a project's rows are addressed from a deployment in another region, in
    either direction: a write from the wrong region, or a read/presign of a row pinned to a
    region this deployment does not serve. Subclasses :class:`OutOfScopeError` deliberately
    — a residency refusal *is* a scope refusal, and it must map to the same 403 at the API
    boundary rather than to a new status code.
    """


class BackupError(ArachneError):
    """A disaster-recovery bundle could not be created or restored (S25, REQ-RESIL-005).

    Raised for an unreadable bundle, a manifest digest that does not match what is inside,
    a bundle written by an older/newer format revision, or a restore refused because the
    target already holds data it would overwrite.
    """

    category = ErrorCategory.LIFECYCLE


class SimulationError(ArachneError):
    """A what-if simulation could not be built or run (S28, area SIM).

    Raised for a hypothesis document that does not parse, one that names a node the model
    does not hold, or a model request no scan data can answer. It is *not* the network
    refusal: a simulation that is asked to touch a target raises
    :class:`SimulationNetworkError` instead, so the two are distinguishable in an audit
    line and in a test.
    """

    category = ErrorCategory.CONFIGURATION


class SimulationNetworkError(SafetyError):
    """A simulation attempted network I/O and was refused (S28, REQ-SIM-003).

    Area SIM's P0 safety property is that the simulation engine is **structurally**
    incapable of reaching the network — no HTTP client, no socket — enforced at the code
    boundary and failing closed. This is the runtime half of that enforcement: the
    :func:`arachne.sim.boundary.no_network` guard denies every socket entry point for the
    duration of a simulation, so even a collaborator ARACHNE did not write (or a dependency
    that dials on import) cannot send a packet. The refusal is recorded as a blocked
    ``simulation.boundary_violation`` audit event before it propagates.

    Subclasses :class:`SafetyError` deliberately — a simulation reaching for the network
    *is* a safety refusal, and it must read as one wherever errors are classified.
    """


class FuzzRefused(SafetyError):  # noqa: N818 - a refusal is not an error condition
    """Fuzzing was refused before anything was sent (S30, area FUZZ, REQ-FUZZ-001).

    Area FUZZ inherits every gate a scan has and adds one of its own, so this is raised for
    the *fuzzing* refusals: no fuzzing attestation, one that does not cover the declared
    targets, an expired or future-dated grant, a target whose declared environment is not a
    non-production one (the default), or a fuzzing request against a target definition that
    carries no ordinary authorization attestation at all. The refusal is recorded as a blocked
    ``fuzz.refused`` audit event *before* it propagates, so "someone tried to fuzz without a
    grant" is answerable from the trail alone.

    Subclasses :class:`SafetyError` deliberately: an unattested fuzz is a safety refusal and
    must read as one wherever errors are classified.
    """

    category = ErrorCategory.SAFETY


class FuzzPayloadRefused(SafetyError):  # noqa: N818 - a refusal is not an error condition
    """A generated test case carried a prohibited payload (S30, REQ-FUZZ-001).

    The prohibition table applies to fuzzing exactly as it does to the proof ladder and to
    remediation: no destructive statement, no state-changing protocol operation, no shell
    metacharacter and no remaining-infrastructure payload may be *generated*, let alone sent.
    The check runs on the bytes the engine produced and before the egress call, so a payload
    that would be refused is caught inside the process — it is never written to a socket.
    Grammar-declared operation codes are additionally confined to their declared read-only
    allowlist, which makes "fuzzing can never select a write operation" a property of the
    grammar rather than of a reviewer's attention.
    """

    category = ErrorCategory.SAFETY


class FuzzBudgetExhaustedError(BudgetExhaustedError):
    """A hard fuzzing bound is spent: the run stops and reports (S30, REQ-FUZZ-001).

    Fuzzing's P0 requirement is that the bounds are *hard* — per-target wall-clock time,
    request and case budgets — so exhausting one **ends** the run rather than degrading it.
    The refusal is audited as a blocked ``fuzz.budget_exhausted`` event and the partial report
    is still returned, because "we stopped because we hit the ceiling" is a result.
    """

    category = ErrorCategory.CONFIGURATION


@dataclass(frozen=True, slots=True)
class ErrorInfo:
    """Bounded, redacted, serializable summary of an exception."""

    error_type: str
    message: str
    category: ErrorCategory = ErrorCategory.INTERNAL
    reason: str | None = None
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error_type": self.error_type,
            "message": self.message,
            "category": self.category.value,
        }
        if self.reason is not None:
            payload["reason"] = self.reason
        if self.context:
            payload["context"] = self.context
        return payload

    def summary(self) -> str:
        """One-line human-readable form used in ``CheckResult.detail``."""
        return f"{self.error_type}: {self.message}"


def error_info(exc: BaseException, *, context: dict[str, Any] | None = None) -> ErrorInfo:
    """Convert any exception into a redacted :class:`ErrorInfo`.

    Never includes a traceback: tracebacks can embed secrets and target data.
    """
    category = exc.category if isinstance(exc, ArachneError) else ErrorCategory.INTERNAL
    reason = exc.reason if isinstance(exc, SafetyError) else None
    message = redact_text(str(exc))[:MAX_ERROR_MESSAGE] or exc.__class__.__name__
    return ErrorInfo(
        error_type=exc.__class__.__name__,
        message=message,
        category=category,
        reason=reason,
        context=dict(context or {}),
    )
