"""The credential broker: the only thing on a scan that may touch credential material (S19).

A check never receives a credential. It receives :attr:`CheckContext.credentials` — this
broker — and asks it for an *outcome*:

* ``await broker.login(...)`` performs a web login flow and returns a
  :class:`~arachne.creds.session.WebSession` (whether a session was established, whether it
  survived, what it reached). The cookie itself lives in the HTTP client's own jar.
* ``await broker.authenticate(authenticator, ...)`` drives a raw-protocol authentication
  attempt. The *protocol* byte-work stays in the module layer (the check builds the
  authenticator); the *secret handling* stays here: this method reads the material, calls
  ``authenticator.attempt(username, password)`` and drops it. So an SMB check can prove
  "these credentials are accepted" without ever holding them.

Every decision is audited: which label was released, for which target, and every refusal —
a credential that is not scoped to the target, a label this node does not hold, a revoked
entry (REQ-CREDS-005, REQ-CREDS-003). The audit records carry the label and the scope
summary, never material.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Protocol
from urllib.parse import urlsplit

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import CredentialError, CredentialScopeError
from arachne.core.logging import get_logger
from arachne.core.vault import (
    WEB_CREDENTIAL_KINDS,
    CredentialHandle,
    CredentialStore,
    release_seam,
)
from arachne.creds.session import (
    DEFAULT_PASSWORD_FIELDS,
    DEFAULT_USER_FIELDS,
    LoginSpec,
    LogoutOutcome,
    WebSession,
    ensure_authenticated,
    perform_login,
    perform_logout,
    session_intact,
)

__all__ = [
    "PROTOCOL_KINDS",
    "Authenticator",
    "CredentialBroker",
    "LogoutOutcome",
    "ProtocolAuthResult",
]

_logger = get_logger("creds.broker")

#: Which credential kind a raw-protocol authenticator may draw on.
PROTOCOL_KINDS: Mapping[str, tuple[str, ...]] = {
    "smb": ("smb",),
    "ssh": ("ssh",),
}


@dataclass(frozen=True, slots=True)
class ProtocolAuthResult:
    """The outcome of a credentialed protocol attempt — a verdict, never a value."""

    protocol: str
    endpoint: str
    #: Whether an attempt was made at all. ``False`` means no credential was available for
    #: this target (unconfigured, out of scope, revoked) and the check should report that
    #: distinctly from "the credentials were refused".
    attempted: bool = True
    #: Whether the peer accepted the credential.
    accepted: bool = False
    #: The peer's own status name, e.g. ``STATUS_LOGON_FAILURE``.
    status_name: str = ""
    detail: str = ""
    #: Redacted exchanges the attempt produced (for the finding's evidence).
    exchanges: tuple[Any, ...] = ()
    #: Which credential label was used (a label, never material).
    label: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "endpoint": self.endpoint,
            "attempted": self.attempted,
            "accepted": self.accepted,
            "status_name": self.status_name,
            "detail": self.detail,
            "label": self.label,
        }


class Authenticator(Protocol):
    """A raw-protocol authentication attempt, supplied by the check that owns the protocol.

    The module layer implements this with its own wire helpers (the SMB conversation lives in
    ``arachne.modules.m2``); the broker calls :meth:`attempt` with the material and never
    hands it anywhere else. ``endpoint`` is the ``host:port`` (or service key) the attempt
    targets, used for scope selection and for the audit record. ``extra`` carries the
    credential's additional fields (an SMB domain, say) — the same values a web login flow
    submits as extra form fields.
    """

    protocol: str
    endpoint: str

    async def attempt(
        self, username: str, password: str, extra: Mapping[str, str]
    ) -> ProtocolAuthResult: ...


@dataclass
class _Refusal:
    label: str
    reason: str


@dataclass
class CredentialBroker:
    """Per-scan credential selection, release and auditing (built by the checks handler).

    ``labels`` are the credential labels the scan named (``ScanOptions.credentials``) — a
    scan never carries material, only labels. ``targets`` are the URLs and hosts the scan
    declared, which is what a credential's scope is checked against: a credential that
    covers none of them cannot be used for this scan at all, and that refusal is audited
    once rather than silently degrading every check into an anonymous one.
    """

    store: CredentialStore | None = None
    labels: Sequence[str] = ()
    auditor: Auditor | None = None
    scan_id: int | None = None
    targets: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    session: WebSession | None = None
    refusals: list[_Refusal] = field(default_factory=list)

    # ------------------------------------------------------------------ selection
    @property
    def configured(self) -> bool:
        """True when the scan named at least one credential and this node holds a vault."""
        return bool(self.labels) and self.store is not None

    def selected_labels(self, kinds: Iterable[str] | None = None) -> tuple[str, ...]:
        """The scan's labels whose kind is in ``kinds`` (all of them when ``None``)."""
        if self.store is None:
            return ()
        wanted = set(kinds) if kinds is not None else None
        found: list[str] = []
        for label in self.labels:
            entry = self.store.get(label)
            if entry is None or not entry.active:
                continue
            if wanted is None or entry.kind in wanted:
                found.append(label)
        return tuple(found)

    def validate_selection(self) -> tuple[str, ...]:
        """Drop (and audit) every named credential this scan cannot legitimately use.

        Two refusals are recorded here, once per scan rather than once per check: a label
        this node's vault does not hold (``credential.unresolved`` — the internal-agent case,
        REQ-CREDS-003) and a held credential whose scope covers no declared target of this
        scan (``credential.scope_rejected``, REQ-CREDS-005). Returns the usable labels.
        """
        usable: list[str] = []
        for label in self.labels:
            entry = self.store.get(label) if self.store is not None else None
            if entry is None:
                self._refuse(
                    label,
                    (
                        "this node has no credential vault, so it does not hold that "
                        "credential (it is never fetched from another node)"
                        if self.store is None
                        else "this node's vault does not hold that credential (it is never "
                        "fetched from another node)"
                    ),
                    action=AuditAction.CREDENTIAL_UNRESOLVED,
                )
                continue
            if not entry.active:
                self._refuse(
                    label,
                    "the credential is revoked",
                    action=AuditAction.CREDENTIAL_SCOPE_REJECTED,
                )
                continue
            if not entry.scope.covers_any(hosts=self.hosts, urls=self.targets):
                self._refuse(
                    label,
                    f"the credential is scoped to {entry.scope.describe()}, which covers none "
                    "of this scan's targets",
                    action=AuditAction.CREDENTIAL_SCOPE_REJECTED,
                )
                continue
            usable.append(label)
        return tuple(usable)

    def handle_for(
        self, kinds: Iterable[str] | None, *, url: str | None = None, host: str | None = None
    ) -> CredentialHandle | None:
        """The first usable handle of a matching kind that covers the target, else ``None``.

        A held credential that does not cover the target is a refusal, recorded and audited
        — not a quiet ``None`` — so an operator can tell "nothing was configured" from "the
        credential was not allowed here".
        """
        if self.store is None:
            return None
        for label in self.selected_labels(kinds):
            try:
                handle = self.store.resolve(label, url=url, host=host)
            except CredentialScopeError as exc:
                self._refuse(label, str(exc), action=AuditAction.CREDENTIAL_SCOPE_REJECTED)
                continue
            except CredentialError as exc:  # a revoked entry, or a vault that cannot read
                self._refuse(label, str(exc), action=AuditAction.CREDENTIAL_SCOPE_REJECTED)
                continue
            if handle is None:
                continue
            self._audit(
                AuditAction.CREDENTIAL_RELEASED,
                scan_id=self.scan_id,
                target=url or host,
                meta={
                    "label": handle.label,
                    "kind": handle.kind,
                    "scope": handle.scope.describe(),
                    "host": host,
                },
            )
            return handle
        return None

    # ------------------------------------------------------------------ web
    async def login(
        self,
        *,
        client: Any,
        inventory: Any,
        url: str,
        kinds: Iterable[str] = WEB_CREDENTIAL_KINDS,
        user_fields: Iterable[str] = DEFAULT_USER_FIELDS,
        password_fields: Iterable[str] = DEFAULT_PASSWORD_FIELDS,
        logout_url: str | None = None,
    ) -> WebSession | None:
        """Authenticate against ``url``'s origin and return the session, or ``None``.

        ``None`` means "this scan is not authenticated": no credential was selected, none
        covered the origin, or the login was refused. Everything that happened is on the
        audit trail and in the returned session's notes where there is one, so a check that
        finds the authenticated surface empty can say *why*.
        """
        if not self.configured:
            return None
        origin = _origin_of(url)
        handle = self.handle_for(kinds, url=url)
        if handle is None:
            return None
        material = handle.material(release_seam())
        spec = self._login_spec(handle, inventory=inventory, origin=origin, logout_url=logout_url)
        if spec is None:
            self._refuse(
                handle.label,
                "no login form was found on the origin and the credential declares no login flow",
                action=AuditAction.CREDENTIAL_SCOPE_REJECTED,
            )
            return None
        if not spec.url:
            self._refuse(
                handle.label,
                "the login flow has no URL",
                action=AuditAction.CREDENTIAL_SCOPE_REJECTED,
            )
            return None
        outcome = await perform_login(client, spec, material)
        session = WebSession(
            label=handle.label,
            kind=handle.kind,
            origin=origin,
            spec=spec,
            authenticated=outcome.ok,
            login_status=outcome.status,
            login_attempts=1,
            login_exchanges=outcome.exchanges,
        )
        session.note(outcome.reason)
        if spec.detected:
            session.note("the login flow was detected from the crawl's own forms")
        self.session = session
        self._audit(
            (
                AuditAction.AUTH_SESSION_ESTABLISHED
                if outcome.ok
                else AuditAction.CREDENTIAL_SCOPE_REJECTED
            ),
            outcome=AuditOutcome.ALLOWED if outcome.ok else AuditOutcome.BLOCKED,
            scan_id=self.scan_id,
            target=origin,
            reason=None if outcome.ok else outcome.reason,
            meta={
                "label": handle.label,
                "kind": handle.kind,
                "status": outcome.status,
                "verified": outcome.verified,
                "login": spec.to_dict(),
            },
        )
        return session

    async def keep_alive(self, *, client: Any, session: WebSession | None = None) -> bool:
        """Re-establish the session if it has expired (REQ-CREDS-001 session keep-alive)."""
        live = session or self.session
        if live is None or self.store is None:
            return False
        handle = self._handle_for_label(live.label)
        if handle is None:
            return live.authenticated
        was_authenticated = live.authenticated
        still = await ensure_authenticated(client, live, handle.material(release_seam()))
        if was_authenticated and live.expired_once:
            self._audit(
                AuditAction.AUTH_SESSION_EXPIRED,
                outcome=AuditOutcome.ALLOWED if still else AuditOutcome.ERROR,
                scan_id=self.scan_id,
                target=live.origin,
                reason=(
                    "the session had expired and was re-established"
                    if still
                    else "the session expired"
                ),
                meta={"label": live.label, "reauths": live.reauths},
            )
        return still

    async def probe_session(self, *, client: Any, session: WebSession | None = None) -> bool | None:
        """Is the session still authenticated? ``None`` when it cannot be told."""
        live = session or self.session
        if live is None:
            return None
        return await session_intact(client, live)

    async def logout(
        self, *, client: Any, session: WebSession | None = None
    ) -> LogoutOutcome | None:
        """Log out and report whether the session survived (``None`` = cannot be told)."""
        live = session or self.session
        if live is None:
            return None
        outcome = await perform_logout(client, live)
        if outcome is not None:
            self._audit(
                AuditAction.AUTH_LOGOUT_OBSERVED,
                outcome=AuditOutcome.ALLOWED if outcome.survived else AuditOutcome.BLOCKED,
                scan_id=self.scan_id,
                target=outcome.url,
                reason=(
                    "the session still worked after the logout request"
                    if outcome.survived
                    else "the logout invalidated the session"
                ),
                meta={"label": live.label, "survived": outcome.survived},
            )
        return outcome

    # ------------------------------------------------------------------ protocols
    async def authenticate(
        self,
        authenticator: Authenticator,
        *,
        url: str | None = None,
        host: str | None = None,
        port: int | None = None,
    ) -> ProtocolAuthResult:
        """Offer a credential to ``authenticator`` (REQ-CREDS-004).

        The material is read here, passed to the authenticator for exactly one attempt, and
        dropped: the check that built the authenticator receives a
        :class:`ProtocolAuthResult`, never a username or a password.
        """
        endpoint = authenticator.endpoint
        if host is None and port is not None:
            host = f"{host}:{port}"
        kinds = PROTOCOL_KINDS.get(authenticator.protocol)
        if kinds is None:
            return ProtocolAuthResult(
                protocol=authenticator.protocol,
                endpoint=endpoint,
                attempted=False,
                detail=f"no credential kind drives a {authenticator.protocol!r} attempt",
            )
        if not self.configured:
            return ProtocolAuthResult(
                protocol=authenticator.protocol,
                endpoint=endpoint,
                attempted=False,
                detail="no credential was selected for this scan",
            )
        handle = self.handle_for(kinds, url=url, host=host)
        if handle is None:
            return ProtocolAuthResult(
                protocol=authenticator.protocol,
                endpoint=endpoint,
                attempted=False,
                detail=(
                    "no credential for this target: none is selected, none is scoped to it, "
                    "or this node does not hold the label"
                ),
            )
        material = handle.material(release_seam())
        result = await authenticator.attempt(
            material.username, material.secret_value(), material.extra_values()
        )
        self._audit(
            AuditAction.CREDENTIAL_RELEASED,
            outcome=AuditOutcome.ALLOWED if result.accepted else AuditOutcome.BLOCKED,
            scan_id=self.scan_id,
            target=endpoint,
            reason=None if result.accepted else f"{result.status_name or 'refused'}",
            meta={
                "label": handle.label,
                "kind": handle.kind,
                "protocol": authenticator.protocol,
                "accepted": result.accepted,
                "status": result.status_name,
            },
        )
        return ProtocolAuthResult(
            protocol=result.protocol or authenticator.protocol,
            endpoint=result.endpoint or endpoint,
            attempted=True,
            accepted=result.accepted,
            status_name=result.status_name,
            detail=result.detail,
            exchanges=result.exchanges,
            label=handle.label,
        )

    # ------------------------------------------------------------------ state
    def describe(self) -> dict[str, Any]:
        """Redacted broker state for the step's stats and the report's methodology block."""
        return {
            "labels": list(self.labels),
            "vault": self.store is not None,
            "session": self.session.to_dict() if self.session is not None else None,
            "refusals": [{"label": item.label, "reason": item.reason} for item in self.refusals],
        }

    # ------------------------------------------------------------------ internals
    def _handle_for_label(self, label: str) -> CredentialHandle | None:
        if self.store is None:
            return None
        try:
            return self.store.resolve(label)
        except CredentialError:
            return None

    def _login_spec(
        self,
        handle: CredentialHandle,
        *,
        inventory: Any,
        origin: str,
        logout_url: str | None,
    ) -> LoginSpec | None:
        """The declared login flow, else the one the crawl's own forms imply."""
        declared = handle.material(release_seam()).login
        spec: LoginSpec | None = None
        if declared:
            spec = LoginSpec.from_declaration(declared)
            if handle.kind == "web-json" and not declared.get("format"):
                # A ``web-json`` credential without an explicit format is a JSON login. The
                # spec is a slots dataclass, so it is copied with ``replace``, not ``__dict__``.
                spec = replace(spec, format="json")
        if spec is None and handle.kind == "web-form":
            # A form credential with no declaration: use the crawl's own login form.
            spec = LoginSpec.detect(inventory, origin=origin)
        if spec is None:
            return None
        if logout_url and not spec.logout_url:
            spec = replace(spec, logout_url=logout_url)
        return spec

    def _refuse(self, label: str, reason: str, *, action: AuditAction) -> None:
        self.refusals.append(_Refusal(label=label, reason=reason))
        _logger.warning(
            "credential refused",
            extra={"event": "credential.refused", "label": label, "reason": reason},
        )
        self._audit(
            action,
            outcome=AuditOutcome.BLOCKED,
            scan_id=self.scan_id,
            target=label,
            reason=reason,
        )

    def _audit(
        self,
        action: AuditAction,
        *,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        scan_id: int | None = None,
        target: str | None = None,
        reason: str | None = None,
        meta: Mapping[str, Any] | None = None,
    ) -> None:
        if self.auditor is None:
            return
        self.auditor.record(
            action,
            outcome=outcome,
            scan_id=scan_id,
            target=target,
            reason=reason,
            meta=dict(meta or {}),
        )


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}" if parts.netloc else ""
