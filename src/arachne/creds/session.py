"""Credentialed web scanning: login flows, session keep-alive, logout detection (S19).

This is where a credential becomes an authenticated session — and the only place in the
build where a web credential is handled. It is called by the credential broker (never by a
check), and it hands back derived state: a :class:`WebSession` describing whether a session
was established, whether it is still alive, and what the authenticated surface looks like.
The session *cookie itself never appears here*: requests go through the scan's
:class:`~arachne.core.http.ScopedHttpClient`, whose ``httpx`` client stores ``Set-Cookie``
in its own jar and replays it, and whose exchange evidence blanks ``set-cookie``/``cookie``
at capture time. Nothing in this module can read the session token, so nothing can leak it.

Three requirements meet here (REQ-CREDS-001):

``login``
    A form or JSON login flow. The flow is *declared* per credential where the operator
    knows it (``login`` in the vault entry) and otherwise **detected** from the crawl's own
    forms (:meth:`~arachne.modules.m3.inventory.WebInventory.login_forms`), which is what
    makes "point a credential at a login form" work without hand-written per-app config.
``session keep-alive``
    :func:`ensure_authenticated` re-probes the session's integrity and re-logs-in when it has
    expired, so a long scan does not silently degrade into an anonymous one.
``logout detection``
    :func:`perform_logout` logs out and then re-probes: a session that still works after a
    logout is the finding (CWE-613, insufficient session expiration).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode, urljoin, urlsplit

from arachne.core.logging import get_logger
from arachne.core.vault import CredentialMaterial

__all__ = [
    "DEFAULT_PASSWORD_FIELDS",
    "DEFAULT_USER_FIELDS",
    "LoginSpec",
    "LogoutOutcome",
    "WebAuthOutcome",
    "WebSession",
    "ensure_authenticated",
    "login_form_present",
    "perform_login",
    "perform_logout",
    "session_intact",
]

_logger = get_logger("creds.session")

#: Field names a login form may use. Detection only — nothing here is a credential.
DEFAULT_USER_FIELDS: tuple[str, ...] = (
    "username",
    "user",
    "userid",
    "user_name",
    "email",
    "login",
    "uname",
    "account",
)
DEFAULT_PASSWORD_FIELDS: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "pass",
    "userpass",
    "secret",
)

#: Status codes that mean "the application accepted the attempt" when a spec does not say.
_ACCEPT_STATUS = (200, 204, 302, 303)
#: Status codes that mean "it refused" when a spec does not say.
_REFUSE_STATUS = (401, 403)
#: A session can be re-established this many times before a check is told it degraded.
MAX_REAUTHS = 2
#: Body text that proves a login form is still being served (case-insensitive).
_PASSWORD_INPUT_MARKERS = ('type="password"', "type='password'", "type=password")


def login_form_present(body: str) -> bool:
    """True when ``body`` still serves a password input (the session is not established)."""
    lowered = body.lower()
    return any(marker in lowered for marker in _PASSWORD_INPUT_MARKERS)


# --------------------------------------------------------------------------- the spec
@dataclass(frozen=True, slots=True)
class LoginSpec:
    """How to authenticate against one web origin: declared, or detected from the crawl.

    Deliberately a value object with no secret in it: it is stored in the vault's ``login``
    block (plumbing) or derived from a crawled form, and it is safe to render in a finding.
    """

    url: str
    method: str = "POST"
    #: ``form`` (urlencoded) or ``json``.
    format: str = "form"
    username_field: str = "username"
    #: The *name* of the password field. Not a credential (bandit flags the word).
    password_field: str = "password"  # noqa: S105
    #: Names of additional fields to submit, taken from the credential's ``extra`` block.
    extra_fields: tuple[str, ...] = ()
    success_statuses: tuple[int, ...] = _ACCEPT_STATUS
    failure_statuses: tuple[int, ...] = _REFUSE_STATUS
    #: Body text that means the attempt failed even though the status looked fine.
    failure_markers: tuple[str, ...] = ()
    #: A URL that is only reachable with a session — the strongest keep-alive signal.
    protected_url: str | None = None
    #: Where a logout lives, when the operator declared it (detection is heuristic).
    logout_url: str | None = None
    #: Whether to follow the login redirect (off: the 302 and its ``Set-Cookie`` are the
    #: evidence, and the cookie jar records it either way).
    follow_redirects: bool = False
    #: True when the spec was detected from a crawled form rather than declared.
    detected: bool = False

    @property
    def kind(self) -> str:
        return "json" if self.format == "json" else "form"

    @classmethod
    def from_declaration(cls, data: Mapping[str, Any]) -> LoginSpec:
        """Build from the vault entry's ``login`` block (unknown keys are ignored)."""
        return cls(
            url=str(data.get("url") or ""),
            method=str(data.get("method") or "POST").upper(),
            format=str(data.get("format") or "form").lower(),
            username_field=str(data.get("username_field") or "username"),
            password_field=str(data.get("password_field") or "password"),
            extra_fields=tuple(str(name) for name in data.get("extra_fields") or ()),
            success_statuses=tuple(
                int(code) for code in data.get("success_statuses") or _ACCEPT_STATUS
            ),
            failure_statuses=tuple(
                int(code) for code in data.get("failure_statuses") or _REFUSE_STATUS
            ),
            failure_markers=tuple(str(item) for item in data.get("failure_markers") or ()),
            protected_url=str(data["protected_url"]) if data.get("protected_url") else None,
            logout_url=str(data["logout_url"]) if data.get("logout_url") else None,
            follow_redirects=bool(data.get("follow_redirects") or False),
            detected=False,
        )

    @classmethod
    def detect(
        cls,
        inventory: Any,
        *,
        origin: str,
        user_fields: Iterable[str] = DEFAULT_USER_FIELDS,
        password_fields: Iterable[str] = DEFAULT_PASSWORD_FIELDS,
    ) -> LoginSpec | None:
        """The first login form the crawl found on ``origin``, as a spec.

        Detection is deliberately conservative: only a form carrying both a password input
        and a user-ish input counts (:meth:`WebInventory.login_forms`), the field names come
        from the form itself rather than a guess, and the first match in crawl order wins so
        a scan is reproducible.
        """
        if inventory is None:
            return None
        forms = inventory.login_forms(user_fields=user_fields, password_fields=password_fields)
        for form in forms:
            page = _origin_of(form.action or form.page_url)
            if page != origin:
                continue
            password = form.password_inputs()
            if not password:
                continue
            password_name = password[0].name
            user_name = form.any_input_named(user_fields)
            if not user_name:
                continue
            action = form.action or form.page_url
            return cls(
                url=urljoin(form.page_url, action),
                method=(form.method or "POST").upper(),
                format="form",
                username_field=user_name,
                password_field=password_name,
                detected=True,
            )
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "format": self.format,
            "username_field": self.username_field,
            "password_field": self.password_field,
            "extra_fields": list(self.extra_fields),
            "protected_url": self.protected_url,
            "logout_url": self.logout_url,
            "detected": self.detected,
        }


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}" if parts.netloc else ""


# --------------------------------------------------------------------------- outcomes
@dataclass(frozen=True, slots=True)
class WebAuthOutcome:
    """What a login attempt produced — reasons and redacted evidence, never a value."""

    ok: bool
    status: int | None
    reason: str
    spec: LoginSpec | None = None
    #: The redacted exchange(s) the attempt produced, for the finding's evidence.
    exchanges: tuple[Any, ...] = ()
    #: True when a second request confirmed the session (a protected URL, or the login page
    #: no longer serving a form).
    verified: bool = False


@dataclass(frozen=True, slots=True)
class LogoutOutcome:
    """What a logout attempt established: did the session survive it?"""

    survived: bool
    url: str
    exchanges: tuple[Any, ...] = ()


@dataclass
class WebSession:
    """The state of one credentialed web session for one scan (mutable, redacted).

    This is what a check sees in place of a credential: whether the session is
    authenticated, whether it had to be re-established, and which surface it reached.
    """

    label: str
    kind: str
    origin: str
    spec: LoginSpec | None = None
    authenticated: bool = False
    login_status: int | None = None
    login_attempts: int = 0
    reauths: int = 0
    keep_alive_probes: int = 0
    expired_once: bool = False
    #: URLs the authenticated crawl reached that the anonymous one did not.
    authenticated_only: tuple[str, ...] = ()
    #: ``None`` when no logout was attempted; otherwise whether the session survived it.
    logout_survived: bool | None = None
    #: The redacted exchanges behind the session's verdicts (login, logout) — evidence a
    #: check attaches to its finding. Redacted at capture, so no credential travels in them.
    login_exchanges: tuple[Any, ...] = ()
    logout_exchanges: tuple[Any, ...] = ()
    notes: list[str] = field(default_factory=list)

    def note(self, text: str) -> None:
        if text and text not in self.notes:
            self.notes.append(text)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "kind": self.kind,
            "origin": self.origin,
            "authenticated": self.authenticated,
            "login_status": self.login_status,
            "login_attempts": self.login_attempts,
            "reauths": self.reauths,
            "keep_alive_probes": self.keep_alive_probes,
            "expired_once": self.expired_once,
            "authenticated_only": list(self.authenticated_only),
            "logout_survived": self.logout_survived,
            "login": self.spec.to_dict() if self.spec is not None else None,
            "notes": list(self.notes),
        }

    def describe(self) -> str:
        if not self.authenticated:
            return f"credential {self.label!r} did not establish a session at {self.origin}"
        return (
            f"credential {self.label!r} authenticated at {self.origin} "
            f"({len(self.authenticated_only)} authenticated-only URL(s), "
            f"{self.reauths} re-authentication(s))"
        )


# --------------------------------------------------------------------------- the flow
def _fields(material: CredentialMaterial, spec: LoginSpec) -> dict[str, str]:
    """The submitted field set: the username, the password and any declared extras."""
    fields = {spec.username_field: material.username, spec.password_field: material.secret_value()}
    for name in spec.extra_fields:
        value = material.extra_value(name, "")
        if value:
            fields[name] = value
    return fields


def _request_body(fields: Mapping[str, str], spec: LoginSpec) -> tuple[bytes, str]:
    if spec.kind == "json":
        return (
            json.dumps(fields).encode("utf-8"),
            "application/json",
        )
    return urlencode(fields).encode("utf-8"), "application/x-www-form-urlencoded"


async def _send(client: Any, spec: LoginSpec, fields: Mapping[str, str]) -> Any:
    body, content_type = _request_body(fields, spec)
    return await client.request(
        spec.method,
        spec.url,
        headers={"Content-Type": content_type},
        content=body,
        follow_redirects=spec.follow_redirects,
    )


def _looks_like_failure(exchange: Any, spec: LoginSpec) -> str | None:
    status = int(getattr(exchange, "status_code", 0))
    if status in spec.failure_statuses:
        return f"the application refused the attempt with HTTP {status}"
    body = str(getattr(exchange, "body", "") or "")
    for marker in spec.failure_markers:
        if marker and marker.lower() in body.lower():
            return f"the response carried the failure marker {marker!r}"
    if status and status not in spec.success_statuses and not 200 <= status < 400:
        return f"the application answered HTTP {status}"
    return None


async def _probe_session(client: Any, spec: LoginSpec) -> bool | None:
    """One integrity probe for ``spec``; ``True`` authenticated, ``False`` gone, ``None`` unknown.

    Two signals, in order of strength: a *declared* protected URL (the application's own
    answer about who may read it), else the login page itself — a session that is
    established is normally no longer offered the login form. ``None`` means the probe could
    not be made at all (a refused or failed request), which a caller must not read as
    "still authenticated".
    """
    if spec.protected_url:
        try:
            exchange = await client.request("GET", spec.protected_url, follow_redirects=False)
        except Exception:  # a probe failure is data, not a session verdict
            return None
        status = int(getattr(exchange, "status_code", 0))
        location = str(exchange.header("location") or "")
        if status in spec.failure_statuses:
            return False
        if 300 <= status < 400 and _same_login_page(location, spec):
            return False
        if 200 <= status < 300:
            return True
        return None
    if not spec.url:
        return None
    try:
        exchange = await client.request("GET", spec.url, follow_redirects=spec.follow_redirects)
    except Exception:
        return None
    return not login_form_present(str(getattr(exchange, "body", "") or ""))


async def session_intact(client: Any, session: WebSession) -> bool | None:
    """:func:`_probe_session` for a live session, counting the probe it made."""
    if session.spec is None:
        return None
    verdict = await _probe_session(client, session.spec)
    session.keep_alive_probes += 1
    return verdict


def _same_login_page(location: str, spec: LoginSpec) -> bool:
    """True when a redirect points back at the login page (the classic "expired" answer)."""
    if not location or not spec.url:
        return False
    target = urljoin(spec.url, location)
    return _origin_of(target) == _origin_of(spec.url) and urlsplit(target).path.rstrip(
        "/"
    ) == urlsplit(spec.url).path.rstrip("/")


async def perform_login(
    client: Any, spec: LoginSpec, material: CredentialMaterial
) -> WebAuthOutcome:
    """Submit the credential once and classify the answer.

    Success is the application's own verdict: an accepted status with no failure marker, and
    — where the spec names a protected URL, or the login page is re-probed — a second request
    that only a session can satisfy. A login that merely returns 200 while still serving the
    form is *not* treated as authenticated.
    """
    fields = _fields(material, spec)
    try:
        exchange = await _send(client, spec, fields)
    except Exception as exc:
        return WebAuthOutcome(
            ok=False,
            status=None,
            reason=f"the login request could not be sent ({exc.__class__.__name__})",
            spec=spec,
        )
    status = int(getattr(exchange, "status_code", 0))
    failure = _looks_like_failure(exchange, spec)
    if failure is not None:
        return WebAuthOutcome(
            ok=False, status=status, reason=failure, spec=spec, exchanges=(exchange,)
        )
    verify = await _probe_session(client, spec)
    if verify is False:
        return WebAuthOutcome(
            ok=False,
            status=status,
            reason=(
                "the application answered the attempt but still served the login form"
                if not spec.protected_url
                else f"{spec.protected_url} still refuses an unauthenticated session"
            ),
            spec=spec,
            exchanges=(exchange,),
        )
    return WebAuthOutcome(
        ok=True,
        status=status,
        reason="the application accepted the credential and served a session",
        spec=spec,
        exchanges=(exchange,),
        verified=verify is True,
    )


async def ensure_authenticated(
    client: Any,
    session: WebSession,
    material: CredentialMaterial,
    *,
    max_reauths: int = MAX_REAUTHS,
) -> bool:
    """Keep the session alive: re-login when a probe says it has gone.

    Called before an authenticated check runs, so a session that expired mid-scan is
    re-established instead of silently degrading into an anonymous one. Bounded, because a
    target that drops every session must not turn a check into a login loop.
    """
    if not session.authenticated or session.spec is None:
        return False
    intact = await session_intact(client, session)
    if intact is None or intact:
        return session.authenticated
    session.expired_once = True
    while session.reauths < max_reauths:
        session.reauths += 1
        outcome = await perform_login(client, session.spec, material)
        session.login_attempts += 1
        if outcome.ok:
            session.authenticated = True
            session.login_status = outcome.status
            session.note(f"the session expired and was re-established (attempt {session.reauths})")
            return True
    session.authenticated = False
    session.note("the session could not be re-established")
    return False


async def perform_logout(client: Any, session: WebSession) -> LogoutOutcome | None:
    """Log out, then re-probe: the finding this exists for is CWE-613.

    A logout that only clears the *client's* cookie leaves the server-side session usable, so
    a captured token keeps working — the session "survived" its own logout. ``None`` means
    the question could not be answered at all (no logout URL declared or detected, or the
    probe failed), which a check must report as "not attempted" rather than as clean.
    """
    spec = session.spec
    if spec is None or not spec.logout_url:
        return None
    exchanges: list[Any] = []
    for method in ("POST", "GET"):
        try:
            exchanges.append(await client.request(method, spec.logout_url, follow_redirects=False))
        except Exception as exc:  # try the other verb; a refusal here is not a verdict
            _logger.debug(
                "logout request failed",
                extra={"event": "auth.logout_failed", "method": method, "error": str(exc)},
            )
            continue
        break
    survived = await session_intact(client, session)
    if survived is None:
        return None
    session.logout_survived = bool(survived)
    session.logout_exchanges = tuple(exchanges)
    if survived:
        session.note("the session still worked after the logout request")
        _logger.info(
            "a session survived logout",
            extra={
                "event": "auth.logout_survived",
                "origin": session.origin,
                "label": session.label,
            },
        )
    return LogoutOutcome(survived=bool(survived), url=spec.logout_url, exchanges=tuple(exchanges))
