"""API-key authentication and role-based authorization (F-07-02, F-08-02, S12; S17 IDAM).

One credential model, three roles, and one rule: **the API is closed unless something is
configured**. A deployment with no static keys, no service accounts and no IdP has no way
in — that is the deny-by-default posture the scanner itself uses for scope (F-01-02),
applied to its own interface, and S17's SSO surface preserves it (REQ-IDAM-002).

Design points:

* **Keys are hashed at load.** The plaintext secret never lives in :class:`ApiKeyStore`
  or in the settings dataclass it was parsed from; verification hashes the presented key
  and compares digests in constant time (``hmac.compare_digest``). S17's DB-backed
  service accounts (:class:`~arachne.data.identity_store.ServiceAccountStore`) use the
  identical scheme, so the storage format is unchanged (REQ-IDAM-003).
* **Roles are ordered.** :data:`ROLE_RANK` makes "scanner can do everything viewer can" a
  comparison, not a hand-maintained table. The three capabilities the spec names
  (admin/scanner/viewer) map onto: read (viewer) < run scans and review findings (scanner)
  < manage targets, delete, and trigger integrations (admin).
* **Every refusal is an ``api.denied`` audit event** with a reason, so a probe against the
  API is visible in the same trail as a probe against a target (F-01-08).
* **Actor identity (S17, REQ-IDAM-004).** A :class:`Principal` knows both the credential
  it presented (``credential``, a key label) and the human it acts for (``user``), so an
  audit row can read ``user alice@corp via key ci-pipeline`` — the enterprise question
  "who, really?" — while a bare service key degrades to ``key ci-pipeline``.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum

from fastapi import HTTPException, Request, status

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import API_ROLES, ApiSettings
from arachne.core.errors import ConfigurationError
from arachne.data.identity_store import ServiceAccountStore, SessionStore

__all__ = [
    "API_KEY_COOKIE",
    "API_KEY_HEADER",
    "ROLE_RANK",
    "SSO_SESSION_COOKIE",
    "ApiKey",
    "ApiKeyStore",
    "CredentialStore",
    "Principal",
    "Role",
    "actor_identity",
    "authenticate",
    "hash_secret",
    "identify",
]

#: The header a machine client presents its key in.
API_KEY_HEADER = "x-api-key"
#: The cookie the web UI stores the key in after login (HttpOnly, SameSite=Strict).
API_KEY_COOKIE = "arachne_api_key"
#: The cookie an SSO login sets (S17). It carries an opaque session token, never the raw
#: IdP token; the token's SHA-256 hash is what the database stores.
SSO_SESSION_COOKIE = "arachne_session"


class Role(StrEnum):
    """The three roles of F-07-02."""

    VIEWER = "viewer"
    SCANNER = "scanner"
    ADMIN = "admin"


#: Numeric rank so ``role >= required`` expresses the capability order.
ROLE_RANK: dict[str, int] = {name: index for index, name in enumerate(API_ROLES)}


def hash_secret(secret: str) -> str:
    """SHA-256 hex digest of an API key secret.

    A plain digest (no per-key salt) is deliberate: the secret is a high-entropy random
    token, not a user password, so the salt's only value would be to slow a dictionary
    attack that does not exist for a 32-byte random key. Keeping the digest unsalted lets a
    deployment rotate the same key across processes by hashing it the same way.
    """
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ApiKey:
    """One configured key: its label, its role and the digest of its secret.

    ``project`` (S14, F-07-06) binds a key to one tenant. ``None`` means deployment-wide;
    a bound key can only see and scan its own project.
    """

    label: str
    role: Role
    digest: str
    project: str | None = None

    @classmethod
    def parse(cls, entry: str) -> ApiKey:
        """Parse a ``label:role:secret[:project]`` entry (validated by :class:`ApiSettings`)."""
        parts = entry.split(":", 3)
        label, role, secret = parts[0], parts[1], parts[2]
        project = parts[3].strip() if len(parts) == 4 and parts[3].strip() else None
        return cls(
            label=label.strip(),
            role=Role(role.strip().lower()),
            digest=hash_secret(secret),
            project=project,
        )


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller of one request.

    ``label`` is the credential label (a key label) or, for an SSO login, the user's
    subject — it stays the stable, unique-ish handle older code and the audit ``meta``
    already use. S17 adds the two halves of REQ-IDAM-004's actor identity: ``user`` (the
    human, e.g. an SSO email or a service account's owner) and ``credential`` (the key
    label presented), plus ``source`` (``api_key`` / ``service_account`` / ``sso``).
    """

    label: str
    role: Role
    #: The tenant this key is bound to (``None`` = deployment-wide), F-07-06.
    project: str | None = None
    #: The human the caller acts for (REQ-IDAM-004); ``None`` for a bare machine key.
    user: str | None = None
    #: A display name (SSO ``name`` claim) when it differs from ``user``.
    display: str | None = None
    #: The email/UPN carried by the IdP (per-user reporting), when known.
    email: str | None = None
    #: The key label that mediated the request (``None`` for a direct SSO session).
    credential: str | None = None
    #: ``api_key`` | ``service_account`` | ``sso`` — where the identity came from.
    source: str = "api_key"
    #: IdP groups the role was derived from (REQ-IDAM-002); empty for key callers.
    groups: tuple[str, ...] = ()

    @property
    def is_admin(self) -> bool:
        return self.role is Role.ADMIN

    @property
    def rank(self) -> int:
        return ROLE_RANK[self.role.value]

    def allows(self, minimum: Role) -> bool:
        return self.rank >= ROLE_RANK[minimum.value]

    @property
    def actor(self) -> str:
        """The audit actor identity: ``user X via key Y`` / ``user X`` / ``key Y``."""
        return actor_identity(user=self.user, credential=self.credential)

    @property
    def is_user(self) -> bool:
        """Whether this principal is a human login (as opposed to a machine key)."""
        return self.source == "sso"


def actor_identity(*, user: str | None = None, credential: str | None = None) -> str:
    """Compose the audit actor string (REQ-IDAM-004).

    ``user X via key Y`` when both halves are known (a service account acting for a human,
    or a user session mediated by a key); ``user X`` for a direct SSO login; ``key Y`` for
    a bare machine credential; ``anonymous`` when neither is known (a refusal).
    """
    if user and credential:
        return f"user {user} via key {credential}"
    if user:
        return f"user {user}"
    if credential:
        return f"key {credential}"
    return "anonymous"


class ApiKeyStore:
    """The configured keys, with a constant-time verification path."""

    def __init__(self, entries: list[str] | tuple[str, ...] = ()) -> None:
        keys: list[ApiKey] = []
        for entry in entries:
            try:
                keys.append(ApiKey.parse(entry))
            except (ValueError, KeyError) as exc:  # pragma: no cover - validated earlier
                msg = f"malformed API key entry {entry!r}: {exc}"
                raise ConfigurationError(msg) from exc
        self._keys = tuple(keys)

    @classmethod
    def from_settings(cls, settings: ApiSettings) -> ApiKeyStore:
        return cls(settings.keys)

    def __len__(self) -> int:
        return len(self._keys)

    @property
    def enabled(self) -> bool:
        """Whether any key is configured; ``False`` means every request is refused."""
        return bool(self._keys)

    def verify(self, presented: str | None) -> Principal | None:
        """Return the principal for ``presented``, or ``None`` when it matches no key."""
        if not presented:
            return None
        digest = hash_secret(presented)
        for key in self._keys:
            if hmac.compare_digest(key.digest, digest):
                return Principal(
                    label=key.label,
                    role=key.role,
                    project=key.project,
                    credential=key.label,
                    source="api_key",
                )
        return None

    def labels(self) -> tuple[str, ...]:
        return tuple(key.label for key in self._keys)


class CredentialStore:
    """Every way a caller can authenticate, in one place (S17, REQ-IDAM-001/003).

    Three credential types, resolved in order of specificity:

    * **static keys** (`ARACHNE_API_KEYS`, the S12 mechanism, unchanged);
    * **service accounts** (DB-backed, REQ-IDAM-003) — hashed, expiring, rotatable, and
      carrying the ``owner`` that turns an audit row into "user X via key Y";
    * **SSO sessions** (REQ-IDAM-001) — an opaque cookie token resolved to the per-user
      principal an OIDC login established.

    ``enabled`` is true only when *something* can authenticate, so a deployment with none
    of the three keeps refusing every request (deny-by-default, REQ-IDAM-002).
    """

    def __init__(
        self,
        static: ApiKeyStore,
        *,
        accounts: ServiceAccountStore | None = None,
        sessions: SessionStore | None = None,
    ) -> None:
        self._static = static
        self._accounts = accounts
        self._sessions = sessions

    @property
    def static(self) -> ApiKeyStore:
        return self._static

    @property
    def enabled(self) -> bool:
        if self._static.enabled:
            return True
        return bool(self._accounts and self._accounts.labels())

    def __len__(self) -> int:
        return len(self._static) + (len(self._accounts.labels()) if self._accounts else 0)

    def labels(self) -> tuple[str, ...]:
        accounts = self._accounts.labels() if self._accounts else ()
        return self._static.labels() + accounts

    def verify_key(self, presented: str | None) -> Principal | None:
        """A presented key/secret → principal, checking static keys then service accounts."""
        principal = self._static.verify(presented)
        if principal is not None:
            return principal
        if self._accounts is None or not presented:
            return None
        record = self._accounts.verify(presented)
        if record is None:
            return None
        return Principal(
            label=record.label,
            role=Role(record.role),
            project=record.project,
            user=record.owner,
            credential=record.label,
            source="service_account",
        )

    def resolve_session(self, token: str | None) -> Principal | None:
        """An SSO session cookie → the per-user principal (REQ-IDAM-001)."""
        if self._sessions is None or not token:
            return None
        record = self._sessions.resolve(token)
        if record is None:
            return None
        return Principal(
            label=record.display,
            role=Role(record.role),
            project=record.project,
            user=record.display,
            display=record.name,
            email=record.email,
            credential=None,
            source="sso",
            groups=record.groups,
        )


def presented_key(request: Request) -> str | None:
    """The API key a request carries, from the header or the UI session cookie."""
    header = request.headers.get(API_KEY_HEADER)
    if header:
        return header.strip()
    cookie = request.cookies.get(API_KEY_COOKIE)
    return cookie.strip() if cookie else None


def identify(request: Request, credentials: CredentialStore) -> Principal | None:
    """The principal behind ``request`` — a key (header/cookie) or an SSO session, else None."""
    principal = credentials.verify_key(presented_key(request))
    if principal is not None:
        return principal
    return credentials.resolve_session(request.cookies.get(SSO_SESSION_COOKIE))


def authenticate(
    request: Request,
    credentials: CredentialStore,
    *,
    auditor: Auditor | None = None,
) -> Principal:
    """Authenticate ``request`` or raise 401, auditing the refusal (F-08-02).

    Missing credential and wrong credential are answered differently on purpose: a client
    that sent nothing gets ``401`` with a hint, a client that sent a bad key gets ``401``
    with no detail about the key.
    """
    key = presented_key(request)
    session_token = request.cookies.get(SSO_SESSION_COOKIE)
    principal = identify(request, credentials)
    if principal is not None:
        return principal
    if key:
        reason = "invalid API key"
    elif session_token:
        reason = "invalid session"
    else:
        reason = "missing API key"
    _deny(request, auditor, reason)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=reason,
        headers={"WWW-Authenticate": "ApiKey"},
    )


def require_role(
    principal: Principal,
    minimum: Role,
    request: Request,
    *,
    auditor: Auditor | None = None,
) -> Principal:
    """Ensure ``principal`` holds at least ``minimum``, auditing a refusal as 403."""
    if principal.allows(minimum):
        return principal
    reason = f"role {principal.role.value} is not permitted (requires {minimum.value})"
    _deny(request, auditor, reason)
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=reason)


def _deny(request: Request, auditor: Auditor | None, reason: str) -> None:
    if auditor is None:
        return
    auditor.record(
        AuditAction.API_DENIED,
        outcome=AuditOutcome.BLOCKED,
        target=str(request.url.path),
        reason=reason,
        meta={
            "method": request.method,
            "path": request.url.path,
            "client": request.client.host if request.client else None,
        },
    )
