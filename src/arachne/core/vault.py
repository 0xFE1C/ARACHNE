"""The credential vault: encrypted at rest, released only as opaque scoped handles (S19).

Three requirements meet here (REQ-CREDS-002, REQ-CREDS-005):

* **Encrypted at rest.** A vault is one sidecar file, encrypted with the same
  encrypt-then-MAC construction the secrets manifest uses (:func:`core.secrets.encrypt_blob`
  — scrypt key derivation, a SHAKE-256 keystream, HMAC-SHA256 over magic+salt+nonce+
  ciphertext), under its own magic so a manifest cannot be replayed as a vault. The key
  comes from ``ARACHNE_VAULT_KEY``; a deployment that configured no key gets *no* vault
  rather than a plaintext one, and a wrong key is refused (a wrong key and a tampered file
  are indistinguishable on purpose). Nothing here is a database table: the vault is
  node-local by construction, which is what makes "credentials cannot leave their scan
  scope" a property of the deployment rather than a promise (REQ-CREDS-003, ADR-240.2).
* **Opaque scoped handles.** A check never receives material. :meth:`FileCredentialVault.resolve`
  returns a :class:`CredentialHandle` whose public surface is *label, kind and scope* — it
  carries the material but publishes no way to read it, and its ``repr``/``to_dict`` are
  redacted. Reading it needs the broker's capability (:func:`release_seam`), which
  ``arachne.creds`` imports and nothing in the module layer does. The failure mode is loud
  (:class:`~arachne.core.errors.CredentialError`) rather than a silent leak.
* **Scope confinement.** Every entry is bound to the hosts and URL prefixes it was stored
  for. :meth:`CredentialHandle.material` is reached only after that scope has been checked,
  so an authenticated request cannot be made against a target the credential was not
  declared for (REQ-CREDS-005). An unscoped entry covers nothing — deny by default, the
  same posture as :class:`~arachne.core.safety.Scope`.

The vault holds *operator-supplied* credentials for the target being assessed, which is a
different thing from the secrets manifest's ledger of credentials *found* on a target: the
manifest records fingerprints of what leaked (S7), the vault holds what was declared for
authorized use (S19). Both are encrypted sidecars; neither reaches a finding, an evidence
blob, a log line or a report.
"""

from __future__ import annotations

import contextlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from pydantic import SecretStr

from arachne.core.errors import (
    ConfigurationError,
    CredentialError,
    CredentialScopeError,
    VaultLockedError,
)
from arachne.core.logging import get_logger
from arachne.core.safety import host_matches_glob, normalize_host, url_under_prefix
from arachne.core.secrets import decrypt_blob, encrypt_blob

__all__ = [
    "AWS_CREDENTIAL_KINDS",
    "CLOUD_CREDENTIAL_KINDS",
    "CREDENTIAL_KINDS",
    "SSH_AUTH_METHODS",
    "SSH_KEY_TYPES",
    "VAULT_MAGIC",
    "WEB_CREDENTIAL_KINDS",
    "CredentialEntry",
    "CredentialHandle",
    "CredentialKind",
    "CredentialMaterial",
    "CredentialScope",
    "CredentialStore",
    "FileCredentialVault",
    "build_vault",
    "release_seam",
]

_logger = get_logger("core.vault")

#: First line of a credential vault file. Distinct from the secrets manifest's magic, and
#: authenticated as part of the MAC, so the two formats cannot be confused or replayed.
VAULT_MAGIC: Final = "ARACHNE-CV-1"

#: What a credential is *for*. The kind decides which checks may select it: a web credential
#: drives a login flow, a protocol credential is offered to a raw-network check.
#: ``ldap`` was added by WP-10 (REQ-DET-014): the AD CS enumeration binds to the directory with
#: an operator-supplied credential. ``cloud-token`` was added by WP-12 (REQ-DET-017): the
#: read-only DigitalOcean posture check spends a bearer token. ``aws-role`` was added by WP-31
#: (REQ-DET-024): the AWS posture checks spend a least-privilege read-only role's static
#: credential, which the broker uses to *sign* one request and never hands to a check. All
#: three are additive — the kind flows through the same scope check, the same single-release
#: seam and the same audit record as the four before them.
CredentialKind = Literal["web-form", "web-json", "ssh", "smb", "ldap", "cloud-token", "aws-role"]
CREDENTIAL_KINDS: Final[tuple[str, ...]] = (
    "web-form",
    "web-json",
    "ssh",
    "smb",
    "ldap",
    "cloud-token",
    "aws-role",
)
#: The kinds a web check may select (both are HTTP login flows; the difference is the body
#: encoding, which the login spec may also override).
WEB_CREDENTIAL_KINDS: Final[tuple[str, ...]] = ("web-form", "web-json")

#: SSH authentication methods a ``ssh`` credential can declare (WP-20, REQ-CREDS-006). The
#: method selects what the stored secret *is*: an SSH password, or an Ed25519 seed. Declaring
#: it explicitly is what stops a password from being offered as a key and vice versa.
SSH_AUTH_METHODS: Final[tuple[str, ...]] = ("password", "publickey")
#: The SSH key types this build authenticates with. Ed25519 only: the module the trust layer
#: already ships is the one the SSH check signs with, not a second implementation.
SSH_KEY_TYPES: Final[tuple[str, ...]] = ("ed25519",)
#: The kinds a read-only cloud API check may select. ``cloud-token`` was added by WP-12
#: (REQ-DET-017): the broker injects the bearer token into one request and hands the check
#: the redacted exchange, so the material never crosses the module boundary.
CLOUD_CREDENTIAL_KINDS: Final[tuple[str, ...]] = ("cloud-token",)

#: The kinds an AWS read-only posture check may select. ``aws-role`` was added by WP-31
#: (REQ-DET-024): the vault holds a least-privilege read-only role's static credential (the
#: access key id in ``username``, the secret in ``secret`` and an optional session token in
#: ``extra["session_token"]``) and the broker signs one request with it, so the material never
#: crosses the module boundary.
AWS_CREDENTIAL_KINDS: Final[tuple[str, ...]] = ("aws-role",)

#: A vault is an operator's working set, not a credential database: cap it.
MAX_ENTRIES: Final = 256
#: A label is an identifier that travels in scan options, audit records and reports.
MAX_LABEL = 64


def _now() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- scope
@dataclass(frozen=True, slots=True)
class CredentialScope:
    """What a credential may be used against: hosts and/or URL prefixes.

    Both dimensions are optional and independently sufficient; an entry with neither covers
    nothing, because the safe default for "may this credential be spent here?" is no.
    Hosts accept ``*.`` subdomain globs exactly as :class:`~arachne.core.safety.Scope` does,
    and URL prefixes are matched with :func:`~arachne.core.safety.url_under_prefix` (a
    prefix test, never a substring one).
    """

    hosts: tuple[str, ...] = ()
    url_prefixes: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        return not self.hosts and not self.url_prefixes

    def covers_host(self, host: str) -> bool:
        if not host:
            return False
        return any(host_matches_glob(host, pattern) for pattern in self.hosts)

    def covers_url(self, url: str) -> bool:
        if not url:
            return False
        if any(url_under_prefix(url, prefix) for prefix in self.url_prefixes):
            return True
        from urllib.parse import urlsplit

        return self.covers_host(urlsplit(url).hostname or "")

    def covers_any(self, *, hosts: Iterable[str] = (), urls: Iterable[str] = ()) -> bool:
        """True when *at least one* candidate is covered (the selection test)."""
        return any(self.covers_host(host) for host in hosts) or any(
            self.covers_url(url) for url in urls
        )

    def to_dict(self) -> dict[str, Any]:
        return {"hosts": list(self.hosts), "url_prefixes": list(self.url_prefixes)}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> CredentialScope:
        raw = dict(data or {})
        return cls(
            hosts=tuple(normalize_host(str(item)) for item in raw.get("hosts") or () if str(item)),
            url_prefixes=tuple(
                str(item).strip() for item in raw.get("url_prefixes") or () if str(item)
            ),
        )

    def describe(self) -> str:
        """A human form for logs, errors and audit metadata (never a secret)."""
        parts: list[str] = []
        if self.hosts:
            parts.append("hosts: " + ", ".join(self.hosts))
        if self.url_prefixes:
            parts.append("urls: " + ", ".join(self.url_prefixes))
        return "; ".join(parts) if parts else "unscoped (denies every target)"


# --------------------------------------------------------------------------- material
@dataclass(frozen=True, slots=True)
class CredentialMaterial:
    """The released credential — **the only shape in which a secret exists in memory**.

    Internal to ``arachne.creds``: constructed by :meth:`FileCredentialVault.resolve` and
    read by the broker, which passes the individual values to a login flow or an
    ``Authenticator`` and drops the object. Its ``repr`` is redacted so an accidental
    ``%r`` in a log line cannot leak it.
    """

    username: str
    secret: SecretStr
    #: Extra fields a flow needs (a SMB domain, an extra form field, a CSRF token).
    extra: Mapping[str, SecretStr] = field(default_factory=dict)
    #: The non-secret login-flow declaration, exactly as the operator stored it.
    login: Mapping[str, Any] = field(default_factory=dict)

    @property
    def username_value(self) -> str:
        return self.username

    def secret_value(self) -> str:
        """The plaintext secret. Called by the login flow, never by a check."""
        return self.secret.get_secret_value()

    def extra_value(self, name: str, default: str = "") -> str:
        value = self.extra.get(name)
        return value.get_secret_value() if value is not None else default

    def extra_values(self) -> dict[str, str]:
        """Every extra field as plaintext — for the one ``attempt``/login call that needs them."""
        return {name: value.get_secret_value() for name, value in self.extra.items()}

    def __repr__(self) -> str:
        return (
            f"CredentialMaterial(username={self.username!r}, secret=SecretStr('**********'), "
            f"extra_fields={sorted(self.extra)}, login_keys={sorted(self.login)})"
        )


#: The capability that unlocks a handle's material. ``arachne.creds`` imports
#: :func:`release_seam`; nothing in the module layer does, so a check that reaches for the
#: material gets a loud :class:`~arachne.core.errors.CredentialError` instead of a secret.
_SEAM: Final = object()


def release_seam() -> object:
    """The broker's capability token (see ``_SEAM``). Not for checks."""
    return _SEAM


# --------------------------------------------------------------------------- handles
@dataclass(frozen=True, slots=True)
class CredentialHandle:
    """A credential as a check sees it: **label, kind and scope, and nothing else**.

    The material is carried but unpublished. There is deliberately no ``secret`` attribute,
    no ``password`` property and no mapping access: the public surface is
    :attr:`label`, :attr:`kind`, :attr:`scope`, the two scope predicates and
    :meth:`describe`/:meth:`to_dict`. A check that needs authenticated reach asks the broker
    (``ctx.credentials``), which performs the flow and hands back derived state — a
    :class:`~arachne.creds.session.WebSession` or a protocol auth result — never a value.
    """

    label: str
    kind: str
    scope: CredentialScope
    _material: CredentialMaterial

    # ------------------------------------------------------------------ public surface
    def covers_host(self, host: str) -> bool:
        return self.scope.covers_host(host)

    def covers_url(self, url: str) -> bool:
        return self.scope.covers_url(url)

    def describe(self) -> dict[str, Any]:
        """Redacted description: safe in a log line, an audit record or a finding."""
        return {
            "label": self.label,
            "kind": self.kind,
            "scope": self.scope.to_dict(),
            "scope_summary": self.scope.describe(),
        }

    def to_dict(self) -> dict[str, Any]:
        return self.describe()

    def __repr__(self) -> str:
        return (
            f"CredentialHandle(label={self.label!r}, kind={self.kind!r}, "
            f"scope={self.scope.describe()!r})"
        )

    # ------------------------------------------------------------------ the seam
    def material(self, seam: object) -> CredentialMaterial:
        """Release the material to the holder of ``seam`` (the credential broker).

        The equivalent of ``SecretStr.get_secret_value()`` at a sanctioned call site: one
        named seam instead of a reachable attribute. Passing anything but
        :func:`release_seam`'s token raises, so a check cannot read a credential by
        accident — and a test asserts the broker is the only caller in the tree.
        """
        if seam is not _SEAM:
            msg = (
                "credential material may only be released through the credential broker "
                "(arachne.creds); checks receive opaque handles"
            )
            raise CredentialError(msg)
        return self._material


# --------------------------------------------------------------------------- records
@dataclass(frozen=True, slots=True)
class CredentialEntry:
    """One stored credential as the operator sees it — metadata only, never material."""

    label: str
    kind: str
    scope: CredentialScope
    created_at: datetime = field(default_factory=_now)
    created_by: str | None = None
    revoked_at: datetime | None = None
    #: Whether a login-flow declaration was stored with it (its *content* is material).
    has_login_spec: bool = False
    has_extra: bool = False

    @property
    def active(self) -> bool:
        return self.revoked_at is None

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "kind": self.kind,
            "scope": self.scope.to_dict(),
            "scope_summary": self.scope.describe(),
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "active": self.active,
            "has_login_spec": self.has_login_spec,
            "has_extra": self.has_extra,
        }


@dataclass(frozen=True, slots=True)
class _StoredCredential:
    """The decrypted vault payload for one label (material lives here, in memory only)."""

    entry: CredentialEntry
    material: CredentialMaterial
    sealed: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "kind": self.entry.kind,
            "scope": self.entry.scope.to_dict(),
            "username": self.material.username,
            "secret": self.material.secret.get_secret_value(),
            "extra": {
                name: value.get_secret_value() for name, value in self.material.extra.items()
            },
            "login": dict(self.material.login),
            "created_at": self.entry.created_at.isoformat(),
            "created_by": self.entry.created_by,
            "revoked_at": self.entry.revoked_at.isoformat() if self.entry.revoked_at else None,
        }


class CredentialStore(Protocol):
    """What the broker needs from a vault (the reserved seam for a managed store)."""

    def labels(self) -> tuple[str, ...]: ...

    def records(self, *, include_revoked: bool = False) -> tuple[CredentialEntry, ...]: ...

    def get(self, label: str) -> CredentialEntry | None: ...

    def resolve(
        self, label: str, *, url: str | None = None, host: str | None = None
    ) -> CredentialHandle | None: ...


# --------------------------------------------------------------------------- the vault
class FileCredentialVault:
    """One encrypted file holding the deployment's credentialed-scanning entries.

    Read-on-demand with a small decrypted cache: the file is decrypted when a label is
    resolved and re-encrypted on every write, so the on-disk form is always ciphertext and
    an operator can confirm that by looking at it. Usage is *not* written back (a counter
    would rewrite the file on every request and put credential-shaped timing in a shared
    file); the audit trail is the record of use.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        passphrase: SecretStr | str,
        max_entries: int = MAX_ENTRIES,
    ) -> None:
        raw = passphrase.get_secret_value() if isinstance(passphrase, SecretStr) else passphrase
        if not raw.strip():
            msg = "a credential vault needs a non-empty passphrase (ARACHNE_VAULT_KEY)"
            raise VaultLockedError(msg)
        self.path = Path(path).expanduser()
        self._passphrase = raw
        self.max_entries = max(1, max_entries)
        self._cache: dict[str, _StoredCredential] | None = None
        self._sealed_count = 0

    # ------------------------------------------------------------------ reading
    def labels(self) -> tuple[str, ...]:
        return tuple(sorted(self._entries()))

    def records(self, *, include_revoked: bool = False) -> tuple[CredentialEntry, ...]:
        entries = [item.entry for item in self._entries().values()]
        if not include_revoked:
            entries = [entry for entry in entries if entry.active]
        return tuple(sorted(entries, key=lambda entry: entry.label))

    def get(self, label: str) -> CredentialEntry | None:
        stored = self._entries().get(label)
        return stored.entry if stored is not None else None

    def resolve(
        self, label: str, *, url: str | None = None, host: str | None = None
    ) -> CredentialHandle | None:
        """The handle for ``label``, **only** if the entry is active and covers the target.

        ``None`` means "this vault does not hold that label" (the broker reports that
        distinctly). A held, active entry that does not cover ``url``/``host`` raises
        :class:`~arachne.core.errors.CredentialScopeError`: the credential exists, so
        quietly returning ``None`` would hide a scope refusal behind an "unconfigured"
        reason (REQ-CREDS-005).
        """
        stored = self._entries().get(label)
        if stored is None:
            return None
        if not stored.entry.active:
            # A revoked credential is present but unusable — also a refusal, not "absent".
            raise CredentialScopeError(
                f"credential {label!r} is revoked and will not be released",
                reason=f"credential {label!r} revoked",
            )
        covered = stored.entry.scope.covers_any(
            hosts=(host,) if host else (), urls=(url,) if url else ()
        )
        if (url is not None or host is not None) and not covered:
            raise CredentialScopeError(
                f"credential {label!r} is scoped to {stored.entry.scope.describe()} and "
                f"does not cover {url or host}",
                reason=f"credential {label!r} is out of its declared scope",
            )
        return CredentialHandle(
            label=label,
            kind=stored.entry.kind,
            scope=stored.entry.scope,
            _material=stored.material,
        )

    # ------------------------------------------------------------------ writing
    def put(
        self,
        label: str,
        *,
        kind: str,
        username: str,
        secret: SecretStr | str,
        scope: CredentialScope | None = None,
        extra: Mapping[str, SecretStr | str] | None = None,
        login: Mapping[str, Any] | None = None,
        created_by: str | None = None,
    ) -> CredentialEntry:
        """Store (or replace) one credential; the file is rewritten encrypted."""
        clean = label.strip()
        if not clean or len(clean) > MAX_LABEL:
            msg = f"a credential label must be 1..{MAX_LABEL} characters"
            raise ConfigurationError(msg)
        if kind not in CREDENTIAL_KINDS:
            expected = ", ".join(CREDENTIAL_KINDS)
            msg = f"{kind!r} is not a credential kind (expected one of {expected})"
            raise ConfigurationError(msg)
        secret_value = secret.get_secret_value() if isinstance(secret, SecretStr) else secret
        if not secret_value:
            msg = f"credential {clean!r} needs a non-empty secret"
            raise ConfigurationError(msg)
        if kind == "ssh":
            # An SSH credential declares what its secret *is*: a password or an Ed25519 seed.
            # Validated at the boundary so a scan cannot offer a password as a key (which the
            # peer would refuse, and which reads as "the stored secret is wrong").
            declared = dict(extra or {})
            method = str(declared.get("auth_method") or declared.get("auth-method") or "password")
            method = method.lower()
            if method not in SSH_AUTH_METHODS:
                msg = (
                    f"an ssh credential's auth_method must be one of "
                    f"{', '.join(SSH_AUTH_METHODS)} (got {method!r})"
                )
                raise ConfigurationError(msg)
            if method == "publickey":
                key_type = str(declared.get("key_type") or "ed25519").lower()
                if key_type not in SSH_KEY_TYPES:
                    msg = (
                        f"this build authenticates with {', '.join(SSH_KEY_TYPES)} SSH keys, "
                        f"not {key_type!r}"
                    )
                    raise ConfigurationError(msg)
        entries = self._entries()
        if clean not in entries and len(entries) >= self.max_entries:
            msg = f"the vault already holds {self.max_entries} credentials"
            raise ConfigurationError(msg)
        effective_scope = scope if scope is not None else CredentialScope()
        material = CredentialMaterial(
            username=username,
            secret=SecretStr(secret_value),
            extra={
                str(name): (value if isinstance(value, SecretStr) else SecretStr(str(value)))
                for name, value in dict(extra or {}).items()
            },
            login=dict(login or {}),
        )
        existing = entries.get(clean)
        entry = CredentialEntry(
            label=clean,
            kind=kind,
            scope=effective_scope,
            created_at=existing.entry.created_at if existing is not None else _now(),
            created_by=created_by or (existing.entry.created_by if existing is not None else None),
            revoked_at=None,
            has_login_spec=bool(material.login),
            has_extra=bool(material.extra),
        )
        entries[clean] = _StoredCredential(entry=entry, material=material, sealed="")
        self._save(entries)
        _logger.info(
            "credential stored",
            extra={
                "event": "credential.stored",
                "label": clean,
                "kind": kind,
                "scope": effective_scope.describe(),
            },
        )
        return entry

    def revoke(self, label: str) -> CredentialEntry | None:
        """Mark an entry revoked in place (lineage survives; the material is dropped)."""
        entries = self._entries()
        stored = entries.get(label)
        if stored is None:
            return None
        revoked = replace(stored.entry, revoked_at=_now())
        entries[label] = _StoredCredential(
            entry=revoked,
            material=CredentialMaterial(username="", secret=SecretStr("revoked")),
            sealed="",
        )
        self._save(entries)
        return revoked

    def remove(self, label: str) -> bool:
        """Delete an entry (and its material) from the vault file."""
        entries = self._entries()
        if label not in entries:
            return False
        del entries[label]
        self._save(entries)
        return True

    # ------------------------------------------------------------------ internals
    def _entries(self) -> dict[str, _StoredCredential]:
        if self._cache is None:
            self._cache = self._load()
        return self._cache

    def _load(self) -> dict[str, _StoredCredential]:
        if not self.path.exists():
            return {}
        blob = self.path.read_bytes()
        if not blob.strip():
            return {}
        payload = json.loads(
            decrypt_blob(
                blob,
                self._passphrase,
                magic=VAULT_MAGIC,
                label="credential vault",
            ).decode("utf-8")
        )
        entries: dict[str, _StoredCredential] = {}
        for label, item in dict(payload.get("entries") or {}).items():
            entries[str(label)] = _stored_from_payload(str(label), dict(item))
        return entries

    def _save(self, entries: Mapping[str, _StoredCredential]) -> None:
        payload = {
            "version": 1,
            "note": (
                "ARACHNE credential vault. Encrypted at rest (scrypt + SHAKE-256 keystream "
                "+ HMAC-SHA256); released to checks only as opaque scoped handles. See ADR-240."
            ),
            "entries": {label: item.to_payload() for label, item in entries.items()},
        }
        blob = encrypt_blob(
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            self._passphrase,
            magic=VAULT_MAGIC,
            label="credential vault",
            key_env="ARACHNE_VAULT_KEY",
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_bytes(blob)
        temporary.replace(self.path)
        with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
            self.path.chmod(0o600)
        self._cache = dict(entries)
        self._sealed_count += 1

    @classmethod
    def from_settings(cls, settings: Any) -> FileCredentialVault | None:
        """The vault ``settings`` asks for, or ``None`` when no vault is configured.

        A configured path with no key is a *refusal*, not a silent downgrade: writing or
        reading credentials in the clear would violate the requirement this class exists
        for (the same rule ``SecretsManifest.from_settings`` applies to the S7 ledger).
        """
        vault = settings.vault
        if not vault.path:
            return None
        if vault.key is None:
            msg = (
                "ARACHNE_VAULT_PATH is set but ARACHNE_VAULT_KEY is not: refusing to use an "
                "unencrypted credential vault"
            )
            raise VaultLockedError(msg)
        return cls(vault.path, passphrase=vault.key, max_entries=vault.max_entries)


def _stored_from_payload(label: str, item: Mapping[str, Any]) -> _StoredCredential:
    entry = CredentialEntry(
        label=label,
        kind=str(item.get("kind") or ""),
        scope=CredentialScope.from_dict(item.get("scope")),
        created_at=_parse_moment(item.get("created_at")) or _now(),
        created_by=item.get("created_by"),
        revoked_at=_parse_moment(item.get("revoked_at")),
        has_login_spec=bool(item.get("login")),
        has_extra=bool(item.get("extra")),
    )
    material = CredentialMaterial(
        username=str(item.get("username") or ""),
        secret=SecretStr(str(item.get("secret") or "")),
        extra={
            str(name): SecretStr(str(value))
            for name, value in dict(item.get("extra") or {}).items()
        },
        login=dict(item.get("login") or {}),
    )
    return _StoredCredential(entry=entry, material=material, sealed="")


def _parse_moment(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:  # a hand-edited vault: treat an unreadable timestamp as absent
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def build_vault(settings: Any) -> FileCredentialVault | None:
    """Build the deployment's vault from settings (``None`` when unconfigured)."""
    return FileCredentialVault.from_settings(settings)
