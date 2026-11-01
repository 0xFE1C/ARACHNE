"""The operator's secrets ledger: a sidecar manifest, encrypted at rest (F-08-04).

Two requirements meet here:

* **Evidence is redacted at capture time.** The HTTP client replaces a credential in a
  response body before any module, log line, audit record or report can see it
  (``core.http``); a check therefore learns *that* a secret was served and *which detector
  fired*, never the value (F-08-01, F-08-04).
* **An operator still needs a ledger.** Deciding what to rotate after "``/.env`` is
  public" requires knowing which credential shapes were found, where, and by which check.
  :class:`SecretsManifest` records exactly that: the detector name, a *masked* fingerprint
  (``AKIA...XY (20 chars)``, the same form ``mask_secret`` produces), the source URL and
  the check that found it.

The manifest never contains a usable value: masking happens where the match is made, and
the raw match is discarded. What the manifest does contain — which systems hold which kinds
of credential — is still sensitive, so the file is **encrypted at rest**. The default is
also *off*: a deployment that has not set ``ARACHNE_SECRETS_MANIFEST`` writes nothing.

Encryption is dependency-free on purpose (the runtime stack of docs/spec/07- §2 has no
crypto library): scrypt derives a 32-byte key from the operator's passphrase, a SHAKE-256
keystream (keyed with a random 128-bit nonce and salt) encrypts, and HMAC-SHA256 over the
header, salt, nonce and ciphertext authenticates. That is encrypt-then-MAC with a fresh
salt per write; the file format is text so it stays diffable and an operator can confirm
it is ciphertext. See ADR-120.6 for why this is acceptable for a local sidecar and why the
embedded secrets are already non-usable.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from pydantic import SecretStr

from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError
from arachne.core.logging import get_logger
from arachne.core.redaction import mask_secret

__all__ = [
    "MANIFEST_MAGIC",
    "SecretRecord",
    "SecretsManifest",
    "decrypt_blob",
    "decrypt_manifest",
    "encrypt_blob",
    "encrypt_manifest",
    "load_manifest",
]

_logger = get_logger("core.secrets")

#: First line of an encrypted manifest. Bumping it changes the format.
MANIFEST_MAGIC: Final = "ARACHNE-SM-1"

_SALT_BYTES: Final = 32
_NONCE_BYTES: Final = 16
_TAG_BYTES: Final = 32
_KEY_BYTES: Final = 32
#: scrypt cost. 2**14 keeps a manifest write well under a tenth of a second while making a
#: stolen file expensive to attack with the operator's passphrase *if* it is weak; the key
#: never leaves memory and the payload is a masked ledger regardless.
_SCRYPT_N: Final = 2**14
_SCRYPT_R: Final = 8
_SCRYPT_P: Final = 1
#: A manifest is a ledger, not a database: cap it so a hostile target cannot grow it.
MAX_RECORDS: Final = 500


@dataclass(frozen=True, slots=True)
class SecretRecord:
    """One masked credential observation (never a usable value)."""

    kind: str
    masked: str
    source: str
    check: str | None = None
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "masked": self.masked,
            "source": self.source,
            "check": self.check,
            "captured_at": self.captured_at.isoformat(),
        }


# --------------------------------------------------------------------------- encryption
def _derive_key(passphrase: str, salt: bytes) -> bytes:
    try:
        return hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_KEY_BYTES,
        )
    except (ValueError, MemoryError) as exc:  # pragma: no cover - platform limits
        raise ConfigurationError(f"cannot derive the manifest key: {exc}") from exc


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    return hashlib.shake_256(b"arachne-manifest" + key + nonce).digest(length)


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def _tag(key: bytes, salt: bytes, nonce: bytes, ciphertext: bytes, magic: str) -> bytes:
    return hmac.new(
        key,
        magic.encode("ascii") + salt + nonce + ciphertext,
        hashlib.sha256,
    ).digest()


def encrypt_blob(
    payload: bytes,
    passphrase: str,
    *,
    magic: str,
    label: str = "secrets manifest",
    key_env: str = "ARACHNE_SECRETS_MANIFEST_KEY",
) -> bytes:
    """Encrypt ``payload`` into the text format (encrypt-then-MAC), under ``magic``.

    The one encryption path this build has: the secrets manifest (S7) and the credential
    vault (S19, ``core.vault``) are the same construction with a different magic — a fresh
    scrypt salt and 128-bit nonce per write, a SHAKE-256 keystream, and HMAC-SHA256 over
    magic, salt, nonce and ciphertext. ``magic`` is inside the MAC so a ciphertext written
    for one purpose cannot be replayed as the other.
    """
    if not passphrase:
        msg = f"a {label} needs a non-empty passphrase ({key_env})"
        raise ConfigurationError(msg)
    salt = os.urandom(_SALT_BYTES)
    nonce = os.urandom(_NONCE_BYTES)
    key = _derive_key(passphrase, salt)
    ciphertext = _xor(payload, _keystream(key, nonce, len(payload)))
    tag = _tag(key, salt, nonce, ciphertext, magic)
    lines = (
        magic,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(nonce).decode("ascii"),
        base64.b64encode(ciphertext).decode("ascii"),
        base64.b64encode(tag).decode("ascii"),
    )
    return ("\n".join(lines) + "\n").encode("ascii")


def decrypt_blob(
    blob: bytes,
    passphrase: str,
    *,
    magic: str,
    label: str = "secrets manifest",
) -> bytes:
    """Verify and decrypt a blob written by :func:`encrypt_blob`; raises on any failure."""
    try:
        lines = blob.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ConfigurationError(f"the {label} is not a text file") from exc
    if len(lines) != 5 or lines[0] != magic:
        msg = f"not an {magic} {label}"
        raise ConfigurationError(msg)
    try:
        salt = base64.b64decode(lines[1], validate=True)
        nonce = base64.b64decode(lines[2], validate=True)
        ciphertext = base64.b64decode(lines[3], validate=True)
        tag = base64.b64decode(lines[4], validate=True)
    except ValueError as exc:
        raise ConfigurationError(f"the {label} is malformed") from exc
    if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES or len(tag) != _TAG_BYTES:
        raise ConfigurationError(f"the {label} has unexpected field sizes")
    key = _derive_key(passphrase, salt)
    expected = _tag(key, salt, nonce, ciphertext, magic)
    if not hmac.compare_digest(expected, tag):
        # A wrong passphrase and a tampered file are indistinguishable on purpose.
        raise ConfigurationError(f"the {label} could not be authenticated")
    return _xor(ciphertext, _keystream(key, nonce, len(ciphertext)))


def encrypt_manifest(payload: bytes, passphrase: str) -> bytes:
    """Encrypt ``payload`` into the text manifest format (encrypt-then-MAC)."""
    return encrypt_blob(
        payload,
        passphrase,
        magic=MANIFEST_MAGIC,
        label="secrets manifest",
        key_env="ARACHNE_SECRETS_MANIFEST_KEY",
    )


def decrypt_manifest(blob: bytes, passphrase: str) -> bytes:
    """Verify and decrypt a manifest; raises :class:`ConfigurationError` on any failure."""
    return decrypt_blob(blob, passphrase, magic=MANIFEST_MAGIC, label="secrets manifest")


def load_manifest(path: str | os.PathLike[str], passphrase: str) -> list[dict[str, Any]]:
    """Read and decrypt a manifest written by the scanner (operator/test helper)."""
    blob = Path(path).read_bytes()
    payload = json.loads(decrypt_manifest(blob, passphrase).decode("utf-8"))
    records = payload.get("secrets")
    if not isinstance(records, list):
        raise ConfigurationError("the secrets manifest payload has no 'secrets' list")
    return [dict(item) for item in records if isinstance(item, dict)]


# --------------------------------------------------------------------------- the ledger
class SecretsManifest:
    """Collects masked credential observations and writes them encrypted at close.

    One instance per scan. :meth:`record` is called by the HTTP client at capture time,
    which is the only place a raw match exists; the client passes the *masked* form in, so
    this class never handles a usable secret.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        passphrase: SecretStr | str,
        max_records: int = MAX_RECORDS,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        raw = passphrase.get_secret_value() if isinstance(passphrase, SecretStr) else passphrase
        if not raw.strip():
            msg = "a secrets manifest needs a non-empty passphrase (ARACHNE_SECRETS_MANIFEST_KEY)"
            raise ConfigurationError(msg)
        self.path = Path(path).expanduser()
        self._passphrase = raw
        self.max_records = max(1, max_records)
        self.metadata = dict(metadata or {})
        self._records: list[SecretRecord] = []
        self._seen: set[tuple[str, str, str]] = set()
        self.written: Path | None = None

    def __len__(self) -> int:
        return len(self._records)

    @property
    def records(self) -> tuple[SecretRecord, ...]:
        return tuple(self._records)

    def record(
        self,
        kind: str,
        masked: str,
        *,
        source: str,
        check: str | None = None,
    ) -> SecretRecord | None:
        """Add one masked observation (deduplicated by kind+masked+source)."""
        if not kind or not masked:
            return None
        key = (kind, masked, source)
        if key in self._seen or len(self._records) >= self.max_records:
            return None
        self._seen.add(key)
        record = SecretRecord(kind=kind, masked=masked, source=source, check=check)
        self._records.append(record)
        return record

    def extend(
        self,
        observations: Iterable[tuple[str, str]],
        *,
        source: str,
        check: str | None = None,
    ) -> None:
        for kind, masked in observations:
            self.record(kind, masked, source=source, check=check)

    def payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "note": (
                "Masked credential fingerprints only (detector, prefix/suffix, length and "
                "location). No usable value is stored. Encrypted at rest; see ADR-120.6."
            ),
            "metadata": self.metadata,
            "secrets": [record.to_dict() for record in self._records],
        }

    def flush(self) -> Path | None:
        """Encrypt and write the manifest; returns the path, or ``None`` when empty."""
        if not self._records:
            return None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.payload(), indent=2, sort_keys=True).encode("utf-8")
        blob = encrypt_manifest(payload, self._passphrase)
        # Write-then-rename so a crash cannot leave a half-written manifest.
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_bytes(blob)
        temporary.replace(self.path)
        with contextlib.suppress(OSError):  # pragma: no cover - platform dependent
            self.path.chmod(0o600)
        self.written = self.path
        _logger.info(
            "secrets manifest written",
            extra={
                "event": "secrets.manifest",
                "path": str(self.path),
                "records": len(self._records),
            },
        )
        return self.path

    @classmethod
    def from_settings(cls, settings: Settings) -> SecretsManifest | None:
        """The manifest ``settings`` asks for, or ``None`` when the feature is off."""
        secrets = settings.secrets
        if not secrets.manifest_path:
            return None
        if secrets.manifest_key is None:
            # Refusing is the only safe answer: writing a plaintext ledger would violate
            # the requirement this class exists for.
            msg = (
                "ARACHNE_SECRETS_MANIFEST is set but ARACHNE_SECRETS_MANIFEST_KEY is not: "
                "refusing to write an unencrypted secrets manifest"
            )
            raise ConfigurationError(msg)
        return cls(
            secrets.manifest_path,
            passphrase=secrets.manifest_key,
            max_records=secrets.max_records,
            metadata={"actor": settings.actor},
        )


def mask_findings(observations: Iterable[str]) -> tuple[tuple[str, str], ...]:
    """Convenience: mask a sequence of raw values (never used on a hot path)."""
    return tuple(("value", mask_secret(value)) for value in observations)
