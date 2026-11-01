"""The deployment key: one signature primitive for the integrity layer (S25).

REQ-TRUST-005 asks for a hash-chained audit log and findings/evidence "signed with a
deployment key". This module is that key and that signature, and nothing else: the
integrity layer (``core.integrity``) decides *what* to sign, this decides *how*.

The construction is HMAC-SHA256 under a deployment key the operator holds, with the
**purpose** of the signature mixed into the message (``domain``) so a signature minted
for one kind of record cannot be replayed as another — an evidence signature is not a
finding signature even when the two payloads coincide. A short key id travels in the
signature so a rotation is visible in the artifact and a verifier can name the key it
refused (``v1:<key id>:<hex>``).

Why symmetric and not a public-key scheme: this runtime stack is deliberately
dependency-free (docs/spec/07- §2 — no ``cryptography``), and a stdlib RSA *private-key*
operation would mean hand-rolling ASN.1 DER parsing in the signing path, where a mistake
is silent. The verifier role (the operator running ``arachne verify-chain``) is the same
party that holds the key, so an HMAC is the honest primitive here. The trade-off — an
auditor who must not be able to forge cannot verify, where a public key would let them —
is recorded in ADR-300.5 as a known limitation, not hidden.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from collections.abc import Mapping
from typing import Any, Final

from pydantic import SecretStr

from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError

__all__ = [
    "SIGNATURE_VERSION",
    "DeploymentSigner",
    "build_signer",
    "canonical_bytes",
    "canonical_text",
    "generate_key",
]

#: Version tag of the signature format, so a future change is detectable rather than
#: merely failing to verify.
SIGNATURE_VERSION: Final = "v1"

#: Domain separator prefix, mixed into every MAC. Distinct from the secrets-manifest /
#: vault constructions (``core.secrets``) so a ciphertext and a signature can never be
#: confused for one another.
_MAGIC: Final = b"arachne-signature\x00"

#: Minimum usable key length; a short key is refused at construction, not at first use.
_MIN_KEY_CHARS: Final = 16


def canonical_text(value: Any) -> str:
    """Deterministic JSON for hashing/signing: sorted keys, no insignificant whitespace.

    The one canonicalisation the whole integrity layer shares, so a digest computed by
    the writer and one recomputed by the verifier agree byte for byte. ``default=str``
    handles the datetimes and enums a row carries.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def canonical_bytes(value: Any) -> bytes:
    """UTF-8 bytes of :func:`canonical_text`."""
    return canonical_text(value).encode("utf-8")


def generate_key() -> str:
    """A fresh deployment key (32 bytes, URL-safe). The operator stores it out of band."""
    return secrets.token_urlsafe(32)


class DeploymentSigner:
    """Signs and verifies integrity artifacts under one deployment key.

    The key never leaves the object; ``key_id`` is a non-secret label (a digest prefix)
    that travels in every signature so a verifier can say *which* key it could not
    verify against.
    """

    __slots__ = ("_key", "key_id")

    def __init__(self, key: str | SecretStr, *, key_id: str | None = None) -> None:
        raw = key.get_secret_value() if isinstance(key, SecretStr) else key
        if len(raw.strip()) < _MIN_KEY_CHARS:
            msg = (
                "the integrity key is too short: mixing in a weak key would make every "
                "signature forgeable, so a key of at least "
                f"{_MIN_KEY_CHARS} characters is required (ARACHNE_INTEGRITY_KEY)"
            )
            raise ConfigurationError(msg)
        self._key = raw.encode("utf-8")
        self.key_id = key_id or hashlib.sha256(self._key).hexdigest()[:16]

    def sign(self, domain: str, payload: bytes) -> str:
        """``v1:<key id>:<hex>`` for ``payload`` in ``domain``."""
        digest = hmac.new(self._key, self._message(domain, payload), hashlib.sha256).hexdigest()
        return f"{SIGNATURE_VERSION}:{self.key_id}:{digest}"

    def verify(self, domain: str, payload: bytes, signature: str | None) -> bool:
        """True when ``signature`` is this key's signature of ``payload`` in ``domain``.

        A malformed signature, a signature from another key id and a wrong signature are
        all ``False`` — the caller reports "not verifiable" either way, which is what
        tamper-evidence needs.
        """
        if not signature:
            return False
        parts = signature.split(":")
        if len(parts) != 3 or parts[0] != SIGNATURE_VERSION:
            return False
        if not hmac.compare_digest(parts[1], self.key_id):
            return False
        expected = self.sign(domain, payload).rsplit(":", 1)[1]
        return hmac.compare_digest(expected, parts[2])

    def _message(self, domain: str, payload: bytes) -> bytes:
        return _MAGIC + domain.encode("utf-8") + b"\x00" + payload

    def __repr__(self) -> str:  # pragma: no cover - debugging aid, never logs the key
        return f"DeploymentSigner(key_id={self.key_id!r})"


def build_signer(settings: Settings | None = None) -> DeploymentSigner | None:
    """The deployment's signer, or ``None`` when no key is configured.

    ``None`` is a legal, audited state: the audit chain still exists and still detects a
    recomputed-hash mismatch, but ``arachne verify-chain --require-signatures`` refuses,
    and the operator guide says so. A deployment that wants the full guarantee sets
    ``ARACHNE_INTEGRITY_KEY``.
    """
    from arachne.core.config import get_settings

    effective = settings or get_settings()
    configured: SecretStr | None = effective.integrity.key
    if configured is None or not configured.get_secret_value().strip():
        return None
    return DeploymentSigner(configured, key_id=effective.integrity.key_id or None)


def sign_mapping(
    signer: DeploymentSigner, domain: str, value: Mapping[str, Any]
) -> str:
    """Convenience: sign a mapping's canonical form."""
    return signer.sign(domain, canonical_bytes(dict(value)))


def verify_mapping(
    signer: DeploymentSigner,
    domain: str,
    value: Mapping[str, Any],
    signature: str | None,
) -> bool:
    """Convenience: verify a mapping's canonical form."""
    return signer.verify(domain, canonical_bytes(dict(value)), signature)
