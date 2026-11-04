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
dependency-free (— no ``cryptography``), and a stdlib RSA *private-key*
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
from collections.abc import Iterable, Mapping
from typing import Any, Final

from pydantic import SecretStr

from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError

__all__ = [
    "SIGNATURE_VERSION",
    "DeploymentSigner",
    "SigningKeyring",
    "build_content_keyring",
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


class SigningKeyring:
    """The keys a deployment will *accept* content signatures from, in preference order.

    One key is the primary — it signs, and it is the deployment's own
    (:func:`build_signer`) — and any number of further keys verify. The reason for a set rather
    than a key is rotation: a marketplace operator who replaces their content key has to keep
    accepting the old one until every pack and index has been re-signed, or the "rotation"
    is a flag day in which nothing loads (REQ-ECOS-008: "rotation is possible without a flag
    day"). Both keys verify during the overlap; the primary still signs.

    An **empty** keyring is a real state and the fail-closed one: with no key configured,
    nothing can be verified, so every signed artifact is refused. That is deliberate — "no key"
    must never mean "accept anything".
    """

    __slots__ = ("_signers",)

    def __init__(self, signers: Iterable[DeploymentSigner] = ()) -> None:
        seen: dict[str, DeploymentSigner] = {}
        for signer in signers:
            seen.setdefault(signer.key_id, signer)
        self._signers = tuple(seen.values())

    @classmethod
    def of(cls, keys: Iterable[str | SecretStr], *, key_ids: Iterable[str] = ()) -> SigningKeyring:
        """Build a keyring from raw key material; blank entries are skipped, not accepted."""
        labels = list(key_ids)
        built: list[DeploymentSigner] = []
        for index, key in enumerate(keys):
            raw = key.get_secret_value() if isinstance(key, SecretStr) else key
            if not raw.strip():
                continue
            label = labels[index] if index < len(labels) and labels[index].strip() else None
            built.append(DeploymentSigner(raw, key_id=label))
        return cls(built)

    def __len__(self) -> int:
        return len(self._signers)

    def __bool__(self) -> bool:
        return bool(self._signers)

    @property
    def signers(self) -> tuple[DeploymentSigner, ...]:
        return self._signers

    @property
    def signer(self) -> DeploymentSigner | None:
        """The primary key: the one this deployment signs with."""
        return self._signers[0] if self._signers else None

    def key_ids(self) -> tuple[str, ...]:
        """Every accepted key id, so a refusal can say what *would* have been accepted."""
        return tuple(signer.key_id for signer in self._signers)

    def admits(self, key_id: str | None) -> bool:
        """True when ``key_id`` is a key this deployment trusts."""
        if not key_id:
            return False
        return any(signer.key_id == key_id for signer in self._signers)

    def sign(self, domain: str, payload: bytes) -> str:
        """Sign with the primary key; a keyring with no key cannot sign."""
        primary = self.signer
        if primary is None:
            msg = (
                "no content key is configured, so nothing can be signed: set "
                "ARACHNE_INTEGRITY_KEY (or ARACHNE_CONTENT_KEYS) first"
            )
            raise ConfigurationError(msg)
        return primary.sign(domain, payload)

    def verify(self, domain: str, payload: bytes, signature: str | None) -> bool:
        """True when *any* accepted key signed ``payload`` in ``domain``.

        The key id in the signature selects the candidate, so a rotation set costs one HMAC
        rather than one per key; and a signature naming a key this deployment does not hold is
        refused without trying anything else.
        """
        if not signature:
            return False
        parts = signature.split(":")
        if len(parts) != 3 or parts[0] != SIGNATURE_VERSION:
            return False
        for signer in self._signers:
            if signer.key_id == parts[1]:
                return signer.verify(domain, payload, signature)
        return False

    def __repr__(self) -> str:  # pragma: no cover - debugging aid, never logs a key
        return f"SigningKeyring(key_ids={self.key_ids()!r})"


def build_content_keyring(settings: Settings | None = None) -> SigningKeyring:
    """The key set content signatures are verified against (REQ-ECOS-008).

    The deployment's own key comes first (:func:`build_signer`, i.e. ``ARACHNE_INTEGRITY_KEY``),
    then ``ARACHNE_CONTENT_KEYS`` — the *additional* keys accepted during a rotation. With
    neither configured the keyring is empty and every signed pack or index is refused, which is
    the fail-closed default the requirement asks for ("defaults to none").
    """
    from arachne.core.config import get_settings

    effective = settings or get_settings()
    signers: list[DeploymentSigner] = []
    primary = build_signer(effective)
    if primary is not None:
        signers.append(primary)
    extras = SigningKeyring.of(effective.integrity.content_keys)
    signers.extend(extras.signers)
    return SigningKeyring(signers)


def sign_mapping(signer: DeploymentSigner, domain: str, value: Mapping[str, Any]) -> str:
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
