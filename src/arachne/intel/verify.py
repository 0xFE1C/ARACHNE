"""Feed verification: nothing is imported that does not verify (REQ-INTEL-002).

A feed is the one thing in a scan an attacker on the network path can change *without
touching the target*: poison the CVE index and every correlation, every severity and every
remediation built on it is wrong in a way no finding-level check can catch. So integrity is
established **before** an import, and there is no "off" mode:

* ``checksum`` — the SHA-256 digest of the payload must equal the digest the deployment
  pinned (inline ``ARACHNE_INTEL_FEED_CHECKSUMS`` or a manifest file). No pin for a source
  means the import is refused, not waved through.
* ``signature`` — a detached signature over the payload must verify against a pinned RSA
  public key. This is the mode for a deployment that mirrors the feeds itself (or a source
  that publishes signatures): the digest check protects against a corrupted mirror, the
  signature against a hostile one.

Both modes return a :class:`VerificationResult` that is recorded on the feed row and shown in
the report's freshness section, so "which data is this deployment's scanning built on, and was
it verified?" is answerable from the evidence rather than from a log line.

The RSA verifier is stdlib-only (``pow``-based RSASSA-PKCS1-v1_5, the same construction S17
uses for OIDC ID tokens) because the runtime stack of ```` §2 has no crypto
library. Ed25519/GPG signatures are refused rather than downgraded — a mode that silently
weakens is worse than a mode that is absent.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import yaml

from arachne.core.errors import ConfigurationError, FeedIntegrityError

__all__ = [
    "VerificationPolicy",
    "VerificationResult",
    "digest_of",
    "normalise_digest",
    "read_checksum_manifest",
    "resolve_expectations",
    "verify_payload",
    "verify_rsa_pkcs1_sha256",
]

#: Hash prefix a pin may carry (``sha256:<hex>`` and a bare ``<hex>`` are both accepted).
_SHA256_PREFIX: Final = "sha256:"

#: ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note 1).
_SHA256_DIGEST_INFO: Final = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass(frozen=True, slots=True)
class VerificationPolicy:
    """How a deployment wants its feeds verified, and what it pinned."""

    mode: str = "checksum"
    #: ``{source: sha256-hex}`` — the out-of-band expectation from the publisher or from an
    #: operator's own trusted fetch.
    digests: dict[str, str] = field(default_factory=dict)
    #: PEM text of the RSA public key, for ``signature`` mode.
    public_key_pem: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in {"checksum", "signature"}:
            msg = f"unknown feed verification mode {self.mode!r}; expected checksum or signature"
            raise ConfigurationError(msg)
        if self.mode == "signature" and not self.public_key_pem:
            msg = "signature verification needs a pinned public key"
            raise ConfigurationError(msg)

    def expected_digest(self, source: str) -> str | None:
        return self.digests.get(source.strip().lower())


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """What was checked, against what, and whether it held."""

    source: str
    mode: str
    digest: str
    verified: bool
    #: ``None`` when the check passed; the refusal reason when it did not.
    reason: str | None = None
    expected: str | None = None
    key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "mode": self.mode,
            "digest": self.digest,
            "verified": self.verified,
            "reason": self.reason,
            "expected": self.expected,
            "key_id": self.key_id,
        }


# --------------------------------------------------------------------------- digests
def digest_of(payload: bytes) -> str:
    """``sha256:<hex>`` of one payload."""
    return f"{_SHA256_PREFIX}{hashlib.sha256(payload).hexdigest()}"


def normalise_digest(value: str) -> str:
    """Normalise a pinned digest to ``sha256:<lowercase hex>``."""
    text = value.strip().lower()
    if text.startswith(_SHA256_PREFIX):
        text = text[len(_SHA256_PREFIX) :]
    text = text.replace(" ", "")
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        msg = f"{value!r} is not a SHA-256 hex digest"
        raise ConfigurationError(msg)
    return f"{_SHA256_PREFIX}{text}"


def read_checksum_manifest(path: str | Path) -> dict[str, str]:
    """Read a pin manifest: ``{source: digest}`` in JSON, YAML or ``source=digest`` lines.

    The manifest is the *out-of-band* half of the check — an operator obtains it from the
    publisher (or produces it from a trusted fetch) and pins it. A manifest that cannot be
    read is an error, never "no pins, therefore nothing to check".
    """
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        msg = f"feed checksum manifest {resolved} does not exist"
        raise ConfigurationError(msg)
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read feed checksum manifest {resolved}: {exc}"
        raise ConfigurationError(msg) from exc
    return parse_checksum_manifest(text, source=str(resolved))


def parse_checksum_manifest(text: str, *, source: str = "<manifest>") -> dict[str, str]:
    """Parse a manifest body (JSON/YAML mapping or ``name=digest`` lines)."""
    stripped = text.strip()
    if not stripped:
        msg = f"{source}: the checksum manifest is empty"
        raise ConfigurationError(msg)
    data: Any
    try:
        data = yaml.safe_load(stripped)
    except yaml.YAMLError:
        data = None
    if isinstance(data, Mapping):
        return {
            str(key).strip().lower(): normalise_digest(str(value)) for key, value in data.items()
        }
    if isinstance(data, list):
        entries = [item for item in data if isinstance(item, Mapping)]
        if entries:
            return {
                str(item.get("source") or item.get("name") or "").strip().lower(): normalise_digest(
                    str(item.get("sha256") or item.get("digest") or "")
                )
                for item in entries
                if item.get("source") or item.get("name")
            }
    # ``name=digest`` lines (and ``name sha256:...``, the sha256sum layout). A trailing
    # colon is tolerated so an unquoted ``kev: sha256:...`` line still names ``kev``.
    pins: dict[str, str] = {}
    for line in stripped.splitlines():
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        name, separator, value = candidate.partition("=")
        if not separator:
            parts = candidate.split(None, 1)
            if len(parts) != 2:
                continue
            name, value = parts[0], parts[1]
        key = name.strip().strip("\"'").rstrip(":").strip().lower()
        if key and value.strip():
            pins[key] = normalise_digest(value.strip().strip("\"'"))
    if not pins:
        msg = f"{source}: no checksum pins found (expected name=sha256:... lines or a mapping)"
        raise ConfigurationError(msg)
    return pins


def resolve_expectations(
    *, inline: Mapping[str, str] | None = None, manifest: str | Path | None = None
) -> dict[str, str]:
    """Merge inline pins with a manifest file; the inline entry wins for the same source."""
    pins: dict[str, str] = {}
    if manifest:
        pins.update(read_checksum_manifest(manifest))
    for name, value in dict(inline or {}).items():
        pins[str(name).strip().lower()] = normalise_digest(str(value))
    return pins


# --------------------------------------------------------------------------- verification
def verify_payload(
    *,
    source: str,
    payload: bytes,
    policy: VerificationPolicy,
    signature: bytes | None = None,
) -> VerificationResult:
    """Verify one feed payload against ``policy``.

    Returns a result whose ``verified`` flag is the *whole* decision: the caller imports only
    when it is true, and audits the refusal with ``reason`` when it is not, so a tampered
    mirror produces a recorded security event rather than a silent skip.
    """
    digest = digest_of(payload)
    if policy.mode == "checksum":
        expected = policy.expected_digest(source)
        if expected is None:
            return VerificationResult(
                source=source,
                mode=policy.mode,
                digest=digest,
                verified=False,
                reason=(
                    f"no pinned sha256 for source {source!r}; refusing to import an "
                    "unverified feed (REQ-INTEL-002)"
                ),
            )
        normalised = normalise_digest(expected)
        return VerificationResult(
            source=source,
            mode=policy.mode,
            digest=digest,
            verified=digest == normalised,
            reason=None if digest == normalised else f"sha256 mismatch: {digest} != {normalised}",
            expected=normalised,
        )

    # signature mode: the digest is provenance, the signature is the decision.
    assert policy.public_key_pem is not None  # guaranteed by VerificationPolicy
    if signature is None:
        return VerificationResult(
            source=source,
            mode=policy.mode,
            digest=digest,
            verified=False,
            reason=(
                f"no detached signature was available for source {source!r}; refusing to "
                "import an unverified feed (REQ-INTEL-002)"
            ),
        )
    key_id = hashlib.sha256(policy.public_key_pem.encode("utf-8")).hexdigest()[:16]
    try:
        verify_rsa_pkcs1_sha256(policy.public_key_pem, payload, signature)
    except FeedIntegrityError as exc:
        return VerificationResult(
            source=source,
            mode=policy.mode,
            digest=digest,
            verified=False,
            reason=str(exc),
            key_id=key_id,
        )
    return VerificationResult(
        source=source, mode=policy.mode, digest=digest, verified=True, key_id=key_id
    )


def verify_rsa_pkcs1_sha256(public_key_pem: str, message: bytes, signature: bytes | str) -> None:
    """Verify a detached RSASSA-PKCS1-v1_5 (SHA-256) signature; raise when it does not hold.

    ``signature`` may be raw bytes or base64/hex/PEM text (the forms a ``.sig`` file arrives
    in). Raises :class:`~arachne.core.errors.FeedIntegrityError` on any failure — a malformed
    key, an unsupported signature algorithm and a wrong signature are all "this payload is not
    signed by the pinned key", which is the honest answer the caller needs.
    """
    raw = _signature_bytes(signature)
    modulus, exponent = rsa_public_numbers(public_key_pem)
    key_size = (modulus.bit_length() + 7) // 8
    if len(raw) != key_size:
        msg = f"signature is {len(raw)} bytes but the key is {key_size} bytes"
        raise FeedIntegrityError(msg)
    value = int.from_bytes(raw, "big")
    if value >= modulus:
        msg = "signature is not a valid RSA value for the pinned key"
        raise FeedIntegrityError(msg)
    recovered = pow(value, exponent, modulus).to_bytes(key_size, "big")
    # RFC 8017 §9.2: 0x00 || 0x01 || 0xFF..FF || 0x00 || DigestInfo || H(message).
    if not recovered.startswith(b"\x00\x01"):
        msg = "signature is not an RSASSA-PKCS1-v1_5 block"
        raise FeedIntegrityError(msg)
    separator = recovered.find(b"\x00", 2)
    if separator == -1 or any(byte != 0xFF for byte in recovered[2:separator]):
        msg = "signature block padding is malformed"
        raise FeedIntegrityError(msg)
    if recovered[separator + 1 :] != _SHA256_DIGEST_INFO + hashlib.sha256(message).digest():
        msg = "RSA signature does not match the pinned public key"
        raise FeedIntegrityError(msg)


def _signature_bytes(signature: bytes | str) -> bytes:
    if isinstance(signature, bytes):
        return signature
    text = signature.strip()
    if text.startswith("-----BEGIN"):
        return _pem_block(text, "SIGNATURE")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        try:
            return bytes.fromhex(text)
        except ValueError as exc:
            msg = "signature is neither PEM, base64 nor hex"
            raise FeedIntegrityError(msg) from exc


# --------------------------------------------------------------------------- RSA keys
def rsa_public_numbers(public_key_pem: str) -> tuple[int, int]:
    """``(modulus, exponent)`` from a PEM RSA public key (SPKI or PKCS#1).

    Both wrappers are two-element SEQUENCEs, so the discriminator is the *second* element's
    tag: an INTEGER (``0x02``) is PKCS#1's ``RSAPublicKey``, a BIT STRING (``0x03``) is
    X.509's ``SubjectPublicKeyInfo`` wrapping it.
    """
    der = _pem_block(public_key_pem, "PUBLIC KEY")
    try:
        outer, _ = _read_der(der, 0)
        children = _der_children(outer)
    except ValueError as exc:
        msg = f"the pinned public key is not a readable DER structure: {exc}"
        raise FeedIntegrityError(msg) from exc
    if len(children) == 2 and children[1][0] == 0x02:  # PKCS#1: SEQUENCE { INTEGER n, INTEGER e }
        return _as_int(children[0]), _as_int(children[1])
    if len(children) == 2 and children[1][0] == 0x03:  # SPKI: SEQUENCE { AlgorithmIdentifier,
        try:  #                                        BIT STRING { RSAPublicKey } }
            bit_string, _ = _read_der(children[1], 0, tag=0x03)
            inner, _ = _read_der(bit_string[1:], 0, tag=0x30)
            parts = _der_children(inner)
        except ValueError as exc:
            msg = f"the pinned public key has no readable RSA public key: {exc}"
            raise FeedIntegrityError(msg) from exc
        if len(parts) < 2 or parts[0][0] != 0x02:
            msg = "the pinned public key is not an RSA key"
            raise FeedIntegrityError(msg)
        return _as_int(parts[0]), _as_int(parts[1])
    msg = "the pinned public key is neither an SPKI nor a PKCS#1 RSA key"
    raise FeedIntegrityError(msg)


def _pem_block(text: str, label: str) -> bytes:
    lines = [
        line.strip()
        for line in text.strip().splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    if not lines:
        msg = f"the pinned {label.lower()} is empty"
        raise FeedIntegrityError(msg)
    try:
        return base64.b64decode("".join(lines), validate=True)
    except (binascii.Error, ValueError) as exc:
        msg = f"the pinned {label.lower()} is not valid base64"
        raise FeedIntegrityError(msg) from exc


def _read_der(data: bytes, offset: int, *, tag: int = 0x30) -> tuple[bytes, int]:
    """Read one DER TLV of ``tag``; return ``(content, next offset)``."""
    if offset >= len(data) or data[offset] != tag:
        msg = f"expected DER tag 0x{tag:02x}"
        raise ValueError(msg)
    offset += 1
    if offset >= len(data):
        raise ValueError("truncated DER length")
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return data[offset:end], end


def _der_children(content: bytes) -> list[bytes]:
    """Split a SEQUENCE body with ``(tag, value)`` pairs, preserving each element's tag."""
    children: list[bytes] = []
    offset = 0
    while offset < len(content):
        tag = content[offset]
        body, offset = _read_der(content, offset, tag=tag)
        children.append(bytes([tag]) + _encode_length(len(body)) + body)
    return children


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def _as_int(element: bytes) -> int:
    body, _ = _read_der(element, 0, tag=0x02)
    return int.from_bytes(body, "big")
