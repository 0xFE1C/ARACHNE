"""The deployment key: one signature primitive for the integrity layer (S25, WP-19).

REQ-TRUST-005 asks for a hash-chained audit log and findings/evidence "signed with a
deployment key". This module is that key and that signature, and nothing else: the
integrity layer (``core.integrity``) decides *what* to sign, this decides *how*.

**Two schemes, one purpose discipline.** REQ-TRUST-008 adds **Ed25519** alongside the original
**HMAC-SHA256** because an HMAC has a property a public key does not: every verifier holds the
signing key and can therefore forge. An auditor who must be able to verify a chain *without*
the power to fabricate one needs the asymmetric scheme, and :class:`Ed25519Signer` is it. The
construction both schemes share is the one that matters most: the **purpose** of a signature is
mixed into the signed message (``domain``), so a signature minted for one kind of record cannot
be replayed as another — an evidence signature is not a finding signature even when the two
payloads coincide — and the same domain separator is used by both, so a scheme change cannot
open a cross-purpose hole.

**The signature format, and why it did not break.** A signature is still three
colon-separated fields: ``<scheme>:<key id>:<hex>``. HMAC signatures keep being minted under
their historical tag ``v1`` — an existing deployment's verifier, and its stored rows, are
unchanged — while ``hmac-sha256`` is accepted as the explicit spelling of the same scheme and
is what a *new* format's readers should expect. Ed25519 signatures carry ``ed25519``. A
verifier therefore dispatches on the first field: an HMAC verifier refuses an Ed25519
signature and vice versa, and :class:`SigningKeyring` — which holds every key a deployment
accepts — verifies either.

**The dual period.** A deployment migrating from HMAC to Ed25519 sets
``ARACHNE_INTEGRITY_ALGORITHM=ed25519`` *and* keeps ``ARACHNE_INTEGRITY_KEY`` set. New rows are
signed with Ed25519; the old HMAC key stays in :func:`build_verifier`'s ring, so rows and
anchors signed before the switch still verify. Once the retention window has passed every
pre-switch row, the HMAC key can be dropped — the cutover is a retention decision, not a flag
day. ``tests/unit/test_signatures.py`` writes a chain under each scheme and verifies both
under one ring.

Why HMAC is still the default: it needs only a shared secret, so a single-host deployment
that never hands a chain to a third party stays as simple as it was. The trade-off is recorded
in ADR-300.5 (as the limitation this requirement closes) and ADR-370 (the redesign).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets
from collections.abc import Iterable, Mapping
from typing import Any, Final, Protocol, runtime_checkable

from pydantic import SecretStr

from arachne.core import ed25519
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError

__all__ = [
    "SCHEME_ED25519",
    "SCHEME_HMAC",
    "SIGNATURE_VERSION",
    "DeploymentSigner",
    "Ed25519Signer",
    "Signer",
    "SigningKeyring",
    "build_content_keyring",
    "build_signer",
    "build_verifier",
    "canonical_bytes",
    "canonical_text",
    "decode_key_material",
    "generate_key",
    "generate_keypair",
    "purpose_message",
    "scheme_of",
]

#: The historical tag for an HMAC-SHA256 signature, still minted so that a deployment which
#: upgrades the *reader* before the *writer* keeps verifying (and so stored rows keep their
#: bytes). It names the scheme, not a separate format.
SIGNATURE_VERSION: Final = "v1"

#: The explicit spellings of the two schemes.
SCHEME_HMAC: Final = "hmac-sha256"
SCHEME_ED25519: Final = "ed25519"

#: Every tag a signature's first field may carry, mapped to the scheme it names.
_SCHEME_TAGS: Final[dict[str, str]] = {
    SIGNATURE_VERSION: SCHEME_HMAC,
    SCHEME_HMAC: SCHEME_HMAC,
    SCHEME_ED25519: SCHEME_ED25519,
}

#: Domain separator prefix, mixed into every signed message. Distinct from the secrets-manifest
#: / vault constructions (``core.secrets``) so a ciphertext and a signature can never be
#: confused for one another, and shared by both schemes so a scheme change cannot re-purpose a
#: signature.
_MAGIC: Final = b"arachne-signature\x00"

#: Minimum usable HMAC key length; a short key is refused at construction, not at first use.
_MIN_KEY_CHARS: Final = 16


def scheme_of(tag: str) -> str | None:
    """The scheme a signature's first field names, or ``None`` when it names none of them."""
    return _SCHEME_TAGS.get(tag.strip().lower())


def purpose_message(domain: str, payload: bytes) -> bytes:
    """The bytes actually signed: the domain separator, the purpose, then the payload.

    One function, used by both schemes, so "the purpose is part of the message" is a property
    of the primitive rather than of each signer's discipline.
    """
    return _MAGIC + domain.encode("utf-8") + b"\x00" + payload


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
    """A fresh HMAC deployment key (32 bytes, URL-safe). The operator stores it out of band."""
    return secrets.token_urlsafe(32)


def generate_keypair() -> tuple[str, str]:
    """A fresh Ed25519 keypair as ``(seed hex, public key hex)``.

    The seed is the *private* half and must be stored like any other secret; the public key is
    what an auditor is given. Hex because it survives a shell, an env file and a YAML document
    without a second encoding question.
    """
    seed = secrets.token_bytes(ed25519.KEY_SIZE)
    return seed.hex(), ed25519.derive_public_key(seed).hex()


def decode_key_material(value: str | bytes, *, expected: int = ed25519.KEY_SIZE) -> bytes:
    """Decode hex or base64/base64url key material of ``expected`` bytes, or refuse.

    Accepting three spellings is a convenience; refusing anything else loudly is the point —
    a key that was silently truncated (or read as text when it was hex) produces signatures
    that "do not verify" forever, which is far worse than a startup error naming the variable.
    """
    if isinstance(value, bytes):
        if len(value) == expected:
            return value
        try:
            text = value.decode("ascii")
        except UnicodeDecodeError:
            text = ""
    else:
        text = value
    candidate = text.strip()
    if not candidate:
        msg = "the key material is empty"
        raise ConfigurationError(msg)
    if len(candidate) == expected * 2:
        try:
            decoded = bytes.fromhex(candidate)
        except ValueError:
            decoded = b""
        if len(decoded) == expected:
            return decoded
    padded = candidate + "=" * (-len(candidate) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            decoded = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        if len(decoded) == expected:
            return decoded
    msg = (
        f"the key material must be {expected} bytes, written as hex ({expected * 2} characters) "
        f"or base64 — got {len(candidate)} character(s) that decode to no such key"
    )
    raise ConfigurationError(msg)


@runtime_checkable
class Signer(Protocol):
    """What the integrity layer needs from a signing scheme.

    Deliberately structural: the HMAC and Ed25519 classes share no state and no base class, and
    a deployment's *verifier* is a :class:`SigningKeyring` (a set of signers, one of which may
    not be able to sign at all). Everything downstream — ``core.integrity``, the audit sink, the
    finding store, the seals — is written against this protocol.
    """

    @property
    def key_id(self) -> str:
        """The non-secret label carried in every signature this key makes."""
        ...

    @property
    def scheme(self) -> str:
        """``hmac-sha256`` or ``ed25519`` — the first field of a signature this key makes."""
        ...

    @property
    def can_sign(self) -> bool:
        """Whether this signer holds signing material (a verifier may hold only the public key)."""
        ...

    def sign(self, domain: str, payload: bytes) -> str:
        """``<scheme>:<key id>:<hex>`` for ``payload`` in ``domain``."""
        ...

    def verify(self, domain: str, payload: bytes, signature: str | None) -> bool:
        """True when ``signature`` is this key's signature of ``payload`` in ``domain``."""
        ...


class DeploymentSigner:
    """Signs and verifies integrity artifacts under one HMAC deployment key.

    The key never leaves the object; ``key_id`` is a non-secret label (a digest prefix)
    that travels in every signature so a verifier can say *which* key it could not
    verify against.
    """

    __slots__ = ("_key", "key_id")

    #: This signer's scheme, as a class attribute too: :class:`SigningKeyring` dispatches on it
    #: without constructing an instance per candidate.
    scheme: Final = SCHEME_HMAC

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

    @property
    def can_sign(self) -> bool:
        """An HMAC signer always holds its key; a verifier is the same object."""
        return True

    def sign(self, domain: str, payload: bytes) -> str:
        """``v1:<key id>:<hex>`` for ``payload`` in ``domain``.

        ``v1`` is the long-standing tag for this scheme and is still what is minted: an older
        reader keeps verifying a newer writer, and stored rows keep their exact bytes.
        """
        digest = hmac.new(self._key, purpose_message(domain, payload), hashlib.sha256).hexdigest()
        return f"{SIGNATURE_VERSION}:{self.key_id}:{digest}"

    def verify(self, domain: str, payload: bytes, signature: str | None) -> bool:
        """True when ``signature`` is this key's signature of ``payload`` in ``domain``.

        A malformed signature, a signature from another key id, a signature in the other
        *scheme* and a wrong signature are all ``False`` — the caller reports "not verifiable"
        either way, which is what tamper-evidence needs.
        """
        if not signature:
            return False
        parts = signature.split(":")
        if len(parts) != 3 or scheme_of(parts[0]) != SCHEME_HMAC:
            return False
        if not hmac.compare_digest(parts[1], self.key_id):
            return False
        expected = self.sign(domain, payload).rsplit(":", 1)[1]
        return hmac.compare_digest(expected, parts[2])

    def __repr__(self) -> str:  # pragma: no cover - debugging aid, never logs the key
        return f"DeploymentSigner(key_id={self.key_id!r})"


class Ed25519Signer:
    """Signs with an Ed25519 seed, or verifies with only the public key (REQ-TRUST-008).

    Two legal shapes, and the difference is the requirement:

    * ``Ed25519Signer(private_key=<seed>)`` — the deployment that signs. The public key is
      derived from the seed, so it cannot disagree with it.
    * ``Ed25519Signer(public_key=<point>)`` — the **auditor**. It verifies every signature the
      holder of the seed made and holds nothing that could make one: :meth:`sign` refuses, and
      there is no code path that turns the public key into a signing key. A test attempts the
      forgery two ways (seeded with the public key, and by editing a valid signature) and both
      fail.

    ``key_id`` is a digest prefix of the *public* key, so it is derivable by any verifier and
    identifies the key that would have to be found to forge.
    """

    __slots__ = ("_public", "_seed", "key_id")

    scheme: Final = SCHEME_ED25519

    def __init__(
        self,
        *,
        private_key: str | bytes | SecretStr | None = None,
        public_key: str | bytes | SecretStr | None = None,
        key_id: str | None = None,
    ) -> None:
        seed = _optional_material(private_key)
        declared = _optional_material(public_key)
        if seed is None and declared is None:
            msg = (
                "an Ed25519 signer needs a private key (to sign and verify) or a public key "
                "(to verify): set ARACHNE_INTEGRITY_ED25519_PRIVATE_KEY or "
                "ARACHNE_INTEGRITY_ED25519_PUBLIC_KEY"
            )
            raise ConfigurationError(msg)
        derived = ed25519.derive_public_key(seed) if seed is not None else None
        if derived is not None and declared is not None and derived != declared:
            msg = (
                "the configured Ed25519 private and public keys do not match: the public key "
                f"for this seed is {derived.hex()}, not {declared.hex()} — one of the two is "
                "from another keypair"
            )
            raise ConfigurationError(msg)
        self._seed = seed
        resolved = derived if derived is not None else declared
        if resolved is None:  # pragma: no cover - both-None was refused before this point
            msg = "an Ed25519 signer needs a private key or a public key"
            raise ConfigurationError(msg)
        self._public = resolved
        if not ed25519.public_key_valid(self._public):
            msg = (
                "the configured Ed25519 public key is not a canonical point on the curve "
                f"({self._public.hex()}) — check it was copied whole"
            )
            raise ConfigurationError(msg)
        self.key_id = key_id or hashlib.sha256(self._public).hexdigest()[:16]

    @property
    def can_sign(self) -> bool:
        """False when this instance holds only the public key (the auditor shape)."""
        return self._seed is not None

    @property
    def public_key(self) -> bytes:
        """The public key, so an auditor's configuration can be compared and published."""
        return self._public

    def sign(self, domain: str, payload: bytes) -> str:
        """``ed25519:<key id>:<hex>`` — and a refusal when this signer has only the public key."""
        if self._seed is None:
            msg = (
                "this Ed25519 signer holds only the public key, so it cannot sign: a verifier "
                "must not be able to forge, and that is the property REQ-TRUST-008 buys. Set "
                "ARACHNE_INTEGRITY_ED25519_PRIVATE_KEY on the host that signs."
            )
            raise ConfigurationError(msg)
        signature = ed25519.sign(self._seed, purpose_message(domain, payload))
        return f"{SCHEME_ED25519}:{self.key_id}:{signature.hex()}"

    def verify(self, domain: str, payload: bytes, signature: str | None) -> bool:
        """True when ``signature`` is a valid Ed25519 signature of this message under this key."""
        if not signature:
            return False
        parts = signature.split(":")
        if len(parts) != 3 or scheme_of(parts[0]) != SCHEME_ED25519:
            return False
        if not hmac.compare_digest(parts[1], self.key_id):
            return False
        try:
            raw = bytes.fromhex(parts[2])
        except ValueError:
            return False
        return ed25519.verify(self._public, purpose_message(domain, payload), raw)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid, never logs the seed
        return f"Ed25519Signer(key_id={self.key_id!r}, can_sign={self.can_sign})"


def _optional_material(value: str | bytes | SecretStr | None) -> bytes | None:
    if value is None:
        return None
    raw = value.get_secret_value() if isinstance(value, SecretStr) else value
    if isinstance(raw, str) and not raw.strip():
        return None
    if isinstance(raw, bytes) and not raw:
        return None
    return decode_key_material(raw)


def _hmac_signer(settings: Settings) -> DeploymentSigner | None:
    configured: SecretStr | None = settings.integrity.key
    if configured is None or not configured.get_secret_value().strip():
        return None
    return DeploymentSigner(configured, key_id=settings.integrity.key_id or None)


def _ed25519_public_material(settings: Settings) -> SecretStr | None:
    return settings.integrity.ed25519_public_key


def _ed25519_signer(settings: Settings) -> Ed25519Signer | None:
    """The deployment's Ed25519 signer (private half) when one is configured."""
    seed = settings.integrity.ed25519_private_key
    if seed is None or not seed.get_secret_value().strip():
        return None
    return Ed25519Signer(
        private_key=seed,
        public_key=_ed25519_public_material(settings),
        key_id=settings.integrity.ed25519_key_id or None,
    )


def _ed25519_verifier(settings: Settings) -> Ed25519Signer | None:
    """An Ed25519 signer for verification: the private half when present, else the public one."""
    signer = _ed25519_signer(settings)
    if signer is not None:
        return signer
    public = _ed25519_public_material(settings)
    if public is None or not public.get_secret_value().strip():
        return None
    return Ed25519Signer(public_key=public, key_id=settings.integrity.ed25519_key_id or None)


def build_signer(settings: Settings | None = None) -> Signer | None:
    """The deployment's signer — the configured algorithm's key, or ``None``.

    ``None`` is a legal, audited state: the audit chain still exists and still detects a
    recomputed-hash mismatch, but ``arachne verify-chain --require-signatures`` refuses,
    and the operator guide says so. A deployment that wants the full guarantee sets
    ``ARACHNE_INTEGRITY_KEY`` (HMAC) or ``ARACHNE_INTEGRITY_ED25519_PRIVATE_KEY`` with
    ``ARACHNE_INTEGRITY_ALGORITHM=ed25519``.

    A deployment configured for Ed25519 that holds *only* the public key returns ``None``
    here — that is the auditor shape: it verifies (:func:`build_verifier`) and must not sign.
    """
    from arachne.core.config import get_settings

    effective = settings or get_settings()
    if effective.integrity.algorithm == "ed25519":
        return _ed25519_signer(effective)
    return _hmac_signer(effective)


class SigningKeyring:
    """The keys a deployment will *accept* signatures from, in preference order.

    One key is the primary — it signs, and it is the deployment's own
    (:func:`build_signer`) — and any number of further keys verify. The reason for a set rather
    than a key is rotation: a marketplace operator who replaces their content key has to keep
    accepting the old one until every pack and index has been re-signed, or the "rotation"
    is a flag day in which nothing loads (REQ-ECOS-008: "rotation is possible without a flag
    day"). Both keys verify during the overlap; the primary still signs.

    A ring is also the **dual-period verifier** of REQ-TRUST-008: it may hold an HMAC key and an
    Ed25519 key at once, dispatch a stored signature to the scheme it names, and so verify a
    chain whose older rows were signed before the scheme changed.

    An **empty** keyring is a real state and the fail-closed one: with no key configured,
    nothing can be verified, so every signed artifact is refused. That is deliberate — "no key"
    must never mean "accept anything".
    """

    __slots__ = ("_signers",)

    def __init__(self, signers: Iterable[Signer] = ()) -> None:
        seen: dict[tuple[str, str], Signer] = {}
        for signer in signers:
            seen.setdefault((signer.scheme, signer.key_id), signer)
        self._signers = tuple(seen.values())

    @classmethod
    def of(cls, keys: Iterable[str | SecretStr], *, key_ids: Iterable[str] = ()) -> SigningKeyring:
        """Build a keyring from raw HMAC key material; blank entries are skipped, not accepted."""
        labels = list(key_ids)
        built: list[Signer] = []
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
    def signers(self) -> tuple[Signer, ...]:
        return self._signers

    @property
    def signer(self) -> Signer | None:
        """The primary key: the one this deployment signs with."""
        return self._signers[0] if self._signers else None

    @property
    def key_id(self) -> str:
        """The primary key's id — the label every signature this ring mints carries.

        Empty when the ring cannot sign (an auditor holding a public key), which is the honest
        answer: there is no key here that would sign. The ids it *accepts* are :meth:`key_ids`.
        """
        primary = self.signer
        if primary is None or not primary.can_sign:
            return ""
        return primary.key_id

    @property
    def scheme(self) -> str:
        """The primary key's scheme (``hmac-sha256`` when there is no key at all)."""
        primary = self.signer
        return primary.scheme if primary is not None else SCHEME_HMAC

    @property
    def can_sign(self) -> bool:
        primary = self.signer
        return primary is not None and primary.can_sign

    def key_ids(self) -> tuple[str, ...]:
        """Every accepted key id, so a refusal can say what *would* have been accepted."""
        return tuple(signer.key_id for signer in self._signers)

    def schemes(self) -> tuple[str, ...]:
        """Every scheme this ring verifies, deduplicated — the dual-period statement."""
        seen: list[str] = []
        for signer in self._signers:
            if signer.scheme not in seen:
                seen.append(signer.scheme)
        return tuple(seen)

    def admits(self, key_id: str | None) -> bool:
        """True when ``key_id`` is a key this deployment trusts."""
        if not key_id:
            return False
        return any(signer.key_id == key_id for signer in self._signers)

    def sign(self, domain: str, payload: bytes) -> str:
        """Sign with the primary key; a keyring with no *signing* key cannot sign.

        Two refusals, because the two situations need different fixes: nothing configured at all
        (there is no key) versus a keyring that accepts only verify-only keys (there is a key,
        and it deliberately cannot forge — the auditor shape).
        """
        primary = self.signer
        if primary is None:
            msg = (
                "no content key is configured, so nothing can be signed: set "
                "ARACHNE_INTEGRITY_KEY (or ARACHNE_CONTENT_KEYS) first"
            )
            raise ConfigurationError(msg)
        if not primary.can_sign:
            msg = (
                "this keyring holds no signing key: every key it accepts is verify-only, so it "
                "can check a signature and must not be able to make one. Set "
                "ARACHNE_INTEGRITY_KEY or ARACHNE_INTEGRITY_ED25519_KEY on the host that signs."
            )
            raise ConfigurationError(msg)
        return primary.sign(domain, payload)

    def verify(self, domain: str, payload: bytes, signature: str | None) -> bool:
        """True when *any* accepted key signed ``payload`` in ``domain``.

        The scheme and key id in the signature select the one candidate, so a rotation set —
        or a dual-period set — costs one signature check rather than one per key; and a
        signature naming a key this deployment does not hold, or a scheme it does not
        implement, is refused without trying anything else.
        """
        if not signature:
            return False
        parts = signature.split(":")
        if len(parts) != 3:
            return False
        scheme = scheme_of(parts[0])
        if scheme is None:
            return False
        for signer in self._signers:
            if signer.scheme == scheme and signer.key_id == parts[1]:
                return signer.verify(domain, payload, signature)
        return False

    def __repr__(self) -> str:  # pragma: no cover - debugging aid, never logs a key
        return f"SigningKeyring(schemes={self.schemes()!r}, key_ids={self.key_ids()!r})"


def build_verifier(settings: Settings | None = None) -> SigningKeyring:
    """Every key this deployment accepts, across **both** schemes (REQ-TRUST-008).

    The ring holds, in order: the configured signing key; the HMAC key whenever one is
    configured (so a chain signed before an Ed25519 cutover still verifies — the documented
    dual period); and the Ed25519 key, private or public, whenever one is configured. It is
    what ``arachne verify-chain`` verifies with, and — because it can hold a public key alone —
    it is the object an auditor who holds no signing material runs.
    """
    from arachne.core.config import get_settings

    effective = settings or get_settings()
    signers: list[Signer] = []
    primary = build_signer(effective)
    if primary is not None:
        signers.append(primary)
    hmac_key = _hmac_signer(effective)
    if hmac_key is not None:
        signers.append(hmac_key)
    ed25519_key = _ed25519_verifier(effective)
    if ed25519_key is not None:
        signers.append(ed25519_key)
    return SigningKeyring(signers)


def build_content_keyring(settings: Settings | None = None) -> SigningKeyring:
    """The key set content signatures are verified against (REQ-ECOS-008).

    The deployment's own keys come first (:func:`build_verifier`, i.e. ``ARACHNE_INTEGRITY_KEY``
    and ``ARACHNE_INTEGRITY_ED25519_*``), then ``ARACHNE_CONTENT_KEYS`` — the *additional* keys
    accepted during a rotation. With neither configured the keyring is empty and every signed
    pack or index is refused, which is the fail-closed default the requirement asks for
    ("defaults to none").
    """
    from arachne.core.config import get_settings

    effective = settings or get_settings()
    signers: list[Signer] = list(build_verifier(effective).signers)
    extras = SigningKeyring.of(effective.integrity.content_keys)
    signers.extend(extras.signers)
    return SigningKeyring(signers)


def sign_mapping(signer: Signer, domain: str, value: Mapping[str, Any]) -> str:
    """Convenience: sign a mapping's canonical form."""
    return signer.sign(domain, canonical_bytes(dict(value)))


def verify_mapping(
    signer: Signer,
    domain: str,
    value: Mapping[str, Any],
    signature: str | None,
) -> bool:
    """Convenience: verify a mapping's canonical form."""
    return signer.verify(domain, canonical_bytes(dict(value)), signature)
