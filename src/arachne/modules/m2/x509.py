"""A bounded X.509 reader for the TLS deep scan (research ch02#14).

Python's ``ssl`` module hands back the peer certificate as DER and — deliberately — refuses
to *decode* it unless it validated the chain against a trust store. For a TLS posture scan
that is exactly backwards: the certificates that matter most are the untrusted, expired and
self-signed ones. This module therefore reads the handful of fields M2 reports (subject,
issuer, validity window, serial, key size, SANs, CA flag) straight out of the DER, using
nothing but the standard library.

Scope and limits, stated plainly:

* **Not a validator.** No signature checking, no chain building, no policy. Validation is
  not the job here — ``m2.tls-deep-scan`` reports what the server presented and separately
  reports whether a *verifying* handshake accepted it (see ``arachne.core.net``).
* **Not a general DER library.** It understands the structures a certificate contains, and
  returns ``None`` the moment the shape is unexpected, rather than half-parsing something.
* **Bounded.** Every read is length-checked, nesting is capped, and SAN/name lists are
  truncated, so a hostile certificate cannot make a scan allocate without limit.
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from arachne.modules.m2.wire import BerReader

__all__ = [
    "CertificateInfo",
    "days_until",
    "parse_certificate",
    "parse_der_time",
]

#: OID bodies (without the leading 0x06 tag/length) for the attributes M2 names.
_OID_NAMES: dict[bytes, str] = {
    bytes.fromhex("550403"): "CN",
    bytes.fromhex("550404"): "SN",
    bytes.fromhex("550405"): "serialNumber",
    bytes.fromhex("550406"): "C",
    bytes.fromhex("550407"): "L",
    bytes.fromhex("550408"): "ST",
    bytes.fromhex("550409"): "street",
    bytes.fromhex("55040a"): "O",
    bytes.fromhex("55040b"): "OU",
    bytes.fromhex("55042a"): "DC",
    bytes.fromhex("2a864886f70d010901"): "emailAddress",
    bytes.fromhex("2a864886f70d0307"): "serverAuth",
}

_OID_SAN = bytes.fromhex("551d11")
_OID_BASIC_CONSTRAINTS = bytes.fromhex("551d13")
_OID_KEY_USAGE = bytes.fromhex("551d0f")
_OID_SIGNATURE_ALGORITHMS = {
    bytes.fromhex("2a864886f70d01010b"): "sha256WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010c"): "sha384WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010d"): "sha512WithRSAEncryption",
    bytes.fromhex("2a864886f70d010105"): "sha1WithRSAEncryption",
    bytes.fromhex("2a864886f70d010104"): "md5WithRSAEncryption",
    bytes.fromhex("2a864886f70d01010a"): "rsassaPss",
    bytes.fromhex("2a8648ce3d040302"): "ecdsa-with-SHA256",
    bytes.fromhex("2a8648ce3d040303"): "ecdsa-with-SHA384",
    bytes.fromhex("2b6570"): "ed25519",
}
_OID_PUBLIC_KEY = {
    bytes.fromhex("2a864886f70d010101"): "rsaEncryption",
    bytes.fromhex("2a8648ce3d0201"): "id-ecPublicKey",
    bytes.fromhex("2b6570"): "Ed25519",
}
_EC_CURVE_BITS = {
    bytes.fromhex("2a8648ce3d030107"): 256,  # prime256v1 / secp256r1
    bytes.fromhex("2b81040022"): 384,  # secp384r1
    bytes.fromhex("2b81040023"): 521,  # secp521r1
    bytes.fromhex("2b8104000a"): 256,  # secp256k1
}

MAX_NAMES = 64
MAX_SANS = 128
MAX_EXTENSIONS = 64


@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """The certificate facts M2 reports, with no trust judgement attached."""

    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    not_before: datetime | None = None
    not_after: datetime | None = None
    serial: str = ""
    signature_algorithm: str | None = None
    public_key_algorithm: str | None = None
    public_key_bits: int | None = None
    subject_alt_names: tuple[str, ...] = ()
    is_ca: bool | None = None
    sha256: str = ""
    der_length: int = 0
    version: int | None = None

    # ------------------------------------------------------------------ derived
    @property
    def common_name(self) -> str | None:
        return self.subject.get("CN") or None

    @property
    def issuer_common_name(self) -> str | None:
        return self.issuer.get("CN") or None

    @property
    def is_self_signed(self) -> bool:
        """True when issuer and subject are identical, which for a leaf means self-signed.

        A self-signed *root* is normal; the caller has to know which one it is looking at,
        which is why this is an observation and not a verdict.
        """
        return bool(self.subject) and self.subject == self.issuer

    def expired(self, *, now: datetime | None = None) -> bool:
        moment = now or datetime.now(UTC)
        return self.not_after is not None and self.not_after < moment

    def not_yet_valid(self, *, now: datetime | None = None) -> bool:
        moment = now or datetime.now(UTC)
        return self.not_before is not None and self.not_before > moment

    def days_until_expiry(self, *, now: datetime | None = None) -> int | None:
        if self.not_after is None:
            return None
        moment = now or datetime.now(UTC)
        return (self.not_after - moment).days

    def hostname_mismatch(self, host: str) -> bool:
        """True when neither the CN nor a SAN matches ``host`` (a plain, lowercase compare).

        Deliberately literal: wildcard matching here would need the same care the hosts file
        gives it, and the caller already reports the SAN list for a human to read.
        """
        candidate = host.strip().lower().rstrip(".")
        names = {name.strip().lower().rstrip(".") for name in self.subject_alt_names}
        if self.common_name:
            names.add(self.common_name.strip().lower().rstrip("."))
        if not names:
            return False  # nothing to compare: not a mismatch we can prove
        for name in names:
            if name == candidate:
                return False
            wildcard = name.startswith("*.") and candidate.endswith(name[1:])
            if wildcard and candidate.count(".") == name.count("."):
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "common_name": self.common_name,
            "issuer_common_name": self.issuer_common_name,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "not_after": self.not_after.isoformat() if self.not_after else None,
            "serial": self.serial,
            "signature_algorithm": self.signature_algorithm,
            "public_key_algorithm": self.public_key_algorithm,
            "public_key_bits": self.public_key_bits,
            "subject_alt_names": list(self.subject_alt_names[:64]),
            "is_ca": self.is_ca,
            "self_signed": self.is_self_signed,
            "expired": self.expired(),
            "not_yet_valid": self.not_yet_valid(),
            "days_until_expiry": self.days_until_expiry(),
            "sha256": self.sha256,
            "der_length": self.der_length,
        }


def parse_der_time(raw: bytes) -> datetime | None:
    """Parse a DER UTCTime (YYMMDDHHMMSSZ) or GeneralizedTime (YYYYMMDDHHMMSSZ)."""
    text = raw.decode("ascii", "replace").strip()
    if text.endswith("Z"):
        text = text[:-1]
    offset_minutes = 0
    if "+" in text[10:] or "-" in text[10:]:
        sign = 1 if "+" in text[10:] else -1
        head, _, tail = text[10:].partition("+" if sign > 0 else "-")
        text = text[:10] + head
        if tail:
            offset_minutes = sign * int(tail[:2] or 0) * 60 + sign * int(tail[2:4] or 0)
    try:
        if len(text) == 12:  # UTCTime
            year = int(text[:2])
            year += 2000 if year < 50 else 1900
            moment = datetime(
                year,
                int(text[2:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                int(text[10:12]),
                tzinfo=UTC,
            )
        elif len(text) >= 14:  # GeneralizedTime
            moment = datetime(
                int(text[:4]),
                int(text[4:6]),
                int(text[6:8]),
                int(text[8:10]),
                int(text[10:12]),
                int(text[12:14]),
                tzinfo=UTC,
            )
        else:
            return None
    except ValueError:
        return None
    from datetime import timedelta

    return moment - timedelta(minutes=offset_minutes)


def days_until(moment: datetime, *, now: datetime | None = None) -> int:
    return (moment - (now or datetime.now(UTC))).days


def _oid_name(body: bytes) -> str:
    return _OID_NAMES.get(body, _format_oid(body))


def _format_oid(body: bytes) -> str:
    """Render an OID body in dotted form (first two arcs share a byte)."""
    if not body:
        return ""
    first = body[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _decode_directory_name(reader: BerReader, *, limit: int = MAX_NAMES) -> dict[str, str]:
    """Decode a Name (SEQUENCE OF RelativeDistinguishedName) into ``{attribute: value}``."""
    name: dict[str, str] = {}
    tag, body = reader.read_tlv()
    if tag != 0x30:
        raise ValueError("expected a Name sequence")
    outer = BerReader(body)
    for _ in range(limit):
        if outer.eof:
            break
        set_tag, set_body = outer.read_tlv()
        if set_tag != 0x31:
            continue
        attribute = BerReader(set_body)
        try:
            atv_tag, atv_body = attribute.read_tlv()
            if atv_tag != 0x30:
                continue
            pair = BerReader(atv_body)
            oid_tag, oid_body = pair.read_tlv()
            _value_tag, value_body = pair.read_tlv()
        except ValueError:
            continue
        if oid_tag != 0x06:
            continue
        key = _oid_name(oid_body)
        name[key] = value_body.decode("utf-8", "replace")
    return name


def parse_certificate(der: bytes) -> CertificateInfo | None:
    """Read a DER certificate into :class:`CertificateInfo`; ``None`` when unreadable."""
    if not der or len(der) < 64:
        return None
    try:
        root = BerReader(der)
        tag, body = root.read_tlv()
        if tag != 0x30:
            return None
        certificate = BerReader(body)
        tbs_tag, tbs_body = certificate.read_tlv()
        if tbs_tag != 0x30:
            return None
        tbs = BerReader(tbs_body)

        version: int | None = None
        first_tag, first_body = tbs.read_tlv()
        if first_tag == 0xA0:  # [0] EXPLICIT version
            version = int.from_bytes(first_body[-1:], "big") + 1
            serial_tag, serial_body = tbs.read_tlv()
        else:
            serial_tag, serial_body = first_tag, first_body
        serial = serial_body.hex() if serial_tag == 0x02 else ""

        signature_tag, signature_body = tbs.read_tlv()
        signature_algorithm = None
        if signature_tag == 0x30:
            algorithm = BerReader(signature_body)
            oid_tag, oid_body = algorithm.read_tlv()
            if oid_tag == 0x06:
                signature_algorithm = _OID_SIGNATURE_ALGORITHMS.get(oid_body, _format_oid(oid_body))

        issuer = _decode_directory_name(tbs)
        validity_tag, validity_body = tbs.read_tlv()
        not_before = not_after = None
        if validity_tag == 0x30:
            validity = BerReader(validity_body)
            before_tag, before_body = validity.read_tlv()
            after_tag, after_body = validity.read_tlv()
            if before_tag in {0x17, 0x18}:
                not_before = parse_der_time(before_body)
            if after_tag in {0x17, 0x18}:
                not_after = parse_der_time(after_body)
        subject = _decode_directory_name(tbs)
        spki_tag, spki_body = tbs.read_tlv()
        public_key_algorithm = None
        public_key_bits: int | None = None
        if spki_tag == 0x30:
            spki = BerReader(spki_body)
            algorithm_tag, algorithm_body = spki.read_tlv()
            if algorithm_tag == 0x30:
                algorithm = BerReader(algorithm_body)
                oid_tag, oid_body = algorithm.read_tlv()
                if oid_tag == 0x06:
                    public_key_algorithm = _OID_PUBLIC_KEY.get(oid_body, _format_oid(oid_body))
                    if oid_body == bytes.fromhex("2a8648ce3d0201"):
                        # EC: the named curve is the next element of the algorithm identifier.
                        try:
                            curve_tag, curve_body = algorithm.read_tlv()
                            if curve_tag == 0x06:
                                public_key_bits = _EC_CURVE_BITS.get(curve_body)
                        except ValueError:
                            public_key_bits = None
            key_tag, key_body = spki.read_tlv()
            if key_tag == 0x03 and public_key_bits is None:
                public_key_bits = _rsa_bits(key_body) or ((len(key_body) - 1) * 8 or None)

        subject_alt_names, is_ca = _read_extensions(tbs)
    except (ValueError, IndexError, StopIteration):
        return None
    return CertificateInfo(
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        signature_algorithm=signature_algorithm,
        public_key_algorithm=public_key_algorithm,
        public_key_bits=public_key_bits,
        subject_alt_names=subject_alt_names,
        is_ca=is_ca,
        sha256=hashlib.sha256(der).hexdigest(),
        der_length=len(der),
        version=version,
    )


def _rsa_bits(bit_string_body: bytes) -> int | None:
    """The RSA modulus size, read out of the SPKI BIT STRING."""
    if len(bit_string_body) < 2 or bit_string_body[0] != 0x00:
        return None
    try:
        reader = BerReader(bit_string_body[1:])
        sequence_tag, sequence_body = reader.read_tlv()
        if sequence_tag != 0x30:
            return None
        inner = BerReader(sequence_body)
        modulus_tag, modulus_body = inner.read_tlv()
        if modulus_tag != 0x02:
            return None
        bits = len(modulus_body) * 8
        if modulus_body and modulus_body[0] == 0x00:
            bits -= 8
        return bits or None
    except ValueError:
        return None


def _read_extensions(tbs: BerReader) -> tuple[tuple[str, ...], bool | None]:
    """Walk the ``[3] EXPLICIT Extensions`` block for SANs and basicConstraints."""
    sans: list[str] = []
    is_ca: bool | None = None
    try:
        while not tbs.eof:
            tag, body = tbs.read_tlv()
            if tag != 0xA3:
                continue
            extensions_sequence = BerReader(body)
            sequence_tag, sequence_body = extensions_sequence.read_tlv()
            if sequence_tag != 0x30:
                continue
            items = BerReader(sequence_body)
            for _ in range(MAX_EXTENSIONS):
                if items.eof:
                    break
                extension_tag, extension_body = items.read_tlv()
                if extension_tag != 0x30:
                    continue
                extension = BerReader(extension_body)
                oid_tag, oid_body = extension.read_tlv()
                if oid_tag != 0x06:
                    continue
                value_tag, value_body = extension.read_tlv()
                if value_tag == 0x01:  # critical BOOLEAN is optional
                    value_tag, value_body = extension.read_tlv()
                if value_tag != 0x04:
                    continue
                if oid_body == _OID_SAN:
                    sans.extend(_parse_san(value_body))
                elif oid_body == _OID_BASIC_CONSTRAINTS:
                    is_ca = _parse_basic_constraints(value_body)
        if not sans:
            # A certificate with no SAN at all is normal for a CA, and for a leaf it is
            # itself worth reporting; the caller sees an empty tuple either way.
            sans = []
    except (ValueError, IndexError):
        return tuple(sans), is_ca
    return tuple(sans), is_ca


def _parse_san(extension_value: bytes) -> list[str]:
    names: list[str] = []
    try:
        reader = BerReader(extension_value)
        sequence_tag, sequence_body = reader.read_tlv()
        if sequence_tag != 0x30:
            return names
        items = BerReader(sequence_body)
        for _ in range(MAX_SANS):
            if items.eof:
                break
            tag, body = items.read_tlv()
            if tag == 0x82 or tag in {0x81, 0x82 - 1}:  # dNSName
                names.append(body.decode("ascii", "replace"))
            elif tag == 0x87:  # iPAddress
                try:
                    names.append(str(ipaddress.ip_address(body)))
                except ValueError:
                    continue
            elif tag == 0xA4:  # directoryName (a Name)
                try:
                    names.append(_decode_directory_name(BerReader(body)).get("CN", ""))
                except ValueError:
                    continue
    except ValueError:
        return names
    return [name for name in names if name]


def _parse_basic_constraints(extension_value: bytes) -> bool | None:
    try:
        reader = BerReader(extension_value)
        sequence_tag, sequence_body = reader.read_tlv()
        if sequence_tag != 0x30:
            return None
        if not sequence_body:
            return False
        inner = BerReader(sequence_body)
        tag, body = inner.read_tlv()
        if tag == 0x01 and body:
            return body[0] != 0
    except ValueError:
        return None
    return None
