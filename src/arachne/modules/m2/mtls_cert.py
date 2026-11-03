"""A throwaway, self-signed client certificate built in process (REQ-DET-011).

The mTLS observation needs to present *a certificate the product does not own* and see what
the server does with it. Two rules constrain how that certificate may exist:

1. **It must never be a credential belonging to a real principal.** So the key below belongs
   to nobody: it is generated once for this probe, published in this file on purpose, and
   its only use is to sign one certificate whose subject names no person, no host and no
   organisation. Nothing in ARACHNE can authenticate with it anywhere — the server the
   probe talks to rejects it precisely because no trust anchor knows it.
2. **It must be generated in process and discarded.** :func:`throwaway_client_certificate`
   builds the DER with the repository's own BER writer (no crypto dependency: the dependency
   set has none, and this module must work in an air-gapped install) and signs it with
   ``pow()``. Nothing is written to disk; the bytes live in one call and are dropped.

Hand-rolled cryptography needs a justification, so: the only primitive used is textbook
RSA PKCS#1 v1.5 over SHA-256 for a **self-signature**, which is a single modular
exponentiation — the same "no crypto dependency" precedent the module records for MD4 and
NTLMv2 (ADR-240.5). It is verified in both directions by the test suite: the certificate
decodes with the platform's own X.509 parser, and its signature re-computes with ``e``. If
either check failed the fixture would be a malformed blob rather than a certificate, and the
mTLS observation would be measuring the wrong thing.

What the probe does with the certificate is in :mod:`arachne.modules.m2.mtls`: it appears in
exactly one TLS ``Certificate`` message and is never used to complete a handshake.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache

from arachne.modules.m2.wire import ber_int, ber_tlv

__all__ = [
    "THROWAWAY_CERTIFICATE_SUBJECT",
    "THROWAWAY_KEY_BITS",
    "certificate_der",
    "verify_self_signature",
]

# --------------------------------------------------------------------------- the throwaway key
#
# A 2048-bit RSA key, generated once for this probe and published deliberately. It is not a
# secret: it exists so that a certificate can be *validly self-signed* without the product
# shipping (or generating at scan time) a credential. `tests/unit/test_mtls.py` proves the
# certificate's signature verifies with the public exponent below, which is what "self-signed"
# means here. Nothing else in ARACHNE reads these values.
_THROWAWAY_N = int(
    "f2e4bfce718fedbd64db936d0bc9e793416dbb2f0d1621a883e750aa8a47e6f5"
    "9daf673a8c5f4becd255c0645d1cb5c27603eb6e52c0cb10e4df56a20ee4bef1"
    "4f24fb97fc80c348998cbc3f86a9d116ceded2bf331f227f9e399ae4d24563e8"
    "1d991f619d833dd78ff0487b22b16295dfdebef9ab16435d28728abf2c956545"
    "59311061b832c11bed3ae4a948bef63d3e5fd3e3ade1fb3c59b47b07332f58a0"
    "f59dd5ea2f707890b43cc794225e825209fe2b5f109cd02a85542cc3cf76d9"
    "519d87a08159efad87a1ff66c5b1a8d2b92dd043aa30bf3bc3b71c349bd82b"
    "1e42c4c8fda4f3f900148e7334c37b1cd6a4c5d7abc494c3ce1daf64a16bba9"
    "60d2d",
    16,
)
_THROWAWAY_E = 65537
_THROWAWAY_D = int(
    "256ca0f00c57d693e6b11d55412a7e1396927373a3b2cc0354b5849c8e3b5766"
    "f3419628737df06b201a65cf20f89e39c4e8c432e6adbd6c1033a83bc68b30af"
    "6a1822eacf5540a1944516b13c0cb8c268a3f4f950456511a03db473bac145cc"
    "3b193f7851266a56271fa8ef4e10624600ed27643d1bec4bb3827885cdb70417"
    "ff341ce82da3821336e8e4d202658a12a51c9d179be6bd30945b98131b1338ca"
    "3b408831266fefb922b9197a883be36872e0309b3adad5f942649650467ec92e"
    "6a50217de89914a38a127d70262dda4199306083300bf51933f468652a3a7156"
    "adacda24e1cb37afe1ae6fbed7fd7c4698c3931677e720dd03c38519c38b2e29",
    16,
)

#: The certificate's only identity. No person, host or organisation — and the reserved
#: ``.invalid`` TLD (RFC 2606) so nothing can resolve it if it ever escaped.
THROWAWAY_CERTIFICATE_SUBJECT = (
    ("organizationName", "ARACHNE throwaway mTLS probe (not a credential)"),
    ("commonName", "arachne-mtls-probe.invalid"),
)
#: The key size, reported in evidence so a reader can see the credential is a real certificate.
THROWAWAY_KEY_BITS = 2048

# --------------------------------------------------------------------------- DER constants
_SEQUENCE = 0x30
_SET = 0x31
_INTEGER = 0x02
_BIT_STRING = 0x03
_OCTET_STRING = 0x04
_NULL = 0x05
_BOOLEAN = 0x01
_OID = 0x06
_UTF8_STRING = 0x0C
_UTC_TIME = 0x17
_EXPLICIT_0 = 0xA0
_EXPLICIT_3 = 0xA3

#: ``sha256WithRSAEncryption`` (1.2.840.113549.1.1.11) — the signature algorithm of the
#: certificate itself.
_SHA256_WITH_RSA = bytes.fromhex("2a864886f70d01010b")
#: ``rsaEncryption`` (1.2.840.113549.1.1.1).
_RSA_ENCRYPTION = bytes.fromhex("2a864886f70d010101")
#: ``sha256`` for the DigestInfo prefix (2.16.840.1.101.3.4.2.1).
_SHA256 = bytes.fromhex("608648016503040201")
_OID_ORGANIZATION = bytes.fromhex("55040a")  # 2.5.4.10
_OID_COMMON_NAME = bytes.fromhex("550403")  # 2.5.4.3
_OID_BASIC_CONSTRAINTS = bytes.fromhex("551d13")  # 2.5.29.19
_OID_KEY_USAGE = bytes.fromhex("551d0f")  # 2.5.29.15
_OID_EXT_KEY_USAGE = bytes.fromhex("551d25")  # 2.5.29.37
_OID_CLIENT_AUTH = bytes.fromhex("2b06010505070302")  # 1.3.6.1.5.5.7.3.2

#: A validity window that is *not* the reason the certificate is rejected: the probe exists
#: so a server can say "I do not trust this", not "this expired".
_NOT_BEFORE = b"200101000000Z"
_NOT_AFTER = b"400101000000Z"

#: ``DigitalSignature`` only (bit 0 of the KeyUsage BIT STRING, unused bits = 7).
_KEY_USAGE_CLIENT = b"\x07\x80"


def _algorithm(oid: bytes) -> bytes:
    """``AlgorithmIdentifier { algorithm, parameters NULL }``."""
    return ber_tlv(_SEQUENCE, ber_tlv(_OID, oid) + ber_tlv(_NULL, b""))


def _name(*pairs: tuple[str, str]) -> bytes:
    """An X.501 ``Name`` from ``(attribute key, value)`` pairs, in the order given."""
    oids = {"organizationName": _OID_ORGANIZATION, "commonName": _OID_COMMON_NAME}
    rdns = b""
    for key, value in pairs:
        attribute = ber_tlv(
            _SEQUENCE, ber_tlv(_OID, oids[key]) + ber_tlv(_UTF8_STRING, value.encode())
        )
        rdns += ber_tlv(_SET, attribute)
    return ber_tlv(_SEQUENCE, rdns)


def _public_key_info() -> bytes:
    # ``ber_int`` is the INTEGER *body*; the tag and length come from ``ber_tlv``.
    modulus = ber_tlv(_INTEGER, ber_int(_THROWAWAY_N))
    exponent = ber_tlv(_INTEGER, ber_int(_THROWAWAY_E))
    rsa_public_key = ber_tlv(_SEQUENCE, modulus + exponent)
    # The public key is a BIT STRING with no unused bits; the leading 0x00 is that count.
    return ber_tlv(
        _SEQUENCE, _algorithm(_RSA_ENCRYPTION) + ber_tlv(_BIT_STRING, b"\x00" + rsa_public_key)
    )


def _digest_info(digest: bytes) -> bytes:
    """``DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }`` for SHA-256."""
    return ber_tlv(_SEQUENCE, _algorithm(_SHA256) + ber_tlv(_OCTET_STRING, digest))


def _sign(tbs: bytes) -> bytes:
    """RSA PKCS#1 v1.5 signature over ``tbs``: one modular exponentiation, nothing else."""
    digest_info = _digest_info(hashlib.sha256(tbs).digest())
    size = (_THROWAWAY_N.bit_length() + 7) // 8
    padding = size - len(digest_info) - 3
    block = b"\x00\x01" + b"\xff" * padding + b"\x00" + digest_info
    signature = pow(int.from_bytes(block, "big"), _THROWAWAY_D, _THROWAWAY_N)
    return signature.to_bytes(size, "big")


def _serial() -> int:
    """A stable serial derived from the subject, so the certificate is reproducible."""
    seed = ",".join(f"{key}={value}" for key, value in THROWAWAY_CERTIFICATE_SUBJECT)
    return int.from_bytes(hashlib.sha256(seed.encode()).digest()[:16], "big") >> 1


def _tbs_certificate() -> bytes:
    name = _name(*THROWAWAY_CERTIFICATE_SUBJECT)
    extensions = (
        ber_tlv(
            _SEQUENCE,
            ber_tlv(_OID, _OID_BASIC_CONSTRAINTS)
            # BasicConstraints ::= SEQUENCE {} — cA absent means FALSE, so this certificate
            # can never be used as a CA.
            + ber_tlv(_OCTET_STRING, ber_tlv(_SEQUENCE, b"")),
        )
        + ber_tlv(
            _SEQUENCE,
            ber_tlv(_OID, _OID_KEY_USAGE)
            + ber_tlv(_BOOLEAN, b"\xff")  # critical TRUE
            + ber_tlv(_OCTET_STRING, ber_tlv(_BIT_STRING, _KEY_USAGE_CLIENT)),
        )
        + ber_tlv(
            _SEQUENCE,
            ber_tlv(_OID, _OID_EXT_KEY_USAGE)
            + ber_tlv(_OCTET_STRING, ber_tlv(_SEQUENCE, ber_tlv(_OID, _OID_CLIENT_AUTH))),
        )
    )
    return ber_tlv(
        _SEQUENCE,
        ber_tlv(_EXPLICIT_0, ber_tlv(_INTEGER, b"\x02"))  # v3
        + ber_tlv(_INTEGER, ber_int(_serial()))
        + _algorithm(_SHA256_WITH_RSA)
        + name  # issuer == subject: self-signed
        + ber_tlv(_SEQUENCE, ber_tlv(_UTC_TIME, _NOT_BEFORE) + ber_tlv(_UTC_TIME, _NOT_AFTER))
        + name
        + _public_key_info()
        + ber_tlv(_EXPLICIT_3, ber_tlv(_SEQUENCE, extensions)),
    )


@lru_cache(maxsize=1)
def certificate_der() -> bytes:
    """The throwaway client certificate as DER, built once per process and kept in memory."""
    tbs = _tbs_certificate()
    # The signature is part of the documented structure; a BIT STRING with no unused bits.
    return ber_tlv(
        _SEQUENCE,
        tbs + _algorithm(_SHA256_WITH_RSA) + ber_tlv(_BIT_STRING, b"\x00" + _sign(tbs)),
    )


def verify_self_signature(der: bytes) -> bool:
    """True when ``der`` is a certificate whose signature verifies against its own key.

    Exposed because "self-signed" is a claim the caller should be able to check: the check
    asserts this before it presents the certificate, so a corrupted build fails loudly
    instead of quietly sending a malformed blob and measuring an OpenSSL parse error.
    """
    outer = _children(der)
    if len(outer) != 3:
        return False
    # The signature covers the *complete* TBSCertificate TLV (header included), while the
    # signature itself is the BIT STRING's value: one unused-bits byte, then the integer.
    tbs = outer[0]
    signature = _value(outer[2])
    if not signature.startswith(b"\x00"):
        return False
    raw = int.from_bytes(signature[1:], "big")
    size = (_THROWAWAY_N.bit_length() + 7) // 8
    recovered = pow(raw, _THROWAWAY_E, _THROWAWAY_N).to_bytes(size, "big")
    expected = _digest_info(hashlib.sha256(tbs).digest())
    return recovered.endswith(expected) and recovered.startswith(b"\x00\x01\xff")


def _children(element: bytes) -> list[bytes]:
    """The value bytes of each child TLV of a constructed element (a tiny DER reader)."""
    body = _value(element)
    out: list[bytes] = []
    index = 0
    while index < len(body):
        start = index
        index += 1  # tag
        length, index = _length(body, index)
        index += length
        out.append(body[start:index])
    return out


def _value(element: bytes) -> bytes:
    if not element:
        return b""
    _, index = _tag(element, 0)
    length, index = _length(element, index)
    return element[index : index + length]


def _tag(data: bytes, index: int) -> tuple[int, int]:
    return data[index], index + 1


def _length(data: bytes, index: int) -> tuple[int, int]:
    first = data[index]
    index += 1
    if first & 0x80:
        count = first & 0x7F
        return int.from_bytes(data[index : index + count], "big"), index + count
    return first, index
