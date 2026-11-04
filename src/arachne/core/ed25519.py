"""Ed25519 (RFC 8032) signatures, in pure Python — the asymmetric half of the deployment key.

REQ-TRUST-008 asks for Ed25519 *alongside* HMAC, and the whole reason is the property an HMAC
cannot have: a verifier must be able to check a signature **without** the power to make one.
That rules out a symmetric key, so this module is the public-key half of
:mod:`arachne.core.signing`.

**Why hand-rolled, and what is deliberately not hand-rolled.** This runtime stack is
dependency-free on purpose (ADR-300.5: "no ``cryptography``"), and the package must work in an
air-gapped install. So the primitive is implemented here from the published algorithm, exactly
as the mTLS fingerprint (ADR-240.5) and the throwaway certificate are, and it is restricted to
the one curve and the one hash RFC 8032 specifies — there is no parameter negotiation, no
ASN.1, no parsing of attacker-chosen key formats beyond the 32-byte encodings below. Correctness
is not asserted in prose: ``tests/unit/test_ed25519.py`` replays the RFC 8032 §7.1 test vectors,
re-derives the public keys, and — when the optional ``cryptography`` wheel happens to be
installed in a developer's environment — cross-checks signatures against it in both directions.

**What it is not.** This is not a constant-time implementation. Scalar multiplication is a
plain square-and-multiply over Python integers, whose running time depends on the scalar's bit
pattern, and CPython's big-integer arithmetic makes no timing guarantees. That is a *documented*
limitation, not a hidden one: it is irrelevant to the threat this control addresses (an auditor
verifying a stored chain, where the key is the deployment's own and the timing observation would
have to come from the machine holding it) and it is named in ``docs/adr/370-*.md`` so that a
deployment whose threat model includes a local timing attacker is told to hold the private key
off the scanning host rather than led to believe the implementation solves it.

The encoding is the RFC's: a 32-byte little-endian point, a 32-byte seed, a 64-byte signature
``R || S``. Every function is a pure function of its bytes.
"""

from __future__ import annotations

import hashlib
from typing import Final

__all__ = [
    "KEY_SIZE",
    "SIGNATURE_SIZE",
    "derive_public_key",
    "public_key_valid",
    "sign",
    "verify",
]

#: The field prime, 2**255 - 19.
_P: Final = 2**255 - 19
#: The group order, l = 2**252 + 27742317777372353535851937790883648493.
_L: Final = 2**252 + 27742317777372353535851937790883648493
#: The curve constant d = -121665/121666.
_D: Final = -121665 * pow(121666, _P - 2, _P) % _P
#: A square root of -1, for the two-step x recovery.
_I: Final = pow(2, (_P - 1) // 4, _P)

#: A seed, a public key: 32 bytes each.
KEY_SIZE: Final = 32
#: ``R || S``: 64 bytes.
SIGNATURE_SIZE: Final = 64

#: A point in extended homogeneous coordinates ``(X, Y, Z, T)`` with ``x = X/Z``, ``y = Y/Z``
#: and ``T = XY/Z``. The affine point is recovered by dividing through by ``Z``.
_Point = tuple[int, int, int, int]

#: The neutral element: ``(0, 1)`` in affine terms.
_IDENTITY: Final[_Point] = (0, 1, 1, 0)


def _add(left: _Point, right: _Point) -> _Point:
    """The unified addition formula for a twisted Edwards curve with ``a = -1``.

    The same formula serves doubling, which is what lets :func:`_scalar_mult` stay short
    enough to read against the RFC — the cost is a little speed, not a separate code path.
    """
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _scalar_mult(point: _Point, scalar: int) -> _Point:
    """``scalar * point``, least-significant bit first. ``scalar`` is reduced by construction."""
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        scalar >>= 1
    return result


def _recover_x(y: int, sign: int) -> int:
    """The x coordinate matching ``y`` and its low bit, or a refusal for a non-point."""
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _I % _P
    if (x * x - x2) % _P != 0:
        msg = "not a point on the Ed25519 curve"
        raise ValueError(msg)
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode_point(data: bytes) -> _Point:
    """A 32-byte encoding as a point; raises :class:`ValueError` for anything else."""
    if len(data) != KEY_SIZE:
        msg = f"an Ed25519 point is {KEY_SIZE} bytes, got {len(data)}"
        raise ValueError(msg)
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _P:
        msg = "the y coordinate is not reduced modulo p"
        raise ValueError(msg)
    x = _recover_x(y, sign)
    return (x, y, 1, x * y % _P)


def _encode_point(point: _Point) -> bytes:
    """The canonical 32-byte encoding: ``y`` with the low bit of ``x`` in the top bit."""
    x, y, z, _ = point
    inverse = pow(z, _P - 2, _P)
    x = x * inverse % _P
    y = y * inverse % _P
    return (y | ((x & 1) << 255)).to_bytes(KEY_SIZE, "little")


def _base_point() -> _Point:
    """The RFC 8032 base point: ``y = 4/5``, ``x`` the even root."""
    y = 4 * pow(5, _P - 2, _P) % _P
    x = _recover_x(y, 0)
    return (x, y, 1, x * y % _P)


_BASE: Final[_Point] = _base_point()


def _expand(seed: bytes) -> tuple[int, bytes]:
    """The RFC 8032 key expansion: the clamped scalar and the 32-byte nonce prefix.

    ``seed`` must already be length-checked by the caller; the two halves are
    SHA-512(seed), the first clamped as the RFC requires (clear the low 3 bits, clear the top
    bit, set the second-highest bit) so every seed maps to a scalar of the right shape.
    """
    digest = bytearray(hashlib.sha512(seed).digest())
    digest[0] &= 248
    digest[31] &= 127
    digest[31] |= 64
    return int.from_bytes(digest[:32], "little"), bytes(digest[32:])


def _check_seed(seed: bytes) -> None:
    if len(seed) != KEY_SIZE:
        msg = f"an Ed25519 seed is {KEY_SIZE} bytes, got {len(seed)}"
        raise ValueError(msg)


def derive_public_key(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte seed (the value a verifier is given)."""
    _check_seed(seed)
    scalar, _ = _expand(seed)
    return _encode_point(_scalar_mult(_BASE, scalar))


def public_key_valid(public: bytes) -> bool:
    """True when ``public`` is a canonical encoding of a point on the curve.

    Canonical matters: a non-canonical encoding of the same point would let one public key
    have two byte spellings, and therefore two key ids for the same key.
    """
    try:
        point = _decode_point(public)
    except ValueError:
        return False
    return _encode_point(point) == public


def sign(seed: bytes, message: bytes) -> bytes:
    """The 64-byte deterministic signature of ``message`` under ``seed`` (RFC 8032 §5.1.6).

    Deterministic on purpose: the same message under the same seed always produces the same
    bytes, so an artefact re-signed by an upgrade either reproduces its old signature exactly or
    the verification notices. No randomness is consumed anywhere in this module.
    """
    _check_seed(seed)
    scalar, prefix = _expand(seed)
    public = _encode_point(_scalar_mult(_BASE, scalar))
    nonce = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % _L
    encoded_r = _encode_point(_scalar_mult(_BASE, nonce))
    challenge = int.from_bytes(hashlib.sha512(encoded_r + public + message).digest(), "little") % _L
    s = (nonce + challenge * scalar) % _L
    return encoded_r + s.to_bytes(KEY_SIZE, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True when ``signature`` is a valid Ed25519 signature of ``message`` under ``public``.

    Every malformed input — a wrong length, a non-canonical or off-curve point, an ``S`` at or
    above the group order, a signature from a different key — is ``False``, never an exception
    and never a pass. A caller reporting tamper-evidence needs one answer for "this is not
    this key's signature of this message", whatever the reason.
    """
    if len(signature) != SIGNATURE_SIZE or not public_key_valid(public):
        return False
    try:
        public_point = _decode_point(public)
        r_point = _decode_point(signature[:KEY_SIZE])
    except ValueError:  # pragma: no cover - public_key_valid already refused a bad public key
        return False
    s = int.from_bytes(signature[KEY_SIZE:], "little")
    if s >= _L:
        return False
    challenge = (
        int.from_bytes(hashlib.sha512(signature[:KEY_SIZE] + public + message).digest(), "little")
        % _L
    )
    left = _scalar_mult(_BASE, s)
    right = _add(r_point, _scalar_mult(public_point, challenge))
    return _encode_point(left) == _encode_point(right)
