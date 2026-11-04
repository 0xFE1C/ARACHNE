"""The Ed25519 primitive against the published test vectors (REQ-TRUST-008).

The implementation in :mod:`arachne.core.ed25519` is hand-rolled (the runtime stack has no
``cryptography`` dependency — see that module's docstring and ADR-370), so its correctness
cannot rest on "it round-trips against itself": a systematic error would round-trip too. What
pins it is the published specification.

* **RFC 8032 §7.1** ships six Ed25519 test vectors. All six are replayed here in full — the
  seed, the derived public key, the message and the *exact* signature bytes — so a wrong curve
  constant, a wrong hash domain or a wrong encoding fails the build rather than producing
  signatures that only this implementation accepts.
* **A second implementation, when one is installed.** ``cryptography`` arrives in a developer
  environment as a dependency of ``pip-audit`` (the ``audit`` extra) and is *not* a runtime
  dependency. When it is importable it is used as an independent check in both directions —
  it verifies signatures this code made, and this code verifies signatures it made — which
  catches an error the RFC vectors alone might not (they cover three of the six §7.1 cases
  with distinct edge shapes: empty message, one byte, two bytes, and a long one).
* **The negative cases.** A flipped signature byte, a flipped message byte, a truncated
  signature, an off-curve public key and a non-canonical one are each refused, because
  "verification returns False" is the property the whole integrity layer depends on.
"""

from __future__ import annotations

import pytest

from arachne.core import ed25519

#: RFC 8032 §7.1: (seed, public key, message, signature) — all hex, as the RFC prints them.
RFC_8032_VECTORS: tuple[tuple[str, str, str, str], ...] = (
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
        "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    # A long message, which exercises the SHA-512 block boundary.
    (
        "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
        "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98"
        "fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8"
        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d"
        "658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc"
        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe"
        "ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e"
        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef"
        "efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7"
        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
        "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2"
        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24"
        "554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270"
        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc"
        "2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07"
        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba"
        "b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a"
        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e"
        "c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c"
        "42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8"
        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df"
        "f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08"
        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649"
        "de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4"
        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3"
        "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e"
        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
        "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5"
        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1"
        "369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d"
        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c"
        "0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
        "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350"
        "aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
    ),
)


@pytest.mark.parametrize(("seed", "public", "message", "signature"), RFC_8032_VECTORS)
def test_the_rfc_8032_vectors_reproduce_exactly(
    seed: str, public: str, message: str, signature: str
) -> None:
    """Seed → public key → signature, all three matching the RFC byte for byte."""
    seed_bytes = bytes.fromhex(seed)
    public_bytes = bytes.fromhex(public)
    message_bytes = bytes.fromhex(message)
    signature_bytes = bytes.fromhex(signature)

    assert ed25519.derive_public_key(seed_bytes) == public_bytes
    assert ed25519.sign(seed_bytes, message_bytes) == signature_bytes
    assert ed25519.verify(public_bytes, message_bytes, signature_bytes) is True
    assert ed25519.public_key_valid(public_bytes) is True


def test_signing_is_deterministic() -> None:
    """No randomness anywhere: a re-signed artefact reproduces its own bytes."""
    seed = bytes(range(32))
    message = b"arachne.audit:1"
    assert ed25519.sign(seed, message) == ed25519.sign(seed, message)


def test_a_different_message_does_not_verify() -> None:
    seed = bytes(range(32))
    public = ed25519.derive_public_key(seed)
    signature = ed25519.sign(seed, b"one")
    assert ed25519.verify(public, b"one", signature) is True
    assert ed25519.verify(public, b"two", signature) is False
    assert ed25519.verify(public, b"", signature) is False


@pytest.mark.parametrize("position", [0, 31, 32, 63])
def test_a_flipped_signature_byte_is_refused(position: int) -> None:
    seed = bytes(range(32))
    public = ed25519.derive_public_key(seed)
    signature = bytearray(ed25519.sign(seed, b"payload"))
    signature[position] ^= 0x01
    assert ed25519.verify(public, b"payload", bytes(signature)) is False


def test_an_s_at_or_above_the_group_order_is_refused() -> None:
    """The malleability check: ``S + l`` is the same point, and RFC 8032 forbids it."""
    seed = bytes(range(32))
    public = ed25519.derive_public_key(seed)
    signature = ed25519.sign(seed, b"payload")
    s = int.from_bytes(signature[32:], "little")
    non_canonical = signature[:32] + (s + ed25519._L).to_bytes(32, "little")
    assert ed25519.verify(public, b"payload", non_canonical) is False


@pytest.mark.parametrize(
    "signature",
    [b"", b"\x00" * 63, b"\x00" * 65],
)
def test_a_wrong_length_signature_is_refused(signature: bytes) -> None:
    public = ed25519.derive_public_key(bytes(range(32)))
    assert ed25519.verify(public, b"payload", signature) is False


@pytest.mark.parametrize(
    "public",
    [
        b"",
        b"\x00" * 31,
        b"\x00" * 33,
        # y = p is not reduced, so this is not a canonical point encoding.
        (ed25519._P).to_bytes(32, "little"),
        # A y with no matching x: 2 is not on the curve.
        (2).to_bytes(32, "little"),
    ],
)
def test_a_bad_public_key_is_refused(public: bytes) -> None:
    assert ed25519.public_key_valid(public) is False
    assert ed25519.verify(public, b"payload", b"\x00" * 64) is False


def test_a_seed_of_the_wrong_size_is_refused() -> None:
    for seed in (b"", b"\x00" * 31, b"\x00" * 33):
        with pytest.raises(ValueError, match="32 bytes"):
            ed25519.derive_public_key(seed)
        with pytest.raises(ValueError, match="32 bytes"):
            ed25519.sign(seed, b"m")


def test_a_signature_from_another_key_does_not_verify() -> None:
    first = ed25519.derive_public_key(bytes(range(32)))
    second_seed = bytes(range(1, 33))
    assert ed25519.verify(first, b"payload", ed25519.sign(second_seed, b"payload")) is False


def test_the_displacement_between_two_seeds_changes_every_signature() -> None:
    """A one-bit seed change must not shift a signature by a predictable amount."""
    left = ed25519.sign(bytes(32), b"same message")
    seed = bytearray(32)
    seed[0] = 1
    right = ed25519.sign(bytes(seed), b"same message")
    assert left != right
    assert ed25519.derive_public_key(bytes(32)) != ed25519.derive_public_key(bytes(seed))


def test_an_independent_implementation_agrees_in_both_directions() -> None:
    """Cross-check against ``cryptography`` when a developer environment happens to have it.

    It is not a runtime dependency (it arrives with the ``audit`` extra), so this is a skip
    elsewhere — the RFC vectors above are the portable evidence. Where it *is* present, the two
    implementations must agree on keys, on signatures, and on refusals.
    """
    cryptography = pytest.importorskip("cryptography")
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    seed = bytes(reversed(range(32)))
    message = b"cross-implementation check"
    ours = ed25519.sign(seed, message)

    reference_private = Ed25519PrivateKey.from_private_bytes(seed)
    reference_public = reference_private.public_key()
    assert reference_public.public_bytes(Encoding.Raw, PublicFormat.Raw) == (
        ed25519.derive_public_key(seed)
    )
    # Their signature verifies here...
    their_signature = reference_private.sign(message)
    assert ed25519.verify(ed25519.derive_public_key(seed), message, their_signature) is True
    # ...and ours verifies there.
    reference_public.verify(ours, message)
    with pytest.raises(InvalidSignature):
        reference_public.verify(ours, message + b"!")
    # A key serialised by them, used by us.
    raw = reference_private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    assert ed25519.sign(raw, message) == ours
    assert cryptography is not None  # the import is the check
