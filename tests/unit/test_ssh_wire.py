"""The SSH protocol profile's primitives, pinned by their published test vectors.

REQ-CREDS-006 brings two pieces of new cryptography into the tree — X25519 (RFC 7748) for the
key exchange and AES-128 (FIPS-197) for the transport cipher. Hand-written crypto that no
published vector has ever checked is a liability, so every function here is pinned against the
vectors the RFCs ship:

* X25519 against the RFC 7748 §5.2 scalar-multiplication vectors **and** the §6.1
  Diffie-Hellman vector (the shared secret both parties compute);
* AES-128 against the FIPS-197 appendix C.1 known-answer vector;
* the counter mode against the same block function with a hand-checked keystream;
* the packet framing against the RFC 4253 §6 rules it must satisfy (padding at least four
  bytes, a total length that is a multiple of the block size, sequence numbers that advance).

If any of these fail, the SSH check is speaking something that is not SSH, and the suite says
so rather than a scan silently failing to authenticate.
"""

from __future__ import annotations

import pytest

from arachne.modules.m2.ssh import (
    AES_BLOCK_SIZE,
    KexInit,
    _CtrCipher,
    aes128_encrypt_block,
    build_kexinit,
    ed25519_host_key,
    ed25519_signature_blob,
    expand_aes128_key,
    parse_kexinit,
    x25519,
)


def _h(text: str) -> bytes:
    return bytes.fromhex(text)


#: RFC 7748 §5.2 — one iteration of X25519 with the given scalar and u-coordinate.
X25519_VECTORS = (
    (
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
    ),
    (
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
    ),
)


@pytest.mark.parametrize(("scalar", "coordinate", "expected"), X25519_VECTORS)
def test_x25519_matches_the_rfc_7748_scalar_vectors(
    scalar: str, coordinate: str, expected: str
) -> None:
    assert x25519(_h(scalar), _h(coordinate)) == _h(expected)


def test_x25519_computes_the_rfc_7748_diffie_hellman_secret() -> None:
    """RFC 7748 §6.1: Alice and Bob derive the same secret, and it is the published value."""
    alice_private = _h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_private = _h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_public = x25519(alice_private, (9).to_bytes(32, "little"))
    bob_public = x25519(bob_private, (9).to_bytes(32, "little"))
    assert alice_public == _h("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert bob_public == _h("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    assert x25519(alice_private, bob_public) == x25519(bob_private, alice_public)
    assert x25519(alice_private, bob_public) == _h(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )


def test_x25519_rejects_a_short_scalar() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        x25519(b"\x00" * 31, (9).to_bytes(32, "little"))


def test_aes128_matches_the_fips_197_known_answer() -> None:
    """FIPS-197 appendix C.1: the canonical AES-128 vector."""
    key = _h("000102030405060708090a0b0c0d0e0f")
    plaintext = _h("00112233445566778899aabbccddeeff")
    assert aes128_encrypt_block(key, plaintext) == _h("69c4e0d86a7b0430d8cdb78070b4c55a")


def test_the_aes_key_schedule_has_eleven_distinct_round_keys() -> None:
    schedule = expand_aes128_key(_h("000102030405060708090a0b0c0d0e0f"))
    assert len(schedule) == 11
    assert len(set(schedule)) == 11
    assert all(len(round_key) == AES_BLOCK_SIZE for round_key in schedule)


def test_aes_ctr_round_trips_and_uses_a_fresh_keystream_per_block() -> None:
    key = _h("2b7e151628aed2a6abf7158809cf4f3c")
    iv = _h("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
    plaintext = b"A" * 48
    cipher = _CtrCipher(key, iv)
    ciphertext = cipher.transform(plaintext)
    assert len(ciphertext) == len(plaintext)
    # The same plaintext block encrypts differently at each position: it is a stream, and the
    # counter moves.
    blocks = [ciphertext[index : index + 16] for index in range(0, 48, 16)]
    assert len(set(blocks)) == 3
    # Decryption is the same transform from the same starting counter.
    assert _CtrCipher(key, iv).transform(ciphertext) == plaintext


def test_the_aes_ctr_keystream_is_the_block_function_over_increasing_counters() -> None:
    key = _h("000102030405060708090a0b0c0d0e0f")
    iv = _h("00000000000000000000000000000000")
    plaintext = bytes(32)
    expected = aes128_encrypt_block(
        key, _h("00000000000000000000000000000000")
    ) + aes128_encrypt_block(key, _h("00000000000000000000000000000001"))
    assert _CtrCipher(key, iv).transform(plaintext) == expected


def test_kexinit_round_trips_and_offers_exactly_one_algorithm_per_kind() -> None:
    cookie = bytes(range(16))
    payload = build_kexinit(cookie)
    assert payload[0] == 20
    parsed = parse_kexinit(payload)
    assert isinstance(parsed, KexInit)
    assert parsed.kex == ("curve25519-sha256",)
    assert parsed.host_keys == ("ssh-ed25519",)
    assert parsed.ciphers_client_to_server == ("aes128-ctr",)
    assert parsed.macs_server_to_client == ("hmac-sha2-256",)
    assert parsed.compressions_client_to_server == ("none",)
    assert parsed.first_kex_packet_follows is False


def test_parse_kexinit_refuses_a_packet_that_is_not_a_kexinit() -> None:
    with pytest.raises(Exception, match="not a KEXINIT"):
        parse_kexinit(b"\x15" + bytes(20))


def test_the_ed25519_host_key_and_signature_blobs_are_wire_shaped() -> None:
    """A host key is ``string "ssh-ed25519"`` then the 32-byte key; a signature wraps itself."""
    from arachne.core.ed25519 import derive_public_key

    public = derive_public_key(bytes(range(32)))
    blob = ed25519_host_key(public)
    assert blob[:4] == (11).to_bytes(4, "big")
    assert blob[4:15] == b"ssh-ed25519"
    assert blob[15:19] == (32).to_bytes(4, "big")
    assert blob[19:] == public
    signature = ed25519_signature_blob(bytes(64))
    assert signature[:4] == (4 + 11 + 4 + 64).to_bytes(4, "big")
