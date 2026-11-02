"""Unit tests for the OIDC verifier and group→role mapping (S17, REQ-IDAM-001/002).

These exercise the pure, security-critical parts — JWT signature and claim validation,
PKCE, and the role binding — without an ASGI app. The canned IdP in
:mod:`tests.helpers.idp` signs the tokens; the fixtures here are the negative cases the
acceptance test cannot easily reach.
"""

from __future__ import annotations

import base64
import json
import time

import pytest
from pydantic import SecretStr
from tests.helpers.idp import CLIENT_ID, IDP_ISSUER, KID, CannedIdP, sign_hs256

from arachne.api.oidc import (
    Jwks,
    code_challenge,
    decode_jwt,
    verify_jwt,
)
from arachne.core.config import SsoSettings
from arachne.core.errors import ConfigurationError, IdentityError

ISSUER = IDP_ISSUER
AUDIENCE = CLIENT_ID


def _jwks(idp: CannedIdP) -> Jwks:
    return Jwks.parse(idp.jwks_document())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- signatures
def test_an_rs256_id_token_round_trips() -> None:
    idp = CannedIdP()
    token = idp.id_token(subject="alice", nonce="n-1", email="alice@corp", groups=["g1"])
    claims = verify_jwt(
        token,
        _jwks(idp),
        algorithms=("RS256",),
        issuer=ISSUER,
        audience=AUDIENCE,
        nonce="n-1",
        now=time.time(),
    )
    assert claims["sub"] == "alice"
    assert claims["email"] == "alice@corp"
    assert claims["groups"] == ["g1"]


def test_a_tampered_payload_is_rejected() -> None:
    idp = CannedIdP()
    token = idp.id_token(subject="alice", nonce="n-1")
    header, _payload, signature = token.split(".")
    forged = json.dumps({"sub": "mallory", "iss": ISSUER, "aud": AUDIENCE, "exp": 9e9}).encode()
    tampered = f"{header}.{_b64url(forged)}.{signature}"
    with pytest.raises(IdentityError, match="signature"):
        verify_jwt(
            tampered,
            _jwks(idp),
            algorithms=("RS256",),
            issuer=ISSUER,
            audience=AUDIENCE,
            now=time.time(),
        )


def test_alg_none_is_never_accepted() -> None:
    idp = CannedIdP()
    header = _b64url(json.dumps({"alg": "none"}).encode())
    payload = _b64url(json.dumps({"sub": "x", "iss": ISSUER, "aud": AUDIENCE, "exp": 9e9}).encode())
    with pytest.raises(IdentityError, match="algorithm"):
        verify_jwt(
            f"{header}.{payload}.",
            _jwks(idp),
            algorithms=("RS256", "HS256"),
            issuer=ISSUER,
            audience=AUDIENCE,
        )


def test_a_symmetric_token_cannot_ride_the_rs256_allowlist() -> None:
    """Alg-confusion guard: an HS256 token is refused when only RS256 is allowed."""
    idp = CannedIdP()
    token = sign_hs256({"sub": "x", "iss": ISSUER, "aud": AUDIENCE, "exp": 9e9}, "shared")
    with pytest.raises(IdentityError, match="algorithm"):
        verify_jwt(token, _jwks(idp), algorithms=("RS256",), issuer=ISSUER, audience=AUDIENCE)


def test_an_hs256_token_verifies_against_an_oct_jwks() -> None:
    secret = "symmetric-test-secret"
    jwks = Jwks.parse({"keys": [{"kty": "oct", "kid": KID, "k": _b64url(secret.encode())}]})
    token = sign_hs256({"sub": "x", "iss": ISSUER, "aud": AUDIENCE, "exp": 9e9}, secret)
    claims = verify_jwt(
        token, jwks, algorithms=("HS256",), issuer=ISSUER, audience=AUDIENCE, now=time.time()
    )
    assert claims["sub"] == "x"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"issuer": "https://other.example"}, "issuer"),
        ({"audience": "someone-else"}, "audience"),
        ({"ttl_s": -3600}, "expired"),
        ({"nonce": "different"}, "nonce"),
    ],
)
def test_standard_claim_failures_are_refused(overrides: dict[str, object], message: str) -> None:
    idp = CannedIdP()
    kwargs = {"subject": "alice", "nonce": "n-1", **overrides}
    token = idp.id_token(**kwargs)  # type: ignore[arg-type]
    with pytest.raises(IdentityError, match=message):
        verify_jwt(
            token,
            _jwks(idp),
            algorithms=("RS256",),
            issuer=ISSUER,
            audience=AUDIENCE,
            nonce="n-1",
            leeway_s=0,
            now=time.time(),
        )


def test_a_token_naming_an_unknown_kid_is_refused() -> None:
    """A multi-key JWKS must not guess: an unmatched ``kid`` is a refusal, not a fallback."""
    idp = CannedIdP()
    document = idp.jwks_document()
    document["keys"].append({**document["keys"][0], "kid": "a-second-key"})
    token = idp.id_token(subject="alice", nonce="n-1", kid="unknown-kid")
    with pytest.raises(IdentityError, match="kid"):
        verify_jwt(
            token,
            Jwks.parse(document),
            algorithms=("RS256",),
            issuer=ISSUER,
            audience=AUDIENCE,
            nonce="n-1",
            now=time.time(),
        )


def test_a_garbage_signature_is_refused() -> None:
    idp = CannedIdP()
    token = idp.id_token(subject="alice", nonce="n-1")
    header, payload, _signature = token.split(".")
    bogus = _b64url(b"\x01" * 128)
    forged = f"{header}.{payload}.{bogus}"
    with pytest.raises(IdentityError, match="signature"):
        verify_jwt(
            forged,
            _jwks(idp),
            algorithms=("RS256",),
            issuer=ISSUER,
            audience=AUDIENCE,
            nonce="n-1",
            now=time.time(),
        )


def test_a_malformed_token_is_refused() -> None:
    with pytest.raises(IdentityError):
        decode_jwt("not-a-jwt")
    with pytest.raises(IdentityError):
        decode_jwt("a.b")


def test_jwks_parse_accepts_a_bare_key_list() -> None:
    idp = CannedIdP()
    parsed = Jwks.parse(idp.jwks_document()["keys"])
    assert len(parsed.keys) == 1
    assert parsed.keys[0]["kid"] == KID


def test_an_empty_jwks_is_refused() -> None:
    with pytest.raises(IdentityError):
        Jwks.parse({"keys": []})


# --------------------------------------------------------------------------- PKCE
def test_pkce_challenge_matches_the_rfc_7636_vector() -> None:
    # RFC 7636 Appendix B.
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


# --------------------------------------------------------------------------- role mapping
def _sso(**overrides: object) -> SsoSettings:
    base: dict[str, object] = {
        "enabled": True,
        "issuer": ISSUER,
        "client_id": AUDIENCE,
        "client_secret": SecretStr("secret"),
        "group_roles": (
            "arachne-viewers:viewer",
            "arachne-scanners:scanner",
            "arachne-admins:admin",
        ),
    }
    base.update(overrides)
    return SsoSettings(**base)  # type: ignore[arg-type]


def test_the_highest_matching_group_wins() -> None:
    sso = _sso()
    assert sso.role_for(["arachne-viewers", "arachne-admins"]) == "admin"
    assert sso.role_for(["arachne-viewers"]) == "viewer"
    assert sso.role_for(["unrelated"]) is None  # deny by default


def test_no_match_denies_unless_a_default_role_is_configured() -> None:
    assert _sso().role_for(["unrelated"]) is None
    assert _sso(default_role="viewer").role_for(["unrelated"]) == "viewer"


def test_group_roles_are_validated_at_startup() -> None:
    with pytest.raises(ConfigurationError):
        _sso(group_roles=("arachne-admins:superuser",))
    with pytest.raises(ConfigurationError):
        _sso(default_role="root")
    with pytest.raises(ConfigurationError):
        _sso(algorithms=("none",))
    with pytest.raises(ConfigurationError):
        _sso(scopes=("profile",))


def test_configured_requires_enablement_and_coordinates() -> None:
    assert _sso().configured
    assert not _sso(enabled=False).configured
    assert not _sso(issuer=None).configured
    assert not _sso(client_id=None).configured
