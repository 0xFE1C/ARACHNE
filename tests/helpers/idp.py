"""A canned OIDC identity provider for the S17 acceptance tests (REQ-IDAM-001).

No socket, no external crypto library: the fixture owns a fixed 1024-bit RSA keypair,
signs ID tokens with RS256, and serves the three documents a login touches — the discovery
document, the JWKS and the token endpoint — through an ``httpx.MockTransport`` that
:class:`~arachne.api.oidc.OidcProvider` is given as its transport.

The flow a test drives:

1. ``GET /api/v1/auth/sso/login`` → a 302 whose ``Location`` is this provider's authorize
   URL; :meth:`CannedIdP.accept_authorization` reads ``state``/``nonce``/PKCE challenge and
   returns an authorization ``code`` (with the ID token queued behind it).
2. ``GET /api/v1/auth/sso/callback?code=…&state=…`` → the app exchanges the code here; the
   token endpoint checks the client secret and the PKCE verifier, then returns the queued
   ID token.
3. The app verifies that token against :meth:`CannedIdP.jwks_document`, maps groups to a
   role, and mints a session cookie.

Every handler call is recorded in ``requests`` so a test can assert what the app actually
sent (and that it sent the client secret and code verifier).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

__all__ = [
    "CLIENT_ID",
    "CLIENT_SECRET",
    "IDP_ISSUER",
    "IDP_PUBLIC_IP",
    "KID",
    "CannedIdP",
    "sign_hs256",
]

#: The displacement address the fixture's host resolves to (public, so the URL policy
#: accepts it without weakening the deployment's private-IP posture).
IDP_PUBLIC_IP = "93.184.216.34"
IDP_ISSUER = "https://idp.example.test"
CLIENT_ID = "arachne-test-client"
CLIENT_SECRET = "client-secret-for-tests"
KID = "s17-test-key"

#: A fixed test RSA keypair (modulus/exponent/private exponent, hex). 1024-bit is plenty
#: for RSASSA-PKCS1-v1_5 + SHA-256 (the digest block needs 94 bytes; this modulus is 128).
_N = int(
    "841cb64cade4839965da13a30d54ffbde885ad2da1cf62f019fa35b6c9f4e421"
    "71aef9543ba7eeb23d368e1ea5565e4752b0fc28599d726f6636830c6bfed501"
    "b1249cc30b971b0b9ec06ae18b07a364d12086acc88e795d6bce9b3c69aaccba"
    "578a8015682359fd19354245aad242764abd8c80dbba950b7873aff234a4764f",
    16,
)
_E = 65537
_D = int(
    "7374081880cb37fa8199101a295783dbb9edc087256670a7357c851e85e5becc"
    "3f66533c3a9a2aae97722ac73b647c25c66d27203818b15e0b2c4e6037accf06"
    "50698f118efdf953223ddcb54d6580263ac94ba23a47d57daf1af5185c9d0ce9"
    "a17b47e1beb5ba9e7ed7922edc53007f7465ee663e43a82e5825a0552816c571",
    16,
)

_DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return _b64url(value.to_bytes(length, "big"))


def _rsa_sign(message: bytes, *, hash_name: str = "sha256") -> bytes:
    """RSASSA-PKCS1-v1_5 sign with the fixture key."""
    key_size = (_N.bit_length() + 7) // 8
    digest = hashlib.new(hash_name, message).digest()
    block = _DIGEST_INFO_SHA256 + digest
    padding = b"\xff" * (key_size - len(block) - 3)
    encoded = b"\x00\x01" + padding + b"\x00" + block
    signature = pow(int.from_bytes(encoded, "big"), _D, _N)
    return signature.to_bytes(key_size, "big")


def sign_hs256(claims: dict[str, Any], secret: str) -> str:
    """Sign a JWT with HS256 (the symmetric family the verifier also accepts)."""
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url(json.dumps(claims, separators=(',', ':')).encode())}"
    )
    mac = hmac.new(secret.encode(), signing_input.encode("ascii"), "sha256").digest()
    return f"{signing_input}.{_b64url(mac)}"


@dataclass
class CannedIdP:
    """A minimal, deterministic OIDC provider backed by ``httpx.MockTransport``."""

    issuer: str = IDP_ISSUER
    client_id: str = CLIENT_ID
    client_secret: str = CLIENT_SECRET
    kid: str = KID
    #: Token lifetime in seconds (a test can make a short/expired token).
    token_ttl_s: int = 300
    requests: list[dict[str, Any]] = field(default_factory=list)
    _codes: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)
    _tokens: dict[str, str] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------ documents
    @property
    def authorization_endpoint(self) -> str:
        return f"{self.issuer}/authorize"

    @property
    def token_endpoint(self) -> str:
        return f"{self.issuer}/token"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer}/jwks"

    def discovery_document(self) -> dict[str, Any]:
        return {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "jwks_uri": self.jwks_uri,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def jwks_document(self) -> dict[str, Any]:
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.kid,
                    "n": _b64url_uint(_N),
                    "e": _b64url_uint(_E),
                }
            ]
        }

    # ------------------------------------------------------------------ tokens
    def id_token(
        self,
        *,
        subject: str,
        nonce: str,
        email: str | None = None,
        name: str | None = None,
        groups: tuple[str, ...] | list[str] = (),
        claims: dict[str, Any] | None = None,
        audience: str | None = None,
        issuer: str | None = None,
        now: float | None = None,
        ttl_s: int | None = None,
        kid: str | None = None,
    ) -> str:
        """Build and RS256-sign an ID token with the given identity and claims."""
        issued = time.time() if now is None else now
        payload: dict[str, Any] = {
            "iss": issuer or self.issuer,
            "aud": audience or self.client_id,
            "sub": subject,
            "iat": int(issued),
            "exp": int(issued + (self.token_ttl_s if ttl_s is None else ttl_s)),
            "nonce": nonce,
            "groups": list(groups),
        }
        if email:
            payload["email"] = email
        if name:
            payload["name"] = name
        if claims:
            payload.update(claims)
        header = {"alg": "RS256", "typ": "JWT", "kid": kid or self.kid}
        signing_input = (
            f"{_b64url(json.dumps(header, separators=(',', ':')).encode())}."
            f"{_b64url(json.dumps(payload, separators=(',', ':')).encode())}"
        )
        signature = _rsa_sign(signing_input.encode("ascii"))
        return f"{signing_input}.{_b64url(signature)}"

    # ------------------------------------------------------------------ flow
    def accept_authorization(
        self,
        authorize_url: str,
        *,
        subject: str = "user-1",
        email: str | None = "alice@corp.example",
        name: str | None = "Alice Example",
        groups: tuple[str, ...] | list[str] = ("arachne-scanners",),
        claims: dict[str, Any] | None = None,
    ) -> str:
        """Read the app's authorize URL, queue an ID token behind a fresh ``code``."""
        query = parse_qs(urlsplit(authorize_url).query)
        nonce = (query.get("nonce") or [""])[0]
        redirect_uri = (query.get("redirect_uri") or [""])[0]
        challenge = (query.get("code_challenge") or [""])[0]
        if not nonce or not challenge:
            msg = "the authorize URL lacks nonce/code_challenge — the app broke PKCE"
            raise AssertionError(msg)
        code = f"code-{secrets.token_hex(8)}"
        self._codes[code] = {
            "challenge": challenge,
            "redirect_uri": redirect_uri,
            "nonce": nonce,
        }
        self._tokens[code] = self.id_token(
            subject=subject,
            nonce=nonce,
            email=email,
            name=name,
            groups=groups,
            claims=claims,
        )
        return code

    def queue_token(self, code: str, token: str, *, challenge: str, redirect_uri: str) -> None:
        """Low-level escape hatch: bind a prepared ID token to a code (failure tests)."""
        self._codes[code] = {"challenge": challenge, "redirect_uri": redirect_uri, "nonce": ""}
        self._tokens[code] = token

    # ------------------------------------------------------------------ transport
    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.requests.append({"method": request.method, "path": path, "query": request.url.query})
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=self.discovery_document())
        if path == "/jwks":
            return httpx.Response(200, json=self.jwks_document())
        if path == "/token":
            return self._handle_token(request)
        return httpx.Response(404, json={"error": "not_found"})

    def _handle_token(self, request: httpx.Request) -> httpx.Response:
        form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
        self.requests[-1]["form"] = form
        if form.get("client_id") != self.client_id:
            return httpx.Response(401, json={"error": "invalid_client"})
        if form.get("client_secret") != self.client_secret:
            return httpx.Response(401, json={"error": "invalid_client"})
        code = form.get("code", "")
        record = self._codes.get(code)
        if record is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        verifier = form.get("code_verifier", "")
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        if challenge != record["challenge"]:
            return httpx.Response(400, json={"error": "invalid_grant", "reason": "pkce"})
        if form.get("redirect_uri") != record["redirect_uri"]:
            return httpx.Response(400, json={"error": "invalid_grant", "reason": "redirect"})
        return httpx.Response(
            200,
            json={
                "access_token": f"access-{secrets.token_hex(8)}",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": self._tokens[code],
            },
        )
