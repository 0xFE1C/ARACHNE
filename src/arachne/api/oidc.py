"""OIDC authorization-code login (S17, area IDAM: REQ-IDAM-001/002).

The enterprise path in: a user authenticates at the corporate IdP and ARACHNE mints a
per-user session — **alongside** API keys, never replacing them. The pieces:

* a compact, dependency-free JWT verifier (:func:`verify_jwt`) supporting the RSA
  (RS256/384/512) and HMAC (HS256/384/512) families — RS256 verification is a straight
  PKCS#1 v1.5 modular-exponentiation check against the JWKS modulus, so no crypto library
  is added to the (dependency-light) default install;
* :class:`OidcProvider`, the authorization-code client: discovery, the authorize URL
  (with ``state`` + OIDC ``nonce`` + PKCE ``S256``), the token exchange, and ID-token
  validation against the provider's JWKS;
* :func:`SsoSettings.role_for` (in :mod:`arachne.core.config`) is the group→role binding
  (REQ-IDAM-002): a login whose groups map to no role, with no ``default_role``, is denied.

**Egress.** The IdP calls go through the one HTTP path (:class:`ScopedHttpClient`,
ADR-05) with the scope pinned to the IdP host — bounded, rate-limited and audited like
every other request ARACHNE makes. Redaction is disabled for *this client only*: the
point of the token exchange is to read credentials back, and a redacted token is not a
token. Nothing from the exchange is ever logged or persisted (the audit line carries only
the response's SHA-256), which the security review records as a deliberate, bounded
exemption (ADR-220.3).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlencode, urlsplit

from arachne.core.audit import Auditor
from arachne.core.config import Settings
from arachne.core.errors import IdentityError
from arachne.core.http import ScopedHttpClient
from arachne.core.safety import Scope

__all__ = [
    "Jwks",
    "OidcEndpoints",
    "OidcProvider",
    "code_challenge",
    "decode_jwt",
    "new_code_verifier",
    "new_nonce",
    "verify_jwt",
]

#: RFC 7636 PKCE: the verifier is 43-128 chars of the unreserved set.
_VERIFIER_BYTES = 48

#: Alg → hashlib name, for both the RSA and HMAC families.
_ALG_HASH: Final[dict[str, str]] = {
    "RS256": "sha256",
    "RS384": "sha384",
    "RS512": "sha512",
    "HS256": "sha256",
    "HS384": "sha384",
    "HS512": "sha512",
}

#: ASN.1 DigestInfo prefixes for RSA PKCS#1 v1.5 (RFC 8017 §9.2 notes 1).
_DIGEST_INFO: Final[dict[str, bytes]] = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


# --------------------------------------------------------------------------- base64url
def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        msg = "token segment is not valid base64url"
        raise IdentityError(msg) from exc


def _b64url_uint(segment: str) -> int:
    return int.from_bytes(_b64url_decode(segment), "big")


# --------------------------------------------------------------------------- JWT
@dataclass(frozen=True, slots=True)
class JwtParts:
    """A decoded-but-unverified JWT: its header, claims and the signed segments."""

    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes


def decode_jwt(token: str) -> JwtParts:
    """Split and decode a JWT without verifying it (never trust the result directly)."""
    parts = token.split(".")
    if len(parts) != 3:
        msg = "an ID token must have three dot-separated segments"
        raise IdentityError(msg)
    header_raw, payload_raw, signature_raw = parts
    try:
        header = json.loads(_b64url_decode(header_raw))
        claims = json.loads(_b64url_decode(payload_raw))
    except json.JSONDecodeError as exc:
        msg = "an ID token segment is not JSON"
        raise IdentityError(msg) from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        msg = "an ID token header and payload must be JSON objects"
        raise IdentityError(msg)
    return JwtParts(
        header=header,
        claims=claims,
        signing_input=f"{header_raw}.{payload_raw}".encode("ascii"),
        signature=_b64url_decode(signature_raw),
    )


def _rsa_pkcs1_verify(
    message: bytes, signature: bytes, modulus: int, exponent: int, hash_name: str
) -> bool:
    """Verify an RS256/384/512 signature (RFC 8017 RSASSA-PKCS1-v1_5, no padding oracle)."""
    key_size = (modulus.bit_length() + 7) // 8
    if len(signature) != key_size:
        return False
    value = int.from_bytes(signature, "big")
    if value >= modulus:
        return False
    recovered = pow(value, exponent, modulus).to_bytes(key_size, "big")
    digest = hashlib.new(hash_name, message).digest()
    expected = _DIGEST_INFO[hash_name] + digest
    if recovered[0] != 0x00 or recovered[1] != 0x01:
        return False
    separator = recovered.find(b"\x00", 2)
    if separator < 10:  # PS must be at least 8 bytes of 0xFF
        return False
    if any(byte != 0xFF for byte in recovered[2:separator]):
        return False
    return hmac.compare_digest(recovered[separator + 1 :], expected)


@dataclass(frozen=True, slots=True)
class Jwks:
    """A provider's JSON Web Key Set, reducible to the material a verifier needs."""

    keys: tuple[dict[str, Any], ...] = ()

    @classmethod
    def parse(cls, document: Any) -> Jwks:
        raw: Any = document.get("keys") if isinstance(document, dict) else document
        if not isinstance(raw, list) or not raw:
            msg = "the provider's JWKS contained no keys"
            raise IdentityError(msg)
        keys = tuple(item for item in raw if isinstance(item, dict))
        if not keys:
            msg = "the provider's JWKS contained no usable keys"
            raise IdentityError(msg)
        return cls(keys=keys)

    def key_for(
        self, kid: str | None, alg: str, *, allow_any: bool = False
    ) -> dict[str, Any] | None:
        """The JWK to verify with: matched by ``kid``, else the sole key of the right use."""
        candidates = list(self.keys)
        if kid is not None:
            named = [key for key in candidates if str(key.get("kid")) == kid]
            if named:
                candidates = named
        if not allow_any and kid is None:
            signing = [key for key in candidates if key.get("use") in (None, "sig")]
            if len(signing) == 1:
                return signing[0]
        if len(candidates) == 1:
            return candidates[0]
        return None


def _key_material(jwk: dict[str, Any]) -> tuple[str, Any, Any]:
    """``(kty, primary, secondary)`` for a JWK — RSA ``(n, e)`` or oct ``(secret,)``."""
    kty = str(jwk.get("kty", ""))
    if kty == "RSA":
        n = jwk.get("n")
        e = jwk.get("e")
        if not isinstance(n, str) or not isinstance(e, str):
            msg = "an RSA JWK is missing its modulus or exponent"
            raise IdentityError(msg)
        return kty, _b64url_uint(n), _b64url_uint(e)
    if kty == "oct":
        k = jwk.get("k")
        if not isinstance(k, str):
            msg = "an oct JWK is missing its key material"
            raise IdentityError(msg)
        return kty, _b64url_decode(k), None
    msg = f"unsupported JWK key type {kty!r} (this build verifies RSA and oct keys)"
    raise IdentityError(msg)


def _verify_signature(parts: JwtParts, jwk: dict[str, Any], alg: str) -> None:
    hash_name = _ALG_HASH[alg]
    kty, primary, secondary = _key_material(jwk)
    if alg.startswith("RS"):
        if kty != "RSA":
            msg = f"algorithm {alg} needs an RSA key, the JWKS provided {kty!r}"
            raise IdentityError(msg)
        ok = _rsa_pkcs1_verify(parts.signing_input, parts.signature, primary, secondary, hash_name)
    else:  # HS*
        if kty != "oct":
            msg = f"algorithm {alg} needs a symmetric key, the JWKS provided {kty!r}"
            raise IdentityError(msg)
        expected = hmac.new(primary, parts.signing_input, hash_name).digest()
        ok = hmac.compare_digest(expected, parts.signature)
    if not ok:
        msg = "the ID token signature did not verify against the provider key"
        raise IdentityError(msg)


def _as_audience(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return ()


def verify_jwt(
    token: str,
    jwks: Jwks,
    *,
    algorithms: tuple[str, ...] | list[str],
    issuer: str,
    audience: str,
    nonce: str | None = None,
    leeway_s: int = 60,
    now: float | None = None,
) -> dict[str, Any]:
    """Verify a JWT's signature and standard claims, returning its claims.

    Checks, in order: structure, ``alg`` against the allowlist (never ``none``),
    key selection from the JWKS, signature, ``iss``, ``aud``, ``exp``/``nbf`` (with
    ``leeway_s``) and the OIDC ``nonce``. Any failure raises :class:`IdentityError` — there
    is no path that returns unverified claims.
    """
    parts = decode_jwt(token)
    alg = str(parts.header.get("alg", ""))
    if alg not in algorithms or alg not in _ALG_HASH:
        msg = f"ID token algorithm {alg!r} is not accepted by this deployment"
        raise IdentityError(msg)
    kid = parts.header.get("kid")
    jwk = jwks.key_for(str(kid) if kid is not None else None, alg)
    if jwk is None and kid is not None:
        msg = "no JWKS key matches the ID token's kid"
        raise IdentityError(msg)
    if jwk is None:
        msg = "the JWKS is ambiguous and the ID token names no kid"
        raise IdentityError(msg)
    _verify_signature(parts, jwk, alg)

    claims = parts.claims
    if str(claims.get("iss", "")) != issuer:
        msg = "the ID token issuer does not match the configured issuer"
        raise IdentityError(msg)
    if audience not in _as_audience(claims.get("aud")):
        msg = "the ID token audience does not include this client"
        raise IdentityError(msg)
    current = time.time() if now is None else now
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or float(exp) < current - leeway_s:
        msg = "the ID token has expired"
        raise IdentityError(msg)
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and float(nbf) > current + leeway_s:
        msg = "the ID token is not yet valid"
        raise IdentityError(msg)
    if nonce is not None and str(claims.get("nonce", "")) != nonce:
        msg = "the ID token nonce does not match this login"
        raise IdentityError(msg)
    return claims


# --------------------------------------------------------------------------- PKCE/state
def new_nonce() -> str:
    return secrets.token_urlsafe(24)


def new_code_verifier() -> str:
    return secrets.token_urlsafe(_VERIFIER_BYTES)


def code_challenge(verifier: str) -> str:
    """The S256 PKCE challenge for ``verifier`` (RFC 7636 §4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# --------------------------------------------------------------------------- provider
@dataclass(frozen=True, slots=True)
class OidcEndpoints:
    """The provider endpoints a login needs (explicit config or discovery)."""

    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    issuer: str | None = None


@dataclass
class _Cache:
    """Discovery/JWKS documents fetched once per provider lifetime."""

    endpoints: OidcEndpoints | None = None
    jwks: Jwks | None = None

    def clear(self) -> None:
        self.endpoints = None
        self.jwks = None


class OidcProvider:
    """The authorization-code client for one configured IdP.

    Construct once per application context. Every network call goes through a dedicated
    :class:`ScopedHttpClient` (scope pinned to the IdP host, redaction off — see the module
    docstring). ``transport``/``resolver`` are injectable so the canned-JWKS/IdP fixture
    drives the whole flow with no socket (REQ-IDAM-001's acceptance test).
    """

    def __init__(
        self,
        settings: Settings,
        *,
        transport: Any = None,
        resolver: Any = None,
        auditor: Auditor | None = None,
        clock: Any = None,
    ) -> None:
        self._settings = settings
        self._sso = settings.sso
        self._transport = transport
        self._resolver = resolver
        self._auditor = auditor
        self._clock = clock
        self._client: ScopedHttpClient | None = None
        self._cache = _Cache()

    # ------------------------------------------------------------------ setup
    @property
    def configured(self) -> bool:
        return self._sso.configured

    @property
    def sso(self) -> Any:
        return self._sso

    def _http(self) -> ScopedHttpClient:
        if self._client is None:
            hosts = self._idp_hosts()
            if not hosts:
                msg = "the SSO issuer has no host to reach"
                raise IdentityError(msg)
            # Redaction is off for this client alone: the token exchange must read
            # credentials back to function, and nothing from it is logged (ADR-220.3).
            self._client = ScopedHttpClient(
                settings=self._settings,
                scope=Scope(allowed_hosts=tuple(hosts)),
                policy=self._settings.safety.policy,
                resolver=self._resolver,
                auditor=self._auditor,
                transport=self._transport,
                redaction_enabled=False,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _idp_hosts(self) -> tuple[str, ...]:
        hosts: list[str] = list(self._sso.allowed_hosts)
        for url in (
            self._sso.issuer,
            self._sso.jwks_url,
            self._sso.authorization_endpoint,
            self._sso.token_endpoint,
        ):
            if url:
                host = urlsplit(url).hostname
                if host and host not in hosts:
                    hosts.append(host)
        return tuple(hosts)

    # ------------------------------------------------------------------ discovery
    async def endpoints(self, *, refresh: bool = False) -> OidcEndpoints:
        if self._cache.endpoints is not None and not refresh:
            return self._cache.endpoints
        if not self.configured:
            msg = "single sign-on is not configured on this deployment"
            raise IdentityError(msg)
        explicit = OidcEndpoints(
            authorization_endpoint=self._sso.authorization_endpoint or "",
            token_endpoint=self._sso.token_endpoint or "",
            jwks_uri=self._sso.jwks_url or "",
            userinfo_endpoint=self._sso.userinfo_endpoint,
            issuer=self._sso.issuer,
        )
        if explicit.authorization_endpoint and explicit.token_endpoint and explicit.jwks_uri:
            self._cache.endpoints = explicit
            return explicit
        document = await self._discover()
        endpoints = OidcEndpoints(
            authorization_endpoint=self._sso.authorization_endpoint
            or str(document.get("authorization_endpoint", "")),
            token_endpoint=self._sso.token_endpoint or str(document.get("token_endpoint", "")),
            jwks_uri=self._sso.jwks_url or str(document.get("jwks_uri", "")),
            userinfo_endpoint=self._sso.userinfo_endpoint
            or (str(document["userinfo_endpoint"]) if document.get("userinfo_endpoint") else None),
            issuer=self._sso.issuer,
        )
        required = (
            endpoints.authorization_endpoint and endpoints.token_endpoint and endpoints.jwks_uri
        )
        if not required:
            msg = "the provider's discovery document is missing required endpoints"
            raise IdentityError(msg)
        self._cache.endpoints = endpoints
        return endpoints

    async def _discover(self) -> dict[str, Any]:
        issuer = (self._sso.issuer or "").rstrip("/")
        url = f"{issuer}/.well-known/openid-configuration"
        exchange = await self._http().get(url, follow_redirects=False)
        if exchange.status_code != 200:
            msg = f"OIDC discovery failed with status {exchange.status_code}"
            raise IdentityError(msg)
        document = exchange.json_body()
        if not isinstance(document, dict):
            msg = "the OIDC discovery document is not a JSON object"
            raise IdentityError(msg)
        discovered_issuer = document.get("issuer")
        if discovered_issuer is not None and str(discovered_issuer).rstrip("/") != issuer:
            msg = "the discovery document's issuer does not match the configured issuer"
            raise IdentityError(msg)
        return document

    # ------------------------------------------------------------------ login
    async def authorization_url(
        self, *, redirect_uri: str, state: str, nonce: str, verifier: str
    ) -> str:
        endpoints = await self.endpoints()
        params = {
            "response_type": "code",
            "client_id": self._sso.client_id or "",
            "redirect_uri": redirect_uri,
            "scope": " ".join(self._sso.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
        }
        separator = "&" if urlsplit(endpoints.authorization_endpoint).query else "?"
        return f"{endpoints.authorization_endpoint}{separator}{urlencode(params)}"

    async def exchange_code(self, *, code: str, verifier: str, redirect_uri: str) -> dict[str, Any]:
        endpoints = await self.endpoints()
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._sso.client_id or "",
            "code_verifier": verifier,
        }
        secret = self._sso.client_secret_value
        if secret:
            body["client_secret"] = secret
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        exchange = await self._http().post(
            endpoints.token_endpoint,
            headers=headers,
            content=urlencode(body),
            follow_redirects=False,
        )
        if exchange.status_code != 200:
            # Never echo the body: it can carry a token even on an error.
            msg = f"the token endpoint refused the code exchange ({exchange.status_code})"
            raise IdentityError(msg)
        document = exchange.json_body()
        if not isinstance(document, dict):
            msg = "the token endpoint returned a non-JSON response"
            raise IdentityError(msg)
        return document

    async def fetch_jwks(self, *, refresh: bool = False) -> Jwks:
        if self._cache.jwks is not None and not refresh:
            return self._cache.jwks
        endpoints = await self.endpoints()
        exchange = await self._http().get(endpoints.jwks_uri, follow_redirects=False)
        if exchange.status_code != 200:
            msg = f"fetching the provider JWKS failed with status {exchange.status_code}"
            raise IdentityError(msg)
        document = exchange.json_body()
        if document is None:
            msg = "the provider JWKS is not valid JSON"
            raise IdentityError(msg)
        jwks = Jwks.parse(document)
        self._cache.jwks = jwks
        return jwks

    async def verify_id_token(self, token: str, *, nonce: str) -> dict[str, Any]:
        """Verify an ID token against the provider JWKS (refreshing once on a new ``kid``)."""
        jwks = await self.fetch_jwks()
        try:
            return verify_jwt(
                token,
                jwks,
                algorithms=self._sso.algorithms,
                issuer=self._sso.issuer or "",
                audience=self._sso.client_id or "",
                nonce=nonce,
                leeway_s=self._sso.leeway_s,
                now=self._now(),
            )
        except IdentityError:
            refreshed = await self.fetch_jwks(refresh=True)
            return verify_jwt(
                token,
                refreshed,
                algorithms=self._sso.algorithms,
                issuer=self._sso.issuer or "",
                audience=self._sso.client_id or "",
                nonce=nonce,
                leeway_s=self._sso.leeway_s,
                now=self._now(),
            )

    def _now(self) -> float:
        return float(self._clock() if self._clock is not None else time.time())

    def groups_from(self, claims: dict[str, Any]) -> tuple[str, ...]:
        """The group claim values used for the role mapping (REQ-IDAM-002)."""
        value = claims.get(self._sso.role_claim)
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        if isinstance(value, list):
            return tuple(str(item) for item in value if str(item).strip())
        return ()

    def role_for(self, claims: dict[str, Any]) -> str | None:
        """Map a verified token's groups to a role, or ``None`` for a deny."""
        return self._sso.role_for(self.groups_from(claims))

    def identity_from(self, claims: dict[str, Any]) -> dict[str, str | None]:
        """The per-user principal fields the session records (REQ-IDAM-001)."""
        return {
            "subject": str(claims.get("sub", "")),
            "email": _first_str(claims.get("email"), claims.get("preferred_username")),
            "name": _first_str(claims.get("name")),
        }


def _first_str(*values: Any) -> str | None:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None
