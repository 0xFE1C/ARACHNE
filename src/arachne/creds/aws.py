"""AWS SigV4 request signing for the read-only posture checks (WP-31, REQ-DET-024).

AWS authenticates every API call with Signature Version 4: the caller signs a canonical
description of the request with a key derived from the secret access key, and the service
recomputes the signature before it answers. The posture checks therefore cannot borrow the
bearer-token path :meth:`~arachne.creds.broker.CredentialBroker.authorized_get` uses for the
DigitalOcean check — they need a signature, which needs the secret.

That is why signing lives *here*, in ``arachne.creds``, and not in the module layer:

* :func:`sign_request` takes the material, computes the headers and returns them. The module
  layer never calls it — the broker does, inside one release, exactly as it injects a bearer
  token for ``authorized_get``. A check asks the broker for an *outcome* (a signed exchange),
  never for the key.
* :func:`verify_request` is the same canonicalization run as a server: the lab fixture uses it
  to prove that the request it received really was signed with the lab's secret, so the
  credential path is exercised rather than asserted.

The implementation is stdlib only — the same deliberate choice S17 made for JWT verification,
S19 for NTLM and the S3 evidence backend for its own signing: a small, audited implementation
beats a dependency in every deployment, including the air-gapped one. Only *static* credentials
(an access key id, a secret access key and an optional session token) are supported, which is
exactly what a least-privilege read-only role's short-lived credentials are placed in the vault
as.

Nothing here logs, stores or returns the secret: the headers carry a signature, and the
signature is not reversible.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final
from urllib.parse import parse_qsl, quote, urlsplit

__all__ = [
    "AUTHORIZATION_PREFIX",
    "SIGNING_ALGORITHM",
    "SigV4Error",
    "access_key_id",
    "derive_signing_key",
    "sign_request",
    "verify_request",
]

#: The algorithm name in the ``Authorization`` header (and the string-to-sign's first line).
SIGNING_ALGORITHM: Final = "AWS4-HMAC-SHA256"
AUTHORIZATION_PREFIX: Final = SIGNING_ALGORITHM + " "
#: How far a signed request's ``X-Amz-Date`` may be from the verifier's clock. AWS uses 15
#: minutes; the lab reuses the value so a slow test process is not a false refusal.
DEFAULT_TOLERANCE_S: Final = 900
#: URI-encoding safe set for the canonical path (RFC 3986 unreserved minus the separators AWS
#: keeps literal in a path segment).
_PATH_SAFE: Final = "/-_.~"
#: URI-encoding safe set for a query parameter name or value.
_QUERY_SAFE: Final = "-_.~"


class SigV4Error(ValueError):
    """A request cannot be canonicalized or its signature cannot be checked."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def derive_signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """``kSigning`` for one (date, region, service): the scoped key the signature uses."""
    key = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    key = _sign(key, region)
    key = _sign(key, service)
    return _sign(key, "aws4_request")


def _canonical_path(path: str) -> str:
    if not path:
        return "/"
    encoded = quote(path, safe=_PATH_SAFE)
    if not encoded.startswith("/"):
        encoded = "/" + encoded
    return encoded


def _canonical_query(query: str) -> str:
    """Sort and re-encode the query string the way AWS canonicalizes it."""
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    encoded = sorted(
        (quote(name, safe=_QUERY_SAFE), quote(value, safe=_QUERY_SAFE)) for name, value in pairs
    )
    return "&".join(f"{name}={value}" for name, value in encoded)


def _canonical_headers(headers: Mapping[str, str]) -> tuple[str, str]:
    lowered = {name.strip().lower(): str(value).strip() for name, value in headers.items()}
    if "host" not in lowered:
        msg = "a SigV4 request needs a Host header"
        raise SigV4Error(msg)
    names = sorted(lowered)
    block = "".join(f"{name}:{lowered[name]}\n" for name in names)
    return block, ";".join(names)


def _canonical_request(
    method: str, url: str, headers: Mapping[str, str], payload_hash: str
) -> tuple[str, str]:
    parts = urlsplit(url)
    header_block, signed_names = _canonical_headers(headers)
    canonical = "\n".join(
        [
            method.upper(),
            _canonical_path(parts.path),
            _canonical_query(parts.query),
            header_block,
            signed_names,
            payload_hash,
        ]
    )
    return canonical, signed_names


def sign_request(
    *,
    method: str,
    url: str,
    service: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    payload: bytes = b"",
    headers: Mapping[str, str] | None = None,
    now: datetime | None = None,
) -> dict[str, str]:
    """The headers that authenticate one request, or raise :class:`SigV4Error`.

    The returned mapping is a *new* dict (the caller's is never mutated) and contains the
    ``Authorization`` header plus ``X-Amz-Date`` and, for a temporary credential, the session
    token. The secret is used and dropped here; nothing in the return value can be turned back
    into it.
    """
    if not access_key or not secret_key:
        msg = "SigV4 needs an access key id and a secret access key"
        raise SigV4Error(msg)
    moment = now or datetime.now(UTC)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = moment.strftime("%Y%m%d")
    parts = urlsplit(url)
    if not parts.hostname:
        msg = f"{url!r} names no host to sign for"
        raise SigV4Error(msg)
    host = parts.netloc
    payload_hash = _sha256(payload)
    signed: dict[str, str] = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        signed["x-amz-security-token"] = session_token
    canonical, signed_names = _canonical_request(method, url, signed, payload_hash)
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [SIGNING_ALGORITHM, amz_date, scope, _sha256(canonical.encode("utf-8"))]
    )
    signature = hmac.new(
        derive_signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    out = dict(headers or {})
    out["Host"] = host
    out["X-Amz-Date"] = amz_date
    out["X-Amz-Content-Sha256"] = payload_hash
    if session_token:
        out["X-Amz-Security-Token"] = session_token
    out["Authorization"] = (
        f"{SIGNING_ALGORITHM} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_names}, Signature={signature}"
    )
    return out


def _authorization_fields(value: str) -> tuple[str, str, str]:
    """``(access_key, scope, signature)`` from an ``Authorization`` header, or raise."""
    if not value.startswith(AUTHORIZATION_PREFIX):
        msg = f"not a {SIGNING_ALGORITHM} header"
        raise SigV4Error(msg)
    fields: dict[str, str] = {}
    for item in value[len(AUTHORIZATION_PREFIX) :].split(","):
        name, _, raw = item.strip().partition("=")
        fields[name] = raw
    credential = fields.get("Credential", "")
    access_key, _, scope = credential.partition("/")
    signature = fields.get("Signature", "")
    if not access_key or not scope or not signature:
        msg = "the Authorization header is missing Credential or Signature"
        raise SigV4Error(msg)
    return access_key, scope, signature


def verify_request(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    service: str,
    region: str,
    secret_key: str,
    payload: bytes = b"",
    now: datetime | None = None,
    tolerance_s: int = DEFAULT_TOLERANCE_S,
) -> bool:
    """Recompute a received request's signature as the service would; ``True`` when it matches.

    The signed-header list is read from the ``Authorization`` header, so the same header set
    the signer chose is the one recomputed. A signature that does not match, a scope that names
    another service or region, and a timestamp outside ``tolerance_s`` all return ``False``
    rather than raising — a caller is deciding whether a request is authentic, not whether it
    is well-formed.
    """
    lowered = {name.lower(): str(value) for name, value in headers.items()}
    authorization = lowered.get("authorization", "")
    amz_date = lowered.get("x-amz-date", "")
    if not authorization or not amz_date:
        return False
    try:
        access_key, scope, signature = _authorization_fields(authorization)
    except SigV4Error:
        return False
    parts = scope.split("/")
    if len(parts) != 4 or parts[1] != region or parts[2] != service:
        return False
    date_stamp, _, _, terminator = parts
    if terminator != "aws4_request":
        return False
    if not _within_tolerance(amz_date, now, tolerance_s):
        return False
    payload_hash = lowered.get("x-amz-content-sha256", _sha256(payload))
    signed_names = _signed_header_names(authorization)
    if signed_names is None:
        return False
    signed = {name: lowered.get(name, "") for name in signed_names}
    canonical, names = _canonical_request(method, url, signed, payload_hash)
    if names != ";".join(signed_names):
        return False
    string_to_sign = "\n".join(
        [SIGNING_ALGORITHM, amz_date, scope, _sha256(canonical.encode("utf-8"))]
    )
    expected = hmac.new(
        derive_signing_key(secret_key, date_stamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    del access_key  # the access key is checked by the caller against the vault's own id
    return hmac.compare_digest(expected, signature)


def _signed_header_names(authorization: str) -> list[str] | None:
    for item in authorization[len(AUTHORIZATION_PREFIX) :].split(","):
        name, _, raw = item.strip().partition("=")
        if name == "SignedHeaders":
            return [part for part in raw.split(";") if part]
    return None


def _within_tolerance(amz_date: str, now: datetime | None, tolerance_s: int) -> bool:
    try:
        moment = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
    except ValueError:
        return False
    reference = now or datetime.now(UTC)
    return abs((reference - moment).total_seconds()) <= tolerance_s


def access_key_id(headers: Mapping[str, str]) -> str:
    """The access key id a request's ``Authorization`` header names, or ``""``."""
    lowered = {name.lower(): str(value) for name, value in headers.items()}
    try:
        return _authorization_fields(lowered.get("authorization", ""))[0]
    except SigV4Error:
        return ""
