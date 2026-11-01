"""Dynamic verification of a statically-found client-side credential (REQ-DEPTH-004).

``m1.js-asset-scan`` finds the *static* half: a served bundle contains a credential shape and
a set of API endpoints. This check is the dynamic half, and it is where an honest design has to
confront a platform invariant:

**A check never receives the value of a secret found in a response.** The HTTP client redacts
at capture (F-08-04) — a bundle's credential arrives as a detector name and a masked
fingerprint, never as a usable string. So "verification" here can never mean replaying the
key, and that is a safety property, not a gap: this scanner does not carry credentials it
found into new requests.

What *can* be verified dynamically, and is what an operator actually needs to know, is the
**impact**: the API endpoint the bundle targets answers a caller who presents nothing at all —
which is the thing that makes a shipped client-side key valueless to its owner and useful to
everyone else. The check therefore:

* presents no credential of any kind — it issues its request on the client's cookie-less path
  (``anonymous=True``), so neither the operator's session nor a cookie the crawl picked up is
  attached, and the claim "nothing was presented" is a property of the request;
* asks each endpoint the crawl found behind the credential-bearing page for an ordinary read,
  and reports the one that answers without credentials;
* plants the ladder's single-use out-of-band token in any URL-valued parameter of that
  endpoint, so the request is confirmed by the target's own connection back to ARACHNE's
  callback service when one exists (REQ-PROOF-005).

That last step is what makes this an **L2** check: it asks for ``ctx.proof.oob_token()``, which
the capability boundary refuses below L2, and it records the token in the proof ledger. When no
callback service is configured the ladder's downgrade rule (REQ-PROOF-003) applies: the check
says so, reports the anonymous-access fact as the in-band L1 observation it is, and claims no
out-of-band proof.

It is opt-in: outside the default set (L2 is opt-in by definition) — and it changes nothing:
one GET per endpoint, an inert nonce in a parameter, no payload.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.extract import extract_endpoints
from arachne.modules.m3.inventory import WebInventory, origin_of
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    owns_origin,
    payloads_for,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["ClientSecretVerify"]

#: How many bundle-named routes one run verifies. A client bundle names a handful of API
#: routes; the cap keeps the guess-verify loop proportional and the estimate honest (F-01-07).
_MAX_ROUTE_CANDIDATES = 6

#: Prefixes that make an extracted route worth verifying: an API surface, not an asset path.
_API_ROUTE_PREFIXES: tuple[str, ...] = ("/api", "/v1", "/v2", "/graphql", "/rest")

#: Parameter names that plausibly carry a URL the server will fetch. Only these get the
#: callback token, so the probe sends no unexpected value anywhere.
_URL_PARAM_HINTS: tuple[str, ...] = (
    "url",
    "uri",
    "link",
    "next",
    "return",
    "returnurl",
    "redirect",
    "redirect_uri",
    "callback",
    "image",
    "avatar",
    "feed",
    "src",
    "target",
    "host",
    "domain",
)


class ClientSecretVerify(WebCheck, Module):
    """``m3.client-secret-verify`` — dynamic verification of a client-side credential (L2)."""

    metadata = CheckMetadata(
        id="m3.client-secret-verify",
        module="M3",
        name="client-secret-verify",
        version="1.0",
        title="Client-side credential impact verification",
        description=(
            "Verifies dynamically what a served bundle's hardcoded credential means: that the "
            "API endpoint behind it answers a caller presenting no credential at all, with the "
            "ladder's single-use out-of-band token planted in a URL-valued parameter for "
            "confirmation. The credential's value is never available to a check (redaction at "
            "capture, F-08-04) and is never replayed; the check proves impact, not possession. "
            "Opt-in (L2)."
        ),
        research_ref="ch03#3",
        proof=ProofLevel.L2,
        cwe="CWE-522",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        enabled_by_default=False,
        estimated_requests=6,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        access = ctx.proof
        origin = origin_of(ctx.asset.value)
        bundles = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and url.lower().split("?")[0].endswith((".js", ".mjs"))
        ]
        if not bundles:
            yield ctx.clean(
                "no client bundle to verify",
                detail="the crawl found no JavaScript asset on this origin",
            )
            return
        # The endpoints to verify are the ones the *bundles* name — not every crawled route.
        # A bundle is where a client-side credential would be spent, so the pair
        # (bundle names the route, route answers without credentials) is the finding; probing
        # the whole crawl would report unrelated public pages, which is noise, not depth.
        candidates = await self._bundle_endpoints(ctx, bundles, origin)
        if not candidates:
            yield ctx.clean(
                "no API route named by the client bundles",
                detail=(
                    f"read {len(bundles)} bundle(s) on this origin; none named an API route to "
                    "verify"
                ),
            )
            return

        # The ladder's single-use token, when one is available. Its *absence* is the recorded
        # downgrade (REQ-PROOF-003), not a reason to skip the in-band half.
        token = None
        callback_url: str | None = None
        if access is not None:
            try:
                issued = access.oob_token()
            except Exception:  # the boundary refused: no L2 capability in this run
                issued = None
            if issued is not None and issued.url is not None:
                token, callback_url = issued.token, issued.url

        findings = 0
        probed = 0
        for endpoint in candidates:
            probed += 1
            # No credential of any kind: the cookie-less path is the point of the probe.
            anonymous = await safe_fetch(ctx, endpoint, session=False, anonymous=True)
            if anonymous is None or not (200 <= anonymous.status_code < 300):
                continue
            out_of_band = False
            exchange = anonymous
            if token is not None and callback_url is not None:
                param = _url_parameter(ctx, endpoint)
                if param is not None:
                    planted = await safe_fetch(
                        ctx,
                        probe_url(endpoint, param, callback_url),
                        session=False,
                        anonymous=True,
                    )
                    if planted is not None:
                        exchange = planted
                    if await access.oob_consume(token) is not None:
                        out_of_band = True
            findings += 1
            yield web_candidate(
                ctx,
                f"API endpoint behind a client bundle answers without credentials: {endpoint}",
                artifact={
                    "signal": "client-secret",
                    "family": "client-side",
                    "endpoint": endpoint,
                    "bundles": bundles[:5],
                    "anonymous_request": True,
                    "status": anonymous.status_code,
                    "out_of_band_confirmed": out_of_band,
                    "proof_level": "L2" if out_of_band else "L1",
                    # Named "replayed_value" rather than "secret_value_used": an evidence *key*
                    # containing "secret" is itself redacted by the key-aware rule (F-08-04),
                    # which would turn this boolean into a placeholder.
                    "replayed_value": False,
                },
                exchanges=(exchange,),
                cwe="CWE-522",
                confidence=0.75 if out_of_band else 0.5,
                detail=(
                    f"{endpoint} returned {anonymous.status_code} to a request that presented "
                    "no cookie and no authorization header, while the origin serves a bundle "
                    "that hardcodes a credential. The credential is therefore not what guards "
                    "this data"
                    + (
                        ", and the target's own connection back to ARACHNE's callback "
                        "confirmed the planted parameter out of band (L2)"
                        if out_of_band
                        else ". No callback service is configured "
                        "(ARACHNE_WEB_SSRF_CALLBACK), so this is the in-band L1 observation: "
                        "the ladder downgraded rather than claiming an out-of-band proof"
                    )
                    + ". The credential's value is never available to a check (redaction at "
                    "capture, F-08-04) and was not replayed; what is proven is the impact."
                ),
                source=endpoint,
            )
        if not findings:
            yield ctx.clean(
                "no anonymously reachable endpoint behind the client bundles",
                detail=(
                    f"read {probed} endpoint(s) on this origin with no credential presented; "
                    "each refused or did not answer"
                ),
                confidence=0.5,
            )

    async def _bundle_endpoints(
        self, ctx: CheckContext, bundles: list[str], origin: str
    ) -> list[str]:
        """The API routes named by the bundles, as absolute URLs (bounded, deduplicated).

        Reading the bundle is itself an anonymous read: the same claim the check makes about
        the endpoints it then verifies. ``extract_endpoints`` is the same extractor M1 uses, so
        "what a route looks like" has one definition.
        """
        found: dict[str, None] = {}
        for bundle in bundles[:3]:
            exchange = await safe_fetch(ctx, bundle, session=False, anonymous=True)
            if exchange is None or not (200 <= exchange.status_code < 300):
                continue
            for route in extract_endpoints(exchange.body, limit=200):
                if route.startswith(_API_ROUTE_PREFIXES):
                    found.setdefault(f"{origin}{route}", None)
                if len(found) >= _MAX_ROUTE_CANDIDATES:
                    return list(found)
        return list(found)


def _url_parameter(ctx: CheckContext, endpoint: str) -> str | None:
    """The first URL-shaped parameter name on ``endpoint``, if any.

    The callback token only goes into a parameter that plausibly holds a URL: the probe must
    never invent a value for a parameter whose meaning it does not know. When the corpus
    declares the hints they win over the built-in list (managed data, F-09-04).
    """
    declared = payloads_for(ctx).strings("ssrf", "param_hints")
    hints = {name.lower() for name in declared} or set(_URL_PARAM_HINTS)
    query = urlsplit(endpoint).query
    for pair in query.split("&"):
        name = pair.split("=", 1)[0].strip()
        if name and name.lower() in hints:
            return name
    return None
