"""Shared M3 check plumbing: the request policy, the oracles' common arithmetic, evidence.

Every M3 check answers the same few questions before it does anything interesting — "is there
an HTTP client?", "what did the crawl find?", "where does this family of payloads get tried?"
— and finishes the same way: a ``skipped`` result with a reason, or a finding whose evidence is
the request/response pair that proved it plus one machine-readable ``artifact`` the heuristic
rules read. Those shared parts live here so the checks themselves read as oracle logic.

Three rules this module exists to enforce (docs/spec/05- M3 "Safety", docs/spec/07- §5/§8):

* **One egress shape.** Every M3 request goes through :func:`fetch`, which routes to the shared
  scoped client (``ctx.http``) with the operator's session headers attached and redirect
  following off. A check never constructs a client and never imports an HTTP library
  (``tests/unit/test_http_hygiene.py``).
* **Nothing is sent in dry-run mode.** ``ctx.http is None`` is the dry run; every check turns
  it into a ``skipped`` result (:func:`http_or_skip`) rather than pretending to have looked
  (F-01-10).
* **A finding cites the exchange that proved it.** :func:`web_candidate` attaches the
  request/response evidence for every exchange the oracle compared *and* an ``artifact``
  payload whose keys the rules in ``templates/rules/heuristic-rules.yaml`` read — so a rule
  fires on a fact, not on prose.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import json
import re
import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, cast
from urllib.parse import urlencode

from arachne.core.http import CookieInfo, HttpExchange
from arachne.core.results import CheckResult, Evidence
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m3.inventory import (
    Page,
    WebInventory,
    build_web_inventory,
    normalize_body,
    origin_of,
)
from arachne.modules.m3.payloads import (
    MAX_WORDLIST_ENTRIES,
    WebPayloads,
    load_payloads,
    load_wordlist,
)

__all__ = [
    "BodyDelta",
    "Reflection",
    "WebCheck",
    "artifact_evidence",
    "b64url_decode",
    "b64url_encode",
    "body_marker",
    "build_callback",
    "classify_reflection",
    "compare_pages",
    "cookie_flag_summary",
    "decode_jwt",
    "exchange_from_page",
    "fetch",
    "find_jwts",
    "form_fields",
    "hmac_sha256_sign",
    "http_or_skip",
    "is_catchall",
    "is_probably_not_found",
    "json_post",
    "make_fetcher",
    "multipart_body",
    "nonce",
    "oob_hit",
    "owns_origin",
    "payload_for",
    "payloads_for",
    "post_form",
    "probe_url",
    "safe_fetch",
    "skip",
    "step_fetcher",
    "text_ratio",
    "web_candidate",
    "web_or_skip",
    "wordlist",
]

#: Default nonce stem, so a reflected probe can be recognised without matching a bare value
#: that might occur naturally in a page (FP control).
NONCE_STEM = "ar9x"


class WebCheck:
    """Base class for M3's checks: one URL asset, whatever the crawl knows about it.

    ``Module.supports`` already restricts a URL-scoped check to URL assets; this narrows it
    once more to an ``http(s)`` URL, because the seed vocabulary can carry a URL-ish value
    whose scheme the safety policy would refuse anyway. Mixing this in *before* the ABC
    (``class SqliOracle(WebCheck, Module)``) is what lets it narrow applicability without
    re-deriving the metadata rule.
    """

    def supports(self, asset: Asset) -> bool:
        if not super().supports(asset):  # type: ignore[misc]
            return False
        if asset.kind != "url":
            return False
        return asset.value.lower().startswith(("http://", "https://"))


# --------------------------------------------------------------------------- payload access
@lru_cache(maxsize=4)
def _payloads_cached(path: str | None) -> WebPayloads:
    return load_payloads(path)


def payloads_for(ctx: CheckContext) -> WebPayloads:
    """The M3 probe corpus (cached per path: parsing YAML per check would be wasteful)."""
    return _payloads_cached(ctx.config.web_payloads)


def payload_for(ctx: CheckContext, *path: str) -> str:
    return payloads_for(ctx).string(*path)


def wordlist(ctx: CheckContext, name: str, *, limit: int | None = None) -> tuple[str, ...]:
    """An M3 wordlist: the operator's directory wins over the packaged file (F-09-04)."""
    return load_wordlist(
        name,
        override_dir=ctx.config.web_payloads,
        limit=limit if limit is not None else MAX_WORDLIST_ENTRIES,
    )


def nonce() -> str:
    """A fresh per-probe marker (so a cached/reflected *other* response cannot confirm)."""
    return f"{NONCE_STEM}{secrets.token_hex(4)}"


# --------------------------------------------------------------------------- preconditions
def http_or_skip(ctx: CheckContext) -> tuple[Any, CheckResult | None]:
    """``(client, None)`` when a live client exists, else ``(None, skipped result)``."""
    client = ctx.http
    if client is None:
        return None, skip(
            ctx,
            "no HTTP client in this run: M3 probes need a live scan "
            "(a dry run sends nothing — F-01-10)",
        )
    return client, None


def web_or_skip(ctx: CheckContext) -> tuple[WebInventory | None, CheckResult | None]:
    """``(inventory, None)`` when the checks step built the crawl, else a skipped result."""
    inventory = ctx.web
    if inventory is None:
        return None, skip(
            ctx,
            "no web inventory for this step: the checks step crawls the endpoints (S6/M3)",
        )
    assert isinstance(inventory, WebInventory)
    return inventory, None


def skip(ctx: CheckContext, reason: str) -> CheckResult:
    """A skipped result carrying a machine-readable reason (never prose matching)."""
    return ctx.skipped(reason)


def owns_origin(ctx: CheckContext) -> bool:
    """True when this asset is the M3 owner of its origin for this scan.

    M3's crawl is per-origin and shared by every check, so if a scan declares two URLs on one
    origin (``http://host/`` and ``http://host/api/``) letting both run every check would
    probe the same pages twice and emit duplicate findings for them. The owner is the
    lexicographically-first URL asset of the origin — deterministic, needs no shared mutable
    state, and leaves the second asset's own origin coverage intact.

    A scan that declares no URL asset at all (a bare host, whose endpoints the discovery step
    derived) has exactly one derived URL per origin, so it always owns.
    """
    try:
        mine = origin_of(ctx.asset.value)
        candidates = sorted(
            record.value
            for record in ctx.step.store.list_assets(ctx.scan_id)
            if record.kind == "url" and origin_of(record.value) == mine
        )
    except Exception:  # a store hiccup must not stop a check from running
        return True
    if not candidates:
        return True
    return candidates[0] == ctx.asset.value


# --------------------------------------------------------------------------- requests
async def fetch(
    ctx: CheckContext,
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    content: bytes | str | None = None,
    follow_redirects: bool | None = None,
    session: bool = True,
    second_identity: bool = False,
    anonymous: bool = False,
) -> HttpExchange:
    """One M3 request through the shared scoped client.

    ``session=True`` attaches the operator's demo session headers (F-08-01, env-only) so an
    authenticated surface is reachable; the client redacts ``cookie``/``authorization`` at
    capture time, so the value never reaches evidence (F-08-04). The default redirect policy
    comes from ``ARACHNE_WEB_FOLLOW_REDIRECTS`` (off): an M3 oracle wants the raw 3xx it
    asked for, not the page it points at.

    ``anonymous=True`` goes further and issues the request on the client's cookie-less path:
    it drops the operator's session *and* any cookie the crawl established, which is what a
    probe whose claim is "reachable without credentials" requires (S29).
    """
    client = ctx.http
    assert client is not None  # callers guard with http_or_skip
    request_headers: dict[str, str] = {}
    if session:
        request_headers.update(ctx.config.session_headers(second=second_identity))
    if headers:
        request_headers.update(headers)
    follow = ctx.config.web.follow_redirects if follow_redirects is None else follow_redirects
    # ``anonymous`` is passed only when it is on. A check that does not need the cookie-less
    # path then sends exactly the request it always did, which keeps every existing caller —
    # and every test double implementing the older ``request`` signature — working unchanged.
    if anonymous:
        return cast(
            HttpExchange,
            await client.request(
                method.upper(),
                url,
                headers=request_headers or None,
                content=content,
                follow_redirects=follow,
                anonymous=True,
            ),
        )
    return cast(
        HttpExchange,
        await client.request(
            method.upper(),
            url,
            headers=request_headers or None,
            content=content,
            follow_redirects=follow,
        ),
    )


async def safe_fetch(ctx: CheckContext, url: str, **kwargs: Any) -> HttpExchange | None:
    """Like :func:`fetch`, but a refusal/failure is ``None`` (already audited by the client).

    A check makes dozens of probes; one blocked or failed request must not abort the rest —
    "errors are data" (docs/spec/07- §4). The client audits a scope/safety refusal, so
    swallowing it here loses no evidence.
    """
    try:
        return await fetch(ctx, url, **kwargs)
    except Exception:  # a probe failure is data, not a check failure
        return None


def probe_url(url: str, name: str, value: str) -> str:
    """``url`` with query parameter ``name`` set to ``value`` (everything else unchanged)."""
    from arachne.modules.m3.inventory import with_params

    return with_params(url, {name: value})


def make_fetcher(ctx: CheckContext) -> Any:
    """A :data:`~arachne.modules.m3.inventory.Fetcher` for the crawl (one policy, one place)."""

    async def _fetch(url: str) -> HttpExchange:
        return await fetch(ctx, url)

    return _fetch


def step_fetcher(step: Any, config: ModuleConfig) -> Any:
    """The crawl's fetcher for the *checks step* (which has a step context, not a check one).

    Built here so the crawl and the checks use one request policy: the operator's session
    headers, no redirect following, and the scan's scoped client (rate limit + audit).
    """

    async def _fetch(url: str) -> HttpExchange:
        headers = config.session_headers()
        return cast(
            HttpExchange,
            await step.http.request(
                "GET",
                url,
                headers=headers or None,
                follow_redirects=config.web.follow_redirects,
            ),
        )

    return _fetch


async def crawl(
    ctx: CheckContext,
    roots: Iterable[str],
) -> WebInventory:
    """Run the shared M3 crawl over ``roots`` (bounded by the deployment settings)."""
    return await build_web_inventory(
        roots,
        make_fetcher(ctx),
        max_pages=ctx.config.web.max_pages,
        max_depth=ctx.config.web.max_depth,
        max_endpoints=ctx.config.web.max_endpoints,
    )


@dataclass(frozen=True, slots=True)
class Reflection:
    """Where an injected marker came back, and in what context (the XSS oracle's read)."""

    context: str
    marker: str
    index: int


def classify_reflection(body: str, *, nonce: str) -> Reflection | None:
    """Classify how the probe for ``nonce`` was reflected, or ``None`` when it was encoded.

    The probe is ``<a{nonce}>"'{nonce}``; each context is keyed on the *raw* fragment that
    proves the corresponding character was not encoded:

    ``html``
        the angle bracket survived (``<a{nonce}>``), so markup was injected directly;
    ``attribute``
        the angle bracket was encoded but a quote was not (``"{nonce}`` / ``'{nonce}``), so a
        crafted value can break out of the attribute it landed in;
    ``script``
        the bare nonce landed inside a ``<script>`` block with both encoded, which is the
        weakest read (the value may never have been a string boundary) but still worth a note.

    An *encoded* reflection (``&lt;``, ``&quot;``, ``&#39;``) is not a finding: that is the
    application doing the right thing, and treating it as one is the classic reflected-XSS
    false positive.
    """
    html_marker = f"<a{nonce}>"
    double_marker = f'"{nonce}'
    single_marker = f"'{nonce}"
    position = body.find(html_marker)
    if position >= 0:
        return Reflection(context="html", marker=html_marker, index=position)
    position = body.find(double_marker)
    if position >= 0:
        return Reflection(context="attribute", marker=double_marker, index=position)
    position = body.find(single_marker)
    if position >= 0:
        return Reflection(context="attribute", marker=single_marker, index=position)
    plain = body.find(nonce)
    if plain >= 0 and _inside_script(body, plain):
        return Reflection(context="script", marker=nonce, index=plain)
    return None


def _inside_script(body: str, index: int) -> bool:
    opening = body.rfind("<script", 0, index)
    if opening < 0:
        return False
    closing = body.find("</script>", index)
    return closing >= 0


# --------------------------------------------------------------------------- multipart
def multipart_body(
    fields: Mapping[str, str],
    files: Sequence[tuple[str, str, str, bytes]] = (),
) -> tuple[bytes, str]:
    """Encode a ``multipart/form-data`` body by hand.

    The shared client takes raw ``content`` (it is the one place an HTTP library lives), so a
    form upload has to be encoded here. Hand-writing it keeps the *file part* explicit — the
    filename and content type the validation matrix varies stay visible at the call site
    rather than hiding inside a library's ``files=`` convenience.

    ``files`` entries are ``(field_name, filename, content_type, content)``.
    """
    boundary = f"----arachne{secrets.token_hex(8)}"
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        chunks.append(str(value).encode("utf-8"))
        chunks.append(b"\r\n")
    for field_name, filename, content_type, content in files:
        chunks.append(f"--{boundary}\r\n".encode())
        chunks.append(
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'
            "\r\n".encode()
        )
        chunks.append(f"Content-Type: {content_type}\r\n\r\n".encode())
        chunks.append(content)
        chunks.append(b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


# --------------------------------------------------------------------------- comparison
@dataclass(frozen=True, slots=True)
class BodyDelta:
    """The measured difference between a probe response and its baseline (the oracle's read)."""

    baseline_status: int
    probe_status: int
    baseline_length: int
    probe_length: int
    ratio: float  # 1.0 = identical normalized bodies, 0.0 = nothing in common

    @property
    def status_changed(self) -> bool:
        return self.baseline_status != self.probe_status

    @property
    def length_delta(self) -> int:
        return self.probe_length - self.baseline_length

    @property
    def body_changed(self) -> bool:
        return self.ratio < 0.999

    def significant(self, *, min_ratio_drop: float = 0.01, min_length_delta: int = 8) -> bool:
        """True when the difference is larger than rendering noise."""
        return (
            self.status_changed
            or self.ratio <= 1.0 - min_ratio_drop
            or abs(self.length_delta) >= min_length_delta
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_status": self.baseline_status,
            "probe_status": self.probe_status,
            "baseline_length": self.baseline_length,
            "probe_length": self.probe_length,
            "ratio": round(self.ratio, 4),
            "status_changed": self.status_changed,
            "length_delta": self.length_delta,
        }


def text_ratio(left: str, right: str) -> float:
    """Similarity of two bodies in ``[0, 1]`` (normalized, bounded for cost)."""
    a = normalize_body(left)[:20000]
    b = normalize_body(right)[:20000]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()


def compare_pages(baseline: Page | HttpExchange, probe: Page | HttpExchange) -> BodyDelta:
    """The delta between a baseline and a probe response (accepts either record type)."""
    base_status = baseline.status if isinstance(baseline, Page) else baseline.status_code
    probe_status = probe.status if isinstance(probe, Page) else probe.status_code
    base_body = baseline.body
    probe_body = probe.body
    return BodyDelta(
        baseline_status=base_status,
        probe_status=probe_status,
        baseline_length=len(normalize_body(base_body)),
        probe_length=len(normalize_body(probe_body)),
        ratio=text_ratio(base_body, probe_body),
    )


def is_probably_not_found(page: Page, not_found: Page | None) -> bool:
    """True when ``page`` looks like the application's own not-found response.

    The comparison is on the *rendering*, not only the status: many applications answer 200
    with a "not found" page, and treating that as a discovery is the fastest way to a
    false-positive flood.
    """
    if not_found is None:
        return False
    if page.status != not_found.status:
        return False
    return text_ratio(page.body, not_found.body) >= 0.9


def is_catchall(page: Page, *, not_found: Page | None, root: Page | None) -> bool:
    """True when ``page`` is the application's catch-all (an SPA answering every path).

    A single-page application returns its shell for unknown paths with a 200; that shell is
    (nearly) identical to the *root* document, while a genuine endpoint's body is not. A
    response that instead matches the application's own not-found page is caught by
    :func:`is_probably_not_found`. Either match means "this path is not a distinct endpoint",
    which is why the test is *any* rather than *all*: requiring agreement with both references
    would let an SPA shell — identical to the root and different from the 404 — through as a
    discovery on every wordlist path.
    """
    for reference in (root, not_found):
        if reference is not None and text_ratio(page.body, reference.body) >= 0.98:
            return True
    return False


def body_marker(body: str, marker: str) -> bool:
    """True when ``marker`` appears verbatim in ``body`` (used for reflected-probe checks)."""
    return bool(marker) and marker in body


# --------------------------------------------------------------------------- cookies
def cookie_flag_summary(cookies: Sequence[CookieInfo]) -> dict[str, Any]:
    """A JSON-safe, value-free summary of the cookies a response set."""
    if not cookies:
        return {"count": 0, "names": [], "insecure_flags": False, "missing": []}
    missing: list[str] = []
    for cookie in cookies:
        missing.extend(cookie.missing_flags)
    return {
        "count": len(cookies),
        "names": [cookie.name for cookie in cookies],
        "insecure_flags": bool(missing),
        "missing": sorted(set(missing)),
        "detail": [cookie.to_dict() for cookie in cookies],
    }


# --------------------------------------------------------------------------- evidence
def artifact_evidence(payload: Mapping[str, Any], *, source: str | None = None) -> Evidence:
    """One machine-readable ``artifact`` the heuristic rules read (redacted + hashed)."""
    return Evidence.of("artifact", dict(payload), source=source)


def exchange_from_page(page: Page) -> HttpExchange:
    """Rebuild an exchange-like record from a stored :class:`Page` (evidence, no new request).

    The crawl keeps :class:`Page` records rather than full exchanges; a check that cites a
    crawled page's response as evidence needs the ``HttpExchange`` shape so the rules can read
    ``evidence.http_response.headers``/``.status_code`` exactly as they would for a fresh probe.
    """
    return HttpExchange(
        method="GET",
        url=page.url,
        status_code=page.status,
        response_headers=dict(page.headers),
        body=page.body,
        elapsed_ms=page.elapsed_ms,
        cookies=page.cookies,
        body_truncated=page.truncated,
        secret_kinds=page.secret_kinds,
    )


def web_candidate(
    ctx: CheckContext,
    title: str,
    *,
    artifact: Mapping[str, Any],
    exchanges: Iterable[HttpExchange | None] = (),
    cwe: str | None = None,
    confidence: float = 0.5,
    detail: str | None = None,
    source: str | None = None,
    extra_evidence: Iterable[Evidence] = (),
) -> CheckResult:
    """A candidate finding citing every exchange the oracle compared plus one artifact.

    The request/response pair satisfies F-02-08 ("request, response, headers, timing"); the
    ``artifact`` carries the oracle's verdict as *facts* so a rule in the shipped corpus can
    fire on them (docs/spec/04- §2.1) instead of re-deriving the comparison. The proof-ladder
    checks (S15) append their ``proof`` evidence through ``extra_evidence`` so a finding can
    carry its level, method and cleanup status next to the oracle's facts.
    """
    evidence: list[Evidence] = []
    primary: str | None = source
    for exchange in exchanges:
        if exchange is None:
            continue
        request, response = exchange.to_evidence()
        evidence.extend((request, response))
        if primary is None:
            primary = exchange.url
    evidence.append(artifact_evidence(artifact, source=primary))
    evidence.extend(extra_evidence)
    return ctx.candidate(
        title,
        detail=detail,
        cwe=cwe,
        evidence=evidence,
        confidence=confidence,
    )


# --------------------------------------------------------------------------- extended helpers
def form_fields(form: Any, *, overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    """A form's submittable fields with ``overrides`` applied (defaults from the page)."""
    fields: dict[str, str] = {}
    for item in form.inputs:
        if item.type.lower() in {"submit", "button", "file", "image", "reset"}:
            continue
        fields[item.name] = item.value or ""
    fields.update(overrides or {})
    return fields


async def post_form(
    ctx: CheckContext,
    url: str,
    fields: Mapping[str, str],
    *,
    session: bool = True,
    second_identity: bool = False,
    extra_headers: Mapping[str, str] | None = None,
    follow_redirects: bool = False,
) -> HttpExchange | None:
    """URL-encode ``fields`` and POST them (one bounded request, errors are ``None``)."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    headers.update(extra_headers or {})
    return await safe_fetch(
        ctx,
        url,
        method="POST",
        headers=headers,
        content=urlencode(fields),
        session=session,
        second_identity=second_identity,
        follow_redirects=follow_redirects,
    )


async def json_post(
    ctx: CheckContext,
    url: str,
    payload: Any,
    *,
    session: bool = True,
    extra_headers: Mapping[str, str] | None = None,
    follow_redirects: bool = False,
    anonymous: bool = False,
) -> HttpExchange | None:
    """POST a JSON body (used by the API-family oracles: GraphQL, mass assignment, pollution)."""
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    headers.update(extra_headers or {})
    return await safe_fetch(
        ctx,
        url,
        method="POST",
        headers=headers,
        content=json.dumps(payload),
        session=session,
        follow_redirects=follow_redirects,
        anonymous=anonymous,
    )


# --------------------------------------------------------------------------- JWT
def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """``(header, payload, signature)`` for a JWS compact token, or ``None``."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, parts[2] if len(parts) > 2 else ""


_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{0,}")


def find_jwts(text: str, *, limit: int = 8) -> tuple[str, ...]:
    """JWS compact tokens present verbatim in ``text`` (bounded, deduplicated)."""
    found: dict[str, None] = {}
    for match in _JWT_RE.finditer(text):
        found.setdefault(match.group(0), None)
        if len(found) >= limit:
            break
    return tuple(found)


def hmac_sha256_sign(secret: bytes, signing_input: str) -> str:
    return b64url_encode(hmac.new(secret, signing_input.encode("ascii"), hashlib.sha256).digest())


# --------------------------------------------------------------------------- OOB callback
def build_callback(ctx: CheckContext, template: str) -> tuple[str, str] | None:
    """``(callback_url, nonce)`` for an OOB probe, or ``None`` when none is configured.

    The callback base is ``ARACHNE_WEB_SSRF_CALLBACK`` — a service on ARACHNE's own
    infrastructure (research ch03#5). With none configured the SSRF check reports itself
    skipped rather than sending anything at the target.
    """
    base = (ctx.config.web.ssrf_callback_url or "").strip()
    if not base:
        return None
    marker = nonce()
    url = template.replace("{base}", base.rstrip("/")).replace("{nonce}", marker)
    return url, marker


async def oob_hit(ctx: CheckContext, base: str, marker: str) -> bool:
    """Ask the callback service whether ``marker`` arrived (best-effort; ``False`` on error).

    The service exposes a bounded ``/hits?nonce=`` listing; the check reads it through the
    scan's own client, so the lookup is scoped, rate-limited and audited like any request.
    """
    exchange = await safe_fetch(
        ctx, f"{base.rstrip('/')}/hits", headers={"X-Arachne-Nonce": marker}
    )
    if exchange is None:
        return False
    return marker in exchange.body
