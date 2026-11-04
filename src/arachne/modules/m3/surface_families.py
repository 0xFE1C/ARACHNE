"""WP-08 surface breadth: header injection, cache deception, authorization and validation.

Five read-only L1 families that the specification names as missing (REQ-DET-004,
REQ-DET-009). Each one confirms a *measured* difference, never a reflection:

``m3.host-header-injection`` — CWE-644
    Sends a forged ``Host``/``X-Forwarded-Host`` and reports only when the forged name
    appears inside an **absolute URL** in the body or a ``Location`` header that the
    canonical response did not carry — the link-poisoning primitive, not a debug echo.
``m3.email-header-injection`` — CWE-93
    Injects CRLF plus a nonce-named header into a mail-address parameter. The finding
    requires the response's structured message headers to *contain* that header with the
    nonce: proof the value was parsed as a header, which a reflected string cannot fake.
``m3.cache-deception`` — CWE-524
    Requests a personalized page through a static-looking path (``/account/x.css``) and
    reports when the same personalized body comes back with shared-cacheable headers. A
    hardened page answers 404 for the static path or marks itself ``private, no-store``.
``m3.authz-bypass`` — CWE-863
    Takes a page the server denied (401/403) and reads alternate renderings of its path
    (trailing slash, case, duplicate separator). A 200 that still carries the protected
    resource's own path segment means the authorization decision covered one spelling, not
    the route — "incorrect authorization", not "missing authorization".
``m3.input-validation-audit`` — CWE-20
    Emits the parent class deliberately, for one specific failure: an out-of-domain numeric
    value (negative, or beyond any sane bound) that the application **accepts** — 2xx, the
    value echoed, the same success shape as the baseline and no error marker. It is never a
    catch-all for "unusual input".

**Shared differential oracle.** Every comparison goes through
:mod:`arachne.modules.m3.breadth_support`, which delegates to the shared
``compare_pages``/``BodyDelta`` arithmetic. No family carries its own similarity or timing
threshold.

**Read-only.** Every request is a GET. The host-header probe changes one request header, the
email probe puts CRLF in a query value, and the cache/authz/validation probes only read.
Nothing is stored, submitted or modified.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit, urlunsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.breadth_support import (
    benign_value,
    differs,
    fetch_page,
    header_value,
    is_shared_cacheable,
    json_key_value,
    page_ratio,
    preferred,
    reproduce,
)
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m3.support import (
    WebCheck,
    exchange_from_page,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    probe_url,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = [
    "AuthzBypass",
    "CacheDeception",
    "EmailHeaderInjection",
    "HostHeaderInjection",
    "InputValidationAudit",
]


def _pages(inventory: WebInventory, origin: str) -> list[Page]:
    """The crawl's pages on one origin, in crawl order."""
    return [
        inventory.pages[url]
        for url in inventory.order
        if origin_of(url) == origin and url in inventory.pages
    ]


def _alternatives(url: str) -> tuple[tuple[str, str], ...]:
    """Read-only alternate renderings of a path (trailing slash, case, duplicate separator)."""
    parts = urlsplit(url)
    path = parts.path or "/"
    segments = [segment for segment in path.split("/") if segment]
    variants: list[tuple[str, str]] = []
    if not path.endswith("/"):
        variants.append(
            (
                "trailing-slash",
                urlunsplit((parts.scheme, parts.netloc, path + "/", parts.query, "")),
            )
        )
    cased = "/" + "/".join(
        segment[:1].upper() + segment[1:] if segment[:1].isalpha() else segment
        for segment in segments
    )
    if cased != path:
        variants.append(
            ("case-variant", urlunsplit((parts.scheme, parts.netloc, cased, parts.query, "")))
        )
    doubled = path.replace("/", "//", 1)
    if doubled != path:
        variants.append(
            (
                "duplicate-separator",
                urlunsplit((parts.scheme, parts.netloc, doubled, parts.query, "")),
            )
        )
    return tuple(variants)


def _path_segments(url: str, minimum: int) -> tuple[str, ...]:
    return tuple(
        segment.lower()
        for segment in urlsplit(url).path.split("/")
        if len(segment) >= minimum and segment.isalnum()
    )


def _is_number(value: str) -> bool:
    try:
        float(value)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- host header
class HostHeaderInjection(WebCheck, Module):
    """``m3.host-header-injection`` — forged Host in an absolute URL (ch03#15, CWE-644)."""

    metadata = CheckMetadata(
        id="m3.host-header-injection",
        module="M3",
        name="host-header-injection",
        version="1.0",
        title="Host header injection",
        description=(
            "Sends one forged Host / X-Forwarded-Host value to crawled pages and reports when "
            "the forged name appears inside an absolute URL in the response body or in a "
            "Location header that the canonical response did not carry. A bare reflection is "
            "not a finding: the poisoned value has to land in a URL the page would hand to a "
            "user. Read-only GET probes."
        ),
        research_ref="ch03#15",
        framework=("WSTG-INPV-17", "CWE-644"),
        cwe="CWE-644",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
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

        payloads = payloads_for(ctx)
        header_names = payloads.strings("host_header", "headers") or ("Host",)
        template = payloads.string(
            "host_header", "forged_host_template", default="arachne-{nonce}.invalid"
        )
        prefixes = payloads.strings("host_header", "absolute_url_prefixes") or (
            "http://",
            "https://",
        )
        path_hints = tuple(hint.lower() for hint in payloads.strings("host_header", "path_hints"))
        origin = origin_of(ctx.asset.value)
        pages = [page for page in _pages(inventory, origin) if page.status == 200]
        pages = list(
            preferred(
                pages,
                lambda page: any(hint in urlsplit(page.url).path.lower() for hint in path_hints),
            )
        )[:4]
        if not pages:
            yield ctx.clean(
                "no page to probe with a forged Host header",
                detail="the crawl recorded no successful page on this origin",
            )
            return

        findings = 0
        for page in pages:
            baseline_exchange = exchange_from_page(page)
            for header in header_names:
                forged = template.replace("{nonce}", nonce())
                fetched = await fetch_page(ctx, page.url, headers={header: forged})
                if fetched is None:
                    continue
                probe_page, probe_exchange = fetched
                if not 200 <= probe_page.status < 300:
                    continue
                location = header_value(probe_exchange.response_headers, "location")
                if forged in location:
                    reflected_in = "location-header"
                elif any(f"{prefix}{forged}" in probe_page.body for prefix in prefixes):
                    reflected_in = "body-absolute-url"
                else:
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Host header injection at {page.url} ({header})",
                    artifact={
                        "signal": "host-header-injection",
                        "family": "host-header-injection",
                        "endpoint": page.url,
                        "header": header,
                        "forged_host": forged,
                        "reflected_in": reflected_in,
                        "observed": f"the forged host appeared in a {reflected_in}",
                        "reproduce": reproduce("GET", page.url, headers={header: forged}),
                    },
                    exchanges=(baseline_exchange, probe_exchange),
                    cwe="CWE-644",
                    confidence=0.8 if reflected_in == "location-header" else 0.75,
                    detail=(
                        f"{page.url} built a {reflected_in.replace('-', ' ')} from the "
                        f"client-supplied {header} '{forged}'"
                    ),
                    source=page.url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no forged host reached a URL",
                detail=f"probed {len(pages)} page(s) with {len(header_names)} header name(s)",
            )


# --------------------------------------------------------------------------- email header
class EmailHeaderInjection(WebCheck, Module):
    """``m3.email-header-injection`` — CRLF creates a mail header (ch03#15, CWE-93)."""

    metadata = CheckMetadata(
        id="m3.email-header-injection",
        module="M3",
        name="email-header-injection",
        version="1.0",
        title="Email header injection",
        description=(
            "Injects a CRLF sequence plus a nonce-named header into a mail-address parameter "
            "and reports only when the application's structured message headers contain that "
            "header with the nonce. That is evidence the value was parsed as a header, not "
            "merely echoed; a validating endpoint rejects it. Read-only GET probes."
        ),
        research_ref="ch03#15",
        framework=("WSTG-INPV-10", "CWE-93"),
        cwe="CWE-93",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
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

        payloads = payloads_for(ctx)
        hints = {name.lower() for name in payloads.strings("email_header", "param_hints")}
        path_hints = tuple(hint.lower() for hint in payloads.strings("email_header", "path_hints"))
        benign = payloads.string(
            "email_header", "benign_value", default="arachne-probe@example.com"
        )
        header_name = payloads.string("email_header", "header_name", default="X-Arachne-Probe")
        template = payloads.string(
            "email_header", "crlf_template", default="{benign}\r\n{header}: {nonce}"
        )
        origin = origin_of(ctx.asset.value)
        candidates = [
            (url, parameter)
            for url, parameter in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
            and any(hint in urlsplit(url).path.lower() for hint in path_hints)
        ][: ctx.config.web.max_params_per_check]
        if not candidates:
            yield ctx.clean(
                "no mail-sending endpoint to probe",
                detail=(
                    "the crawl found no mail-address parameter on a subscribe/contact/reset path"
                ),
            )
            return

        findings = 0
        for url, parameter in candidates:
            baseline = await fetch_page(ctx, probe_url(url, parameter, benign))
            if baseline is None:
                continue
            marker = nonce()
            injected = template.replace("{benign}", benign).replace("{header}", header_name)
            injected = injected.replace("{nonce}", marker)
            fetched = await fetch_page(ctx, probe_url(url, parameter, injected))
            if fetched is None:
                continue
            page, exchange = fetched
            if not 200 <= page.status < 300:
                continue
            if header_name.lower() in baseline[0].body.lower():
                continue
            composed = json_key_value(page.body, header_name)
            if composed is None or marker not in composed:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Email header injection in '{parameter}'",
                artifact={
                    "signal": "email-header-injection",
                    "family": "email-header-injection",
                    "endpoint": url,
                    "parameter": parameter,
                    "injected_header": header_name,
                    "observed": f"the message headers contain {header_name}: {composed}",
                    "reproduce": reproduce("GET", probe_url(url, parameter, injected)),
                },
                exchanges=(baseline[1], exchange),
                cwe="CWE-93",
                confidence=0.85,
                detail=(
                    f"{url} accepted CRLF in '{parameter}' and put '{header_name}: {marker}' "
                    "into the message headers"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no email header was created",
                detail=f"probed {len(candidates)} mail-address parameter(s) with a CRLF payload",
            )


# --------------------------------------------------------------------------- cache deception
class CacheDeception(WebCheck, Module):
    """``m3.cache-deception`` — private page served for a static path (ch03#17, CWE-524)."""

    metadata = CheckMetadata(
        id="m3.cache-deception",
        module="M3",
        name="cache-deception",
        version="1.0",
        title="Web cache deception",
        description=(
            "Requests a personalized page through a static-looking path (a nonce named .css) "
            "and reports when the same personalized body is returned with shared-cacheable "
            "headers. A shared cache will store that response, so a third party who requests "
            "the static path receives the private page. Distinct from cache poisoning: no "
            "unkeyed input is injected. Read-only GET probes."
        ),
        research_ref="ch03#17",
        framework=("WSTG-ATHN-06", "CWE-524"),
        compliance=("ISO-A.8.27",),
        cwe="CWE-524",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
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

        payloads = payloads_for(ctx)
        hints = tuple(
            hint.lower() for hint in payloads.strings("cache_deception", "private_path_hints")
        )
        suffixes = payloads.strings("cache_deception", "static_suffixes") or (".css",)
        template = payloads.string("cache_deception", "suffix_template", default="arachne-{nonce}")
        invite = payloads.strings("cache_deception", "cacheable_directives")
        deny = payloads.strings("cache_deception", "private_directives")
        status_headers = payloads.strings("cache_deception", "cache_status_headers")
        origin = origin_of(ctx.asset.value)
        candidates = [
            page
            for page in _pages(inventory, origin)
            if page.status == 200 and any(hint in urlsplit(page.url).path.lower() for hint in hints)
        ][:6]
        if not candidates:
            yield ctx.clean(
                "no private page to probe for cache deception",
                detail="the crawl found no account/portal/profile-like page",
            )
            return

        findings = 0
        for page in candidates:
            parts = urlsplit(page.url)
            static_path = (
                parts.path.rstrip("/") + "/" + template.replace("{nonce}", nonce()) + suffixes[0]
            )
            static_url = urlunsplit((parts.scheme, parts.netloc, static_path, parts.query, ""))
            fetched = await fetch_page(ctx, static_url)
            if fetched is None:
                continue
            probe_page, probe_exchange = fetched
            if probe_page.status != 200:
                continue
            similarity = page_ratio(page, probe_page)
            if similarity < 0.95:
                continue
            if not is_shared_cacheable(
                probe_exchange.response_headers,
                invite=invite,
                deny=deny,
                status_headers=status_headers,
            ):
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Web cache deception: {page.url} is cacheable at a static path",
                artifact={
                    "signal": "cache-deception",
                    "family": "cache-deception",
                    "private_endpoint": page.url,
                    "static_path": static_url,
                    "cache_control": header_value(probe_exchange.response_headers, "cache-control"),
                    "cache_status": header_value(probe_exchange.response_headers, "x-cache"),
                    "body_similarity": round(similarity, 4),
                    "observed": (
                        "the personalized page was returned at a static-looking path "
                        "with shared-cacheable headers"
                    ),
                    "reproduce": reproduce("GET", static_url),
                },
                exchanges=(exchange_from_page(page), probe_exchange),
                cwe="CWE-524",
                confidence=0.75,
                detail=(
                    f"{page.url} is served unchanged at {static_url} and invites a shared cache "
                    "to store it"
                ),
                source=page.url,
            )
        if not findings:
            yield ctx.clean(
                "no cacheable private page at a static path",
                detail=f"probed {len(candidates)} private-looking page(s)",
            )


# --------------------------------------------------------------------------- authorization bypass
class AuthzBypass(WebCheck, Module):
    """``m3.authz-bypass`` — a denied path reachable through an alternate spelling (CWE-863)."""

    metadata = CheckMetadata(
        id="m3.authz-bypass",
        module="M3",
        name="authz-bypass",
        version="1.0",
        title="Authorization-schema bypass",
        description=(
            "Takes a page the server denied (401/403) and reads alternate renderings of its "
            "path: a trailing slash, a case variant and a duplicated separator. A 200 that "
            "still carries a segment of the protected path means the authorization decision "
            "covered one spelling of the route and not the handler behind it — incorrect "
            "authorization (CWE-863), not a missing check. Read-only GET probes."
        ),
        research_ref="ch03#18",
        framework=("WSTG-ATHZ-02", "CWE-863"),
        compliance=("CIS-6.7", "CIS-6.8", "ISO-A.5.15", "ISO-A.5.3", "PCI-7"),
        cwe="CWE-863",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=10,
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

        payloads = payloads_for(ctx)
        denied_statuses = {
            int(value) for value in payloads.strings("authz_bypass", "denied_statuses")
        }
        minimum = int(payloads.number("authz_bypass", "min_segment_length", default=4))
        origin = origin_of(ctx.asset.value)
        denied = [page for page in _pages(inventory, origin) if page.status in denied_statuses][:4]
        if not denied:
            yield ctx.clean(
                "no authorization-denied page to compare",
                detail="the crawl recorded no 401/403 response on this origin",
            )
            return

        findings = 0
        for page in denied:
            segments = _path_segments(page.url, minimum)
            if not segments:
                continue
            for technique, alternate in _alternatives(page.url):
                fetched = await fetch_page(ctx, alternate)
                if fetched is None:
                    continue
                probe_page, probe_exchange = fetched
                if probe_page.status != 200:
                    continue
                lowered = probe_page.body.lower()
                matched = next((segment for segment in segments if segment in lowered), None)
                if matched is None:
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Authorization bypass: {page.url} reachable as {technique}",
                    artifact={
                        "signal": "authz-bypass",
                        "family": "authz-bypass",
                        "technique": technique,
                        "protected_endpoint": page.url,
                        "denied_status": page.status,
                        "alternate": alternate,
                        "alternate_status": probe_page.status,
                        "recovered_segment": matched,
                        "observed": "the denied path answered 200 for an alternate spelling",
                        "reproduce": reproduce("GET", alternate),
                    },
                    exchanges=(exchange_from_page(page), probe_exchange),
                    cwe="CWE-863",
                    confidence=0.8,
                    detail=(
                        f"{page.url} answered {page.status} while {alternate} ({technique}) "
                        f"returned the protected content"
                    ),
                    source=page.url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no alternate path bypassed the denial",
                detail=f"probed {len(denied)} denied page(s) with alternate spellings",
            )


# --------------------------------------------------------------------------- input validation
class InputValidationAudit(WebCheck, Module):
    """``m3.input-validation-audit`` — an out-of-domain numeric value accepted (CWE-20)."""

    metadata = CheckMetadata(
        id="m3.input-validation-audit",
        module="M3",
        name="input-validation-audit",
        version="1.0",
        title="Input validation audit",
        description=(
            "Probes numeric parameters with an out-of-domain value (negative or far beyond any "
            "sane bound) and reports only when the application accepts it: a 2xx response that "
            "echoes the value, keeps the baseline's success shape and carries no error marker. "
            "CWE-20 is emitted deliberately for this one specific failure, never as a catch-all "
            "for unusual input. Read-only GET probes."
        ),
        research_ref="ch03#30",
        framework=("WSTG-BUSL-01", "CWE-20"),
        compliance=("CIS-16.12", "ISO-A.8.28", "PCI-6"),
        cwe="CWE-20",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
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

        payloads = payloads_for(ctx)
        hints = {name.lower() for name in payloads.strings("input_validation", "param_hints")}
        values = payloads.strings("input_validation", "out_of_domain_values") or ("-17",)
        type_probe = payloads.string("input_validation", "type_probe", default="1ar9x")
        markers = tuple(
            marker.lower() for marker in payloads.strings("input_validation", "error_markers")
        )
        origin = origin_of(ctx.asset.value)
        candidates = [
            (url, parameter)
            for url, parameter in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        targets = [
            (url, parameter)
            for url, parameter in candidates
            if _is_number(benign_value(url, parameter, ""))
        ]
        if not targets:
            yield ctx.clean(
                "no numeric parameter to validate",
                detail="the crawl found no numeric parameter with an implicit domain",
            )
            return

        findings = 0
        for url, parameter in targets:
            benign = benign_value(url, parameter, "1")
            baseline = await fetch_page(ctx, probe_url(url, parameter, benign))
            if baseline is None:
                continue
            for value in values:
                fetched = await fetch_page(ctx, probe_url(url, parameter, value))
                if fetched is None:
                    continue
                page, exchange = fetched
                if not 200 <= page.status < 300:
                    continue
                lowered = page.body.lower()
                if value not in page.body or value in baseline[0].body:
                    continue
                if any(marker in lowered for marker in markers):
                    continue
                if not differs(baseline[0], page):
                    continue
                if page_ratio(baseline[0], page) < 0.85:
                    # A different rendering (a "not found" page) is not "accepted".
                    continue
                type_page = await fetch_page(ctx, probe_url(url, parameter, type_probe))
                type_enforced = bool(
                    type_page is not None
                    and (
                        type_page[0].status >= 400
                        or any(marker in type_page[0].body.lower() for marker in markers)
                    )
                )
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Out-of-domain value accepted for '{parameter}'",
                    artifact={
                        "signal": "input-validation",
                        "family": "input-validation",
                        "constraint": "numeric-range",
                        "endpoint": url,
                        "parameter": parameter,
                        "accepted_value": value,
                        "accepted_status": page.status,
                        "type_check_enforced": type_enforced,
                        "observed": f"the application accepted {value} for '{parameter}'",
                        "reproduce": reproduce("GET", probe_url(url, parameter, value)),
                    },
                    exchanges=(baseline[1], exchange),
                    cwe="CWE-20",
                    confidence=0.7,
                    detail=(
                        f"{url} accepted the out-of-domain value {value} for numeric parameter "
                        f"'{parameter}' with a success response"
                    ),
                    source=url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no out-of-domain value accepted",
                detail=f"probed {len(targets)} numeric parameter(s) with {len(values)} value(s)",
            )
