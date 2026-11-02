"""M3 hardening-family oracles: NoSQL injection (ch03#2), path traversal (ch03#12), file
inclusion (ch03#13) and CRLF / HTTP header injection (ch03#15).

All four follow the M3 contract exactly : a probe is detection-only
and a confirmation is a *measured difference* against a baseline the check establishes first
(or a canary the probe can only have caused). None of them extracts data, executes code or
writes anything:

``m3.nosql-oracle``
    Injects MongoDB-style operator values and parameter-name suffixes (``'``, ``"``,
    ``{"$ne": null}``, ``{"$gt": ""}``, ``[$ne]=``, ``[$regex]=``) and confirms the family when
    the response diverges from the benign baseline for a reason that is not merely the probe
    being echoed. Read-only: a predicate is only made true/false.
``m3.directory-traversal``
    Walks the traversal encoding matrix (plain, URL-encoded, dot-encoded, overlong, backslash,
    ``file://``) against file-name parameters and confirms by a world-readable file's header
    line (``root:x:0:0:`` / ``[extensions]``) that the benign baseline did not carry. Nothing
    sensitive is read.
``m3.file-inclusion``
    LFI is confirmed when a world-readable file's header line, or the base64 of a PHP opening
    tag from a ``php://filter`` read, appears where the baseline had none. The RFI probe only
    *references* an unresolvable ``.invalid`` host and is flagged only on a clear in-response
    include side effect — the payload is never fetched and no remote code is executed.
``m3.crlf-injection``
    Injects ``\\r\\n``-bearing header fragments into parameters and flags only the *observation*
    that the injected header (``X-Injected``), an injected ``Set-Cookie`` name, or a split
    ``Location`` came back. No response splitting is attempted beyond reading the response.

The managed corpus (``templates/m3/payloads.yaml``) has no section for these four families, so
their probe strings are reviewed constants here rather than invented inline, mirroring how the
extended families keep family-specific data beside the oracle that consumes it.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, origin_of
from arachne.modules.m3.support import (
    BodyDelta,
    WebCheck,
    compare_pages,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = [
    "CrlfInjection",
    "DirectoryTraversal",
    "FileInclusion",
    "NosqlOracle",
]

# --------------------------------------------------------------------------- payloads (data)
#: NoSQL: bare values an operator-style back-end may parse as a query. ``$ne``/``$gt`` turn a
#: parameter into a predicate; a bare quote breaks out of a quoted string it was interpolated
#: into.
_NOSQL_VALUE_PAYLOADS: tuple[str, ...] = (
    "'",
    '"',
    '{"$ne": null}',
    '{"$gt": ""}',
)

#: NoSQL: parameter-name suffixes (MongoDB array/operator injection). ``with_params`` encodes the
#: bracket syntax, so the server sees ``param[$ne]=1`` rather than a literal string value.
_NOSQL_OPERATOR_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("[$ne]", "1"),
    ("[$gt]", ""),
    ("[$regex]", ".*"),
)

#: Path traversal: the encoding classes of research ch03#12 (plain, URL-encoded, dot-encoded,
#: overlong separators, backslash, absolute ``file://`` wrapper). Tried against file-name
#: parameters only.
_TRAVERSAL_PAYLOADS: tuple[str, ...] = (
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//....//etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini",
    "file:///etc/passwd",
)

#: The header line of a world-readable, non-secret file read by traversal (``/etc/passwd`` and
#: the Windows ``win.ini`` section header).
_TRAVERSAL_CANARIES: tuple[re.Pattern[str], ...] = (
    re.compile(r"root:[x*]?:0:0:"),
    re.compile(r"\[(extensions|fonts|mci extensions)\]", re.IGNORECASE),
)

#: File inclusion: LFI canaries. ``php://filter`` reads re-encode the file, so the marker is the
#: base64 of the PHP opening tag (``PD9waHA``) rather than the source itself.
_LFI_PAYLOADS: tuple[str, ...] = (
    "/etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=../index.php",
)

#: The header line of a world-readable, non-secret file, plus the base64 of ``<?php``.
_LFI_CANARIES: tuple[re.Pattern[str], ...] = (
    re.compile(r"root:[x*]?:0:0:"),
    re.compile(r"PD9waHA"),
)

#: The RFI probe references an unresolvable ``.invalid`` host (RFC 2606): it must never reach a
#: real server, and the check reads only the *response* for an include side effect.
_RFI_HOST = "arachne-rfi.invalid"
_RFI_PAYLOAD = f"http://{_RFI_HOST}/ar9x.txt"
_RFI_INDICATORS: tuple[str, ...] = (
    "allow_url_include",
    "url file-access is disabled",
    "http:// wrapper is disabled",
    "failed to open stream",
    "failed opening",
)

#: CRLF: a header fragment appended (via a CR/LF sequence) to the injected value. ``{marker}``
#: makes each probe unique, so a pre-existing response header cannot be mistaken for injection.
_CRLF_MARKER_HOST = "arachne-crlf.invalid"
_CRLF_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("injected-header", "\r\nX-Injected: {marker}"),
    ("injected-cookie", "\r\nSet-Cookie: {marker}=1"),
    ("location-split", f"\r\nLocation: https://{_CRLF_MARKER_HOST}/{{marker}}"),
)


# --------------------------------------------------------------------------- NoSQL (ch03#2)
class NosqlOracle(WebCheck, Module):
    """``m3.nosql-oracle`` — operator-injection differentials (ch03#2)."""

    metadata = CheckMetadata(
        id="m3.nosql-oracle",
        module="M3",
        name="nosql-oracle",
        version="1.0",
        title="NoSQL injection oracle",
        description=(
            "Injects MongoDB-style operator payloads (a bare quote, a JSON predicate such as "
            '{"$ne": null}, and the [$ne]/[$gt]/[$regex] parameter-name suffixes) into query '
            "parameters and confirms the family by a response differential against the benign "
            "baseline that is not merely the probe being echoed. Read-only: it only makes a "
            "back-end predicate true or false, and never extracts or modifies data."
        ),
        research_ref="ch03#2",
        framework=("WSTG-INPV-05", "CWE-943"),
        cwe="CWE-943",
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

        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(limit=ctx.config.web.max_params_per_check)
            if origin_of(url) == origin
        ]
        if not targets:
            yield ctx.clean(
                "no query parameter to probe",
                detail="the crawl found no parameter on this origin",
            )
            return

        findings = 0
        for url, param in targets:
            finding = await self._probe(ctx, url, param)
            if finding is None:
                continue
            findings += 1
            yield finding
        if not findings:
            yield ctx.clean(
                "no NoSQL injection differential observed",
                detail=(
                    f"probed {len(targets)} parameter(s) with quote, predicate and operator "
                    "payloads"
                ),
            )

    async def _probe(self, ctx: CheckContext, url: str, param: str) -> CheckResult | None:
        baseline = await safe_fetch(ctx, probe_url(url, param, "1"), follow_redirects=False)
        if baseline is None:
            return None
        for payload in _NOSQL_VALUE_PAYLOADS:
            injected = await safe_fetch(ctx, probe_url(url, param, payload), follow_redirects=False)
            hit = _query_differential(baseline, injected, payload)
            if hit is None:
                continue
            delta, probe_exchange = hit
            return self._candidate(
                ctx, url, param, payload, "value", baseline, probe_exchange, delta
            )
        for suffix, value in _NOSQL_OPERATOR_SUFFIXES:
            probe = f"{param}{suffix}"
            injected = await safe_fetch(ctx, probe_url(url, probe, value), follow_redirects=False)
            hit = _query_differential(baseline, injected, value)
            if hit is None:
                continue
            delta, probe_exchange = hit
            return self._candidate(
                ctx, url, param, probe, "operator", baseline, probe_exchange, delta
            )
        return None

    def _candidate(
        self,
        ctx: CheckContext,
        url: str,
        param: str,
        probe: str,
        kind: str,
        baseline: HttpExchange,
        injected: HttpExchange,
        delta: BodyDelta,
    ) -> CheckResult:
        return web_candidate(
            ctx,
            f"NoSQL injection differential in '{param}'",
            artifact={
                "signal": "nosql-injection",
                "family": "nosql",
                "endpoint": url,
                "parameter": param,
                "payload_class": kind,
                "probe": probe,
                "delta": delta.to_dict(),
                "nonce": nonce(),
            },
            exchanges=(baseline, injected),
            cwe="CWE-943",
            confidence=0.6,
            detail=(
                f"{url} parameter '{param}' answered the {kind} probe '{probe}' differently "
                "from the benign baseline"
            ),
            source=url,
        )


# ------------------------------------------------------------------- directory traversal
class DirectoryTraversal(WebCheck, Module):
    """``m3.directory-traversal`` — encoding matrix vs a file canary (ch03#12)."""

    metadata = CheckMetadata(
        id="m3.directory-traversal",
        module="M3",
        name="directory-traversal",
        version="1.0",
        title="Directory traversal oracle",
        description=(
            "Walks the traversal encoding matrix (plain, URL-encoded, dot-encoded, overlong "
            "separators, backslash, and the absolute file:// wrapper) against file-name "
            "parameters, and confirms the class by content: a world-readable, non-secret file's "
            "header line (root:x:0:0: / [extensions]) appears in the probe response where the "
            "benign baseline had none. Read-only: it reads one harmless system file."
        ),
        research_ref="ch03#12",
        framework=("WSTG-ATHZ-01", "CWE-22"),
        cwe="CWE-22",
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

        file_params = {
            name.lower() for name in payloads_for(ctx).strings("traversal", "file_params")
        }
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=file_params)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no file-name parameter to probe",
                detail="the crawl found no parameter whose name suggests a file path",
            )
            return

        findings = 0
        for url, param in targets:
            baseline = await safe_fetch(
                ctx, probe_url(url, param, "arachne-baseline.txt"), follow_redirects=False
            )
            if baseline is None:
                continue
            hit = await self._probe_matrix(ctx, url, param, baseline)
            if hit is None:
                continue
            findings += 1
            yield hit
        if not findings:
            yield ctx.clean(
                "no traversal canary observed",
                detail=f"probed {len(targets)} file-name parameter(s) across the encoding matrix",
            )

    async def _probe_matrix(
        self, ctx: CheckContext, url: str, param: str, baseline: HttpExchange
    ) -> CheckResult | None:
        for payload in _TRAVERSAL_PAYLOADS:
            injected = await safe_fetch(ctx, probe_url(url, param, payload), follow_redirects=False)
            if injected is None:
                continue
            canary = _first_canary(injected.body, baseline.body, _TRAVERSAL_CANARIES)
            if canary is None:
                continue
            delta = compare_pages(baseline, injected)
            return web_candidate(
                ctx,
                f"Directory traversal reads outside the web root (via '{param}')",
                artifact={
                    "signal": "directory-traversal",
                    "family": "directory-traversal",
                    "endpoint": url,
                    "parameter": param,
                    "payload": payload,
                    "canary": canary,
                    "delta": delta.to_dict(),
                    "nonce": nonce(),
                },
                exchanges=(baseline, injected),
                cwe="CWE-22",
                confidence=0.85,
                detail=(
                    f"{url} parameter '{param}' disclosed a world-readable system file "
                    "header line outside the web root"
                ),
                source=url,
            )
        return None


# --------------------------------------------------------------------------- file inclusion
class FileInclusion(WebCheck, Module):
    """``m3.file-inclusion`` — LFI/RFI canaries and an include side effect (ch03#13)."""

    metadata = CheckMetadata(
        id="m3.file-inclusion",
        module="M3",
        name="file-inclusion",
        version="1.0",
        title="File inclusion oracle",
        description=(
            "Confirms local file inclusion when a world-readable file's header line, or the "
            "base64 of a PHP opening tag from a php://filter read, appears in the probe "
            "response. The remote-file-inclusion probe only *references* an unresolvable "
            ".invalid host and is reported only on a clear in-response include side effect "
            "(a wrapper/allow_url_include diagnostic). The payload is never fetched and no "
            "remote code is executed."
        ),
        research_ref="ch03#13",
        framework=("WSTG-ATHZ-01", "CWE-98"),
        cwe="CWE-98",
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

        file_params = {
            name.lower() for name in payloads_for(ctx).strings("traversal", "file_params")
        }
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=file_params)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no file-name parameter to probe",
                detail="the crawl found no parameter whose name suggests a file path",
            )
            return

        findings = 0
        for url, param in targets:
            baseline = await safe_fetch(
                ctx, probe_url(url, param, "arachne-baseline.txt"), follow_redirects=False
            )
            if baseline is None:
                continue
            finding = await self._probe(ctx, url, param, baseline)
            if finding is None:
                continue
            findings += 1
            yield finding
        if not findings:
            yield ctx.clean(
                "no file inclusion observed",
                detail=f"sent LFI/RFI probes to {len(targets)} file-name parameter(s)",
            )

    async def _probe(
        self, ctx: CheckContext, url: str, param: str, baseline: HttpExchange
    ) -> CheckResult | None:
        for payload in _LFI_PAYLOADS:
            injected = await safe_fetch(ctx, probe_url(url, param, payload), follow_redirects=False)
            if injected is None:
                continue
            canary = _first_canary(injected.body, baseline.body, _LFI_CANARIES)
            if canary is None:
                continue
            return web_candidate(
                ctx,
                f"Local file inclusion disclosed a file via '{param}'",
                artifact={
                    "signal": "file-inclusion",
                    "family": "file-inclusion",
                    "technique": "lfi",
                    "endpoint": url,
                    "parameter": param,
                    "payload": payload,
                    "canary": canary,
                    "delta": compare_pages(baseline, injected).to_dict(),
                    "nonce": nonce(),
                },
                exchanges=(baseline, injected),
                cwe="CWE-98",
                confidence=0.85,
                detail=f"{url} parameter '{param}' disclosed a file outside the web root",
                source=url,
            )

        injected = await safe_fetch(
            ctx, probe_url(url, param, _RFI_PAYLOAD), follow_redirects=False
        )
        if injected is None:
            return None
        indicator = _rfi_indicator(injected.body)
        if indicator is None:
            return None
        return web_candidate(
            ctx,
            f"Remote file inclusion attempt recognised via '{param}'",
            artifact={
                "signal": "file-inclusion",
                "family": "file-inclusion",
                "technique": "rfi",
                "endpoint": url,
                "parameter": param,
                "include_host": _RFI_HOST,
                "indicator": indicator,
                "delta": compare_pages(baseline, injected).to_dict(),
                "nonce": nonce(),
            },
            exchanges=(baseline, injected),
            cwe="CWE-98",
            confidence=0.6,
            detail=(
                f"{url} parameter '{param}' reported an include side effect for the "
                f"unresolvable host {_RFI_HOST}"
            ),
            source=url,
        )


# ------------------------------------------------------------------- CRLF / header injection
class CrlfInjection(WebCheck, Module):
    """``m3.crlf-injection`` — CR/LF header-injection observation (ch03#15)."""

    metadata = CheckMetadata(
        id="m3.crlf-injection",
        module="M3",
        name="crlf-injection",
        version="1.0",
        title="CRLF / HTTP header injection oracle",
        description=(
            "Injects CR/LF-bearing header fragments into query parameters and flags only what "
            "the response *shows*: an echoed X-Injected header, an injected Set-Cookie name, or "
            "a Location carrying the injected host (header/response splitting). The check "
            "observes the split; it never attempts to exploit it or smuggle a second response."
        ),
        research_ref="ch03#15",
        framework=("WSTG-INPV-15", "CWE-113"),
        cwe="CWE-113",
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

        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(limit=ctx.config.web.max_params_per_check)
            if origin_of(url) == origin
        ]
        if not targets:
            yield ctx.clean(
                "no query parameter to probe",
                detail="the crawl found no parameter on this origin",
            )
            return

        findings = 0
        for url, param in targets:
            finding = await self._probe(ctx, url, param)
            if finding is None:
                continue
            findings += 1
            yield finding
        if not findings:
            yield ctx.clean(
                "no header injection observed",
                detail=f"sent CRLF probes to {len(targets)} parameter(s)",
            )

    async def _probe(self, ctx: CheckContext, url: str, param: str) -> CheckResult | None:
        baseline = await safe_fetch(ctx, probe_url(url, param, "1"), follow_redirects=False)
        if baseline is None:
            return None
        for technique, template in _CRLF_PAYLOADS:
            marker = f"ar9x{nonce()}"
            injected = await safe_fetch(
                ctx, probe_url(url, param, template.format(marker=marker)), follow_redirects=False
            )
            if injected is None:
                continue
            observed = _crlf_observed(injected, marker)
            if observed is None:
                continue
            return web_candidate(
                ctx,
                f"HTTP header injection in '{param}' ({technique})",
                artifact={
                    "signal": "crlf-injection",
                    "family": "crlf",
                    "endpoint": url,
                    "parameter": param,
                    "technique": observed,
                    "marker": marker,
                    "delta": compare_pages(baseline, injected).to_dict(),
                },
                exchanges=(baseline, injected),
                cwe="CWE-113",
                confidence=0.8,
                detail=f"{url} parameter '{param}' echoed an injected HTTP header ({observed})",
                source=url,
            )
        return None


# --------------------------------------------------------------------------- helpers
def _first_canary(
    body: str, baseline_body: str, canaries: tuple[re.Pattern[str], ...]
) -> str | None:
    """The first canary that appears in ``body`` but not in ``baseline_body`` (its text)."""
    for pattern in canaries:
        match = pattern.search(body)
        if match is not None and pattern.search(baseline_body) is None:
            return match.group(0)
    return None


def _query_differential(
    baseline: HttpExchange, injected: HttpExchange | None, probe: str
) -> tuple[BodyDelta, HttpExchange] | None:
    """A significant response differential that is *not* just the probe echoed back."""
    if injected is None:
        return None
    delta = compare_pages(baseline, injected)
    if not delta.significant(min_ratio_drop=0.05, min_length_delta=16):
        return None
    if _is_pure_reflection(baseline, injected, probe, delta):
        return None
    return delta, injected


def _is_pure_reflection(
    baseline: HttpExchange, injected: HttpExchange, probe: str, delta: BodyDelta
) -> bool:
    """True when the only change is ``probe`` being echoed verbatim (not a query effect)."""
    if delta.status_changed or not probe:
        return False
    return probe in injected.body and abs(delta.length_delta) <= len(probe) + 16


def _rfi_indicator(body: str) -> str | None:
    """A clear include side effect naming the RFI wrapper, in a body that mentions our host."""
    lowered = body.lower()
    if _RFI_HOST not in lowered:
        return None
    for indicator in _RFI_INDICATORS:
        if indicator.lower() in lowered:
            return indicator
    return None


def _crlf_observed(exchange: HttpExchange, marker: str) -> str | None:
    """Which injected header the response carries, if any (``None`` when none did)."""
    for name, value in exchange.response_headers.items():
        lowered = name.lower()
        if lowered == "x-injected" and marker in value:
            return "injected-header"
        if lowered == "set-cookie" and f"{marker}=" in value.lower():
            return "injected-cookie"
        if lowered == "location" and _CRLF_MARKER_HOST in value and marker in value:
            return "location-split"
    for cookie in exchange.cookies:
        if cookie.name == marker:
            return "injected-cookie"
    return None
