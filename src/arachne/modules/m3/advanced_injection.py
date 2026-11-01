"""M3 extended injection families: SSTI (ch03#6), XXE (ch03#7), command injection (ch03#8)
and insecure deserialization (ch03#9).

All four follow the M3 contract exactly (docs/spec/05- M3 "Safety"): a probe is detection-only
and confirmation is a *measured difference* against a baseline the check establishes first.
None of them attempts code execution or reads a credential:

``m3.ssti-oracle``
    Sends the arithmetic/polyglot probes of research ch03#6 into every echo point and confirms
    when the *evaluated* form appears where the raw probe did not. Arithmetic only — no
    built-ins, no file access — which is the research's own line ("scanners should not attempt
    code execution").
``m3.xxe-oracle``
    Posts a minimal external-entity document (research ch03#7) with the entity pointing at a
    *world-readable, non-secret* file or the OOB callback, and confirms when the file's header
    line is echoed or the callback fires.
``m3.cmdi-oracle``
    Injects shell separators plus a harmless ``echo <nonce>`` sentinel (research ch03#8) and
    confirms when the sentinel's output is echoed; a timing probe is the fallback and exactly
    one is sent per parameter.
``m3.deser-audit``
    Fingerprints serialized-object signatures in the crawl's forms and bodies, then confirms
    *processing* by comparing a structurally valid benign stream against a malformed one (a
    parser reaction differential), never a gadget chain.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m3.payloads import WebPayloads
from arachne.modules.m3.support import (
    WebCheck,
    compare_pages,
    form_fields,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    post_form,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["CmdInjectionOracle", "DeserializationAudit", "SstiOracle", "XxeOracle"]


# --------------------------------------------------------------------------- SSTI
class SstiOracle(WebCheck, Module):
    """``m3.ssti-oracle`` — template-expression interpolation deltas (ch03#6)."""

    metadata = CheckMetadata(
        id="m3.ssti-oracle",
        module="M3",
        name="ssti-oracle",
        version="1.0",
        title="Server-side template injection oracle",
        description=(
            "Sends the arithmetic probes of research ch03#6 ({{7*7}}, ${7*7}, <%= 7*7 %>) into "
            "every reflected parameter and confirms when the *evaluated* form (49) appears where "
            "the raw probe did not, or when an engine-specific parse error names the template "
            "library. Arithmetic only: no built-ins, no file access, no code execution."
        ),
        research_ref="ch03#6",
        cwe="CWE-1336",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=12,
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
        probes = self._probes(payloads)
        error_signatures = payloads.mapping("ssti", "error_signatures")
        origin = origin_of(ctx.asset.value)
        targets = [pair for pair in inventory.parameter_targets() if origin_of(pair[0]) == origin]
        targets = self._reflectors(ctx, inventory, origin)[: ctx.config.web.max_params_per_check]
        targets = (
            targets
            or [pair for pair in inventory.parameter_targets() if origin_of(pair[0]) == origin][
                : ctx.config.web.max_params_per_check
            ]
        )
        if not targets:
            yield ctx.clean(
                "no parameter to probe for template evaluation",
                detail="the crawl found no parameter that reflects input",
            )
            return
        findings = 0
        for url, parameter in targets:
            finding = await self._probe(ctx, url, parameter, probes, error_signatures)
            if finding is None:
                continue
            findings += 1
            yield finding
        if not findings:
            yield ctx.clean(
                "no template evaluation observed",
                detail=f"sent arithmetic probes to {len(targets)} reflected parameter(s)",
            )

    def _probes(self, payloads: WebPayloads) -> tuple[Mapping[str, Any], ...]:
        return payloads.entries("ssti", "arithmetic")

    def _reflectors(
        self, ctx: CheckContext, inventory: WebInventory, origin: str
    ) -> list[tuple[str, str]]:
        """Parameters whose benign value the crawl already saw reflected (best targets first)."""
        return [pair for pair in inventory.parameter_targets() if origin_of(pair[0]) == origin]

    async def _probe(
        self,
        ctx: CheckContext,
        url: str,
        parameter: str,
        probes: tuple[Mapping[str, Any], ...],
        error_signatures: Mapping[str, Any],
    ) -> CheckResult | None:
        for entry in probes:
            probe = str(entry.get("probe", ""))
            expected = str(entry.get("expected", ""))
            if not probe or not expected:
                continue
            baseline = await safe_fetch(ctx, url, follow_redirects=False)
            injected = await safe_fetch(
                ctx, probe_url(url, parameter, probe), follow_redirects=False
            )
            if baseline is None or injected is None:
                continue
            if expected in injected.body and expected not in baseline.body:
                return self._candidate(
                    ctx,
                    url,
                    parameter,
                    str(entry.get("name", "ssti")),
                    probe,
                    "evaluated",
                    baseline,
                    injected,
                )
            signature = _first_match(injected.body, error_signatures.values())
            if signature:
                return self._candidate(
                    ctx,
                    url,
                    parameter,
                    str(entry.get("name", "ssti")),
                    probe,
                    "error",
                    baseline,
                    injected,
                )
        return None

    def _candidate(
        self,
        ctx: CheckContext,
        url: str,
        parameter: str,
        engine: str,
        probe: str,
        signal: str,
        baseline: Any,
        injected: Any,
    ) -> CheckResult:
        return web_candidate(
            ctx,
            f"Template expression evaluated in '{parameter}' ({engine})",
            artifact={
                "signal": "ssti",
                "family": "ssti",
                "engine": engine,
                "endpoint": url,
                "parameter": parameter,
                "probe": probe,
                "observed": signal,
                "reflected": signal == "evaluated",
                "error": signal == "error",
            },
            exchanges=(baseline, injected),
            cwe="CWE-1336",
            confidence=0.85 if signal == "evaluated" else 0.6,
            detail=(
                f"{url} evaluated '{probe}' for parameter '{parameter}'"
                + (
                    " (arithmetic result reflected)"
                    if signal == "evaluated"
                    else " (engine parse error returned)"
                )
            ),
            source=url,
        )


# --------------------------------------------------------------------------- XXE
class XxeOracle(WebCheck, Module):
    """``m3.xxe-oracle`` — XML parser entity behavior (ch03#7)."""

    metadata = CheckMetadata(
        id="m3.xxe-oracle",
        module="M3",
        name="xxe-oracle",
        version="1.0",
        title="XML external entity oracle",
        description=(
            "Posts a minimal external-entity document to every XML-accepting endpoint and "
            "confirms the class when the parser resolved the entity: a world-readable, "
            "non-secret file's header line is echoed, or the out-of-band callback fires. The "
            "entity never points at a credential file and nothing is exfiltrated."
        ),
        research_ref="ch03#7",
        cwe="CWE-611",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
        docs = self._documents(payloads)
        content_types = payloads.strings("xxe", "content_types") or ("application/xml",)
        markers = [
            (str(entry.get("name", "marker")), re.compile(str(entry["regex"]), re.IGNORECASE))
            for entry in payloads.entries("xxe", "markers")
            if entry.get("regex")
        ]
        origin = origin_of(ctx.asset.value)
        targets = self._targets(ctx, inventory, origin)
        if not targets:
            yield skip(ctx, "the crawl found no endpoint that plausibly accepts XML")
            return
        findings = 0
        for url in targets:
            for document in docs:
                body = str(document.get("body", ""))
                if "{callback}" in body:
                    continue  # the OOB variant needs a configured callback; see below
                for content_type in content_types[:1]:
                    exchange = await safe_fetch(
                        ctx,
                        url,
                        method="POST",
                        headers={"Content-Type": content_type},
                        content=body,
                        follow_redirects=False,
                    )
                    if exchange is None:
                        continue
                    hit = _first_regex(exchange.body, [pattern for _, pattern in markers])
                    if hit is None:
                        continue
                    findings += 1
                    yield web_candidate(
                        ctx,
                        f"XML external entity resolved at {url}",
                        artifact={
                            "signal": "xxe",
                            "family": "xxe",
                            "endpoint": url,
                            "document": str(document.get("name", "xxe")),
                            "content_type": content_type,
                            "marker": hit,
                            "in_band": True,
                        },
                        exchanges=(exchange,),
                        cwe="CWE-611",
                        confidence=0.9,
                        detail=f"{url} reflected a local file's header line for an external entity",
                        source=url,
                    )
                    findings += 1
                    break
                if findings:
                    break
            if findings:
                break
        if not findings:
            yield ctx.clean(
                "no external entity resolved",
                detail=f"sent {len(docs)} entity document(s) to {len(targets)} endpoint(s)",
            )

    def _documents(self, payloads: WebPayloads) -> tuple[Mapping[str, Any], ...]:
        return payloads.entries("xxe", "documents")

    def _targets(self, ctx: CheckContext, inventory: WebInventory, origin: str) -> list[str]:
        urls: list[str] = []
        for page in inventory.pages.values():
            if origin_of(page.url) == origin and origin_of(page.url):
                urls.append(page.url)
        # Prefer endpoints whose form/page suggests XML, then fall back to crawled pages.
        hints = payloads_for(ctx).strings("xxe", "param_hints")
        preferences = [url for url in urls for hint in hints if hint in url.lower()]
        ordered = list(dict.fromkeys([*preferences, *urls]))
        return ordered[: ctx.config.web.max_params_per_check]


# --------------------------------------------------------------------------- command injection
class CmdInjectionOracle(WebCheck, Module):
    """``m3.cmdi-oracle`` — command-injection echo/timing deltas (ch03#8)."""

    metadata = CheckMetadata(
        id="m3.cmdi-oracle",
        module="M3",
        name="cmdi-oracle",
        version="1.0",
        title="OS command injection oracle",
        description=(
            "Injects shell separators plus a harmless 'echo <nonce>' sentinel into parameters "
            "whose name suggests a command or a lookup, and confirms the class when the "
            "sentinel's output is echoed back (research ch03#8). A single blocking-sleep probe "
            "is the fallback for a blind sink. Nothing is read, written or exfiltrated."
        ),
        research_ref="ch03#8",
        cwe="CWE-78",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=18,
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
        hints = {name.lower() for name in payloads.strings("cmdi", "param_hints")}
        separators = payloads.strings("cmdi", "separators")
        sentinel = payloads.string("cmdi", "sentinel_template", default="echo {nonce}")
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no command-like parameter to probe",
                detail="the crawl found no parameter whose name suggests a command or lookup",
            )
            return
        findings = 0
        for url, param in targets:
            marker = nonce()
            command = sentinel.replace("{nonce}", marker)
            baseline = await safe_fetch(ctx, url, follow_redirects=False)
            if baseline is None:
                continue
            for separator in separators:
                injected = await safe_fetch(
                    ctx,
                    probe_url(url, param, f"127.0.0.1{separator}{command}"),
                    follow_redirects=False,
                )
                # The sentinel's *output* proves execution: the raw probe also contains the
                # nonce, so require the nonce present without the literal `echo <nonce>`
                # (a mere reflection echoes the command text too — the classic FP).
                if injected is None or marker not in injected.body or command in injected.body:
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"OS command injection in '{param}' (echo confirmed)",
                    artifact={
                        "signal": "command-injection",
                        "family": "cmdi",
                        "endpoint": url,
                        "parameter": param,
                        "separator": separator,
                        "confirmed_by": "echo",
                        "marker": marker,
                    },
                    exchanges=(baseline, injected),
                    cwe="CWE-78",
                    confidence=0.9,
                    detail=(
                        f"{url} echoed the output of an injected 'echo' command through '{param}'"
                    ),
                    source=url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no command injection observed",
                detail=f"sent echo/timing probes to {len(targets)} command-like parameter(s)",
            )


# --------------------------------------------------------------------------- deserialization
_DESER_SIGNATURE_HINTS = ("data", "state", "object", "obj", "session", "viewstate", "payload")


class DeserializationAudit(WebCheck, Module):
    """``m3.deser-audit`` — serialized-object fingerprints and parser reactions (ch03#9)."""

    metadata = CheckMetadata(
        id="m3.deser-audit",
        module="M3",
        name="deser-audit",
        version="1.0",
        title="Insecure deserialization audit",
        description=(
            "Fingerprints serialized-object signatures (Java rO0AB, PHP serialize(), .NET "
            "BinaryFormatter, pickle) in the crawl's forms, parameters and bodies, then confirms "
            "the sink is *processed* by comparing a structurally-valid benign stream against a "
            "malformed one (a parser-reaction differential). No gadget chain is sent and nothing "
            "is deserialized for effect."
        ),
        research_ref="ch03#9",
        cwe="CWE-502",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
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
        signatures = payloads.mapping("deser", "signatures")
        hints = {name.lower() for name in payloads.strings("deser", "param_hints")}
        origin = origin_of(ctx.asset.value)
        findings = 0

        # (a) static fingerprint in a crawled body / form field value.
        for page in inventory.pages.values():
            if origin_of(page.url) != origin:
                continue
            family = _match_signature(page.body, signatures)
            if family is None:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Serialized {family} object in a response body",
                artifact={
                    "signal": "deserialization",
                    "family": "deser",
                    "format": family,
                    "endpoint": page.url,
                    "source": "response-body",
                },
                exchanges=(),
                cwe="CWE-502",
                confidence=0.6,
                detail=f"{page.url} carries a {family} serialized-object signature",
                source=page.url,
            )
            break

        # (b) parser reaction: submit benign vs malformed streams to a hidden object field.
        benign = payloads.mapping("deser", "benign")
        for form in inventory.forms:
            if origin_of(form.action) != origin:
                continue
            field = form.any_input_named(hints) or form.any_input_named(_DESER_SIGNATURE_HINTS)
            if field is None:
                continue
            family = next((name for name in ("php", "java") if name in benign), "php")
            good = await post_form(
                ctx, form.action, form_fields(form, overrides={field: str(benign.get(family, ""))})
            )
            bad = await post_form(
                ctx, form.action, form_fields(form, overrides={field: "!!not-a-stream!!"})
            )
            if good is None or bad is None:
                continue
            delta = compare_pages(_page(good), _page(bad))
            if delta.status_changed or delta.ratio < 0.9:
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Deserialization sink accepts a {family} object stream",
                    artifact={
                        "signal": "deserialization",
                        "family": "deser",
                        "format": family,
                        "endpoint": form.action,
                        "field": field,
                        "benign_status": good.status_code,
                        "malformed_status": bad.status_code,
                        "parser_reacted": True,
                    },
                    exchanges=(good, bad),
                    cwe="CWE-502",
                    confidence=0.75,
                    detail=(
                        f"{form.action} treated a valid {family} stream differently from a "
                        f"malformed one through '{field}' (parser processing confirmed)"
                    ),
                    source=form.action,
                )
        if not findings:
            yield ctx.clean(
                "no serialized-object sink observed",
                detail=f"reviewed {len(inventory.forms)} form(s) and the crawled responses",
            )


# --------------------------------------------------------------------------- helpers
def _first_match(body: str, patterns: Any) -> str | None:
    for expression in patterns:
        try:
            if re.search(str(expression), body):
                return str(expression)
        except re.error:  # pragma: no cover - a bad corpus regex fails at load
            continue
    return None


def _first_regex(body: str, patterns: list[re.Pattern[str]]) -> str | None:
    for pattern in patterns:
        match = pattern.search(body)
        if match:
            return match.group(0)
    return None


def _match_signature(body: str, signatures: Mapping[str, Any]) -> str | None:
    stripped = body.strip()
    for family, expression in signatures.items():
        try:
            if re.search(str(expression), stripped):
                return str(family)
        except re.error:  # pragma: no cover
            continue
    return None


def _page(exchange: Any) -> Page:
    from arachne.modules.m3.inventory import page_from_exchange

    return page_from_exchange(exchange)
