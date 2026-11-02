"""M3 proof-ladder checks (S15, area ``PROOF``): the L2/L3/L4 rows of the ladder.

These checks are the *capability carriers* of the proof ladder — each declares its level
in metadata (REQ-PROOF-001), each is opt-in by construction (an L2+ check can never be
enabled by default), and the L3/L4 rows additionally demand the state-change
attestation. The engine-side helpers they use live in :mod:`arachne.proof`; the checks
only decide *where* to inject and *what* the target's reaction means:

``m3.sqli-oob``
    L2 — time-free blind SQLi (ch03#1): the injected predicate carries the OOB token,
    and the hit that comes back proves the predicate executed without any blocking
    sleep and without reading a byte.
``m3.xxe-oob``
    L2 — OOB XXE (ch03#7): the external entity points at the callback token, so a
    resolved entity is proven by the callback hit, not by echoing a local file.
``m3.cmdi-oob``
    L2 — blind command injection (ch03#8): the payload is the *allowlisted* one-shot
    echo text; an execution monitor (the lab simulates one) phones the hit home.
``m3.ssti-oob``
    L2 — server-side template rendering (ch03#6): a template that references the
    callback token proves the engine evaluates and can reach out (the SSTI→SSRF
    primitive), with arithmetic-only template content otherwise.
``m3.rce-echo``
    L3 — the one-shot command proof (REQ-PROOF-007): exactly one
    ``echo arachne-<nonce>`` through the strongest hinted sink, attested.
``m3.state-marker``
    L4 — the INSERT-first marker-row proof (REQ-PROOF-008), attested: write, verify,
    auto-restore, re-verify, all through the shared SQL policy.

Every one of them composes with the existing gates: the scoped HTTP client (capture →
redact → audit, REQ-PROOF-012), the active-checks opt-in, the orchestrator's proof gate,
and — through ``ctx.proof`` — the capability boundary that refuses anything above the
declared level.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import AsyncIterator
from typing import Any

from arachne.core.proof import CallbackToken, ProofLevel, command_payload_for
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, origin_of, with_params
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    owns_origin,
    payloads_for,
    post_form,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = [
    "CmdiOobProbe",
    "RceEchoProof",
    "SqliOobProbe",
    "SstiOobProbe",
    "StateMarkerProof",
    "XxeOobProbe",
]


def _strongest_origin_target(
    ctx: CheckContext, inventory: WebInventory, hint_order: tuple[str, ...]
) -> tuple[str, str] | None:
    """The same-origin ``(url, parameter)`` with the *strongest* name hint (L3 one-shot).

    The one-shot is spent once, so the sink is chosen deliberately: a parameter whose name
    matches an early hint ("cmd", "ping", "host") beats a late one ("name", "url") — the
    late ones are usually plain reflections (an XSS sink), which would waste the single
    execution on a target that cannot execute anything.
    """
    origin = origin_of(ctx.asset.value)
    rank = {name.lower(): index for index, name in enumerate(hint_order)}
    candidates: list[tuple[int, int, str, str]] = []
    for crawl_order, (url, param) in enumerate(inventory.parameter_targets(names=set(hint_order))):
        if origin_of(url) != origin:
            continue
        candidates.append((rank.get(param.lower(), len(rank)), crawl_order, url, param))
    if not candidates:
        return None
    _rank, _order, url, param = min(candidates)
    return url, param


def _origin_targets(
    ctx: CheckContext, inventory: WebInventory, hints: frozenset[str] | set[str]
) -> list[tuple[str, str]]:
    origin = origin_of(ctx.asset.value)
    return [
        (url, param)
        for url, param in inventory.parameter_targets(names=hints)
        if origin_of(url) == origin
    ][: ctx.config.web.max_params_per_check]


def _oob_url(ctx: CheckContext) -> tuple[CallbackToken, str] | None:
    """``(token, url)`` for this check's callback, or ``None`` when downgraded.

    The downgrade path (REQ-PROOF-003): no callback service configured means the L2
    variant cannot prove a blind sink — it reports *why* as a skip, which is the
    recorded note at check level (the plan-level note is the planner's).
    """
    access = ctx.proof
    if access is None:
        return None
    try:
        issued = access.oob_token()
    except Exception:
        return None
    if issued.url is None:  # in-process service without a base URL: nothing to inject
        return None
    return issued.token, issued.url


def _oob_urls(ctx: CheckContext, count: int) -> list[tuple[CallbackToken, str]] | None:
    """One token per sink, so a hit names the exact parameter that reached it.

    ``None`` when the check is downgraded (no callback configured). Tokens are bounded
    by the sink budget (``max_params_per_check``) and the service's per-scan cap.
    """
    issued: list[tuple[CallbackToken, str]] = []
    for _index in range(max(1, count)):
        built = _oob_url(ctx)
        if built is None:
            return None
        issued.append(built)
    return issued


def _downgraded_skip(what: str) -> CheckResult:
    """A skip result that reads as the L2→L1 downgrade note (REQ-PROOF-003)."""
    return CheckResult(
        status="info",
        title="Out-of-band proof variant: not run",
        detail=(
            "downgraded to L1: no out-of-band callback is available "
            f"(ARACHNE_WEB_SSRF_CALLBACK); {what}"
        ),
        confidence=0.0,
        evidence=(
            Evidence.of(
                "note",
                {
                    "skipped": True,
                    "reason": (
                        "downgraded to L1: no out-of-band callback is available "
                        f"(ARACHNE_WEB_SSRF_CALLBACK); {what}"
                    ),
                    "check": "proof-ladder",
                },
            ),
        ),
    )


def _proof_evidence(ctx: CheckContext, payload: dict[str, Any], *, source: str) -> Evidence:
    """The ``proof`` evidence item (REQ-PROOF-012: same capture → redact → audit path)."""
    return ctx.evidence("proof", payload, source=source)


# --------------------------------------------------------------------------- L2: blind SQLi
class SqliOobProbe(WebCheck, Module):
    """``m3.sqli-oob`` — time-free blind SQLi, out-of-band confirmation (ch03#1)."""

    metadata = CheckMetadata(
        id="m3.sqli-oob",
        module="M3",
        name="sqli-oob",
        version="1.0",
        title="Blind SQL injection, out-of-band",
        description=(
            "Injects a predicate that carries this check's out-of-band callback token into "
            "parameters whose name suggests a SQL sink, and confirms the class when the "
            "back-end resolved the predicate and reached the token (research ch03#1's "
            "out-of-band oracle). No sleep, no data read or extracted: the single hit is "
            "the proof, and it is matched single-use to this finding. Opt-in (L2)."
        ),
        research_ref="ch03#1",
        framework=("WSTG-INPV-05", "CWE-89"),
        proof=ProofLevel.L2,
        cwe="CWE-89",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=4,
        enabled_by_default=False,
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
        template = payloads.string("sqli_oob", "probe_template", default="' OR 1=1-- {callback}")
        hints = {name.lower() for name in payloads.strings("sqli", "param_hints")} or {
            "q",
            "query",
            "search",
            "id",
            "category",
        }
        targets = _origin_targets(ctx, inventory, hints)
        if not targets:
            yield ctx.clean(
                "no SQL-like parameter to probe",
                detail="the crawl found no parameter whose name suggests a SQL sink",
            )
            return
        tokens = _oob_urls(ctx, len(targets))
        if tokens is None:
            yield _downgraded_skip("this variant cannot prove a blind sink without one")
            return
        probes: list[dict[str, Any]] = []
        for (url, param), (_token, callback_url) in zip(targets, tokens, strict=False):
            injected = await safe_fetch(
                ctx, with_params(url, {param: template.replace("{callback}", callback_url)})
            )
            probes.append(
                {
                    "endpoint": url,
                    "parameter": param,
                    "status": None if injected is None else injected.status_code,
                }
            )
        findings = 0
        for (url, param), (token, _url) in zip(targets, tokens, strict=False):
            hit = await ctx.proof.oob_consume(token)
            if hit is None:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Blind SQL injection: the predicate executed and reached the callback "
                f"through '{param}'",
                artifact={
                    "signal": "sqli-oob",
                    "family": "sqli",
                    "endpoint": url,
                    "parameter": param,
                    "callback_token": str(token),
                    "out_of_band": True,
                    "time_free": True,
                },
                extra_evidence=(
                    _proof_evidence(
                        ctx,
                        {
                            "level": "L2",
                            "method": "out-of-band callback (time-free blind SQLi)",
                            "callback_token": str(token),
                            "hit": hit.to_dict(),
                            "cleanup": "none required (no state was changed)",
                        },
                        source=url,
                    ),
                ),
                cwe="CWE-89",
                confidence=0.9,
                detail=(
                    f"{url} resolved the injected predicate and connected to the callback token"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no out-of-band resolution",
                detail="probed: " + ", ".join(f"{p['parameter']}={p['status']}" for p in probes),
            )


# --------------------------------------------------------------------------- L2: OOB XXE
class XxeOobProbe(WebCheck, Module):
    """``m3.xxe-oob`` — external entity resolution proven by the callback (ch03#7)."""

    metadata = CheckMetadata(
        id="m3.xxe-oob",
        module="M3",
        name="xxe-oob",
        version="1.0",
        title="XML external entity, out-of-band",
        description=(
            "Posts a minimal XML document whose single external entity is this check's "
            "callback token, and confirms the class when the parser resolved the entity "
            "(research ch03#7's out-of-band variant). The entity points at ARACHNE's own "
            "callback service — never at a file, a credential, or a third party. Opt-in (L2)."
        ),
        research_ref="ch03#7",
        framework=("WSTG-INPV-07", "CWE-611"),
        proof=ProofLevel.L2,
        cwe="CWE-611",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        enabled_by_default=False,
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
        template = payloads.string(
            "xxe_oob",
            "document_template",
            default=(
                '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "{callback}">]><r>&xxe;</r>'
            ),
        )
        content_types = payloads.strings("xxe", "content_types") or ("application/xml",)
        origin = origin_of(ctx.asset.value)
        hints = set(payloads.strings("xxe", "param_hints")) or {"xml", "parse", "import"}
        urls: list[str] = []
        for page in inventory.pages.values():
            if origin_of(page.url) == origin:
                urls.append(page.url)
        urls.extend(
            url
            for url, _param in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        )
        # Prefer endpoints whose URL suggests XML (a parser is a deliberate surface), then
        # the rest of the origin's pages; the budget still bounds the probe count.
        preferred = [url for url in urls if any(hint in url.lower() for hint in hints)]
        targets = list(dict.fromkeys([*preferred, *urls]))[: ctx.config.web.max_params_per_check]
        if not targets:
            yield skip(ctx, "the crawl found no endpoint that plausibly accepts XML")
            return
        tokens = _oob_urls(ctx, len(targets))
        if tokens is None:
            yield _downgraded_skip("this variant cannot prove a blind parser")
            return
        probes: list[dict[str, Any]] = []
        for url, (_token, callback_url) in zip(targets, tokens, strict=False):
            document = template.replace("{callback}", callback_url)
            for content_type in content_types[:1]:
                exchange = await safe_fetch(
                    ctx,
                    url,
                    method="POST",
                    headers={"Content-Type": content_type},
                    content=document,
                    follow_redirects=False,
                )
                probes.append(
                    {"endpoint": url, "status": None if exchange is None else exchange.status_code}
                )
        findings = 0
        for url, (token, _callback_url) in zip(targets, tokens, strict=False):
            hit = await ctx.proof.oob_consume(token)
            if hit is None:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"XML external entity resolved: the parser fetched the callback token at {url}",
                artifact={
                    "signal": "xxe-oob",
                    "family": "xxe",
                    "endpoint": url,
                    "callback_token": str(token),
                    "out_of_band": True,
                },
                extra_evidence=(
                    _proof_evidence(
                        ctx,
                        {
                            "level": "L2",
                            "method": "out-of-band callback (external entity resolution)",
                            "callback_token": str(token),
                            "hit": hit.to_dict(),
                            "cleanup": "none required (no state was changed)",
                        },
                        source=url,
                    ),
                ),
                cwe="CWE-611",
                confidence=0.9,
                detail=f"{url} resolved the external entity and connected to the callback token",
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no external entity resolved out-of-band",
                detail="posted the entity document to: "
                + ", ".join(f"{p['endpoint']}={p['status']}" for p in probes),
            )


# --------------------------------------------------------------------------- L2: blind cmdi
class CmdiOobProbe(WebCheck, Module):
    """``m3.cmdi-oob`` — blind command injection, confirmed by an execution monitor."""

    metadata = CheckMetadata(
        id="m3.cmdi-oob",
        module="M3",
        name="cmdi-oob",
        version="1.0",
        title="Blind OS command injection, out-of-band",
        description=(
            "Injects shell separators plus the allowlisted one-shot echo text "
            "('echo arachne-<nonce>') into parameters whose name suggests a command sink, "
            "and confirms the class when an execution monitor reports the echo to this "
            "check's callback token (research ch03#8's blind variant). The payload is the "
            "ladder's single allowlisted command; nothing else is ever sent. Opt-in (L2)."
        ),
        research_ref="ch03#8",
        framework=("WSTG-INPV-12", "CWE-78"),
        proof=ProofLevel.L2,
        cwe="CWE-78",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        enabled_by_default=False,
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
        separators = payloads.strings("cmdi", "separators") or (";", "|", "&&")
        targets = _origin_targets(ctx, inventory, hints)
        if not targets:
            yield ctx.clean(
                "no command-like parameter to probe",
                detail="the crawl found no parameter whose name suggests a command or lookup",
            )
            return
        tokens = _oob_urls(ctx, len(targets))
        if tokens is None:
            yield _downgraded_skip("a blind command sink needs the monitor's hit")
            return
        probes: list[dict[str, Any]] = []
        for (url, param), (token, _callback_url) in zip(targets, tokens, strict=False):
            payload = command_payload_for(str(token))
            for separator in separators[:2]:
                injected = await safe_fetch(
                    ctx,
                    probe_url(url, param, f"127.0.0.1{separator}{payload}"),
                    follow_redirects=False,
                )
                probes.append(
                    {
                        "endpoint": url,
                        "parameter": param,
                        "status": None if injected is None else injected.status_code,
                    }
                )
        findings = 0
        for (url, param), (token, _callback_url) in zip(targets, tokens, strict=False):
            hit = await ctx.proof.oob_consume(token)
            if hit is None:
                continue
            findings += 1
            payload = command_payload_for(str(token))
            yield web_candidate(
                ctx,
                f"Blind command injection: the allowlisted echo executed and the monitor "
                f"reported it through '{param}'",
                artifact={
                    "signal": "cmdi-oob",
                    "family": "cmdi",
                    "endpoint": url,
                    "parameter": param,
                    "callback_token": str(token),
                    "out_of_band": True,
                },
                extra_evidence=(
                    _proof_evidence(
                        ctx,
                        {
                            "level": "L2",
                            "method": "out-of-band execution monitor (allowlisted echo)",
                            "callback_token": str(token),
                            "payload": payload,
                            "hit": hit.to_dict(),
                            "cleanup": "none required (no state was changed)",
                        },
                        source=url,
                    ),
                ),
                cwe="CWE-78",
                confidence=0.85,
                detail=f"{url} executed the echo sentinel; the monitor matched the callback token",
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no execution reported out-of-band",
                detail="probed: " + ", ".join(f"{p['parameter']}={p['status']}" for p in probes),
            )


# --------------------------------------------------------------------------- L2: SSTI
class SstiOobProbe(WebCheck, Module):
    """``m3.ssti-oob`` — template evaluation with a server-side reach-out (ch03#6)."""

    metadata = CheckMetadata(
        id="m3.ssti-oob",
        module="M3",
        name="ssti-oob",
        version="1.0",
        title="Server-side template injection, out-of-band",
        description=(
            "Injects an arithmetic-only template that also references this check's callback "
            "token into parameters on rendering endpoints, and confirms the class when the "
            "template engine evaluated the content and reached the token (the SSTI→SSRF "
            "primitive, research ch03#6). The template payload is inert arithmetic plus the "
            "token reference — no built-ins, no attribute chains. Opt-in (L2)."
        ),
        research_ref="ch03#6",
        framework=("WSTG-INPV-08", "WSTG-INPV-18", "CWE-1336"),
        proof=ProofLevel.L2,
        cwe="CWE-1336",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=4,
        enabled_by_default=False,
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
        template = payloads.string("ssti_oob", "probe_template", default="{{7*7}}[{callback}]")
        hints = {name.lower() for name in payloads.strings("ssti", "param_hints")} or {
            "template",
            "tpl",
            "render",
            "view",
            "name",
            "message",
        }
        targets = _origin_targets(ctx, inventory, hints)
        if not targets:
            yield ctx.clean(
                "no template-like parameter to probe",
                detail="the crawl found no parameter whose name suggests a rendering sink",
            )
            return
        tokens = _oob_urls(ctx, len(targets))
        if tokens is None:
            yield _downgraded_skip("this variant cannot prove a blind renderer")
            return
        probes: list[dict[str, Any]] = []
        for (url, param), (_token, callback_url) in zip(targets, tokens, strict=False):
            injected = await safe_fetch(
                ctx, with_params(url, {param: template.replace("{callback}", callback_url)})
            )
            probes.append(
                {
                    "endpoint": url,
                    "parameter": param,
                    "status": None if injected is None else injected.status_code,
                }
            )
        findings = 0
        for (url, param), (token, _callback_url) in zip(targets, tokens, strict=False):
            hit = await ctx.proof.oob_consume(token)
            if hit is None:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Server-side template injection: the engine evaluated the template and "
                f"reached the callback through '{param}'",
                artifact={
                    "signal": "ssti-oob",
                    "family": "ssti",
                    "endpoint": url,
                    "parameter": param,
                    "callback_token": str(token),
                    "out_of_band": True,
                },
                extra_evidence=(
                    _proof_evidence(
                        ctx,
                        {
                            "level": "L2",
                            "method": "out-of-band callback (template evaluation)",
                            "callback_token": str(token),
                            "hit": hit.to_dict(),
                            "cleanup": "none required (no state was changed)",
                        },
                        source=url,
                    ),
                ),
                cwe="CWE-1336",
                confidence=0.9,
                detail=f"{url} evaluated the template and connected to the callback token",
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no template evaluation out-of-band",
                detail="probed: " + ", ".join(f"{p['parameter']}={p['status']}" for p in probes),
            )


# --------------------------------------------------------------------------- L3: one-shot
class RceEchoProof(WebCheck, Module):
    """``m3.rce-echo`` — the L3 one-shot allowlisted command proof (REQ-PROOF-007)."""

    metadata = CheckMetadata(
        id="m3.rce-echo",
        module="M3",
        name="rce-echo",
        version="1.0",
        title="One-shot command execution proof",
        description=(
            "Executes exactly one benign, allowlisted command — 'echo arachne-<nonce>' — "
            "through the strongest command sink the crawl identified, and reports the echoed "
            "nonce as proof of execution (REQ-PROOF-007). There is no parameter that could "
            "carry a different command; the output is captured redacted and the execution is "
            "audited. Requires the RCE probe switch, the active-checks opt-in AND an "
            "attestation that authorizes state changes (L3)."
        ),
        research_ref="ch03#8",
        framework=("WSTG-INPV-12", "CWE-78"),
        proof=ProofLevel.L3,
        cwe="CWE-78",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=3,
        enabled_by_default=False,
        requires_active_checks=True,
        requires_state_attestation=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not ctx.config.web.rce_probe:
            yield skip(
                ctx,
                "the one-shot command proof is disabled (set ARACHNE_WEB_RCE_PROBE=true, "
                "select m3.rce-echo and authorize state changes in the attestation)",
            )
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
        if access is None:
            yield skip(ctx, "proof support is not wired for this step")
            return
        payloads = payloads_for(ctx)
        hint_order = tuple(payloads.strings("cmdi", "param_hints")) or ("cmd", "ping", "host")
        target = _strongest_origin_target(ctx, inventory, hint_order)
        if target is None:
            yield ctx.clean(
                "no command sink for the one-shot proof",
                detail="the crawl found no parameter whose name suggests a command sink",
            )
            return
        url, param = target
        separators = payloads.strings("cmdi", "separators") or (";",)
        proof = access.command_proof()
        separator = separators[0]
        baseline = await safe_fetch(ctx, url, follow_redirects=False)
        if baseline is None:
            yield skip(ctx, f"the sink {url} was unreachable; nothing was executed")
            return

        async def sink(value: str) -> Any:
            return await safe_fetch(ctx, probe_url(url, param, f"127.0.0.1{separator}{value}"))

        try:
            result = await proof.prove(sink)
        except Exception as exc:
            yield ctx.error(exc)
            return
        if not result.reflected:
            yield ctx.clean(
                "one-shot echo not reflected",
                detail=f"executed '{result.payload}' through '{param}' at {url}; "
                "the nonce did not come back",
            )
            return
        yield web_candidate(
            ctx,
            f"Command execution proven with one allowlisted echo through '{param}'",
            artifact={
                "signal": "rce-echo",
                "family": "cmdi",
                "endpoint": url,
                "parameter": param,
                "nonce": result.nonce,
                "payload": result.payload,
                "one_shot": True,
            },
            extra_evidence=(_proof_evidence(ctx, proof.evidence_payload(result), source=url),),
            cwe="CWE-78",
            confidence=0.95,
            detail=f"{url} executed the single allowlisted echo and returned its nonce",
            source=url,
        )


# --------------------------------------------------------------------------- L4: state marker
class StateMarkerProof(WebCheck, Module):
    """``m3.state-marker`` — the L4 INSERT-first, auto-restored marker proof (REQ-PROOF-008)."""

    metadata = CheckMetadata(
        id="m3.state-marker",
        module="M3",
        name="state-marker",
        version="1.0",
        title="State-change proof (marker row)",
        description=(
            "Proves write access with the ladder's minimal footprint: an INSERT of one "
            "calm marker row into arachne_poc (or the obviously-fake record the deployment "
            "names), verification that it is visible, an automatic restore, and "
            "re-verification that it is gone (REQ-PROOF-008). DELETE/DROP/TRUNCATE/ALTER/"
            "GRANT and multi-statement payloads are refused in code; identity stores are "
            "refused outright. Requires the state probe switch, the active-checks opt-in "
            "AND an attestation that authorizes state changes (L4)."
        ),
        research_ref="ch03#1",
        framework=("WSTG-INPV-05", "CWE-89"),
        proof=ProofLevel.L4,
        cwe="CWE-89",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        enabled_by_default=False,
        requires_active_checks=True,
        requires_state_attestation=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not ctx.config.web.state_probe:
            yield skip(
                ctx,
                "the state-change proof is disabled (set ARACHNE_WEB_STATE_PROBE=true, "
                "select m3.state-marker and authorize state changes in the attestation)",
            )
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        access = ctx.proof
        if access is None:
            yield skip(ctx, "proof support is not wired for this step")
            return
        payloads = payloads_for(ctx)
        sink_path = payloads.string("state", "sink_path", default="/poc-sql")
        origin = origin_of(ctx.asset.value)
        sink_url = origin.rstrip("/") + sink_path
        # Preflight: the proof sink must be this origin's real SQL surface. A 404 (some
        # other origin — e.g. the scan's own callback host) means nothing here can execute
        # statements, and the L4 helper must never be handed a dead executor.
        preflight = await safe_fetch(ctx, sink_url, follow_redirects=False)
        if preflight is None or preflight.status_code >= 400:
            yield skip(
                ctx,
                f"no SQL proof sink at {sink_path} on this origin (HTTP "
                + (str(preflight.status_code) if preflight is not None else "error")
                + "); nothing was written",
            )
            return
        executor = _WebSqlExecutor(ctx, sink_url)
        try:
            helper = access.sql(executor)
        except Exception as exc:
            yield ctx.error(exc)
            return
        nonce_value = secrets.token_hex(12)
        try:
            record = await helper.insert_marker(nonce=nonce_value)
        except Exception as exc:
            yield ctx.error(exc)
            return
        restored = record.restored and record.restore_verified
        yield ctx.candidate(
            "State-change access proven (marker row inserted and restored)",
            detail=(
                f"INSERT-first marker row in {record.table} at {sink_url}: written, "
                f"verified, restored={'yes' if restored else 'NO'}, "
                f"re-verified={'yes' if record.restore_verified else 'no'}"
            ),
            cwe="CWE-89",
            confidence=0.95 if restored else 0.7,
            evidence=(
                _proof_evidence(
                    ctx,
                    {
                        "level": "L4",
                        "method": "INSERT-first marker row (auto-restored)",
                        "change": record.to_dict(),
                        "cleanup": "restored inline and re-verified"
                        if restored
                        else "NOT restored — see the report's state-changes table",
                    },
                    source=sink_url,
                ),
            ),
        )


class _WebSqlExecutor:
    """Runs one statement at a time through the deployment's SQL proof sink.

    The sink (``POST <sink>`` with ``sql`` and a JSON ``params`` list) is the L4
    deployment's own surface — in the lab it is the fixture's ``/poc-sql`` route, which
    executes the statement on the lab's SQLite database. The request goes through the
    scan's scoped client, so capture → redact → audit applies (REQ-PROOF-012).
    """

    def __init__(self, ctx: CheckContext, sink_url: str) -> None:
        self._ctx = ctx
        self._sink = sink_url

    async def execute(self, sql: str, params: Any = ()) -> str:
        exchange = await post_form(
            self._ctx,
            self._sink,
            {"sql": sql, "params": json.dumps(list(params))},
        )
        if exchange is None:
            return ""
        return exchange.body
