"""Client-side reflection oracle (research ch03#3, CWE-79).

Research ch03#3's *first* half is the reflection classifier: put a marker into every echoed
input and record where and how it comes back. That is exactly what this check does, with a
deliberately inert probe and no browser:

* the probe is ``<a{nonce}>"'<nonce>`` — an **unknown** element (it renders as nothing and
  executes nothing) plus the two quote characters. There is no ``script`` tag, no event
  handler, no ``javascript:`` URL and no encoded payload: even if it lands unencoded in a page,
  it cannot run;
* a hit is the *raw* marker coming back, which proves the application did not encode the
  angle bracket or the quote. The context is classified from which marker survived
  (``html`` when ``<a…>`` came back intact, ``attribute`` when only the quotes did,
  ``script`` when the bare nonce landed inside a script block);
* an encoded reflection (``&lt;a…&gt;``) is **not** a finding — that is the application doing
  the right thing, and treating it as one is the classic reflected-XSS false positive.

The second half of research ch03#3 (DOM-sink reachability in a headless browser) is *not*
implemented here: it needs a JavaScript engine, which this stage does not ship. The check
therefore reports server-side reflection only, and ADR-100.4 records the gap rather than
pretending a string match in a static body proves a DOM XSS.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import origin_of, page_from_exchange
from arachne.modules.m3.support import (
    WebCheck,
    classify_reflection,
    compare_pages,
    exchange_from_page,
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

__all__ = ["XssOracle"]

#: Confidence by reflection context: an unencoded ``<`` in the HTML body is a direct markup
#: injection; a quote breakout is one step removed; a bare nonce inside a script block is the
#: weakest read (it may be a value that was never meant to be a string boundary).
_CONTEXT_CONFIDENCE = {"html": 0.8, "attribute": 0.6, "script": 0.5}


class XssOracle(WebCheck, Module):
    """``m3.xss-oracle`` — reflected-input context classification (ch03#3)."""

    metadata = CheckMetadata(
        id="m3.xss-oracle",
        module="M3",
        name="xss-oracle",
        version="1.0",
        title="Cross-site scripting reflection oracle",
        description=(
            "Sends one inert marker (an unknown element plus quote characters, unique per "
            "request) into every query-string parameter and classifies how the response "
            "reflects it: unencoded HTML, an unencoded quote inside an attribute, or a bare "
            "value inside a script block. An encoded reflection is reported as clean. The probe "
            "cannot execute in any browser, and DOM-sink verification is out of scope for this "
            "stage."
        ),
        research_ref="ch03#3",
        framework=("WSTG-INPV-01", "WSTG-CLNT-03", "CWE-79"),
        cwe="CWE-79",
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
        assert inventory is not None

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

        payloads = payloads_for(ctx)
        template = payloads.string("xss", "probe_template", default="<a{nonce}>\"'{nonce}")
        findings = 0
        for url, param in targets:
            marker_nonce = nonce()
            probe_value = template.format(nonce=marker_nonce)
            baseline = await safe_fetch(ctx, url, follow_redirects=False)
            probe = await safe_fetch(
                ctx, probe_url(url, param, probe_value), follow_redirects=False
            )
            if probe is None:
                continue
            reflection = classify_reflection(probe.body, nonce=marker_nonce)
            if reflection is None:
                continue
            findings += 1
            baseline_page = page_from_exchange(baseline) if baseline is not None else None
            yield web_candidate(
                ctx,
                f"Reflected input reaches unencoded output ({reflection.context} context)",
                artifact={
                    "signal": "xss",
                    "family": "xss",
                    "context": reflection.context,
                    "endpoint": url,
                    "parameter": param,
                    "payload_class": "inert-markup-marker",
                    "raw_reflection": True,
                    "encoded_reflection": False,
                    "marker_index": reflection.index,
                    "delta": compare_pages(
                        baseline_page or page_from_exchange(probe), probe
                    ).to_dict(),
                    "responses_differ": baseline is None
                    or compare_pages(page_from_exchange(baseline), probe).significant(),
                },
                exchanges=(
                    exchange_from_page(baseline_page) if baseline_page is not None else None,
                    probe,
                ),
                confidence=_CONTEXT_CONFIDENCE.get(reflection.context, 0.5),
                detail=(
                    f"{url} parameter '{param}' reflected the raw marker in {reflection.context} "
                    "context (no output encoding)"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no unencoded reflection observed",
                detail=f"probed {len(targets)} parameter(s); every echo was encoded or absent",
            )
