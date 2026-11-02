"""M4 client-side asset checks: secrets shipped to the browser (research ch04#14).

This is the cheapest secret-disclosure class: the bytes are already public, and the server
willingly sent them. The check reads only what the shared crawl fetched, and it reads the
*detector names* the HTTP client's redactor reported — never a value, because redaction
happened before the ``Page`` was built (F-08-04).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, origin_of
from arachne.modules.m3.support import web_or_skip
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    exchange_from_page,
    finding_cap,
    http_or_skip,
    m4_candidate,
    owns_origin,
    secrets_in,
    skip,
)

__all__ = ["ClientSecrets"]


class ClientSecrets(UrlCheck, Module):
    """``m4.client-secrets`` — credentials in JavaScript and HTML (ch04#14)."""

    metadata = CheckMetadata(
        id="m4.client-secrets",
        module="M4",
        name="client-secrets",
        version="1.0",
        title="Credential material in client-side assets",
        description=(
            "Reviews every JavaScript bundle and HTML document the crawl fetched and reports "
            "the ones whose raw bytes matched a secret detector (cloud access key, provider "
            "API token, JWT, credentialed URL, PEM key). Only the detector names and the "
            "asset's provenance are reported; the values were redacted at capture time."
        ),
        research_ref="ch04#14",
        framework=("WSTG-INFO-05", "WSTG-CLNT-12", "CWE-798"),
        cwe="CWE-798",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="passive",
        safe=True,
        verifiable=True,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 review for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        origin = asset_origin(ctx)
        pages = [
            page
            for page in inventory.pages.values()
            if origin_of(page.url) == origin and secrets_in(page)
        ]
        if not pages:
            yielded = False
            for page in inventory.pages.values():
                if origin_of(page.url) != origin:
                    continue
                yielded = True
                break
            yield ctx.clean(
                "no credential material found in client-side assets",
                detail=(
                    f"reviewed the crawl for {origin}"
                    if yielded
                    else "the crawl fetched no page for this origin"
                ),
            )
            return
        # JavaScript first: a secret in a bundle is the classic case, and a bundle is served
        # to every visitor.
        pages.sort(
            key=lambda page: (
                not page.url.split("?")[0].endswith((".js", ".mjs")),
                page.url,
            )
        )
        cap = finding_cap(ctx)
        for page in pages[:cap]:
            detectors = list(secrets_in(page))
            yield m4_candidate(
                ctx,
                f"Credential material in client-side asset: {page.url.rsplit('/', 1)[-1]}",
                artifact={
                    "signal": "client-side-credentials",
                    "family": "client-secrets",
                    "page": page.url,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "detectors": detectors,
                    "is_script": page.url.split("?")[0].endswith((".js", ".mjs", ".css")),
                    "origin": origin,
                },
                exchanges=(exchange_from_page(page),),
                confidence=0.85,
                detail=(
                    f"{page.url} matched {len(detectors)} secret detector(s): "
                    f"{', '.join(detectors)}"
                ),
                source=page.url,
            )
