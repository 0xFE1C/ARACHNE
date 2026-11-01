"""M4 identity-surface checks: user enumeration, anonymous APIs, default credentials.

The first two are read-only in effect — they ask the application a question any user
could ask — and are bounded so they cannot become a brute-force. The third is an
authentication attempt, so it is **off by default three times over**: the check is
``enabled_by_default=False`` (it must be named explicitly), it is ``active`` (it needs
``--active-checks`` and the attestation), and ``ARACHNE_M4_DEFAULT_CREDENTIALS`` must be
true. With all three on it makes *one* vendor-default attempt per detected product, paced,
never retried, and reports only a successful authentication. That is existence
verification, not credential testing (research ch04#10, safety text).
"""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import AsyncIterator
from urllib.parse import urlencode

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Form, WebInventory
from arachne.modules.m3.support import web_or_skip
from arachne.modules.m4.corpus import CredentialProduct, DashboardPanel, M4Corpus
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    corpus_for,
    exchange_from_page,
    fetch_page,
    finding_cap,
    http_or_skip,
    m4_candidate,
    owns_origin,
    path_url,
    skip,
    text_contains_any,
)

__all__ = ["DefaultCredentials", "UnauthApiAudit", "UserEnumeration"]

#: Paths whose data should never be anonymous: the internal/administrative API surface.
_INTERNAL_HINTS = ("/internal/", "/admin/", "/private/", "/export/", "/backup/", "/manage")


class UserEnumeration(UrlCheck, Module):
    """``m4.user-enumeration`` — login/API response differential (ch04#28)."""

    metadata = CheckMetadata(
        id="m4.user-enumeration",
        module="M4",
        name="user-enumeration",
        version="1.0",
        title="Username enumeration through a login differential",
        description=(
            "Submits a single dummy password for a few candidate user names (plus one random "
            "name as the invalid baseline) to each credential form the crawl found, and "
            "reports a form whose answers differ by status, marker or body length. At most a "
            "handful of attempts, one password each: the check confirms that existence is "
            "observable, it never guesses a credential."
        ),
        research_ref="ch04#28",
        cwe="CWE-204",
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
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        forms = inventory.login_forms(
            user_fields=corpus.user_fields(), password_fields=corpus.password_fields()
        )
        if not forms:
            yield ctx.clean(
                "no credential form found to test for enumeration",
                detail="the crawl found no login form",
            )
            return
        cap = finding_cap(ctx)
        findings = 0
        for form in forms[:2]:
            finding = await self._enumerate(ctx, form, corpus)
            if finding is None:
                continue
            findings += 1
            yield finding
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "login responses look uniform",
                detail=f"tested {min(len(forms), 2)} credential form(s) with a dummy password",
            )

    async def _enumerate(
        self, ctx: CheckContext, form: Form, corpus: M4Corpus
    ) -> CheckResult | None:
        user_field = form.any_input_named(corpus.user_fields())
        password_field = form.any_input_named(corpus.password_fields())
        if user_field is None or password_field is None:
            return None
        names = list(corpus.candidate_names()[:2])
        baseline_name = f"ar9x{secrets.token_hex(4)}"
        probes = [*names, baseline_name]
        observations: list[tuple[str, int, int, str | None]] = []
        exchanges = []
        hidden = {
            item.name: item.value or ""
            for item in form.inputs
            if item.name
            and item.name not in {user_field, password_field}
            and item.type.lower() == "hidden"
        }
        for name in probes:
            body = urlencode({user_field: name, password_field: corpus.dummy_password(), **hidden})
            page = await fetch_page(
                ctx,
                form.action,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=body,
                session=False,
            )
            if page is None:
                continue
            marker = text_contains_any(page.body, corpus.valid_markers())
            invalid = text_contains_any(page.body, corpus.invalid_markers())
            observations.append(
                (name, page.status, page.body_length, marker if marker else invalid)
            )
            exchanges.append(exchange_from_page(page))
        if len(observations) < 2:
            return None
        baseline = observations[-1]
        differing = [
            item
            for item in observations[:-1]
            if item[1] != baseline[1] or abs(item[2] - baseline[2]) >= 24 or item[3] != baseline[3]
        ]
        if not differing:
            return None
        statuses = {item[1] for item in observations}
        yield_marker = differing[0][3]
        return m4_candidate(
            ctx,
            f"Username enumeration on {form.action}",
            artifact={
                "signal": "user-enumeration",
                "family": "user-enumeration",
                "endpoint": form.action,
                "names_probed": len(observations),
                "differential": True,
                "matched_names": [item[0] for item in differing][:3],
                "status_spread": sorted(statuses),
                "baseline_status": baseline[1],
                "marker": yield_marker,
            },
            exchanges=exchanges,
            confidence=0.85 if yield_marker else 0.72,
            detail=(
                f"{form.action} answered differently for {len(differing)} candidate name(s) "
                f"than for a random one (statuses: {sorted(statuses)})"
            ),
            source=form.action,
        )


class UnauthApiAudit(UrlCheck, Module):
    """``m4.unauth-api-audit`` — documented/internal API routes without auth (ch04#29)."""

    metadata = CheckMetadata(
        id="m4.unauth-api-audit",
        module="M4",
        name="unauth-api-audit",
        version="1.0",
        title="Data-bearing API route answers without authentication",
        description=(
            "Replays the routes recovered from an exposed API document and the internal-"
            "looking routes the crawl found, deliberately without the operator's session, "
            "and reports a 200 JSON answer that carries records. A 401/403 is the control "
            "working and is not reported. GET only."
        ),
        research_ref="ch04#29",
        cwe="CWE-306",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=6,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        candidates = _api_candidates(inventory)
        if not candidates:
            yield skip(ctx, "the crawl found no documented or internal API route to replay")
            return
        data_types = tuple(item.lower() for item in corpus.unauth_data_content_types())
        denied = set(corpus.unauth_auth_status())
        cap = finding_cap(ctx)
        findings = 0
        for url, from_doc in candidates[:6]:
            page = await fetch_page(ctx, url, session=False)
            if page is None or page.status in denied or page.status != 200:
                continue
            content_type = page.content_type.lower()
            if not any(item in content_type for item in data_types):
                continue
            shape = _data_shape(page.body)
            if shape is None:
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"API route answers anonymously with data: {url.rsplit('/', 1)[-1] or '/'}",
                artifact={
                    "signal": "unauthenticated-api",
                    "family": "unauth-api",
                    "endpoint": url,
                    "status": page.status,
                    "content_type": page.content_type,
                    "records": shape[0],
                    "shape": shape[1],
                    "documented": from_doc,
                    "bytes": page.body_length,
                },
                exchanges=(exchange_from_page(page),),
                confidence=0.85 if from_doc else 0.8,
                detail=(
                    f"{url} returned HTTP 200 {page.content_type} with {shape[0]} "
                    f"{shape[1]} record(s) and no authentication"
                ),
                source=url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no anonymous data-bearing API route found",
                detail=f"replayed {min(len(candidates), 6)} route(s) without a session",
            )


class DefaultCredentials(UrlCheck, Module):
    """``m4.default-credentials`` — vendor-default pair against a detected panel (ch04#10)."""

    metadata = CheckMetadata(
        id="m4.default-credentials",
        module="M4",
        name="default-credentials",
        version="1.0",
        title="Vendor default credentials accepted",
        description=(
            "Fingerprints a management panel, then makes at most one vendor-default "
            "authentication attempt per product, paced and never retried, and reports only "
            "a successful login. Off by default: needs ARACHNE_M4_DEFAULT_CREDENTIALS=true, "
            "the check named explicitly and the active-checks opt-in. It verifies "
            "existence; it never sprays or guesses."
        ),
        research_ref="ch04#10",
        cwe="CWE-1392",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=10,
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
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        if not ctx.config.m4.default_credentials:
            yield skip(
                ctx,
                "default-credential verification is disabled (set "
                "ARACHNE_M4_DEFAULT_CREDENTIALS=true, select m4.default-credentials "
                "explicitly, and authorize active checks)",
            )
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        pairs = {item.product: item for item in corpus.credential_products()}
        detected = await self._detect_panels(ctx, origin, corpus)
        if not detected:
            yield ctx.clean(
                "no management panel with a known default pair was detected",
                detail=f"fingerprinted panels on {origin}",
            )
            return
        max_attempts = ctx.config.m4.default_credentials_max_attempts
        pacing = ctx.config.m4.default_credentials_pacing_s
        attempts = 0
        findings = 0
        for product, _path in detected:
            entry = pairs.get(product)
            if entry is None or attempts >= max_attempts:
                continue
            if pacing > 0 and attempts > 0:
                # Lockout-safe pacing: a detection must not look like a login flood.
                await asyncio.sleep(pacing)
            attempts += 1
            finding = await self._attempt(ctx, origin, entry)
            if finding is None:
                continue
            findings += 1
            yield finding
            if findings >= finding_cap(ctx):
                break
        if not findings:
            yield ctx.clean(
                "no vendor default credential accepted",
                detail=f"made {attempts} paced default-credential attempt(s)",
            )

    async def _detect_panels(
        self, ctx: CheckContext, origin: str, corpus: M4Corpus
    ) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        for panel in corpus.dashboards():
            assert isinstance(panel, DashboardPanel)
            if not panel.paths:
                continue
            path = panel.paths[0]
            page = await fetch_page(ctx, path_url(origin, path))
            if page is None or page.status >= 400:
                continue
            if text_contains_any(page.body, panel.markers) is not None:
                found.append((panel.product, path))
        return found

    async def _attempt(
        self, ctx: CheckContext, origin: str, entry: CredentialProduct
    ) -> CheckResult | None:
        url = path_url(origin, entry.login_path)
        page = await fetch_page(
            ctx,
            url,
            method=entry.method,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            content=urlencode(entry.fields),
            session=False,
        )
        if page is None or page.status >= 400:
            return None
        success = text_contains_any(page.body, entry.success_markers)
        failure = text_contains_any(page.body, entry.failure_markers)
        if success is None or failure is not None:
            return None
        return m4_candidate(
            ctx,
            f"{entry.product} accepts its vendor default credential",
            artifact={
                "signal": "default-credential",
                "family": "default-credentials",
                "product": entry.product,
                "login_path": entry.login_path,
                "status": page.status,
                "vendor_default": True,
                "success_marker": success,
                "attempts": 1,
            },
            exchanges=(exchange_from_page(page),),
            confidence=0.9,
            detail=(
                f"{url} answered with '{success}' for the {entry.product} vendor-default "
                "pair; no second attempt was made"
            ),
            source=url,
        )


# --------------------------------------------------------------------------- helpers
def _api_candidates(inventory: WebInventory) -> list[tuple[str, bool]]:
    """``(url, from_document)`` pairs worth replaying without a session."""
    found: list[tuple[str, bool]] = []
    seen: set[str] = set()
    for url, source in inventory.endpoints.items():
        if source == "api-doc" and url not in seen:
            seen.add(url)
            found.append((url, True))
    for page in inventory.pages.values():
        path = page.url.lower()
        if any(hint in path for hint in _INTERNAL_HINTS) and page.url not in seen:
            seen.add(page.url)
            found.append((page.url, False))
    return found


def _data_shape(body: str) -> tuple[int, str] | None:
    """``(records, shape)`` for a JSON body that carries data, else ``None``."""
    try:
        document = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(document, list):
        return (len(document), "list") if document else None
    if isinstance(document, dict):
        for value in document.values():
            if isinstance(value, list) and value:
                return len(value), "collection"
        scalars = [value for value in document.values() if not isinstance(value, (dict, list))]
        if len(scalars) >= 2:
            return len(scalars), "object"
    return None
