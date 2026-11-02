"""Shared plumbing for the WP-08 breadth families (REQ-DET-004, REQ-DET-009).

Nine checks in two modules need the same few primitives: one GET that returns both the
crawl's :class:`Page` view and the :class:`HttpExchange` evidence, the benign value a URL
already carried, the application's own record count, and the *one* differential test every
oracle must use. Keeping them here is the "shared differential oracle" of REQ-DET-009: a
new family registers its comparison through :func:`differs` (and, for the query families,
:func:`count_records`) rather than growing private similarity, timing or regex logic.

The comparison itself is not reimplemented. :func:`differs` delegates to
:func:`~arachne.modules.m3.support.compare_pages`, whose :class:`BodyDelta` is the single
place an M3 oracle's "is this a real difference?" threshold lives. That is what makes an
FP-2 decision reviewable in one file instead of nine.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, TypeVar
from urllib.parse import parse_qs, urlsplit

from arachne.core.http import HttpExchange
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, page_from_exchange
from arachne.modules.m3.support import compare_pages, safe_fetch, text_ratio

T = TypeVar("T")

__all__ = [
    "benign_value",
    "count_records",
    "differs",
    "fetch_page",
    "first_signature",
    "header_value",
    "is_shared_cacheable",
    "json_key_value",
    "page_ratio",
    "preferred",
    "reproduce",
]


def preferred(items: Iterable[T], predicate: Callable[[T], bool]) -> tuple[T, ...]:
    """``items`` with the ones matching ``predicate`` first, otherwise in their given order.

    A family's path hints say where its sink is *most likely*; they order the bounded probe
    list rather than narrowing it, so a URL that does not match is still probed when the
    budget allows. Ordering is stable, so a run's probes are reproducible.
    """
    matches: list[T] = []
    rest: list[T] = []
    for item in items:
        (matches if predicate(item) else rest).append(item)
    return (*matches, *rest)


async def fetch_page(
    ctx: CheckContext,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
) -> tuple[Page, HttpExchange] | None:
    """One read-only GET as ``(page, exchange)``, or ``None`` when it failed or was refused.

    A probe failure is data, not a check failure: the scoped client has already audited a
    refusal, and one dead parameter must not abort the rest of the family.
    """
    exchange = await safe_fetch(ctx, url, headers=headers, follow_redirects=False)
    if exchange is None:
        return None
    return page_from_exchange(exchange), exchange


def benign_value(url: str, parameter: str, default: str) -> str:
    """The value the crawl already saw for ``parameter`` (the baseline's held-constant input)."""
    values = parse_qs(urlsplit(url).query, keep_blank_values=True).get(parameter)
    if values and values[0]:
        return values[0]
    return default


def first_signature(body: str, signatures: Mapping[str, Any]) -> str | None:
    """The first engine-specific error signature that fires on ``body`` (or ``None``)."""
    for expression in signatures.values():
        try:
            match = re.search(str(expression), body, re.IGNORECASE)
        except re.error:  # pragma: no cover - a bad corpus regex fails at load
            continue
        if match is not None:
            return match.group(0)[:160]
    return None


def count_records(body: str, marker: str) -> int:
    """How many of the application's own result records the body renders."""
    return body.count(marker) if marker else 0


def differs(baseline: Page, probe: Page, *, min_length_delta: int = 1) -> bool:
    """A measured difference larger than the page's own rendering noise (the shared oracle)."""
    return compare_pages(baseline, probe).significant(
        min_ratio_drop=0.0, min_length_delta=min_length_delta
    )


def page_ratio(left: Page, right: Page) -> float:
    """Normalized body similarity in ``[0, 1]`` (the shared comparison's arithmetic)."""
    return text_ratio(left.body, right.body)


def reproduce(method: str, url: str, *, headers: Mapping[str, str] | None = None) -> str:
    """The exact request a human can replay to confirm the claim by hand."""
    rendered = f"{method} {url}"
    if headers:
        rendered += " with " + ", ".join(f"{name}: {value}" for name, value in headers.items())
    return rendered


def header_value(headers: Mapping[str, str], name: str) -> str:
    """A response header's value, case-insensitively (the client preserves wire casing)."""
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return ""


def is_shared_cacheable(
    headers: Mapping[str, str],
    *,
    invite: Sequence[str] = ("public", "max-age", "s-maxage"),
    deny: Sequence[str] = ("private", "no-store", "no-cache"),
    status_headers: Sequence[str] = ("x-cache", "cf-cache-status", "x-proxy-cache", "age"),
) -> bool:
    """True when a shared cache is invited to store the response.

    ``Cache-Control`` carries an inviting directive (``public`` or an explicit
    ``max-age``/``s-maxage``) without any private directive, or a fronting proxy reports a
    cache status. A response with no caching header at all is *not* treated as cacheable: the
    claim needs positive evidence. The three vocabularies come from the probe corpus, so an
    operator can tune them without touching code.
    """
    control = header_value(headers, "cache-control").lower()
    if any(directive in control for directive in deny):
        return False
    if any(directive in control for directive in invite):
        return True
    return any(header_value(headers, name) for name in status_headers)


def json_key_value(body: str, name: str) -> str | None:
    """The first scalar value under a mapping key equal to ``name`` anywhere in a JSON body.

    Used by the email-header family: a JSON ``headers`` object that now contains the injected
    header name is evidence the CRLF created a *header*, which a plain reflection cannot
    produce. A non-JSON body answers ``None``.
    """
    try:
        document = json.loads(body)
    except (ValueError, TypeError):
        return None
    return _find_key(document, name.lower())


def _find_key(node: Any, lowered: str) -> str | None:
    if isinstance(node, Mapping):
        for key, value in node.items():
            if str(key).lower() == lowered and isinstance(value, str):
                return value
        for value in node.values():
            found = _find_key(value, lowered)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = _find_key(item, lowered)
            if found is not None:
                return found
    return None
