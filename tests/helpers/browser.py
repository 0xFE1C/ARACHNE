"""A scripted ``Navigator``: a browser's contract without a browser.

The crawl's safety and behaviour must be testable in an installation that does not contain
the optional ``browser`` extra — that is the whole point of making the browser optional. So
the crawl talks to a :class:`~arachne.browser.crawl.Navigator` protocol, and this module
implements it from a dictionary of routes.

A scripted page declares what the *server* sent (``raw_body``) and what *JavaScript* then did
(``links``, ``sink_records``, ``history_routes``). Sink record values contain the literal
``{marker}`` placeholder, which the navigator substitutes with the marker it finds in the URL
it was asked for — that is the simulation of "the page's script read ``location.hash`` and
wrote it into ``innerHTML``". Hostile behaviour is declared the same way: ``refused_requests``
for a page that tried a non-HTTP scheme or an off-scope origin, ``downloads`` for a page that
tried to save a file, ``error`` for a navigation that failed.

Nothing here opens a socket: the scripted navigator is data. That is what lets the safety
suite assert "an out-of-scope navigation produces no request" as a *test* rather than as an
intention.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

from arachne.browser.crawl import QUERY_MARKER_PARAM, RenderedPage
from arachne.browser.sinks import DEFAULT_STEM

__all__ = ["ScriptedNavigator", "ScriptedPage", "marker_in", "sink_record"]


def marker_in(url: str, *, stem: str = DEFAULT_STEM) -> str | None:
    """The marker the crawl planted in ``url`` (fragment first, then the query parameter)."""
    parts = urlsplit(url)
    if parts.fragment.startswith(stem):
        return parts.fragment
    values = parse_qs(parts.query).get(QUERY_MARKER_PARAM, [])
    for value in values:
        if value.startswith(stem):
            return value
    return None


@dataclass(frozen=True, slots=True)
class ScriptedPage:
    """What one navigation produces: the server's bytes plus what the page's script did."""

    raw_body: str = ""
    #: Anchor/form hrefs present in the *rendered* DOM (what ``eval_on_selector_all`` returns).
    links: tuple[str, ...] = ()
    #: Sink calls whose value carries the marker; ``{marker}`` is substituted per navigation.
    sink_records: tuple[Mapping[str, object], ...] = ()
    #: Routes the page pushed onto the History API.
    history_routes: tuple[str, ...] = ()
    #: Requests the browser guard or the proxy refused while rendering this page.
    refused_requests: tuple[str, ...] = ()
    #: Downloads the page attempted (recorded and cancelled, never saved).
    downloads: tuple[str, ...] = ()
    status: int = 200
    error: str | None = None


@dataclass
class ScriptedNavigator:
    """A ``Navigator`` over declared routes, recording every URL it was asked to open."""

    pages: Mapping[str, ScriptedPage] = field(default_factory=dict)
    #: The default answer for a route the script does not declare (a 404-shaped page).
    fallback: ScriptedPage = field(default_factory=ScriptedPage)
    marker_stem: str = DEFAULT_STEM
    #: Every URL handed to :meth:`navigate`, in order — the assertion surface for "was this
    #: navigation even attempted?".
    navigations: list[str] = field(default_factory=list)
    closed: bool = False

    async def navigate(self, url: str) -> RenderedPage:
        self.navigations.append(url)
        page = self._lookup(url)
        marker = marker_in(url, stem=self.marker_stem) or ""
        return RenderedPage(
            url=url,
            final_url=url.split("#", 1)[0],
            status=page.status,
            raw_body=page.raw_body,
            links=tuple(page.links),
            sink_records=tuple(_substitute(record, marker) for record in page.sink_records),
            history_routes=tuple(page.history_routes),
            refused_requests=tuple(page.refused_requests),
            downloads=tuple(page.downloads),
            error=page.error,
        )

    async def aclose(self) -> None:
        self.closed = True

    def paths(self) -> tuple[str, ...]:
        """The paths of every navigation, deduplicated and in order (fragment dropped)."""
        return tuple(dict.fromkeys(urlsplit(url).path for url in self.navigations))

    def _lookup(self, url: str) -> ScriptedPage:
        parts = urlsplit(url)
        for key, page in self.pages.items():
            if key == parts.path or key == f"{parts.path}?{parts.query}":
                return page
            if key.startswith("http") and key.split("#", 1)[0] == url.split("#", 1)[0]:
                return page
        return self.fallback


def _substitute(record: Mapping[str, object], marker: str) -> dict[str, Any]:
    """``{marker}`` in a record's value becomes the marker the crawl planted."""
    out = dict(record)
    value = out.get("value")
    if isinstance(value, str):
        out["value"] = value.replace("{marker}", marker)
    return out


def sink_record(sink: str, *, value: str = "{marker}", url: str = "") -> dict[str, str]:
    """One instrumentation-shaped record (the same keys the injected script pushes)."""
    return {"sink": sink, "value": value, "url": url}
