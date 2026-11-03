"""URL arithmetic the browser crawl needs, with no dependency on a detection module.

The M3 inventory has the equivalent helpers (:func:`~arachne.modules.m3.inventory.origin_of`,
``with_params``), but ``browser`` must not import ``modules.m3``: ``modules.m3.__init__``
imports the check that drives this crawl, so the dependency would be a genuine import cycle
and ``import arachne.browser.crawl`` would fail on a partially initialised module. These are
the same six operations, kept here so the subsystem is importable on its own — which is also
what lets the optional extra be absent without the rest of the product noticing.
"""

from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit

__all__ = [
    "HTTP_SCHEMES",
    "fragment_of",
    "is_http_url",
    "origin_of",
    "path_and_query",
    "same_origin",
    "strip_fragment",
    "with_param",
]

#: The only two schemes the browser may navigate (REQ-DET-015).
HTTP_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def is_http_url(url: str) -> bool:
    """True when ``url`` is an absolute ``http``/``https`` URL."""
    return urlsplit(url).scheme.lower() in HTTP_SCHEMES


def origin_of(url: str) -> str:
    """``scheme://host:port`` with the scheme's default port made explicit."""
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        port = 443 if scheme == "https" else 80
    return f"{scheme}://{host}:{port}"


def same_origin(url: str, origin: str) -> bool:
    return is_http_url(url) and origin_of(url) == origin


def path_and_query(url: str) -> str:
    """``path?query`` — what an HTML response would contain if it named this URL."""
    parts = urlsplit(url)
    return f"{parts.path}?{parts.query}" if parts.query else parts.path


def strip_fragment(url: str) -> str:
    """``url`` without its fragment (a fragment is never sent to the server)."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def fragment_of(url: str) -> str:
    return urlsplit(url).fragment


def with_param(url: str, name: str, value: str) -> str:
    """``url`` with query parameter ``name`` set to ``value`` (percent-encoded).

    Existing parameters keep their order and an existing ``name`` is replaced in place, so
    the marker navigation differs from the plain one in exactly one character run.
    """
    parts = urlsplit(url)
    pairs: list[tuple[str, str]] = []
    replaced = False
    for pair in parts.query.split("&"):
        if not pair:
            continue
        key, _, current = pair.partition("=")
        if key == name:
            pairs.append((key, value))
            replaced = True
        else:
            pairs.append((key, current))
    if not replaced:
        pairs.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(pairs), ""))
