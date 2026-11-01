"""The M3 web inventory: one bounded crawl every M3 check reads (ADR-100.2).

M2's checks share a :class:`~arachne.modules.m2.inventory.NetworkInventory` so the port scan
happens once; M3's checks share this object for the same reason. Twelve checks each crawling
the application would multiply the request count by twelve, make the plan's estimate fiction,
and — worst — turn twelve independent guesses about "what are the parameters here?" into
twelve different answers.

The crawl is deliberately narrow, because it is the only thing in M3 that runs before a check
has decided anything:

* **same-origin, GET-only, no redirects followed** — the walk never leaves the host it started
  on and never changes state; the raw 3xx is what the open-redirect check wants anyway;
* **bounded** by ``ARACHNE_WEB_MAX_PAGES`` and ``ARACHNE_WEB_MAX_DEPTH`` (F-01-07);
* **destructive paths skipped** — a link whose path looks like logout/delete/unsubscribe is
  recorded as an endpoint but not walked, so the crawl cannot log the operator out of the
  application it is measuring;
* **out-of-scope is not an error** — the shared client refuses and audits it, the crawl moves
  on (F-01-02).

What it collects is exactly what the oracles need: every fetched page with its response
(status, headers, body, cookies, timing), every form with its fields, the parameter names
seen on every URL, and the endpoint set (linked, formed and derived). The crawl does not
decide anything about vulnerabilities — that is each check's job.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Final
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from arachne.core.http import CookieInfo, HttpExchange
from arachne.core.results import sha256_of

__all__ = [
    "DESTRUCTIVE_PATH_RE",
    "Endpoint",
    "Form",
    "FormInput",
    "Page",
    "WebInventory",
    "build_web_inventory",
    "extract_document",
    "is_html_content_type",
    "normalize_body",
    "origin_of",
    "same_origin",
    "url_param_names",
    "with_params",
]

#: Link/path fragments the crawl will record but never follow: a scanner must not log itself
#: out of the application, delete a record or unsubscribe an address while measuring it.
#: ``-``/``_`` count as a trailing boundary too (S19): an application spells these actions
#: ``/logout-soft``, ``/delete-account`` or ``/revoke_token`` as often as ``/logout``, and a
#: word boundary alone let the crawl follow a hyphenated logout — which logs the *scanner*
#: out mid-scan. The prefix still has to be the whole segment word (``/deleted-items`` and
#: ``/removeable`` stay non-destructive).
DESTRUCTIVE_PATH_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:^|/)(?:logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe|revoke|"
    r"deactivate|disable|drop)(?:$|[/?.#_-])",
    re.IGNORECASE,
)

#: A fetcher: ``url -> HttpExchange``. Supplied by ``m3.support`` so this module owns the
#: walk and the caller owns the request policy (session headers, redirect handling, audit).
Fetcher = Callable[[str], Awaitable[HttpExchange]]

_WHITESPACE_RE: Final[re.Pattern[str]] = re.compile(r"\s+")


# --------------------------------------------------------------------------- document model
@dataclass(frozen=True, slots=True)
class FormInput:
    """One form control."""

    name: str
    type: str = "text"
    value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.type}


@dataclass(frozen=True, slots=True)
class Form:
    """A discovered HTML form (the input the CSRF, upload and auth checks read)."""

    action: str
    method: str = "GET"
    inputs: tuple[FormInput, ...] = ()
    enctype: str = ""
    page_url: str = ""

    @property
    def is_post(self) -> bool:
        return self.method.upper() == "POST"

    @property
    def is_multipart(self) -> bool:
        return "multipart/form-data" in self.enctype.lower()

    def input_names(self) -> tuple[str, ...]:
        return tuple(item.name for item in self.inputs if item.name)

    def has_input(self, name: str) -> bool:
        lowered = name.lower()
        return any(item.name.lower() == lowered for item in self.inputs)

    def any_input_named(self, candidates: Iterable[str]) -> str | None:
        wanted = {name.lower() for name in candidates}
        for item in self.inputs:
            if item.name.lower() in wanted:
                return item.name
        return None

    def file_inputs(self) -> tuple[FormInput, ...]:
        return tuple(item for item in self.inputs if item.type.lower() == "file")

    def password_inputs(self) -> tuple[FormInput, ...]:
        return tuple(item for item in self.inputs if item.type.lower() == "password")

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "enctype": self.enctype,
            "inputs": [item.to_dict() for item in self.inputs],
        }


@dataclass(frozen=True, slots=True)
class Page:
    """One fetched response, as every M3 check and the rules see it."""

    url: str
    status: int
    headers: Mapping[str, str]
    body: str
    content_type: str
    elapsed_ms: float
    cookies: tuple[CookieInfo, ...] = ()
    truncated: bool = False
    #: Which secret detectors fired on the raw body (the value is already redacted — this is
    #: how M4's exposure checks learn "this page carries an AWS key" without the key).
    secret_kinds: tuple[str, ...] = ()

    @property
    def is_html(self) -> bool:
        return is_html_content_type(self.content_type) or self.body.lstrip()[:1] == "<"

    @property
    def body_length(self) -> int:
        return len(self.body)

    @property
    def body_fingerprint(self) -> str:
        """SHA-256 of the whitespace-normalized body — the crawl's "same page?" key."""
        return sha256_of(normalize_body(self.body))

    @property
    def host(self) -> str:
        return urlsplit(self.url).netloc.lower()

    def header(self, name: str, default: str | None = None) -> str | None:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return default

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme.lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "bytes": self.body_length,
            "elapsed_ms": self.elapsed_ms,
            "cookies": [cookie.to_dict() for cookie in self.cookies],
            "truncated": self.truncated,
            "secret_kinds": list(self.secret_kinds),
        }


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A URL the crawl or a check discovered (whether or not it was fetched)."""

    url: str
    source: str = "crawl"
    status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "source": self.source, "status": self.status}


@dataclass
class WebInventory:
    """Everything the M3 checks share: pages, forms, parameters, endpoints, cookies."""

    roots: tuple[str, ...] = ()
    origin: str | None = None
    #: Every declared root's origin: the set the crawl is allowed to walk inside.
    origins: tuple[str, ...] = ()
    pages: dict[str, Page] = field(default_factory=dict)
    order: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    endpoints: dict[str, str] = field(default_factory=dict)  # url -> source
    #: Set by m3.api-surface once it has learned the application's not-found signature; used
    #: by the crawl's own catch-all reasoning and available to any check that wants it.
    not_found: Page | None = None
    #: The same not-found answer per origin, so a later check (M4's exposure probes) does not
    #: re-learn it once per check. Filled on demand; never persisted.
    not_found_by_origin: dict[str, Page] = field(default_factory=dict)
    visited: int = 0
    skipped_destructive: int = 0
    failed: int = 0

    # ------------------------------------------------------------------ accessors
    def add_page(self, page: Page) -> None:
        if page.url not in self.pages:
            self.order.append(page.url)
        self.pages[page.url] = page
        self.endpoints.setdefault(page.url, "crawl")

    def add_endpoint(self, url: str, *, source: str = "crawl", status: int | None = None) -> None:
        self.endpoints.setdefault(url, source)
        del status

    def first_page(self) -> Page | None:
        for url in self.order:
            return self.pages[url]
        return None

    def html_pages(self) -> tuple[Page, ...]:
        return tuple(self.pages[url] for url in self.order if self.pages[url].is_html)

    def pages_for_host(self, host: str) -> tuple[Page, ...]:
        lowered = host.lower()
        return tuple(page for page in self.pages.values() if page.host == lowered)

    def parameter_targets(
        self, *, names: Iterable[str] | None = None, limit: int | None = None
    ) -> tuple[tuple[str, str], ...]:
        """``(url, parameter)`` pairs whose parameter name matches ``names`` (a hint set).

        ``names=None`` yields every query parameter. The order is crawl order then
        parameter-name order, so a check's probes are deterministic run to run.
        """
        wanted = {name.lower() for name in names} if names is not None else None
        pairs: list[tuple[str, str]] = []
        for url in self.order:
            for name in url_param_names(url):
                if wanted is not None and name.lower() not in wanted:
                    continue
                pairs.append((url, name))
                if limit is not None and len(pairs) >= limit:
                    return tuple(pairs)
        return tuple(pairs)

    def all_parameter_names(self) -> tuple[str, ...]:
        seen: dict[str, None] = {}
        for url in self.order:
            for name in url_param_names(url):
                seen.setdefault(name, None)
        for form in self.forms:
            for item in form.inputs:
                if item.name:
                    seen.setdefault(item.name, None)
        return tuple(seen)

    def cookies(self) -> tuple[CookieInfo, ...]:
        """Every distinct ``Set-Cookie`` observed across the crawl, in first-seen order."""
        seen: dict[tuple[str, bool, bool, str | None], CookieInfo] = {}
        for url in self.order:
            for cookie in self.pages[url].cookies:
                key = (cookie.name, cookie.secure, cookie.httponly, cookie.samesite)
                seen.setdefault(key, cookie)
        return tuple(seen.values())

    def session_cookies(self, names: Iterable[str]) -> tuple[CookieInfo, ...]:
        wanted = {name.lower() for name in names}
        return tuple(cookie for cookie in self.cookies() if cookie.name.lower() in wanted)

    def forms_at(self, url: str) -> tuple[Form, ...]:
        return tuple(form for form in self.forms if form.page_url == url)

    def login_forms(
        self, *, user_fields: Iterable[str], password_fields: Iterable[str]
    ) -> tuple[Form, ...]:
        """Forms that look like a credential login (a password field plus a user field)."""
        users = {name.lower() for name in user_fields}
        passwords = {name.lower() for name in password_fields}
        found: list[Form] = []
        for form in self.forms:
            has_password = any(item.name.lower() in passwords for item in form.password_inputs())
            has_user = any(item.name.lower() in users for item in form.inputs)
            if has_password and has_user:
                found.append(form)
        return tuple(found)

    def upload_forms(self) -> tuple[Form, ...]:
        """Forms that can carry a file (multipart enctype or a file input)."""
        return tuple(form for form in self.forms if form.is_multipart or form.file_inputs())

    def state_changing_forms(self, fragments: Iterable[str]) -> tuple[Form, ...]:
        """Forms whose action/path looks mutating, or that are POSTs."""
        hints = tuple(fragment.lower() for fragment in fragments)
        found: list[Form] = []
        for form in self.forms:
            if form.is_post:
                found.append(form)
                continue
            target = f"{urlsplit(form.action).path}?{urlsplit(form.action).query}".lower()
            if any(hint in target for hint in hints):
                found.append(form)
        return tuple(found)

    def server_banner(self) -> str | None:
        for url in self.order:
            value = self.pages[url].header("server")
            if value:
                return value
        return None

    def summary(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "pages": len(self.pages),
            "forms": len(self.forms),
            "endpoints": len(self.endpoints),
            "parameters": len(self.all_parameter_names()),
            "cookies": len(self.cookies()),
            "visited": self.visited,
            "skipped_destructive": self.skipped_destructive,
            "failed": self.failed,
            "server": self.server_banner(),
        }


# --------------------------------------------------------------------------- url helpers
def same_origin(url: str, origin: str | None) -> bool:
    if not origin:
        return False
    return origin_of(url) == origin


def origin_of(url: str) -> str:
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


def is_html_content_type(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return "html" in lowered or "xhtml" in lowered


def normalize_body(body: str) -> str:
    """Collapse whitespace so two renderings of the same page compare equal."""
    return _WHITESPACE_RE.sub(" ", body).strip()


def url_param_names(url: str) -> tuple[str, ...]:
    """The query-parameter names of ``url``, in order (deduplicated, empties dropped)."""
    query = urlsplit(url).query
    if not query:
        return ()
    names: dict[str, None] = {}
    for pair in query.split("&"):
        if not pair:
            continue
        name = pair.partition("=")[0]
        if name:
            names.setdefault(name, None)
    return tuple(names)


def with_params(url: str, overrides: Mapping[str, str]) -> str:
    """Return ``url`` with ``overrides`` applied to its query (percent-encoded).

    Existing parameters are preserved in order; an override replaces the *first* occurrence of
    its name, and a new name is appended. This is how an oracle substitutes one value without
    disturbing the rest of the request — the differential needs everything else held equal.
    """
    parts = urlsplit(url)
    remaining = dict(overrides)
    pairs: list[tuple[str, str]] = []
    for pair in parts.query.split("&"):
        if not pair:
            continue
        name, _, value = pair.partition("=")
        if name in remaining:
            pairs.append((name, remaining.pop(name)))
        else:
            pairs.append((name, value))
    pairs.extend(remaining.items())
    query = urlencode(pairs, doseq=False)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, parts.fragment))


# --------------------------------------------------------------------------- extraction
class _LinkFormParser(HTMLParser):
    """Collects links and forms from one HTML document (stdlib only, no HTML fixing)."""

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._form_stack: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ tags
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        if tag in {"a", "area", "link", "iframe", "frame"} and attributes.get("href"):
            self._add_link(attributes["href"])
        elif tag in {"script", "img", "source"} and attributes.get("src"):
            self._add_link(attributes["src"])
        elif tag == "form":
            self._form_stack.append(
                {
                    "action": attributes.get("action", ""),
                    "method": attributes.get("method", "GET"),
                    "enctype": attributes.get("enctype", ""),
                    "inputs": [],
                }
            )
        elif tag in {"input", "textarea", "select", "button"} and self._form_stack:
            name = attributes.get("name") or attributes.get("id") or ""
            if name:
                self._form_stack[-1]["inputs"].append(
                    FormInput(
                        name=name,
                        type=attributes.get("type", tag if tag != "input" else "text"),
                        value=attributes.get("value") or None,
                    )
                )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form_stack:
            self._close_form()

    def close(self) -> None:
        super().close()
        while self._form_stack:
            self._close_form()

    # ------------------------------------------------------------------ internals
    def _add_link(self, raw: str) -> None:
        candidate = raw.strip()
        if not candidate or candidate.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
            return
        self.links.append(urljoin(self.base_url, candidate))

    def _close_form(self) -> None:
        data = self._form_stack.pop()
        action = data["action"] or self.base_url
        self.forms.append(
            Form(
                action=urljoin(self.base_url, action),
                method=str(data["method"]).upper(),
                inputs=tuple(data["inputs"]),
                enctype=str(data["enctype"]),
                page_url=self.base_url,
            )
        )


def extract_document(html: str, base_url: str) -> tuple[tuple[str, ...], tuple[Form, ...]]:
    """``(links, forms)`` from one HTML document, resolved against ``base_url``."""
    parser = _LinkFormParser(base_url)
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # a broken document must not break the crawl (docs/spec/07- §4)
        return tuple(dict.fromkeys(parser.links)), tuple(parser.forms)
    return tuple(dict.fromkeys(parser.links)), tuple(parser.forms)


# --------------------------------------------------------------------------- the crawl
def page_from_exchange(exchange: HttpExchange) -> Page:
    """Project an :class:`HttpExchange` onto the crawl's :class:`Page` record."""
    return Page(
        url=exchange.url,
        status=exchange.status_code,
        headers=dict(exchange.response_headers),
        body=exchange.body,
        content_type=str(exchange.header("content-type") or ""),
        elapsed_ms=exchange.elapsed_ms,
        cookies=tuple(exchange.cookies),
        truncated=exchange.body_truncated,
        secret_kinds=tuple(exchange.secret_kinds),
    )


async def build_web_inventory(
    roots: Iterable[str],
    fetch: Fetcher,
    *,
    max_pages: int = 20,
    max_depth: int = 2,
    max_endpoints: int = 200,
) -> WebInventory:
    """Crawl ``roots`` breadth-first through ``fetch`` and return the shared inventory.

    ``fetch`` is the caller's request policy (session headers, no redirect following, audit),
    so this function contains no request decision at all — only the walk.

    Each declared root is walked within *its own* origin: an application reachable over both
    ``http`` and ``https`` is two origins, and a link found on one must not pull the crawl onto
    the other (the shared client would refuse it anyway, but a refused hop per page is noise).
    ``max_pages`` bounds the whole crawl, across every origin, so the cost stays predictable.
    """
    inventory = WebInventory()
    root_list = tuple(dict.fromkeys(roots))
    inventory.roots = root_list
    inventory.origins = tuple(dict.fromkeys(origin_of(root) for root in root_list))
    inventory.origin = inventory.origins[0] if inventory.origins else None
    allowed = set(inventory.origins)
    for root in root_list:
        inventory.add_endpoint(root, source="root")

    queue: deque[tuple[str, int]] = deque((root, 0) for root in root_list)
    seen: set[str] = set()
    while queue and len(inventory.pages) < max_pages:
        url, depth = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        if origin_of(url) not in allowed:
            continue
        if DESTRUCTIVE_PATH_RE.search(urlsplit(url).path):
            inventory.skipped_destructive += 1
            continue
        page = await _fetch_page(url, fetch, inventory)
        if page is None:
            continue
        inventory.add_page(page)
        if depth >= max_depth or not page.is_html:
            continue
        links, forms = extract_document(page.body, page.url)
        for form in forms:
            inventory.forms.append(form)
            _record_endpoint(inventory, form.action, "form", max_endpoints)
        for link in links:
            if origin_of(link) not in allowed:
                continue
            _record_endpoint(inventory, link, "link", max_endpoints)
            if link not in seen:
                queue.append((link, depth + 1))
    return inventory


async def _fetch_page(url: str, fetch: Fetcher, inventory: WebInventory) -> Page | None:
    try:
        exchange = await fetch(url)
    except Exception:
        # A refusal (scope, safety, transport) is not the crawl's failure: the request was
        # audited by the client, and the walk continues with the rest of the surface.
        inventory.failed += 1
        return None
    inventory.visited += 1
    return page_from_exchange(exchange)


def _record_endpoint(inventory: WebInventory, url: str, source: str, limit: int) -> None:
    if len(inventory.endpoints) >= limit:
        return
    inventory.endpoints.setdefault(url, source)


def fingerprint(body: str) -> str:
    """The crawl's body identity (kept as a module function for tests)."""
    return hashlib.sha256(normalize_body(body).encode("utf-8")).hexdigest()
