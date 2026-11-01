"""The M3 crawl: what every check reads, so its bounds and accessors are worth pinning.

The crawl is the one thing in M3 that runs before a check has decided anything, and its rules
are safety rules as much as engineering ones: same-origin only, GET only, bounded page count
and depth, and destructive paths recorded but never walked. A bug here either misses surface
(a check then reports "clean" for work it never did) or touches more of the application than
the plan promised.
"""

from __future__ import annotations

import pytest

from arachne.core.http import HttpExchange
from arachne.modules.m3.inventory import (
    DESTRUCTIVE_PATH_RE,
    WebInventory,
    build_web_inventory,
)

INDEX = (
    "<a href='/a'>a</a><a href='/b'>b</a><a href='http://other.example/x'>off</a>"
    "<a href='/logout'>logout</a>"
    "<form action='/login' method='post'>"
    "<input name='username'><input type='password' name='password'></form>"
    "<form action='/upload' method='post' enctype='multipart/form-data'>"
    "<input type='file' name='f'></form>"
)
PAGE_A = "<a href='/a?q=1'>q</a><a href='/deep/deeper/1'>deep</a>"


def exchange(
    url: str, body: str, *, status: int = 200, headers: dict[str, str] | None = None
) -> HttpExchange:
    return HttpExchange(
        method="GET",
        url=url,
        status_code=status,
        response_headers=headers or {"content-type": "text/html"},
        body=body,
    )


class Fetch:
    """A scripted fetcher recording every URL it was asked for."""

    def __init__(self, routes: dict[str, HttpExchange]) -> None:
        self.routes = routes
        self.requested: list[str] = []

    async def __call__(self, url: str) -> HttpExchange:
        self.requested.append(url)
        if url not in self.routes:
            return exchange(url, "<h1>404</h1>", status=404)
        return self.routes[url]


async def test_the_crawl_visits_pages_breadth_first_and_stays_on_the_origin() -> None:
    fetch = Fetch(
        {
            "http://h/": exchange("http://h/", INDEX),
            "http://h/a": exchange("http://h/a", PAGE_A),
            "http://h/b": exchange("http://h/b", "<p>b</p>"),
        }
    )
    inventory = await build_web_inventory(["http://h/"], fetch, max_pages=10, max_depth=2)
    assert "http://other.example/x" not in fetch.requested, "the crawl left the origin"
    assert "http://h/logout" not in fetch.requested, "a destructive path was walked"
    assert inventory.skipped_destructive == 1
    # Depth 1 links appear before depth 2 ones in insertion order.
    assert inventory.order[:3] == ["http://h/", "http://h/a", "http://h/b"]


async def test_the_crawl_is_bounded_by_page_count_and_depth() -> None:
    routes = {
        f"http://h/p{i}": exchange(f"http://h/p{i}", f"<a href='/p{i + 1}'>next</a>")
        for i in range(6)
    }
    routes["http://h/"] = exchange("http://h/", "<a href='/p0'>first</a>")
    fetch = Fetch(routes)
    shallow = await build_web_inventory(["http://h/"], fetch, max_pages=10, max_depth=1)
    assert "http://h/p1" not in shallow.order  # two hops away

    fetch2 = Fetch(routes)
    capped = await build_web_inventory(["http://h/"], fetch2, max_pages=3, max_depth=5)
    assert len(capped.pages) <= 3


async def test_forms_and_parameters_are_collected_for_the_checks() -> None:
    fetch = Fetch(
        {"http://h/": exchange("http://h/", INDEX), "http://h/a": exchange("http://h/a", PAGE_A)}
    )
    inventory = await build_web_inventory(["http://h/"], fetch)
    assert [form.action for form in inventory.forms] == ["http://h/login", "http://h/upload"]
    login = inventory.login_forms(user_fields=["username"], password_fields=["password"])[0]
    assert login.action.endswith("/login")
    assert inventory.upload_forms()[0].is_multipart
    assert ("http://h/a?q=1", "q") in inventory.parameter_targets()
    assert inventory.parameter_targets(names=["q"]) == (("http://h/a?q=1", "q"),)


async def test_a_failing_fetch_is_counted_not_fatal() -> None:
    class Boom(Fetch):
        async def __call__(self, url: str) -> HttpExchange:
            self.requested.append(url)
            raise RuntimeError("connection refused")

    fetch = Boom({})
    inventory = await build_web_inventory(["http://h/"], fetch)
    assert inventory.failed == 1 and inventory.pages == {}


def test_hyphenated_destructive_paths_are_recognised() -> None:
    """S19: the actions are hyphenated in the wild, and a missed one logs the scanner out."""
    for path in ("/logout-soft", "/delete-account", "/revoke_token", "/signout-all"):
        assert DESTRUCTIVE_PATH_RE.search(path), path
    # Still a word match, not a substring one.
    for path in ("/deleted-items", "/removeable", "/login-soft"):
        assert not DESTRUCTIVE_PATH_RE.search(path), path


def test_destructive_paths_are_recognised() -> None:
    for path in ("/logout", "/user/delete", "/signout", "/unsubscribe", "/admin/remove"):
        assert DESTRUCTIVE_PATH_RE.search(path), path
    for path in ("/login", "/deleted-items", "/settings", "/removeable"):
        assert not DESTRUCTIVE_PATH_RE.search(path), path


def test_inventory_accessors_summarise_the_surface() -> None:
    inventory = WebInventory(origin="http://h:80", roots=("http://h/",))
    inventory.add_page(
        exchange("http://h/", "<html></html>", headers={"server": "arachne-lab/1.0"})
    )
    summary = inventory.summary()
    assert summary["pages"] == 1
    assert summary["server"] == "arachne-lab/1.0"
    assert inventory.server_banner() == "arachne-lab/1.0"
    assert inventory.first_page() is not None


@pytest.mark.parametrize("path", ["/logout", "/delete", "/revoke"])
async def test_a_destructive_link_is_recorded_as_an_endpoint(path: str) -> None:
    fetch = Fetch({"http://h/": exchange("http://h/", f"<a href='{path}'>d</a>")})
    inventory = await build_web_inventory(["http://h/"], fetch)
    assert f"http://h{path}" in inventory.endpoints
    assert f"http://h{path}" not in inventory.pages
    assert f"http://h{path}" not in fetch.requested
