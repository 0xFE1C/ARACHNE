"""The headless browser, behind an optional extra (REQ-DET-015).

``playwright`` is an **extra** (``arachne[browser]``), never a runtime dependency: the default
install, the air-gapped install and the whole test suite must work with it absent, and the
crawl must then report itself *skipped* rather than failing (R-16's structural mitigation —
"the risk does not reach the common deployment unless the operator opts in"). The import
therefore lives inside :meth:`PlaywrightNavigator.start` and its absence is a recorded value,
never an exception.

Chromium is launched with the literal switch set from :mod:`arachne.browser.hardening` — the
proxy is passed as ``--proxy-server`` rather than through Playwright's own ``proxy`` option so
that the flags in the launch argv and the flags the hardening test asserts are the same list,
not two descriptions of the same intent. The browser context carries the permission denials,
and four guards on top:

* **scheme guard** — every request is checked by :func:`~arachne.browser.hardening.scheme_allowed`
  and aborted when it is not ``http``/``https``, so a ``file:``, ``data:`` or ``blob:``
  navigation is refused *inside* the browser (the proxy would refuse it too, but a request the
  browser never makes is better than one refused at the edge);
* **download guard** — a download event is recorded and the download is cancelled; nothing is
  ever written to disk, let alone executed;
* **file-chooser guard** — a file chooser is recorded and cancelled; the crawl never puts a
  local path into a page;
* **popup guard** — a popup is closed immediately, so a page cannot open its way past the
  page budget or the scope of the crawl.

Sub-resources on other origins are *not* exempted: they go to the proxy, the proxy applies the
scope gate, and an out-of-scope origin is refused (recorded as ``refused_requests``). That is
``INV-1`` applied to a browser — deny by default, including the third-party CDN — and it is why
a page whose bundle lives off-scope renders as an empty shell rather than as a leak.

This module is small on purpose. Everything that decides *what* the crawl does lives in
:mod:`arachne.browser.crawl` and is tested without a browser; what is left here is the
transport, and its acceptance evidence is the optional integration module
(``tests/integration/test_browser_lab.py``), which runs when the extra is installed.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Any, Final

from arachne.browser.crawl import RenderedPage
from arachne.browser.hardening import (
    BROWSER_EXTRA,
    capability_report,
    context_kwargs,
    launch_args,
    scheme_allowed,
)
from arachne.browser.sinks import DEFAULT_STEM, instrument_source

__all__ = [
    "BROWSER_EXTRA",
    "PlaywrightNavigator",
    "browser_available",
    "unavailable_reason",
]

#: How much of a response body is kept. The raw body is only ever used for two substring
#: tests (is this route in the server's HTML? is the marker in it?), so a cap costs nothing.
MAX_BODY_CHARS: Final = 400_000

#: Links collected from the rendered DOM per page.
MAX_LINKS: Final = 300


def browser_available() -> bool:
    """True when the optional browser driver is installed in this installation."""
    try:  # pragma: no cover - the branch depends on the install, not on the code
        import playwright.async_api  # noqa: F401
    except Exception:
        return False
    return True


def unavailable_reason() -> str:
    """Why the crawl cannot run here (the text a skipped result carries)."""
    return (
        f"no browser driver installed: install arachne[{BROWSER_EXTRA}] to crawl "
        "JavaScript-rendered routes and DOM sinks (the rest of the product is unaffected)"
    )


@dataclass(slots=True)
class PlaywrightNavigator:
    """One hardened Chromium, reduced to :meth:`navigate` (the crawl's only browser surface)."""

    proxy_url: str
    marker_stem: str = DEFAULT_STEM
    timeout_ms: int = 20_000
    #: How long to let a client-side router finish rendering after the document load event.
    #: A page that never settles must not be able to hold the crawl open — the crawl's own
    #: time budget is the outer bound, and this is the inner one.
    settle_ms: int = 1_500

    _playwright: Any = field(default=None, init=False, repr=False)
    _browser: Any = field(default=None, init=False, repr=False)
    _context: Any = field(default=None, init=False, repr=False)
    _page: Any = field(default=None, init=False, repr=False)
    _refused: list[str] = field(default_factory=list, init=False, repr=False)
    _downloads: list[str] = field(default_factory=list, init=False, repr=False)
    _file_choosers: list[str] = field(default_factory=list, init=False, repr=False)
    #: The guard callbacks are synchronous (Playwright invokes them on the loop thread) but
    #: their cancels are coroutines; the tasks are held so the loop cannot collect one
    #: mid-flight (RUF006).
    _tasks: set[asyncio.Task[None]] = field(default_factory=set, init=False, repr=False)

    # ------------------------------------------------------------------ lifecycle
    async def start(self) -> PlaywrightNavigator:  # pragma: no cover - needs the extra
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=True, args=list(launch_args(self.proxy_url))
        )
        self._context = await self._browser.new_context(**context_kwargs())
        await self._context.add_init_script(instrument_source(self.marker_stem))
        self._context.on("page", self._on_page)
        self._page = await self._context.new_page()
        self._page.set_default_timeout(self.timeout_ms)
        self._page.on("download", self._on_download)
        self._page.on("filechooser", self._on_file_chooser)
        await self._context.route("**/*", self._on_request)
        return self

    async def aclose(self) -> None:  # pragma: no cover - needs the extra
        for closer in (self._context, self._browser):
            if closer is not None:
                with contextlib.suppress(Exception):
                    await closer.close()
        if self._playwright is not None:
            with contextlib.suppress(Exception):
                await self._playwright.stop()
        self._context = self._browser = self._playwright = self._page = None

    @property
    def capabilities(self) -> dict[str, Any]:  # pragma: no cover - trivial projection
        return capability_report(self.proxy_url)

    # ------------------------------------------------------------------ guards
    async def _on_request(self, route: Any) -> None:  # pragma: no cover - needs the extra
        """Abort any request that is not http(s); everything else goes to the proxy."""
        request_url = str(getattr(route.request, "url", ""))
        if scheme_allowed(request_url):
            with contextlib.suppress(Exception):
                await route.continue_()
            return
        self._refused.append(request_url)
        with contextlib.suppress(Exception):
            await route.abort()

    def _on_download(self, download: Any) -> None:  # pragma: no cover - needs the extra
        """Record a download attempt and cancel it: nothing is written, nothing is run.

        ``accept_downloads=False`` already means Playwright cancels the download; the event is
        still recorded (it is evidence that the page tried) and the cancel is defensive. The
        task is kept so the loop cannot garbage-collect it mid-flight.
        """
        name = str(getattr(download, "suggested_filename", "") or "download")
        self._downloads.append(name)
        with contextlib.suppress(Exception):
            self._tasks.add(asyncio.get_running_loop().create_task(_cancel_quietly(download)))

    def _on_file_chooser(self, chooser: Any) -> None:  # pragma: no cover - needs the extra
        """Record a file chooser and dismiss it without setting any path."""
        self._file_choosers.append("file-chooser")
        with contextlib.suppress(Exception):
            self._tasks.add(asyncio.get_running_loop().create_task(_dismiss_quietly(chooser)))

    def _on_page(self, page: Any) -> None:  # pragma: no cover - needs the extra
        """Close any window the crawl did not open (a popup is a page budget bypass)."""
        if self._page is not None and page is not self._page:
            with contextlib.suppress(Exception):
                self._tasks.add(asyncio.get_running_loop().create_task(_close_quietly(page)))

    # ------------------------------------------------------------------ navigation
    async def navigate(self, url: str) -> RenderedPage:  # pragma: no cover - needs the extra
        self._refused.clear()
        self._downloads.clear()
        self._file_choosers.clear()
        if self._page is None or not browser_available():
            return RenderedPage(url=url, error=unavailable_reason())
        try:
            response = await self._page.goto(url, wait_until="load", timeout=self.timeout_ms)
        except Exception as exc:
            # A refused navigation is data: the proxy refused it, or the page failed to load.
            return RenderedPage(
                url=url,
                error=f"{type(exc).__name__}: {exc}"[:200],
                refused_requests=tuple(self._refused),
                downloads=tuple(self._downloads),
            )
        with contextlib.suppress(Exception):
            await self._page.wait_for_timeout(self.settle_ms)
        raw = ""
        status: int | None = None
        if response is not None:
            with contextlib.suppress(Exception):
                status = int(response.status)
            with contextlib.suppress(Exception):
                raw = (await response.body()).decode("utf-8", errors="replace")[:MAX_BODY_CHARS]
        links = await self._eval(
            "Array.from(document.querySelectorAll('a[href], area[href], form[action]'))"
            ".map(function (el) { return el.href || el.action; }).filter(Boolean)",
            limit=MAX_LINKS,
        )
        sinks = await self._eval("window.__arachneSinkTrace || []")
        history = await self._eval("window.__arachneRouteTrace || []")
        return RenderedPage(
            url=url,
            final_url=str(self._page.url),
            status=status,
            raw_body=raw,
            links=tuple(str(link) for link in links)[:MAX_LINKS],
            sink_records=tuple(sinks)[:64],
            history_routes=tuple(str(route) for route in history)[:MAX_LINKS],
            refused_requests=tuple(self._refused),
            downloads=tuple(self._downloads),
        )

    async def _eval(self, expression: str, *, limit: int = 64) -> list[Any]:
        """Evaluate a read-only expression in the page and return a bounded list."""
        try:
            value = await self._page.evaluate(f"() => ({expression})")
        except Exception:
            return []
        return list(value)[:limit] if isinstance(value, list) else []


async def _cancel_quietly(download: Any) -> None:  # pragma: no cover - needs the extra
    with contextlib.suppress(Exception):
        await download.cancel()


async def _dismiss_quietly(chooser: Any) -> None:  # pragma: no cover - needs the extra
    with contextlib.suppress(Exception):
        await chooser.set_files([])


async def _close_quietly(page: Any) -> None:  # pragma: no cover - needs the extra
    with contextlib.suppress(Exception):
        await page.close()
