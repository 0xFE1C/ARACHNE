"""The reconnaissance-breadth lab (WP-34, REQ-DET-027).

Two small fixtures for the two M1 checks that read the crawl rather than a third party:

* :func:`build_inventory` builds the :class:`~arachne.modules.m3.inventory.WebInventory` the
  crawl would have produced — a page set with headers and bodies — so the technology-breadth
  check can be driven without a crawl and with an exact control over what the pages publish;
* :func:`start_vhost_lab` serves one origin whose answer depends on the ``Host`` header, which
  is what virtual-host discovery probes: the same address answering a second application for a
  second name.

The inventory builder writes no request of its own, and the lab answers only ``GET``/``HEAD``
with static documents. Neither fixture authenticates, writes or executes anything.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from arachne.modules.m3.inventory import Page, WebInventory

__all__ = [
    "ORIGIN_BODY",
    "VHOST_BODY",
    "VHOST_NAME",
    "VhostLab",
    "build_inventory",
    "start_vhost_lab",
]

#: The name the lab serves a second application for.
VHOST_NAME = "vhost.lab.test"

#: The origin's own page: it names the alternate host (an absolute link), which is where the
#: check's candidate set comes from.
ORIGIN_BODY = (
    "<!doctype html><html><head><title>Arachne lab</title>"
    "<meta name='generator' content='arachne-lab 1.4'>"
    "</head><body><h1>Lab</h1>"
    "<p>Partner console: <a href='http://vhost.lab.test/'>vhost.lab.test</a></p>"
    "<script src='/app.js'></script></body></html>"
)

#: The alternate application's page: a *different* document, which is what corroborates it.
VHOST_BODY = (
    "<!doctype html><html><head><title>Partner console</title></head>"
    "<body><h1>Partner console</h1><p>internal reporting only</p></body></html>"
)

#: A page set that publishes no technology marker (the decoy for the breadth check).
PLAIN_BODY = "<!doctype html><html><body><h1>Hello</h1></body></html>"


def build_inventory(
    origin: str,
    *,
    pages: Iterable[Mapping[str, object]] | None = None,
    host: str | None = None,
) -> WebInventory:
    """A crawl inventory for ``origin``.

    ``pages`` is a sequence of ``{"url", "status", "headers", "body", "content_type"}`` rows;
    the default is the single origin page. Every page's host is the origin's host unless the row
    overrides it, so the origin's baseline fingerprint resolves.
    """
    rows = list(pages) if pages is not None else [{"url": origin, "body": ORIGIN_BODY}]
    inventory = WebInventory(roots=(origin,), origin=host, origins=(origin,))
    for row in rows:
        url = str(row["url"])
        headers = {str(k): str(v) for k, v in dict(row.get("headers") or {}).items()}  # type: ignore[arg-type]
        inventory.add_page(
            Page(
                url=url,
                status=int(row.get("status", 200)),  # type: ignore[arg-type]
                headers=headers,
                body=str(row.get("body", "")),
                content_type=str(row.get("content_type", "text/html; charset=utf-8")),
                elapsed_ms=1.0,
            )
        )
    inventory.visited = len(rows)
    return inventory


@dataclass
class VhostLab:
    """A running Host-branching lab: the origin's own page, and the alternate name's page."""

    base_url: str
    port: int
    vhost: str = VHOST_NAME
    requests: list[str] = field(default_factory=list)


class _Handler(BaseHTTPRequestHandler):
    server_version = "arachne-recon-lab/1.0"
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True
    lab: VhostLab

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def do_GET(self) -> None:
        host = (self.headers.get("Host") or "").split(":", 1)[0].lower()
        self.lab.requests.append(f"{self.command} {self.path} Host={host}")
        body = VHOST_BODY if host == self.lab.vhost else ORIGIN_BODY
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_HEAD(self) -> None:
        self.do_GET()


@contextmanager
def start_vhost_lab(*, vhost: str = VHOST_NAME) -> Iterator[VhostLab]:
    """Start the Host-branching lab on an ephemeral loopback port."""
    lab = VhostLab(base_url="", port=0, vhost=vhost)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    _Handler.lab = lab
    lab.port = int(server.server_address[1])
    lab.base_url = f"http://127.0.0.1:{lab.port}"
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
