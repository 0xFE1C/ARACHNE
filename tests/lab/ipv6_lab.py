"""An IPv6-only loopback lab (REQ-DET-007).

Nothing in the shipped lab binds ``::1``, so "an IPv6-only fixture is scanned by the port, TLS
and header families" had no fixture to prove itself against. This module adds exactly that:
an HTTP server and a TLS server bound to ``::1`` only — no ``127.0.0.1`` listener on those
ports exists — so a scan that works here demonstrably used IPv6.

They reuse the M2 lab's handlers (a real nginx-flavoured HTTP response and the expired,
self-signed TLS endpoint), so the assertions are about the address family, not about a second
implementation of the protocol.
"""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field

from tests.lab.arachne_lab import Handler, _http, _tls_handler

__all__ = ["IPV6_HOST", "Ipv6Lab", "start_ipv6_lab"]

#: The one address this lab listens on. There is deliberately no IPv4 twin.
IPV6_HOST = "::1"


class _Ipv6Server:
    """A threaded TCP server bound to one IPv6 address (the IPv6 twin of ``_TcpServer``)."""

    def __init__(self, handler: Handler, *, name: str) -> None:
        self.handler = handler
        self.name = name
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # IPv6-only: ``IPV6_V6ONLY`` keeps a dual-stack Linux kernel from also accepting IPv4
        # connections, so "this target is reachable over IPv6" cannot pass by accident.
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        self.socket.bind((IPV6_HOST, 0))
        self.socket.listen(16)
        self.socket.settimeout(0.2)
        self.port = int(self.socket.getsockname()[1])
        self._running = True
        self._thread = threading.Thread(target=self._serve, name=f"lab6-{name}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while self._running:
            try:
                connection, _ = self.socket.accept()
            except (TimeoutError, OSError):
                if not self._running:
                    return
                continue
            threading.Thread(
                target=self._handle,
                args=(connection,),
                daemon=True,
                name=f"lab6-{self.name}-conn",
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(5.0)
            self.handler(connection)
        except Exception:  # a fixture must never fail a test by raising in its thread
            return
        finally:
            with suppress(OSError):
                connection.close()

    def stop(self) -> None:
        self._running = False
        with suppress(OSError):
            self.socket.close()


@dataclass
class Ipv6Lab:
    """The two IPv6-only endpoints, plus the target definition fragment to scan them."""

    host: str = IPV6_HOST
    http_port: int = 0
    tls_port: int = 0
    _servers: list[_Ipv6Server] = field(default_factory=list)

    @property
    def http_url(self) -> str:
        return f"http://[{self.host}]:{self.http_port}/"

    def stop(self) -> None:
        for server in self._servers:
            server.stop()
        self._servers.clear()


@contextmanager
def start_ipv6_lab() -> Iterator[Ipv6Lab]:
    lab = Ipv6Lab()
    for name, handler, attribute in (
        ("ipv6-http", _http, "http_port"),
        ("ipv6-tls", _tls_handler(), "tls_port"),
    ):
        server = _Ipv6Server(handler, name=name)
        server.start()
        lab._servers.append(server)
        setattr(lab, attribute, server.port)
    try:
        yield lab
    finally:
        lab.stop()
