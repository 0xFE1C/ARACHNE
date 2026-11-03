"""A tiny HTTP/3 server for the QUIC parity tests (REQ-DET-006).

``aioquic`` is an optional extra (``arachne[quic]``), so this module imports it **inside** the
factory: importing the lab module must never require it. A test that needs a QUIC server asks
``aioquic_available()`` first (or ``pytest.importorskip``), so the suite passes identically
with and without the extra installed.

The server answers one GET with a configurable header set, which is what lets the parity test
plant the defect it exists to find: a QUIC path whose security headers are weaker than the
TCP path's.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

__all__ = ["QuicLab", "aioquic_available", "start_http3_lab"]

CERT_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "lab"


def aioquic_available() -> bool:
    try:
        import aioquic.h3.connection  # noqa: F401
    except Exception:
        return False
    return True


@dataclass
class QuicLab:
    """One running HTTP/3 endpoint."""

    port: int
    headers: dict[str, str] = field(default_factory=dict)
    _server: Any = None

    @property
    def base_url(self) -> str:
        return f"https://127.0.0.1:{self.port}/"


@asynccontextmanager
async def start_http3_lab(headers: dict[str, str] | None = None):
    """Serve one HTTP/3 GET on ``127.0.0.1`` with ``headers``; yield a :class:`QuicLab`.

    The request path is ignored: every GET answers 200 with the configured headers, because
    the observation under test is the header set, not routing.
    """
    from aioquic.asyncio import serve
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration

    extra = dict(headers or {})
    encoded = [(name.encode(), value.encode()) for name, value in extra.items()]

    class _Server(QuicConnectionProtocol):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._http = H3Connection(self._quic)

        def quic_event_received(self, event: Any) -> None:
            for http_event in self._http.handle_event(event):
                if not isinstance(http_event, HeadersReceived):
                    continue
                self._http.send_headers(
                    http_event.stream_id,
                    [(b":status", b"200"), *encoded],
                    end_stream=True,
                )
                self.transmit()

    configuration = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    configuration.load_cert_chain(str(CERT_DIR / "valid.crt"), str(CERT_DIR / "valid.key"))
    server = await serve(
        "127.0.0.1",
        0,
        configuration=configuration,
        create_protocol=partial(_Server),
    )
    sockname = server._transport.get_extra_info("sockname")
    lab = QuicLab(port=int(sockname[1]), headers=extra, _server=server)
    try:
        yield lab
    finally:
        server.close()
        wait = getattr(server, "wait_closed", None)
        if wait is not None:
            with suppress(TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(wait(), 2)
