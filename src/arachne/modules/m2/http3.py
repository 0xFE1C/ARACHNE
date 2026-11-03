"""HTTP/3 and QUIC probing behind an optional extra (REQ-DET-006).

A growing share of edge deployments terminate QUIC only. A scanner that cannot speak it
reports nothing at all for such a target, and — worse — reports the *absence* of findings as
a clean bill of health. This module gives the header and TLS-parameter families a way to ask
the same question over HTTP/3 as over HTTP/2.

**The dependency rule is the hard part.** ``aioquic`` is an optional extra (``arachne[quic]``),
never a runtime dependency: the air-gapped install, the default install and the test suite must
all work without it. So:

* the import is inside the function that needs it, and its absence is a *recorded observation*
  ("QUIC probing is unavailable in this installation"), never a failure and never a finding;
* the Alt-Svc advertisement is read over HTTP/1.1/2, so "does this target claim HTTP/3?" is
  answered even when the extra is absent;
* only the handshake needs the extra, and a failed or refused handshake is data, not an error.

What this module owns is the transport; what a *finding* is stays with the caller. The M2
check (``m2.http3-probe``) compares the security-relevant response headers of the two
transports, which is the observation that makes "equivalent findings over HTTP/2 and HTTP/3"
testable: a deployment whose QUIC path serves a weaker header set is reported.
"""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "HTTP3_EXTRA",
    "SECURITY_HEADERS",
    "Http3Response",
    "alt_svc_http3",
    "http3_available",
    "http3_get",
    "missing_security_headers",
]

#: The name of the optional dependency group in ``pyproject.toml``.
HTTP3_EXTRA = "quic"

#: Response headers whose *absence* is what a security-header check reports. Kept here (rather
#: than imported from a web module) so this transport module has no dependency on M3/M4.
SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
)


def http3_available() -> bool:
    """True when the optional QUIC client is installed in this installation."""
    try:  # pragma: no cover - the branch depends on the install, not on the code
        import aioquic.h3.connection  # noqa: F401
    except Exception:
        return False
    return True


def alt_svc_http3(headers: dict[str, str]) -> str | None:
    """The ``Alt-Svc`` advertising HTTP/3, or ``None`` when the target does not claim it.

    ``Alt-Svc: h3=":443"; ma=86400`` is how an edge announces that the same origin answers
    QUIC. The whole header value is returned (it is the evidence), while the *presence* of an
    ``h3`` alternative is what the caller keys on.
    """
    for name, value in headers.items():
        if name.lower() != "alt-svc":
            continue
        if any(token.strip().lower().startswith(("h3", '"h3')) for token in value.split(",")):
            return value
        if "h3" in value.lower():
            return value
    return None


def missing_security_headers(
    headers: dict[str, str], *, required: tuple[str, ...] = SECURITY_HEADERS
) -> tuple[str, ...]:
    """The security headers absent from a response, lower-cased, in declaration order."""
    present = {name.lower() for name in headers}
    return tuple(name for name in required if name not in present)


@dataclass(frozen=True, slots=True)
class Http3Response:
    """One HTTP/3 response: the status, the headers and how it was obtained."""

    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body_length: int = 0
    transport: str = "h3"
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None


async def http3_get(
    host: str,
    port: int,
    *,
    path: str = "/",
    server_name: str | None = None,
    wait_s: float = 6.0,
) -> Http3Response:
    """``GET path`` over HTTP/3, or an :class:`Http3Response` carrying the reason it failed.

    The caller must have authorized ``host`` already: this function is the byte-level QUIC
    client and deliberately knows nothing about scope. The M2 check calls it only after the
    scoped HTTP client has reached the same origin, which is what keeps it behind the same
    scope gate (ADR-05's "one egress path" rule is about not inventing a second *unscoped*
    one).

    Without the extra the response says so and no socket is opened.
    """
    if not http3_available():
        return Http3Response(
            error=(
                f"HTTP/3 support is not installed: install arachne[{HTTP3_EXTRA}] to probe "
                "QUIC (the rest of the product is unaffected)"
            )
        )
    try:  # pragma: no cover - exercised only where the optional extra is installed
        return await asyncio.wait_for(
            _fetch(host, port, path=path, server_name=server_name), wait_s
        )
    except TimeoutError:
        return Http3Response(error="timeout")
    except Exception as exc:  # a QUIC handshake that fails is data, not a crash
        return Http3Response(error=f"{type(exc).__name__}: {exc}"[:300])


async def _fetch(  # pragma: no cover - requires the optional extra
    host: str, port: int, *, path: str, server_name: str | None
) -> Http3Response:
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration

    class _H3Client(QuicConnectionProtocol):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._http = H3Connection(self._quic)
            self._done: asyncio.Future[Http3Response] | None = None
            self._status: int | None = None
            self._headers: dict[str, str] = {}
            self._body = 0

        async def get(self, target: str, authority: str) -> Http3Response:
            stream_id = self._quic.get_next_available_stream_id()
            self._http.send_headers(
                stream_id,
                [
                    (b":method", b"GET"),
                    (b":scheme", b"https"),
                    (b":authority", authority.encode()),
                    (b":path", target.encode()),
                ],
                end_stream=True,
            )
            self.transmit()
            loop = asyncio.get_running_loop()
            self._done = loop.create_future()
            return await self._done

        def quic_event_received(self, event: Any) -> None:
            for http_event in self._http.handle_event(event):
                if isinstance(http_event, HeadersReceived):
                    for name, value in http_event.headers:
                        key = name.decode().lower()
                        if key == ":status":
                            self._status = int(value)
                        elif not key.startswith(":"):
                            self._headers[key] = value.decode(errors="replace")
                    if http_event.stream_ended:
                        self._finish()
                elif isinstance(http_event, DataReceived):
                    self._body += len(http_event.data)
                    if http_event.stream_ended:
                        self._finish()

        def _finish(self) -> None:
            if self._done is not None and not self._done.done():
                self._done.set_result(
                    Http3Response(
                        status_code=self._status,
                        headers=dict(self._headers),
                        body_length=self._body,
                    )
                )

    configuration = QuicConfiguration(
        is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
    )
    configuration.server_name = server_name or host
    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=_H3Client,
        wait_connected=True,
    ) as client:
        assert isinstance(client, _H3Client)
        return await client.get(path, server_name or host)
