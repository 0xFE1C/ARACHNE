"""The scope-bound forward proxy: the browser's only way out (REQ-DET-015, INV-2).

A browser resolves DNS itself, follows redirects itself and opens WebRTC itself. Any of those
would silently bypass the scope gate that every other request in ARACHNE passes through
(R-16: "the headless browser becomes a hole in the scope gate"). The mitigation is structural
and it is this module: **all** browser traffic goes to a loopback HTTP proxy that ARACHNE
runs, and that proxy asks the *same* :func:`~arachne.core.safety.validate_url` gate — same
scope, same address policy, same resolver — before it opens a socket. The browser is
configured with no direct egress and no resolver of its own
(:mod:`arachne.browser.hardening`), so the proxy is not "one of the ways out"; it is the
only one.

Three properties make this the same gate and not a second, weaker one:

* **Validation happens before the connection.** :meth:`ScopeProxy._authorize` runs the gate,
  and only a `ResolvedUrl` from it reaches :func:`open_upstream`. A refusal never dials.
* **The validated address is the address dialled.** The proxy connects to the literal that
  the gate resolved and checked. It never re-resolves, so a DNS-rebinding answer cannot win a
  race between the check and the connect (this is the per-hop revalidation property of
  ``INV-3``, applied to a transport that cannot ask the caller to re-validate).
* **A refusal is audited identically.** ``scope.rejected`` for a host outside the declared
  scope, ``safety.blocked`` for an address outside the policy, ``airgap.blocked`` for a host
  the air-gapped estate's allowlist does not cover: the same three actions the shared HTTP
  client writes (F-01-08, REQ-RESIL-001), so "what did the browser try to reach?" is
  answerable from the audit trail alone. Air-gapped mode is a first-class mode, so a second
  scoped transport must not be a way *around* a control the first one enforces.

The proxy speaks HTTP/1.1 in its two permitted forms — ``CONNECT host:port`` for TLS and
absolute-form requests for plain HTTP — and a path-only request line is resolved against the
``Host`` header. Anything else (a non-HTTP scheme, a missing or contradictory target) is
refused with a 4xx and audited, because a request the proxy cannot *name* is a request it
cannot validate (ADR-05's one-egress-path rule is about not inventing an unscoped path; a
scoped second transport is what ``m2.http3-probe`` already does).
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Final
from urllib.parse import urlsplit

from arachne.core.airgap import AirgapPolicy
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import OutOfScopeError, SafetyError
from arachne.core.safety import (
    HostResolver,
    ResolvedUrl,
    Scope,
    UrlSafetyPolicy,
    validate_url,
)

__all__ = [
    "MAX_HEADER_BYTES",
    "ProxyRefusal",
    "ScopeProxy",
    "open_upstream",
    "refusal_summary",
]

#: Headers that describe the client-to-proxy hop and must not be forwarded to the origin.
_HOP_BY_HOP_HEADERS: Final[frozenset[str]] = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

#: A request head larger than this is refused rather than buffered: the proxy is reachable
#: only by the browser ARACHNE started, and a hostile page must not be able to make it
#: allocate without bound.
MAX_HEADER_BYTES: Final = 64 * 1024

#: How long to wait for a head, a connect or a byte. Bounded so one wedged socket cannot
#: stall the crawl past its own budget.
_IO_TIMEOUT_S: Final = 20.0


@dataclass(frozen=True, slots=True)
class ProxyRefusal:
    """One request the proxy refused, and why (the evidence a test asserts on)."""

    target: str
    reason: str
    action: str

    def to_dict(self) -> dict[str, str]:
        return {"target": self.target, "reason": self.reason, "action": self.action}


async def open_upstream(
    address: str, port: int, *, timeout_s: float = _IO_TIMEOUT_S
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Dial ``address`` (a literal the gate already resolved and checked) and return the pair.

    Module-level so a test can arm it: replacing this with a function that raises proves a
    refused navigation never dialled. The proxy calls it with the address from
    :class:`~arachne.core.safety.ResolvedUrl`, never with a hostname, so there is no second,
    unchecked resolution between the gate and the socket.
    """
    return await asyncio.wait_for(asyncio.open_connection(address, port), timeout_s)


@dataclass(slots=True)
class ScopeProxy:
    """A loopback forward proxy that refuses to dial anything the scope gate refuses."""

    scope: Scope
    auditor: Auditor
    policy: UrlSafetyPolicy = field(default_factory=UrlSafetyPolicy)
    resolver: HostResolver | None = None
    #: The deployment's air-gapped egress policy (S25, REQ-RESIL-001), copied from the scan's
    #: HTTP client. Inert unless the deployment set ``ARACHNE_AIRGAPPED``; when it did, a host
    #: the air-gap allowlist does not cover is refused here exactly as it is refused on the
    #: shared egress path — a second scoped transport must not become a way *around* a control
    #: that the first one enforces.
    airgap: AirgapPolicy = field(default_factory=AirgapPolicy)
    airgap_scope_hosts: tuple[str, ...] = ()
    #: Counters for evidence and tests. ``dialed`` is the literal address:port the proxy
    #: actually connected to, which is how a test proves the *validated* address was used.
    seen: int = 0
    allowed: int = 0
    blocked: int = 0
    refusals: list[ProxyRefusal] = field(default_factory=list)
    dialed: list[str] = field(default_factory=list)

    _server: asyncio.AbstractServer | None = field(default=None, init=False, repr=False)
    _port: int = field(default=0, init=False, repr=False)
    _connectors: set[asyncio.Task[None]] = field(default_factory=set, init=False, repr=False)

    # ------------------------------------------------------------------ lifecycle
    @property
    def port(self) -> int:
        return self._port

    @property
    def proxy_url(self) -> str:
        """The ``--proxy-server`` value: loopback and an ephemeral port."""
        return f"http://127.0.0.1:{self._port}"

    async def start(self) -> ScopeProxy:
        """Bind on ``127.0.0.1:0`` and serve. Returns ``self`` for chaining."""
        self._server = await asyncio.start_server(self._serve, host="127.0.0.1", port=0)
        socket = self._server.sockets[0] if self._server.sockets else None
        if socket is None:  # pragma: no cover - a listening asyncio server always has one
            raise RuntimeError("the browser proxy could not determine its bound port")
        self._port = int(socket.getsockname()[1])
        return self

    async def aclose(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        for task in list(self._connectors):
            task.cancel()
        self._connectors.clear()

    # ------------------------------------------------------------------ the gate
    async def _authorize(self, url: str) -> ResolvedUrl | None:
        """Run the shared scope gate, auditing a refusal. ``None`` means "refused".

        Then the air-gap policy, which the shared client applies separately from the scope
        check: a host can be inside the scan's declared scope and outside the air-gapped
        estate's allowlist, and only the policy decides that. Both refusals happen before
        :func:`open_upstream` is ever reached.
        """
        try:
            resolved = await validate_url(
                url, self.scope, policy=self.policy, resolver=self.resolver
            )
        except OutOfScopeError as exc:
            self._refuse(url, exc.reason or "out-of-scope", AuditAction.SCOPE_REJECTED)
            return None
        except SafetyError as exc:
            self._refuse(url, exc.reason or "unsafe-url", AuditAction.SAFETY_BLOCKED)
            return None
        airgap_refusal = self.airgap.refusal(resolved.host, scope_hosts=self.airgap_scope_hosts)
        if airgap_refusal is not None:
            self._refuse(url, airgap_refusal, AuditAction.AIRGAP_BLOCKED)
            return None
        return resolved

    def _refuse(self, target: str, reason: str, action: AuditAction) -> None:
        self.blocked += 1
        self.refusals.append(ProxyRefusal(target=target, reason=reason, action=str(action)))
        self.auditor.record(
            action,
            outcome=AuditOutcome.BLOCKED,
            target=target,
            reason=reason,
            meta={"method_hint": "browser-proxy"},
        )

    # ------------------------------------------------------------------ serving
    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connectors.add(task)
        try:
            await self._handle(reader, writer)
        except Exception:  # noqa: S110 - one connection's failure must not stop the proxy;
            # the refusal path audits anything that matters, and a truncated or hostile
            # request is not a scanner event. Closing the connection is the whole response.
            pass
        finally:
            if task is not None:
                self._connectors.discard(task)
            with contextlib.suppress(Exception):
                writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await self._read_head(reader)
        if head is None:
            await self._respond(writer, 400, "Bad Request", "malformed proxy request")
            return
        request_line, headers = head
        self.seen += 1
        target = request_line.partition(" ")[0].upper() == "CONNECT"
        method, _, rest = request_line.partition(" ")
        authority, _, version = rest.partition(" ")
        if not method or not authority:
            await self._respond(writer, 400, "Bad Request", "malformed request line")
            return

        url = self._target_url(method, authority, headers)
        if url is None:
            self._refuse(authority, "non-http-target", AuditAction.SAFETY_BLOCKED)
            await self._respond(writer, 403, "Forbidden", "only http(s) targets are proxied")
            return

        resolved = await self._authorize(url)
        if resolved is None:
            await self._respond(writer, 403, "Forbidden", "out of scope")
            return

        upstream = await self._dial(resolved)
        if upstream is None:
            await self._respond(writer, 502, "Bad Gateway", "upstream unreachable")
            return

        up_reader, up_writer = upstream
        self.allowed += 1
        try:
            if target:
                await self._tunnel(writer, reader, up_writer, up_reader)
            else:
                await self._forward(
                    writer, reader, up_writer, up_reader, method, authority, version, headers
                )
        finally:
            with contextlib.suppress(Exception):
                up_writer.close()
            with contextlib.suppress(Exception):
                await up_writer.wait_closed()

    async def _dial(
        self, resolved: ResolvedUrl
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        """Dial the first validated address that answers. Literals only — no re-resolution."""
        for address in resolved.addresses:
            try:
                pair = await open_upstream(address, resolved.port)
            except Exception:  # noqa: S112 - a refused/unreachable address is data: the next
                # validated address (a multi-homed host) is tried, and the caller answers 502
                # when none of them answers. None of these addresses is unvalidated: they all
                # came from the gate.
                continue
            self.dialed.append(f"{address}:{resolved.port}")
            return pair
        return None

    @staticmethod
    def _target_url(method: str, authority: str, headers: dict[str, str]) -> str | None:
        """The absolute URL a request targets, or ``None`` when it cannot be named.

        ``CONNECT host:port`` is the TLS case (the browser then speaks TLS through the
        tunnel, so the proxy never sees plaintext). An absolute-form request line already
        carries the URL. A path-only line is completed from ``Host`` — and refused when there
        is no ``Host`` to complete it with, because a request the proxy cannot name is a
        request it cannot validate. Anything else, including ``file:///etc/passwd``, is
        ``None``: the caller audits and refuses it.
        """
        if method == "CONNECT":
            host, _, port = authority.rpartition(":")
            if not host:
                return None
            return f"https://{host}:{port}/"
        scheme = urlsplit(authority).scheme.lower()
        if scheme in {"http", "https"}:
            return authority
        if authority.startswith("/"):
            host = headers.get("host", "").strip()
            if not host:
                return None
            return f"http://{host}{authority}"
        return None

    # ------------------------------------------------------------------ framing
    @staticmethod
    async def _read_head(
        reader: asyncio.StreamReader,
    ) -> tuple[str, dict[str, str]] | None:
        """Read and parse one request head, bounded. ``None`` means "unparseable"."""
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), _IO_TIMEOUT_S)
        except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return None
        if len(raw) > MAX_HEADER_BYTES:
            return None
        try:
            text = raw.decode("latin-1")
        except UnicodeDecodeError:  # pragma: no cover - latin-1 decodes every byte
            return None
        lines = text.split("\r\n")
        request_line = lines[0]
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, separator, value = line.partition(":")
            if separator:
                headers[name.strip().lower()] = value.strip()
        return request_line, headers

    async def _tunnel(
        self,
        client_writer: asyncio.StreamWriter,
        client_reader: asyncio.StreamReader,
        up_writer: asyncio.StreamWriter,
        up_reader: asyncio.StreamReader,
    ) -> None:
        """``200 Connection Established`` and then pipe bytes both ways (TLS passthrough)."""
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        await self._pump(client_reader, up_writer, up_reader, client_writer)

    async def _forward(
        self,
        client_writer: asyncio.StreamWriter,
        client_reader: asyncio.StreamReader,
        up_writer: asyncio.StreamWriter,
        up_reader: asyncio.StreamReader,
        method: str,
        authority: str,
        version: str,
        headers: dict[str, str],
    ) -> None:
        """Forward a plain-HTTP request in origin form, then pipe the exchange both ways.

        The method, the headers and the body are passed through unchanged — the browser is
        measuring the application, so the request it makes must be the request the
        application sees. Only the framing changes: the absolute-form target becomes
        origin-form, and the hop-by-hop proxy headers are dropped because they describe the
        *client-to-proxy* hop and mean nothing to the origin.
        """
        parts = urlsplit(authority)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        upstream_version = version if version.startswith("HTTP/") else "HTTP/1.1"
        up_writer.write(f"{method} {path} {upstream_version}\r\n".encode())
        for name, value in headers.items():
            if name in _HOP_BY_HOP_HEADERS or name == "host":
                continue
            up_writer.write(f"{name}: {value}\r\n".encode())
        up_writer.write(f"Host: {parts.netloc}\r\n".encode())
        up_writer.write(b"Connection: close\r\n\r\n")
        await up_writer.drain()
        await self._pump(client_reader, up_writer, up_reader, client_writer)

    @staticmethod
    async def _pump(
        client_reader: asyncio.StreamReader,
        up_writer: asyncio.StreamWriter,
        up_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        async def copy(source: asyncio.StreamReader, sink: asyncio.StreamWriter) -> None:
            while True:
                try:
                    chunk = await asyncio.wait_for(source.read(65536), _IO_TIMEOUT_S)
                except (TimeoutError, OSError):
                    return
                if not chunk:
                    return
                sink.write(chunk)
                try:
                    await sink.drain()
                except OSError:
                    return

        tasks = [
            asyncio.create_task(copy(client_reader, up_writer)),
            asyncio.create_task(copy(up_reader, client_writer)),
        ]
        try:
            await asyncio.gather(*tasks)
        except Exception:  # noqa: S110 - pragma: no cover - a severed pipe is a closed
            # connection, which is the normal end of a tunnel. The tasks are cancelled below.
            pass
        finally:
            for task in tasks:
                task.cancel()

    @staticmethod
    async def _respond(writer: asyncio.StreamWriter, status: int, phrase: str, detail: str) -> None:
        body = f"{detail}\n".encode()
        writer.write(
            f"HTTP/1.1 {status} {phrase}\r\n".encode()
            + b"Content-Type: text/plain\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        with contextlib.suppress(Exception):
            await writer.drain()


def refusal_summary(proxy: ScopeProxy) -> dict[str, object]:
    """A JSON-safe summary of what the proxy saw (evidence for a finding or a step stat)."""
    return {
        "requests": proxy.seen,
        "allowed": proxy.allowed,
        "blocked": proxy.blocked,
        "refusals": [refusal.to_dict() for refusal in proxy.refusals],
        "dialed": list(proxy.dialed),
    }
