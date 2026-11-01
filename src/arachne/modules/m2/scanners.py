"""Scanner backends: the python-nmap wrapper and the pure-Python connect fallback.

 asks for "python-nmap (thin), masscan wrapper, ... pure-Python fallbacks
for core HTTP checks", and M2 is where that trade-off is real: ``nmap`` gives better port
state classification and service/version fingerprints, but it is an external binary that
many deployments (and every CI runner without the package installed) do not have. So M2
always has a working backend:

``ConnectBackend``
    Pure Python, on top of :class:`~arachne.core.net.ScopedNetClient`. It is the **default**
    and the fallback: a TCP ``connect()`` scan over a top-ports policy, plus the active
    identification suite of ``m2.fingerprint``. It needs no privileges and no external tool,
    which is what makes the offline lab scan possible.
``NmapBackend``
    A thin adapter over ``python-nmap``, used when the library *and* the ``nmap`` binary are
    both present and ``ARACHNE_NET_NMAP_ENABLED`` is set. It is deliberately thin: it maps
    nmap's result dictionary onto :class:`PortFinding` and nothing else, so no probe logic
    lives in a place a test cannot reach.

``pick_backend`` chooses, and records *why* in the finding it returns, because "which tool
produced this evidence" is part of the provenance a report has to carry (F-02-10).
"""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from arachne.core.config import NetSettings, Settings
from arachne.core.logging import get_logger
from arachne.core.net import ScopedNetClient

__all__ = [
    "ConnectBackend",
    "NmapBackend",
    "PortFinding",
    "ScanBackend",
    "pick_backend",
]

_logger = get_logger("modules.m2.scanners")


@dataclass(frozen=True, slots=True)
class PortFinding:
    """One probed port: its state, and whatever the backend could name about it."""

    host: str
    port: int
    state: str
    protocol: str = "tcp"
    banner: str = ""
    #: The port catalogue's hint for this port (never a conclusion).
    service_hint: str | None = None
    #: Set when the backend itself identified the service (nmap's ``-sV``).
    product: str | None = None
    version: str | None = None
    #: Which backend produced this finding (``connect``, ``nmap``).
    source: str = "connect"
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def open(self) -> bool:
        return self.state == "open"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "source": self.source,
        }
        if self.service_hint:
            payload["service_hint"] = self.service_hint
        if self.product:
            payload["product"] = self.product
            payload["version"] = self.version
        if self.banner:
            payload["banner"] = self.banner[:256]
        if self.elapsed_ms:
            payload["elapsed_ms"] = self.elapsed_ms
        if self.error:
            payload["error"] = self.error
        return payload


class ScanBackend(Protocol):
    """What a port scanner has to provide for M2's checks."""

    @property
    def name(self) -> str: ...

    async def probe_ports(
        self,
        host: str,
        ports: Sequence[int],
        *,
        protocol: str = "tcp",
    ) -> tuple[PortFinding, ...]: ...


@dataclass
class ConnectBackend:
    """The pure-Python TCP connect scan (research ch02#5) over the scoped net client."""

    client: ScopedNetClient
    settings: NetSettings
    #: The catalogue's service hints, so a finding carries the port's neutral name.
    hints: Mapping[int, str] = field(default_factory=dict)

    @property
    def name(self) -> str:
        return "connect"

    async def probe_ports(
        self,
        host: str,
        ports: Sequence[int],
        *,
        protocol: str = "tcp",
    ) -> tuple[PortFinding, ...]:
        if protocol != "tcp":
            msg = "the connect backend probes TCP only"
            raise ValueError(msg)
        outcomes = await self.client.probe_ports(host, ports)
        return tuple(
            PortFinding(
                host=outcome.host,
                port=outcome.port,
                state=outcome.state,
                banner=outcome.banner,
                service_hint=self.hints.get(outcome.port),
                source=self.name,
                elapsed_ms=outcome.elapsed_ms,
                error=outcome.error,
            )
            for outcome in outcomes
        )


class NmapBackend:
    """A thin ``python-nmap`` adapter (research ch02#4/#7/#9).

    Constructed with the ``PortScanner`` instance so tests can pass a fake and assert on the
    mapping without nmap installed. Blocking calls run in a worker thread, so an nmap scan
    never stalls the event loop.
    """

    #: nmap arguments: connect scan (no raw-socket privileges needed), version detection at
    #: the lightest intensity, no DNS and no host discovery — M2 already knows the target is
    #: up, and ``-Pn`` keeps the scan honest about what was probed.
    DEFAULT_ARGUMENTS = "-sT -Pn -n --version-light --max-retries 2"

    def __init__(
        self,
        scanner: Any,
        *,
        settings: NetSettings,
        arguments: str | None = None,
        hints: Mapping[int, str] | None = None,
    ) -> None:
        self._scanner = scanner
        self.settings = settings
        self.arguments = arguments or self.DEFAULT_ARGUMENTS
        self.hints = dict(hints or {})
        self.last_error: str | None = None

    @property
    def name(self) -> str:
        return "nmap"

    @classmethod
    def available(cls, settings: NetSettings, *, which: Any = shutil.which) -> bool:
        """True when python-nmap *and* the ``nmap`` binary are present and nothing forbids it."""
        if not settings.nmap_enabled:
            return False
        try:
            import nmap  # noqa: F401  (the import itself is the availability check)
        except Exception:
            return False
        return which("nmap") is not None

    @classmethod
    def from_settings(
        cls, settings: Settings, *, hints: Mapping[int, str] | None = None
    ) -> NmapBackend | None:
        """Build a backend bound to a real ``PortScanner``, or ``None`` when unavailable."""
        if not cls.available(settings.net):
            return None
        try:
            import nmap
        except Exception:  # pragma: no cover - guarded by available()
            return None
        return cls(nmap.PortScanner(), settings=settings.net, hints=hints)

    async def probe_ports(
        self,
        host: str,
        ports: Sequence[int],
        *,
        protocol: str = "tcp",
    ) -> tuple[PortFinding, ...]:
        port_spec = ",".join(str(port) for port in sorted(set(ports)))
        if not port_spec:
            return ()

        def run() -> dict[str, Any]:
            self._scanner.scan(hosts=host, ports=port_spec, arguments=self.arguments)
            return dict(self._scanner[host])

        try:
            result = await asyncio.wait_for(
                asyncio.to_thread(run), float(self.settings.nmap_timeout_s)
            )
        except TimeoutError:
            self.last_error = "nmap timed out"
            _logger.warning(
                "nmap scan timed out",
                extra={"event": "m2.nmap_timeout", "host": host, "ports": port_spec},
            )
            return ()
        except Exception as exc:  # a backend failure degrades to no findings, never a crash
            self.last_error = f"{exc.__class__.__name__}: {exc}"
            _logger.warning(
                "nmap scan failed",
                extra={"event": "m2.nmap_failed", "host": host, "error": self.last_error},
            )
            return ()

        findings: list[PortFinding] = []
        for port_protocol in ("tcp", "udp"):
            table = result.get(port_protocol) or {}
            if not isinstance(table, Mapping):
                continue
            for raw_port, info in table.items():
                if not isinstance(info, Mapping):
                    continue
                try:
                    port = int(raw_port)
                except (TypeError, ValueError):
                    continue
                product = _clean(info.get("product")) or None
                version = _clean(info.get("version")) or None
                findings.append(
                    PortFinding(
                        host=host,
                        port=port,
                        state=str(info.get("state", "unknown")),
                        protocol=port_protocol,
                        service_hint=self.hints.get(port) or _clean(info.get("name")) or None,
                        product=product,
                        version=version,
                        banner=_banner_from(info),
                        source=self.name,
                    )
                )
        return tuple(findings)


def _clean(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _banner_from(info: Mapping[str, Any]) -> str:
    """A banner-shaped summary of what nmap reported (its own banner is in ``extrainfo``)."""
    parts = [
        part
        for part in (
            _clean(info.get("product")),
            _clean(info.get("version")),
            _clean(info.get("extrainfo")),
        )
        if part
    ]
    return " ".join(parts)[:256]


def pick_backend(
    client: ScopedNetClient,
    *,
    settings: Settings | None = None,
    hints: Mapping[int, str] | None = None,
    prefer_nmap: bool = True,
) -> ScanBackend:
    """Choose the best available backend: nmap when present and allowed, else connect."""
    effective = settings or client.settings
    if prefer_nmap:
        backend = NmapBackend.from_settings(effective, hints=hints)
        if backend is not None:
            return backend
    return ConnectBackend(client=client, settings=effective.net, hints=dict(hints or {}))
