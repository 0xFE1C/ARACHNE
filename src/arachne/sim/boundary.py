"""The zero-network boundary of area SIM (REQ-SIM-003).

Area SIM's P0 safety property is structural, not conventional: the simulation engine is
**incapable** of reaching the network. Two mechanisms enforce it, and neither trusts the
other.

**At the code boundary (static).** :mod:`arachne.sim.hygiene` declares the imports this
package may not contain — the socket family, the HTTP clients, ``asyncio``, ``subprocess``,
and every ARACHNE module that owns an egress path (``core.http``, ``core.net``,
``modules``, ``creds``, ``proof``, ``intel``, ``plugins``, …). ``test_sim_safety.py`` walks
the package's sources with that list, so a future edit that adds ``import httpx`` to a
simulation file fails CI rather than shipping.

**At runtime (fail closed).** :func:`no_network` is a context manager every public
simulation entry point wraps itself in. For its duration it replaces the socket family's
entry points — the ``socket`` constructor, ``create_connection``, ``getaddrinfo``,
``gethostbyname``, and the methods of both future *and already-constructed* sockets — with
a guard that records a **blocked** ``simulation.boundary_violation`` audit event and raises
:class:`~arachne.core.errors.SimulationNetworkError`. That covers what a source scan
cannot: a collaborator ARACHNE did not write, a dependency that dials on first use, or an
object whose ``__getattr__`` re-exports a client. The call never completes, the error is
never swallowed, and the audit trail says which entry point was tried.

The two halves are why the requirement's accept criterion — *"the sim module cannot reach
the network even if misconfigured"* — is testable in both directions: statically (the
source is clean) and dynamically (an armed socket during a simulation yields a refusal and
zero packets).
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import SimulationNetworkError

__all__ = ["NETWORK_ENTRY_POINTS", "guard_auditor", "is_armed", "no_network"]

#: The socket entry points :func:`no_network` denies, in the order a message names them.
#: Exported so a test can assert *every* one is armed — the boundary is only as strong as
#: its least-patched name.
NETWORK_ENTRY_POINTS: Final[tuple[str, ...]] = (
    "socket.socket",
    "socket.socket.connect",
    "socket.socket.connect_ex",
    "socket.socket.sendto",
    "socket.create_connection",
    "socket.getaddrinfo",
    "socket.gethostbyname",
    "socket.gethostbyname_ex",
)

_REFUSAL: Final = "the simulation engine is structurally offline (REQ-SIM-003)"

#: The genuine ``socket.socket`` class, captured at import time. The guard must restore the
#: real class rather than whatever a previous patch happened to leave behind.
_REAL_SOCKET: Final[type[socket.socket]] = socket.socket

#: The auditor the installed guard reports to, and whether one is installed. Module state
#: because the patched socket callables receive no context of their own; the guard owns it
#: for its lifetime and an exception in the body always restores the previous value.
_current_auditor: Auditor | None = None
_installed: bool = False


def guard_auditor() -> Auditor | None:
    """The auditor of the installed guard (``None`` when no guard is installed)."""
    return _current_auditor if _installed else None


def is_armed() -> bool:
    """True while a :func:`no_network` guard is installed (the boundary is live)."""
    return _installed


def _refuse(entry_point: str, auditor: Auditor | None) -> None:
    """Record the violation and fail closed. This function never returns."""
    if auditor is not None:
        auditor.record(
            AuditAction.SIMULATION_BOUNDARY_VIOLATION,
            outcome=AuditOutcome.BLOCKED,
            reason=_REFUSAL,
            meta={"entry_point": entry_point},
        )
    msg = f"simulation attempted network I/O through {entry_point}: {_REFUSAL}"
    raise SimulationNetworkError(msg, reason="simulation-network-forbidden")


@dataclass(frozen=True, slots=True)
class _EntryPoints:
    """The real callables the guard replaces, so the restore is exact."""

    getaddrinfo: Any
    gethostbyname: Any
    gethostbyname_ex: Any
    create_connection: Any
    connect: Any
    connect_ex: Any
    sendto: Any

    @classmethod
    def capture(cls) -> _EntryPoints:
        return cls(
            getaddrinfo=socket.getaddrinfo,
            gethostbyname=socket.gethostbyname,
            gethostbyname_ex=socket.gethostbyname_ex,
            create_connection=socket.create_connection,
            connect=_REAL_SOCKET.connect,
            connect_ex=_REAL_SOCKET.connect_ex,
            sendto=_REAL_SOCKET.sendto,
        )


class _DeniedSocket(socket.socket):
    """A socket that cannot be constructed while the boundary is installed."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _refuse("socket.socket", _current_auditor)


@contextmanager
def no_network(auditor: Auditor | None = None) -> Iterator[None]:
    """Deny every network entry point for the duration of the block (REQ-SIM-003).

    Nesting is safe: the inner guard restores the outer one's state when it exits, so a
    simulation that runs a sub-simulation keeps the boundary up across both — and the inner
    guard *inherits* the outer one's auditor, because the boundary is one boundary and a
    violation deep inside a sub-simulation belongs in the same trail as one at the edge. The
    restore happens in a ``finally``, so a simulation that raises still leaves the process able
    to scan afterwards.
    """
    global _current_auditor, _installed
    previous = (_current_auditor, _installed)
    effective = auditor if auditor is not None else (_current_auditor if _installed else None)
    real = _EntryPoints.capture()

    def denied(name: str) -> Any:
        def _deny(*_args: Any, **_kwargs: Any) -> Any:
            _refuse(name, effective)

        return _deny

    _current_auditor = effective
    _installed = True
    # Method patches land on the *real* class first, so a socket constructed before the
    # guard was installed cannot use its methods either; the constructor swap then stops any
    # new socket from existing at all.
    _REAL_SOCKET.connect = denied("socket.socket.connect")  # type: ignore[method-assign]
    _REAL_SOCKET.connect_ex = denied("socket.socket.connect_ex")  # type: ignore[method-assign]
    _REAL_SOCKET.sendto = denied("socket.socket.sendto")  # type: ignore[method-assign]
    socket.socket = _DeniedSocket  # type: ignore[misc]
    socket.getaddrinfo = denied("socket.getaddrinfo")
    socket.gethostbyname = denied("socket.gethostbyname")
    socket.gethostbyname_ex = denied("socket.gethostbyname_ex")
    socket.create_connection = denied("socket.create_connection")
    try:
        yield
    finally:
        _REAL_SOCKET.connect = real.connect  # type: ignore[method-assign]
        _REAL_SOCKET.connect_ex = real.connect_ex  # type: ignore[method-assign]
        _REAL_SOCKET.sendto = real.sendto  # type: ignore[method-assign]
        socket.socket = _REAL_SOCKET  # type: ignore[misc]
        socket.getaddrinfo = real.getaddrinfo
        socket.gethostbyname = real.gethostbyname
        socket.gethostbyname_ex = real.gethostbyname_ex
        socket.create_connection = real.create_connection
        _current_auditor, _installed = previous
