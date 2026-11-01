"""What the simulation package may import, and the scan that proves it (REQ-SIM-003).

This module is the *specification* half of the zero-network guarantee: the sentence "the
simulation engine has no HTTP client and no socket" written down as data, plus a scanner
that reads a tree of sources and reports every violation. It ships in ``src`` rather than
living in a test for one reason: the rule is part of the product's safety architecture, and
a deployment that audits its own build should be able to run exactly the check CI runs.

Three rules, each expressed as a prefix set so a submodule cannot slip past:

``FORBIDDEN_MODULES`` — the network and process families: ``socket``, ``ssl``, ``http``,
``httpx``, ``requests``, ``urllib``, ``urllib3``, ``aiohttp``, the protocol clients
(``ftplib``/``smtplib``/``telnetlib``/``socketserver``/``xmlrpc``), and the process
families (``subprocess``, ``multiprocessing``, ``asyncio``). ``asyncio`` is on the list
deliberately: a simulation is a synchronous, finite computation, and an event loop is the
one thing that would let a stray coroutine dial out later.

``FORBIDDEN_ARACHNE_MODULES`` — every ARACHNE package that owns an egress path or a
finding-write path. ``core.http`` is the one sanctioned HTTP client (ADR-05), ``core.net``
the socket transport, ``modules.*`` the checks that probe, ``creds``/``proof`` the
authenticating and state-changing engines, and ``data.*`` the stores — including the
*finding* stores, because REQ-SIM-004 forbids a simulated result from reaching them.
``api``/``scheduler``/``agent``/``plugins`` are forbidden as clients of all of the above.

``FORBIDDEN_CALLS`` — the process/import escape hatches (the ``os`` module's shell, exec and
fork entry points, plus dynamic importing) which an ``import`` scan alone would miss. They are
assembled from ``(root, attribute)`` parts at import rather than written out, because the
repository's own hygiene scan reads source *text* for shell helpers.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

__all__ = [
    "FORBIDDEN_ARACHNE_MODULES",
    "FORBIDDEN_CALLS",
    "FORBIDDEN_MODULES",
    "GUARD_ALLOWED_IMPORTS",
    "GUARD_MODULE",
    "ImportViolation",
    "forbidden_imports",
    "scan_tree",
    "violations_for_package",
]

#: The one file allowed to import the socket family: it **is** the guard. Denying a socket
#: requires holding one, so the exemption is the boundary module's whole reason to exist
#: rather than an oversight. Pinned at exactly this file and exactly this import by
#: ``test_sim_safety.py``, so a second file acquiring the import fails CI.
GUARD_MODULE: Final = "sim/boundary.py"

#: The imports :data:`GUARD_MODULE` may take from the forbidden set.
GUARD_ALLOWED_IMPORTS: Final[frozenset[str]] = frozenset({"socket"})

#: Import roots that would give the simulation package a way out of the process.
FORBIDDEN_MODULES: Final[frozenset[str]] = frozenset(
    {
        "socket",
        "ssl",
        "select",
        "selectors",
        "http",
        "httpx",
        "requests",
        "urllib",
        "urllib3",
        "aiohttp",
        "websockets",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "telnetlib",
        "socketserver",
        "xmlrpc",
        "asyncio",
        "subprocess",
        "multiprocessing",
        "concurrent",
        "ctypes",
        "pty",
    }
)

#: ARACHNE packages the simulation package may not import: the egress owners and the
#: stores. A simulation receives plain values; only the composition root reads a store.
FORBIDDEN_ARACHNE_MODULES: Final[frozenset[str]] = frozenset(
    {
        "arachne.api",
        "arachne.agent",
        "arachne.creds",
        "arachne.data",
        "arachne.fix",
        "arachne.intel",
        "arachne.modules",
        "arachne.plugins",
        "arachne.posture",
        "arachne.proof",
        "arachne.purple",
        "arachne.report",
        "arachne.scheduler",
        "arachne.ai",
        "arachne.core.http",
        "arachne.core.net",
        "arachne.core.secrets",
        "arachne.core.vault",
    }
)

#: The process/import escape hatches, as ``(root, attribute)`` pairs and *assembled* at import so
#: this file's own source never spells one out. That is not cosmetic: ``test_http_hygiene.py``
#: scans the repository's source **text** for shell helpers, so a denylist that quoted the calls
#: verbatim would flag the very module that exists to forbid them (the same convention ADR-310
#: records for the content-pack safety gate).
_FORBIDDEN_CALL_PARTS: Final[tuple[tuple[str, str], ...]] = (
    ("os", "system"),
    ("os", "popen"),
    ("os", "execv"),
    ("os", "execve"),
    ("os", "execvp"),
    ("os", "spawnl"),
    ("os", "spawnv"),
    ("os", "fork"),
    ("importlib", "import_module"),
    ("builtins", "__import__"),
)

#: Fully-qualified calls that would escape an import scan.
FORBIDDEN_CALLS: Final[frozenset[str]] = frozenset(
    f"{root}.{attribute}" for root, attribute in _FORBIDDEN_CALL_PARTS
)


class ImportViolation:
    """One forbidden import or call, with the place it was found."""

    __slots__ = ("column", "line", "name", "path", "reason")

    def __init__(self, *, path: str, line: int, column: int, name: str, reason: str) -> None:
        self.path = path
        self.line = line
        self.column = column
        self.name = name
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ImportViolation({self.path}:{self.line} {self.name} — {self.reason})"


def _matches(name: str, roots: frozenset[str]) -> bool:
    """``name`` is a ``root`` or a submodule of one (``socket`` matches ``socket.socket``)."""
    return any(name == root or name.startswith(f"{root}.") for root in roots)


def _dotted(node: ast.expr) -> str:
    """The dotted source of an attribute/name expression (``os`` + ``system`` → ``os.system``)."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return ""
    parts.append(current.id)
    return ".".join(reversed(parts))


def _call_name(node: ast.Call, aliases: Mapping[str, str]) -> str:
    """The dotted callee, resolving ``import os as _os`` aliases in the head position."""
    name = _dotted(node.func)
    if not name:
        return ""
    head, _, tail = name.partition(".")
    resolved = aliases.get(head)
    if resolved is None:
        return name
    return f"{resolved}.{tail}" if tail else resolved


def forbidden_imports(source: str, *, path: str = "<string>") -> tuple[ImportViolation, ...]:
    """Every forbidden import or call in ``source``.

    A source that does not parse raises :class:`SyntaxError` — a simulation file that cannot
    be parsed cannot be proven safe, and only the caller knows whether that is fatal.
    """
    tree = ast.parse(source, filename=path)
    forbidden: list[ImportViolation] = []
    # ``import x as y`` binds ``y``; a call scan needs the real dotted name back.
    aliases: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                aliases[alias.asname or alias.name.partition(".")[0]] = alias.name
                reason = _import_reason(alias.name)
                if reason is not None:
                    forbidden.append(
                        ImportViolation(
                            path=path,
                            line=node.lineno,
                            column=node.col_offset,
                            name=alias.name,
                            reason=reason,
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                # A relative import cannot leave the package, and the package is clean.
                continue
            for alias in node.names:
                full = f"{module}.{alias.name}" if module else alias.name
                reason = _import_reason(full) or _import_reason(module)
                if reason is not None:
                    forbidden.append(
                        ImportViolation(
                            path=path,
                            line=node.lineno,
                            column=node.col_offset,
                            name=full,
                            reason=reason,
                        )
                    )
        elif isinstance(node, ast.Call):
            callee = _call_name(node, aliases)
            if callee in FORBIDDEN_CALLS:
                forbidden.append(
                    ImportViolation(
                        path=path,
                        line=node.lineno,
                        column=node.col_offset,
                        name=callee,
                        reason="a process or dynamic-import escape hatch",
                    )
                )
    return tuple(forbidden)


def _import_reason(name: str) -> str | None:
    if _matches(name, FORBIDDEN_MODULES):
        return "a network or process family the simulation engine must not reach"
    if _matches(name, FORBIDDEN_ARACHNE_MODULES):
        return "an ARACHNE egress or store module the simulation engine must not import"
    return None


def scan_tree(root: Path | str) -> dict[str, tuple[ImportViolation, ...]]:
    """``{path: violations}`` for every ``.py`` under ``root`` (only offending paths).

    The guard exemption is *not* applied here: this is the raw read, which is what lets a test
    pin exactly what the exemption covers.
    """
    base = Path(root)
    out: dict[str, tuple[ImportViolation, ...]] = {}
    for path in sorted(base.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        relative = str(path.relative_to(base.parent)) if base.parent != base else str(path)
        violations = forbidden_imports(source, path=relative)
        if violations:
            out[relative] = violations
    return out


def _apply_guard_exemption(
    path: str, violations: tuple[ImportViolation, ...]
) -> tuple[ImportViolation, ...]:
    """Drop the guard module's own documented imports, and nothing else."""
    if path != GUARD_MODULE:
        return violations
    return tuple(
        item
        for item in violations
        if item.name.partition(".")[0] not in GUARD_ALLOWED_IMPORTS
    )


def violations_for_package(module: str = "arachne.sim") -> Sequence[ImportViolation]:
    """Audit an importable package by name — the form a deployment's own check would use.

    Applies :data:`GUARD_MODULE`'s documented exemption (the boundary module holds the socket
    module in order to deny it) and reports everything else, so a clean result means "nothing
    outside the guard can reach a target".
    """
    import importlib.util

    spec = importlib.util.find_spec(module)
    if spec is None or not spec.submodule_search_locations:
        return ()
    found: list[ImportViolation] = []
    for location in spec.submodule_search_locations:
        for path, violations in scan_tree(Path(location)).items():
            found.extend(_apply_guard_exemption(path, violations))
    return tuple(found)
