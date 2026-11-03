"""The AI package's primitive audit, as a pure source analysis (REQ-AGENT-011, G5 clause 5).

The capability-scoped tool registry (``ai.tools``) says which tools the AI layer *may* call.
This module says what the AI layer cannot *reach*, by analysing the package's own source: no
module under ``src/arachne/ai/`` may import a process, socket or filesystem-write primitive.
Together the two are the contract — an enumerated surface, and no second door to the primitives
the surface deliberately omits.

It is a source-level check rather than a runtime one on purpose. A runtime check would observe
the imports that happened to be executed in a test; a source check fails on the import the moment
it is written, in any module, including one no test covers. ``tests/unit/test_ai_capability.py``
runs it, and its self-test feeds the checker a synthetic module containing an offending import and
asserts that it is reported — a checker that cannot fail on the case it exists for is worse than
no checker.

Two deliberate properties of the audit itself:

* **It touches no files.** :func:`scan_source` receives program text and returns findings; the
  caller (a test) owns the decision about which files to read. A safety checker that walks and
  reads paths of its own is one more thing whose scope has to be argued about, and this one's
  scope should be exactly "the text I was given".
* **Reads are not banned.** Reading a prompt corpus or a cached answer is not a capability a
  model can direct, and banning it would push legitimate code out of the package for no safety
  gain. What is banned is the write, the process and the socket.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Final

__all__ = [
    "FORBIDDEN_ATTRIBUTES",
    "FORBIDDEN_CALLS",
    "FORBIDDEN_MODULES",
    "ForbiddenPrimitive",
    "scan_modules",
    "scan_source",
]

#: Modules that may not be imported at all, with the kind of primitive they are.
FORBIDDEN_MODULES: Final[dict[str, str]] = {
    "subprocess": "process",
    "asyncio.subprocess": "process",
    "multiprocessing": "process",
    "pty": "process",
    "ctypes": "process",
    "socket": "socket",
    "socketserver": "socket",
    "ssl": "socket",
    "http.client": "socket",
    "http.server": "socket",
    "http.cookiejar": "socket",
    "urllib.request": "socket",
    "ftplib": "socket",
    "smtplib": "socket",
    "telnetlib": "socket",
    "shutil": "filesystem-write",
    "tempfile": "filesystem-write",
}

#: ``(module, attribute)`` calls that are forbidden even when the module itself may be imported.
#:
#: Keyed as a pair rather than as one dotted string on purpose: this table *names* the primitives
#: it forbids, and a dotted spelling of a shell or process call written into this package would
#: itself match the substring audits that look for one (``tests/unit/test_http_hygiene.py`` scans
#: the tree for exactly that shape). A pair is the same rule stated without pretending the package
#: calls it.
FORBIDDEN_CALLS: Final[dict[tuple[str, str], str]] = {
    ("os", "system"): "process",
    ("os", "popen"): "process",
    ("os", "fork"): "process",
    ("os", "forkpty"): "process",
    ("os", "kill"): "process",
    ("os", "killpg"): "process",
    ("os", "execv"): "process",
    ("os", "execve"): "process",
    ("os", "execl"): "process",
    ("os", "execlp"): "process",
    ("os", "execvp"): "process",
    ("os", "spawnl"): "process",
    ("os", "spawnv"): "process",
    ("os", "spawnvp"): "process",
    ("os", "remove"): "filesystem-write",
    ("os", "unlink"): "filesystem-write",
    ("os", "rmdir"): "filesystem-write",
    ("os", "removedirs"): "filesystem-write",
    ("os", "mkdir"): "filesystem-write",
    ("os", "makedirs"): "filesystem-write",
    ("os", "rename"): "filesystem-write",
    ("os", "replace"): "filesystem-write",
    ("os", "chmod"): "filesystem-write",
    ("os", "chown"): "filesystem-write",
    ("os", "truncate"): "filesystem-write",
    ("os", "symlink"): "filesystem-write",
    ("os", "link"): "filesystem-write",
    ("os", "write"): "filesystem-write",
}

#: Attribute names that mutate when called. Matched on the name alone, so any receiver is caught.
#:
#: There is deliberately no ``run``/``Popen``/``check_output`` entry. Those calls cannot be reached
#: without one of the banned module imports above, and matching the bare attribute name reported
#: ordinary code — ``runner.run("triage")``, ``asyncio.run(coro)`` — as a process launch. A rule
#: that fires on normal code is a rule people learn to ignore, which costs more than the marginal
#: case it catches.
FORBIDDEN_ATTRIBUTES: Final[dict[str, str]] = {
    "write_text": "filesystem-write",
    "write_bytes": "filesystem-write",
    "mkdir": "filesystem-write",
    "makedirs": "filesystem-write",
    "touch": "filesystem-write",
    "unlink": "filesystem-write",
    "rmdir": "filesystem-write",
    "symlink_to": "filesystem-write",
    "hardlink_to": "filesystem-write",
}

#: The mode flags that make the ``open`` builtin a write.
_WRITE_MODE_FLAGS: Final = "wax+"


@dataclass(frozen=True, slots=True)
class ForbiddenPrimitive:
    """One finding: which module and line, which primitive kind, and what was written there."""

    module: str
    line: int
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"{self.module}:{self.line}: {self.kind}: {self.detail}"


def scan_modules(sources: Mapping[str, str]) -> tuple[ForbiddenPrimitive, ...]:
    """Scan ``{module name: source}`` (the caller decides what is in scope)."""
    findings: list[ForbiddenPrimitive] = []
    for module, source in sorted(sources.items()):
        findings.extend(scan_source(source, module=module))
    return tuple(findings)


def scan_source(source: str, *, module: str) -> tuple[ForbiddenPrimitive, ...]:
    """Scan one module's source text (the seam the self-test drives with synthetic code)."""
    tree = ast.parse(source, filename=module)
    return (*_scan_imports(tree, module), *_scan_calls(tree, module))


def _scan_imports(tree: ast.AST, module: str) -> Iterator[ForbiddenPrimitive]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                kind = _module_kind(alias.name)
                if kind is not None:
                    yield ForbiddenPrimitive(module, node.lineno, kind, f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom) and node.module:
            kind = _module_kind(node.module)
            if kind is not None:
                names = ", ".join(alias.name for alias in node.names)
                yield ForbiddenPrimitive(
                    module, node.lineno, kind, f"from {node.module} import {names}"
                )


def _module_kind(name: str) -> str | None:
    """The kind of a dotted import name, by exact or by leading match."""
    if name in FORBIDDEN_MODULES:
        return FORBIDDEN_MODULES[name]
    for prefix in FORBIDDEN_MODULES:
        if name.startswith(f"{prefix}."):
            return FORBIDDEN_MODULES[prefix]
    return None


def _scan_calls(tree: ast.AST, module: str) -> Iterator[ForbiddenPrimitive]:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_name(node.func)
        kind = _forbidden_call(dotted) if dotted else None
        if kind is not None:
            yield ForbiddenPrimitive(module, node.lineno, kind, f"{dotted}()")
            continue
        yield from _scan_attribute_call(node, module)


def _forbidden_call(dotted: str) -> str | None:
    """The kind of a ``receiver.attribute()`` call, when the pair is in the table."""
    owner, separator, attribute = dotted.rpartition(".")
    if not separator:
        return None
    return FORBIDDEN_CALLS.get((owner, attribute))


def _scan_attribute_call(node: ast.Call, module: str) -> Iterator[ForbiddenPrimitive]:
    name = _called_name(node.func)
    if name is None:
        return
    if name == "open":
        if _opens_for_write(node):
            yield ForbiddenPrimitive(
                module, node.lineno, "filesystem-write", "open() in write mode"
            )
        return
    kind = FORBIDDEN_ATTRIBUTES.get(name)
    if kind is not None:
        yield ForbiddenPrimitive(module, node.lineno, kind, f"{name}()")


def _called_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _opens_for_write(node: ast.Call) -> bool:
    """True for an ``open`` call whose mode is a literal that can write."""
    modes: Iterable[ast.AST] = list(node.args[1:2])
    for keyword in node.keywords:
        if keyword.arg == "mode":
            modes = [*modes, keyword.value]
    for candidate in modes:
        if not isinstance(candidate, ast.Constant) or not isinstance(candidate.value, str):
            continue
        if any(flag in candidate.value for flag in _WRITE_MODE_FLAGS):
            return True
    return False


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _dotted_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return None
