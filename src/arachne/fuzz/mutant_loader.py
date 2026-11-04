"""A pytest plugin that mutes a module and scopes a run (REQ-QUAL-008).

The mutation gate needs to answer one question, once per mutant: *would the test suite notice
if this line were wrong?* Answering it means running the real tests against a real altered
module — not a stub, not a monkeypatch the test could see through. This plugin is the whole of
the runner's pytest-side machinery, and it does three things:

**1. Load one module from a mutant's source file.** The runner writes the altered source to a
temporary file and names the target in the environment:

* ``ARACHNE_MUTANT_MODULE`` — the import name to intercept, e.g. ``arachne.core.safety``.
* ``ARACHNE_MUTANT_SOURCE`` — the file holding the altered source for it.

Loading goes through :class:`importlib.machinery.SourceFileLoader`, the same loader CPython
uses for an ordinary ``.py`` file: this plugin decides *which file* a module name resolves to
and nothing more. The rest of the package, the tests and the fixtures are imported normally, so
a run exercises the real code with exactly one module swapped.

The finder is installed from ``pytest_load_initial_conftests``, which runs **before** the
rootdir ``conftest.py`` files are imported. That ordering is the whole trick: the root
``tests/conftest.py`` imports ``arachne`` modules, and a finder installed any later would find
the real module already in ``sys.modules`` — every mutant of that module would then "survive",
and the gate would report a test gap that is really a plugin bug. (It did, once. That is why
the check below exists.)

**2. Refuse to report a verdict it cannot trust.** ``pytest_sessionfinish`` raises the session's
own exit status to an internal error when a mutant was requested but never loaded. The runner
classifies that as ``error`` — neither killed nor survived — so a malfunction can never flatter
the score. A gate that silently measures nothing is worse than no gate.

**3. Scope the run.** ``ARACHNE_MUTANT_TESTS`` holds a JSON list of the paths that cover the
target modules. Selection travels in the environment, never on the command line, so the argv
the runner builds is a fixed list of literals with nothing spliced into it.

All three are inert when their variables are unset, so passing ``-p arachne.fuzz.mutant_loader``
to an ordinary run changes nothing.
"""

from __future__ import annotations

import json
import os
import sys
from importlib.abc import MetaPathFinder
from importlib.machinery import ModuleSpec, SourceFileLoader
from importlib.util import spec_from_loader
from pathlib import Path
from types import ModuleType
from typing import Any, Final

import typer

__all__ = [
    "MODULE_ENV",
    "SOURCE_ENV",
    "STATUS_ENV",
    "TESTS_ENV",
    "MutantFinder",
    "install",
    "loaded_module",
    "mutant_is_loaded",
    "mutant_spec",
    "scoped_paths",
    "status_report",
]

MODULE_ENV: Final = "ARACHNE_MUTANT_MODULE"
SOURCE_ENV: Final = "ARACHNE_MUTANT_SOURCE"
#: A path the session-finish hook writes its verdict to. The runner reads this file rather
#: than guessing from pytest's stdout: "did this module really get swapped" is a fact the
#: plugin knows first-hand, and a text scrape only infers.
STATUS_ENV: Final = "ARACHNE_MUTANT_STATUS"
TESTS_ENV: Final = "ARACHNE_MUTANT_TESTS"

#: pytest's "internal error" exit status; the runner maps it to an *errored* mutant.
_INTERNAL_ERROR: Final = 3

#: The module name the finder actually served, if any. Read by the session-finish check.
_SERVED: dict[str, str] = {}


def mutant_spec() -> tuple[str, str] | None:
    """``(module, source_path)`` when the environment names a mutant, else ``None``."""
    module = os.environ.get(MODULE_ENV, "").strip()
    source = os.environ.get(SOURCE_ENV, "").strip()
    if not module or not source:
        return None
    return module, source


def loaded_module() -> str | None:
    """The module name the finder served in this process, or ``None``."""
    return _SERVED.get("module")


def mutant_is_loaded() -> bool:
    """True when the target name really resolves to the mutant's file, right now.

    Checked against ``sys.modules`` rather than remembered from ``find_spec``: a mutant whose
    module raises on import is *served* and then discarded by the import system, and that is an
    error, not a load. The difference matters — it is what separates "the gate measured this
    mutant" from "the gate measured the original code and would have said so".
    """
    spec = mutant_spec()
    if spec is None:
        return False
    module = sys.modules.get(spec[0])
    if not isinstance(module, ModuleType):
        return False
    origin = getattr(getattr(module, "__spec__", None), "origin", None)
    if not origin:
        return False
    try:
        return Path(str(origin)).resolve() == Path(spec[1]).resolve()
    except OSError:  # pragma: no cover - a path that cannot be resolved is not a load
        return False


def status_report() -> dict[str, object]:
    """What this process did, for the runner to read instead of parsing pytest's output."""
    spec = mutant_spec()
    return {
        "module": spec[0] if spec else None,
        "attempted": spec is not None,
        "loaded": mutant_is_loaded(),
    }


def scoped_paths() -> tuple[Path, ...]:
    """The resolved roots this run is limited to, or ``()`` for an unscoped run."""
    raw = os.environ.get(TESTS_ENV, "").strip()
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(Path(str(item)).resolve() for item in parsed)


def _in_scope(path: Path, roots: tuple[Path, ...]) -> bool:
    resolved = path.resolve()
    return any(resolved == root or root in resolved.parents for root in roots)


class MutantFinder(MetaPathFinder):
    """Resolve exactly one module name to the mutant's file, and everything else normally."""

    def __init__(self, module: str, source: str) -> None:
        self._module = module
        self._source = source

    def find_spec(
        self, fullname: str, path: Any = None, target: ModuleType | None = None
    ) -> ModuleSpec | None:
        if fullname != self._module:
            return None
        loader = SourceFileLoader(fullname, self._source)
        _SERVED["module"] = fullname
        return spec_from_loader(fullname, loader, origin=self._source)


def install() -> bool:
    """Install the finder when the environment names a mutant. Returns whether it did."""
    spec = mutant_spec()
    if spec is None:
        return False
    module, source = spec
    if not Path(source).is_file():
        msg = f"the mutant source {source} does not exist"
        raise FileNotFoundError(msg)
    if any(isinstance(finder, MutantFinder) for finder in sys.meta_path):
        return True  # already installed by an earlier hook
    # A module that has already been imported cannot be re-resolved by a finder, so drop it
    # and let the next import go through ours. This is a safety net: the hook below installs
    # early enough that it should never be needed.
    sys.modules.pop(module, None)
    sys.meta_path.insert(0, MutantFinder(module, source))
    return True


def pytest_load_initial_conftests(early_config: Any = None) -> None:
    """pytest hook: install before the rootdir ``conftest.py`` files are imported."""
    install()


def pytest_configure(config: Any) -> None:
    """pytest hook: make sure the finder is in place (idempotent)."""
    install()


def pytest_sessionfinish(session: Any, exitstatus: Any) -> None:
    """pytest hook: record what happened, and refuse a verdict no mutant earned."""
    spec = mutant_spec()
    if spec is None:
        return
    report = status_report()
    status_path = os.environ.get(STATUS_ENV, "").strip()
    if status_path:
        try:
            Path(status_path).write_text(json.dumps(report), encoding="utf-8")
        except OSError as exc:  # pragma: no cover - a write failure is reported, not fatal
            typer.echo(f"mutation gate: could not write the status file: {exc}", err=True)
    if report["loaded"]:
        return
    typer.echo(
        f"mutation gate: the mutant of {spec[0]} was never loaded, so this run measured the "
        "original code. Reporting an internal error rather than a verdict.",
        err=True,
    )
    session.exitstatus = _INTERNAL_ERROR


def pytest_collection_modifyitems(config: Any, items: list[Any]) -> None:
    """pytest hook: keep only the tests that cover the mutated modules."""
    roots = scoped_paths()
    if not roots:
        return
    kept: list[Any] = []
    dropped: list[Any] = []
    for item in items:
        target = getattr(item, "path", None)
        collection = kept if target is not None and _in_scope(Path(target), roots) else dropped
        collection.append(item)
    if dropped:
        config.hook.pytest_deselected(items=dropped)
    items[:] = kept
