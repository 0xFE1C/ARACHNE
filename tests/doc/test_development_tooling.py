"""Development tooling stays outside the distribution (REQ-QUAL-015).

Two requirements demand tools that read the build-time scaffolding — the handoff gate
(REQ-QUAL-013) and the preamble gate (REQ-QUAL-014) — while a third forbids any shipped file
from naming it (REQ-DOC-006). Both hold at once only if the tooling lives outside the
packaged tree, so that is where it lives: a repository-root ``tools`` package. This module
asserts the three properties that keep it there:

* the wheel and the sdist carry none of it, read from the archives' member lists rather than
  assumed from the build configuration;
* no module inside the packaged tree imports it, directly or transitively — every packaged
  module's imports are parsed and the import closure is walked;
* the release build leaves it in place, and both gates still answer on the command line.

The distribution pairing is shared with the release-surface module through the session-scoped
fixture in this directory's conftest: both inspect the same archives, built once.
"""

from __future__ import annotations

import ast
import importlib
import tarfile
import zipfile
from pathlib import Path
from typing import Final

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGED_TREE = REPO_ROOT / "src"
TOOLING_PACKAGE = "tools"
TOOLING_DIR = REPO_ROOT / TOOLING_PACKAGE
#: The development gates the requirement names. They must exist and be executable.
TOOLING_MODULES: Final = ("tools/wp_check.py", "tools/preamble_check.py")
GATE_MODULES: Final = ("tools.wp_check", "tools.preamble_check")


def _members(distributions: tuple[Path, Path]) -> list[tuple[str, list[str]]]:
    wheel, sdist = distributions
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_members = archive.getnames()
    return [(wheel.name, wheel_members), (sdist.name, sdist_members)]


def _relative_member(name: str) -> str:
    """Drop an sdist's top-level ``arachne-<version>/`` directory from a member name."""
    head, _, rest = name.partition("/")
    if head.startswith("arachne-") and rest:
        return rest
    return name


def test_the_distributions_carry_no_development_tooling(
    distributions: tuple[Path, Path],
) -> None:
    """Neither archive contains the ``tools`` package, at any depth."""
    for archive_name, members in _members(distributions):
        offenders = sorted(
            {
                member
                for member in members
                if _relative_member(member) == TOOLING_PACKAGE
                or _relative_member(member).startswith(f"{TOOLING_PACKAGE}/")
            }
        )
        assert offenders == [], (
            f"{archive_name} carries the development tooling; the packaging configuration is "
            "shipping it:\n" + "\n".join(offenders)
        )
        print(f"{archive_name}: {len(members)} members, 0 development tooling files")


def test_the_packaged_tree_is_still_the_product(distributions: tuple[Path, Path]) -> None:
    """Negative control: the absence above is not an empty archive."""
    wheel, sdist = distributions
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_members = archive.getnames()
    assert "arachne/__init__.py" in wheel_members
    assert any(member.endswith("src/arachne/__init__.py") for member in sdist_members)


def _packaged_modules() -> dict[str, Path]:
    """Every module of the packaged tree, named as an import would name it."""
    modules: dict[str, Path] = {}
    for path in sorted(PACKAGED_TREE.rglob("*.py")):
        parts = list(path.relative_to(PACKAGED_TREE).with_suffix("").parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        modules[".".join(parts)] = path
    return modules


def _absolute_imports(path: Path) -> set[str]:
    """The absolute module names ``path`` imports.

    Relative imports are ignored on purpose: they cannot leave the module's own package, so
    they cannot name a separate top-level package. An import of the tooling from anywhere in
    the closure is therefore always an absolute import of *some* packaged module — and every
    packaged module is in :func:`_packaged_modules`.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


def _import_closure(graph: dict[str, set[str]], root: str) -> set[str]:
    seen: set[str] = set()
    stack = [root]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(graph.get(name, ()))
    return seen


def _is_tooling(name: str) -> bool:
    return name == TOOLING_PACKAGE or name.startswith(f"{TOOLING_PACKAGE}.")


@pytest.fixture(scope="module")
def import_graph() -> dict[str, set[str]]:
    """``{module: absolute imports}`` for the whole packaged tree, parsed once."""
    modules = _packaged_modules()
    assert modules, "the packaged tree was not found; the walk measured nothing"
    return {name: _absolute_imports(path) for name, path in modules.items()}


def _reachable_from_any(graph: dict[str, set[str]]) -> set[str]:
    """Everything the packaged tree can reach by following imports from any of its modules."""
    reached: set[str] = set()
    for root in graph:
        reached |= _import_closure(graph, root)
    return reached


def test_no_packaged_module_imports_the_development_tooling(
    import_graph: dict[str, set[str]],
) -> None:
    """No module under ``src/arachne`` imports the tooling, directly or transitively."""
    direct = sorted(
        name for name, imports in import_graph.items() if any(map(_is_tooling, imports))
    )
    assert direct == [], (
        "these packaged modules import the development tooling, which a user never receives:\n"
        + "\n".join(direct)
    )

    reached = sorted(name for name in _reachable_from_any(import_graph) if _is_tooling(name))
    assert reached == [], f"the package's import closure reaches the tooling: {reached}"


def test_the_import_walk_actually_walks(import_graph: dict[str, set[str]]) -> None:
    """Negative control: the closure is a real walk over a real tree, not an empty set.

    Without this, the absence assertion above would pass just as well on a graph that parsed
    no imports at all.
    """
    assert len(import_graph) > 400, f"the walk found only {len(import_graph)} packaged modules"
    assert "arachne.core.safety" in import_graph, "the safety core is not in the packaged tree"
    reached = _reachable_from_any(import_graph)
    assert reached >= set(import_graph), "the walk did not cover every packaged module"
    # And it follows edges: a deep module reaches modules it does not name itself.
    deep = _import_closure(import_graph, "arachne.core.orchestrator")
    assert len(deep) > 3, f"the closure from the orchestrator is {sorted(deep)}"
    assert deep - import_graph["arachne.core.orchestrator"], "the closure followed no edge"


def test_the_release_cleanup_leaves_the_development_tooling_in_place(
    distributions: tuple[Path, Path],
) -> None:
    """The tools survive the release build, outside the packaged tree, and still run.

    The fixture has built the wheel and the sdist by the time this test runs, so "the cleanup
    left them in place" is measured after the operation rather than assumed. Removing the
    build-time scaffolding is the cleanup's job (REQ-DOC-006); the tooling is what it must
    keep, and it is what reads that scaffolding afterwards.
    """
    assert distributions, "the release build did not run"
    for relative in (*TOOLING_MODULES, "tools/__init__.py"):
        tool = REPO_ROOT / relative
        assert tool.is_file(), f"{relative} was removed by the release build"
        assert PACKAGED_TREE not in tool.parents, f"{relative} lives inside the packaged tree"


def test_both_gates_are_executable_module_entry_points() -> None:
    """Each gate's ``main`` is wired to the command line and answers ``--help`` with 0.

    ``--help`` is argparse's own path, so a return of ``SystemExit(0)`` proves the module has
    a parser and an entry point a caller can reach — no process needed, and no dependency on
    which interpreter a ``python`` on ``PATH`` happens to be.
    """
    for name in GATE_MODULES:
        module = importlib.import_module(name)
        assert callable(module.main), f"{name} exposes no main()"
        with pytest.raises(SystemExit) as exit_info:
            module.main(["--help"])
        assert exit_info.value.code == 0
        assert Path(module.__file__ or "").parent == TOOLING_DIR
