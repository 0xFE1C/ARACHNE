"""The release surface: build-time scaffolding never reaches a user (REQ-DOC-006).

Three artefacts sit beside the product in this repository but are not part of it — the
specification directory, the prompt library and the tracker. They are how the programme was
built, not what it built. REQ-DOC-006 states the property three ways: they are absent from
every distribution, no shipped source, test or document names them as a target, and removing
them leaves the repository valid.

This module asserts the first two halves by *measuring* them:

* the wheel and the sdist are built with the project's own build backend and their member
  lists are read — the surface is not assumed from the build configuration, because
  hatchling's ``include`` is additive and that configuration read fluently as an exclusion
  when it was not one (the defect this module exists to keep closed);
* every file on the shipped surface is searched for a reference.

The third half — removing them leaves the gates green — is a one-off demonstration recorded
in the commit that performed the removal; a test cannot assert it without deleting the
artefacts again on every run.

**Why the names are assembled from fragments.** This module's subject is the artefacts'
names, and one of the criteria is that a plain ``grep`` over the shipped surface finds none
of them. A checker whose own bytes spelled a name out would be the only hit for its own
search, so :func:`artefact_names` builds the three strings at run time. That is not an
exclusion list — nothing is skipped or excused; the search runs over every file, and the
needles are simply not words this file contains.
"""

from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

import pytest
from build import ProjectBuilder

REPO_ROOT = Path(__file__).resolve().parents[2]

#: The trees a user reads as source and as tests. REQ-DOC-006's acceptance criterion names
#: these two, and ``grep -rn <names> src tests`` returning nothing is the printed evidence.
SOURCE_TREES = ("src", "tests")

#: The documentation surface. The same requirement says "no shipped source, **test or
#: document**", so the document half is asserted here too. The link checker cannot see a
#: citation whose first path segment starts with a dot, which is exactly the shape these
#: names have (recorded as a programme-level issue), so this search is what covers them.
DOCUMENT_TREES = ("docs",)
ROOT_DOCUMENTS = ("CHANGELOG.md", "CONTRIBUTING.md", "README.md", "SECURITY.md")

#: Byte-compiled caches mirror the sources scanned below and are neither committed nor
#: written by a contributor. Scanning them would make this test depend on whether the suite
#: has run before.
_PYCACHE = "__pycache__"


def artefact_names() -> tuple[str, ...]:
    """The build-time artefacts' names, as the needles a search looks for.

    Built from fragments at run time, so no contiguous copy of any name exists in this
    file's bytes; see the module docstring.
    """
    dot = "."
    return (f"{dot}spec/", f"PROMPT{dot}md", f"STATE{dot}md")


def _files_under(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(
        child for child in path.rglob("*") if child.is_file() and _PYCACHE not in child.parts
    )


def references_to_scaffolding(paths: tuple[str, ...]) -> list[str]:
    """Every named path whose bytes contain one of :func:`artefact_names`.

    Bytes, not text: the search a reader runs is ``grep``, which reads bytes, and a name
    inside a JSON corpus or a hand-written asset counts exactly as one in a docstring.
    """
    needles = tuple(name.encode() for name in artefact_names())
    offenders: list[str] = []
    for relative in paths:
        for path in _files_under(REPO_ROOT / relative):
            if any(needle in path.read_bytes() for needle in needles):
                offenders.append(str(path.relative_to(REPO_ROOT)))
    return offenders


@pytest.fixture(scope="module")
def distributions(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Build the wheel and the sdist with the project's own backend, into a scratch directory.

    :class:`build.ProjectBuilder` reads ``[build-system]`` from ``pyproject.toml`` and invokes
    that backend's PEP 517 hooks, so the artefacts inspected here are the project's own output
    rather than a hand-rolled stand-in. The backend is imported from this interpreter rather
    than an isolated environment, which is why ``build`` and ``hatchling`` are development
    dependencies: the suite never reaches for PyPI to answer a question about its own tree.
    """
    outdir = tmp_path_factory.mktemp("dist")
    builder = ProjectBuilder(str(REPO_ROOT))
    sdist = Path(builder.build("sdist", str(outdir)))
    wheel = Path(builder.build("wheel", str(outdir)))
    assert wheel.suffix == ".whl", f"the backend produced {wheel.name}, not a wheel"
    assert sdist.name.endswith(".tar.gz"), f"the backend produced {sdist.name}, not an sdist"
    return wheel, sdist


def _members(wheel: Path, sdist: Path) -> list[tuple[str, list[str]]]:
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_members = archive.getnames()
    return [(wheel.name, wheel_members), (sdist.name, sdist_members)]


def test_the_distributions_carry_no_build_time_artefact(
    distributions: tuple[Path, Path],
) -> None:
    """The wheel and the sdist contain none of the three names, and no ``docs/`` tree."""
    needles = (*artefact_names(), "docs/")
    for archive_name, members in _members(*distributions):
        offenders = sorted(
            {member for member in members if any(needle in member for needle in needles)}
        )
        assert offenders == [], (
            f"{archive_name} carries build-time artefacts; the packaging configuration is "
            "shipping them:\n" + "\n".join(offenders)
        )
        print(f"{archive_name}: {len(members)} members, 0 build-time artefacts")


def test_the_distributions_carry_the_product_and_its_suite(
    distributions: tuple[Path, Path],
) -> None:
    """The exclusions did not empty the archives.

    An absence assertion passes just as well on an empty file. These are the files a user who
    installs the wheel, and a contributor who unpacks the sdist, must receive.
    """
    wheel, sdist = distributions
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
    with tarfile.open(sdist) as archive:
        sdist_members = archive.getnames()
    assert "arachne/__init__.py" in wheel_members, "the wheel does not carry the package"
    assert any(member.endswith("src/arachne/__init__.py") for member in sdist_members), (
        "the sdist does not carry the source tree"
    )
    assert any(member.endswith("tests/conftest.py") for member in sdist_members), (
        "the sdist dropped the suite a source contributor runs"
    )


def test_no_shipped_source_or_test_names_a_build_time_artefact() -> None:
    """REQ-DOC-006's acceptance criterion, on the surface it names.

    Reproduces ``grep -rn <names> src tests`` and requires it to be empty: a reference is a
    bug, because the path will not exist for the user who receives this repository.
    """
    offenders = references_to_scaffolding(SOURCE_TREES)
    assert offenders == [], (
        "these files name a build-time artefact that does not exist for a user; re-point the "
        "reference at a shipped document under docs/:\n" + "\n".join(offenders)
    )


def test_no_shipped_document_names_a_build_time_artefact() -> None:
    """The same search over the documentation surface.

    REQ-DOC-006 covers documents as well as code and tests, and the link checker does not read
    a dot-prefixed first segment, so this is the search that holds the document half.
    """
    offenders = references_to_scaffolding(DOCUMENT_TREES + ROOT_DOCUMENTS)
    assert offenders == [], (
        "these documents name a build-time artefact a reader cannot open:\n" + "\n".join(offenders)
    )
