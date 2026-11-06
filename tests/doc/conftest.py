"""The distributions under test, built once per session.

Two modules assert properties of the same wheel and sdist — that no build-time artefact
reaches a user (REQ-DOC-006) and that the development tooling stays out of them while
staying in the repository (REQ-QUAL-015). Building the pair is the most expensive thing in
the documentation layer, so the fixture is session-scoped: the archives are built once and
both modules read them.

The build uses the project's own backend (``build.ProjectBuilder`` over ``[build-system]``),
so what is inspected is the project's real output rather than a hand-rolled stand-in.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from build import ProjectBuilder

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def distributions(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """Build the wheel and the sdist with the project's own backend, into a scratch directory.

    :class:`build.ProjectBuilder` reads ``[build-system]`` from ``pyproject.toml`` and invokes
    that backend's PEP 517 hooks. The backend is imported from this interpreter rather than an
    isolated environment, which is why ``build`` and ``hatchling`` are development
    dependencies: the suite never reaches for PyPI to answer a question about its own tree.
    """
    outdir = tmp_path_factory.mktemp("dist")
    builder = ProjectBuilder(str(REPO_ROOT))
    sdist = Path(builder.build("sdist", str(outdir)))
    wheel = Path(builder.build("wheel", str(outdir)))
    assert wheel.suffix == ".whl", f"the backend produced {wheel.name}, not a wheel"
    assert sdist.name.endswith(".tar.gz"), f"the backend produced {sdist.name}, not an sdist"
    return wheel, sdist
