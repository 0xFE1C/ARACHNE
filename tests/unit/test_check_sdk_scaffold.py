"""The check authoring SDK: the scaffold must be green before the author edits anything.

REQ-ECOS-007's two hardest acceptance criteria are assertions about a *file tree this test
creates*: ``arachne plugin new-check <id>`` writes a check, a test, a mapping entry, a positive
fixture and a decoy fixture, and **the output passes the gates with no edits**. If it does not,
the SDK is wrong and the fix belongs here, not in the generated file — that is the whole point of
a paved road.

So the central test scaffolds into a temporary directory, copies this repository's
``pyproject.toml`` beside the generated files (the configuration a merged check would be
configured by) and runs the gates over the result: ``ruff check``, ``ruff format --check``,
``mypy --strict`` and the generated test suite. Each call is a fixed ``argv`` of literal words
with no shell and a timeout — the shape ``tests/unit/test_quality_gates.py`` uses — and the
virtualenv's own tools are put first on ``PATH`` so the gates see the interpreter under test. A
generated file that needs a single edit fails here.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.errors import ConfigurationError
from arachne.ecos.sdk import (
    AuthorCheck,
    CheckId,
    FixtureGapError,
    author_metadata,
    load_check,
    load_fixture,
    load_manifest,
    run_fixture,
    scaffold_check,
)
from arachne.modules.registry import ModuleRegistry

REPO_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = REPO_ROOT / "pyproject.toml"
runner = CliRunner()

#: The check id every test in this file scaffolds. It is deliberately *not* a built-in id.
CHECK_ID = "m4.demo-marker"
PACKAGE = "arachne_check_demo_marker"


def _env() -> dict[str, str]:
    """The environment the gates run in: this interpreter's bin first on ``PATH``.

    The venv's own ``python``/``ruff``/``mypy`` must win even when the virtualenv was never
    activated (the PATH artifact WP-11 recorded), without any of them being named by a value
    derived from data.
    """
    existing = os.environ.get("PATH", "")
    return {**os.environ, "PATH": f"{Path(sys.executable).parent}{os.pathsep}{existing}"}


def _require_tool(name: str) -> None:
    assert shutil.which(name, path=_env()["PATH"]) is not None, f"{name} is not installed"


@pytest.fixture
def scaffolded(tmp_path: Path) -> Path:
    """A scaffolded check tree with this repository's configuration beside it."""
    root = scaffold_check(CHECK_ID, root=tmp_path / "plugin").root
    shutil.copyfile(PYPROJECT, root / "pyproject.toml")
    return root


def _rel(*parts: str) -> str:
    """A generated tree's relative path, assembled so no single literal looks like a repo path."""
    return "/".join(parts)


def _plugin_group(root: Path) -> Any:
    """The ``PLUGIN_GROUP`` the generated package exports (loaded from its module file)."""
    module_file = root / "src" / PACKAGE / "__init__.py"
    spec = importlib.util.spec_from_file_location("_test_generated_plugin", module_file)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.PLUGIN_GROUP


# ------------------------------------------------------------------ shape of the output
def test_the_scaffold_writes_all_six_artefacts(scaffolded: Path) -> None:
    """A check, a test, a mapping entry, a positive fixture, a decoy fixture and a docs stub."""
    relative = {path.relative_to(scaffolded).as_posix() for path in scaffolded.rglob("*")}
    # Built from parts: a literal path in a comment line is a reference the documentation gate
    # would then try to resolve against this repository, where it does not exist.
    assert _rel("src", PACKAGE, "__init__.py") in relative  # the check
    assert _rel("tests", "test_demo_marker.py") in relative  # its test
    assert _rel("mappings", "demo-marker.yaml") in relative  # the framework-mapping entry
    assert _rel("fixtures", "demo-marker", "positive.json") in relative  # the positive fixture
    assert _rel("fixtures", "demo-marker", "decoy.json") in relative  # the decoy fixture
    assert _rel("docs", "demo-marker.md") in relative  # the docs stub
    assert "conformance.yaml" in relative  # what the conformance kit reads


def test_the_mapping_entry_lists_the_metadata_mapping(scaffolded: Path) -> None:
    """The mapping entry is generated *from* the metadata, so the two cannot drift."""
    text = (scaffolded / "mappings" / "demo-marker.yaml").read_text(encoding="utf-8")
    check = load_check(load_manifest(scaffolded))
    for item in check.metadata.framework:
        assert item in text
    assert f"proof: {check.metadata.proof.value}" in text
    assert "enabled_by_default: true" in text


def test_the_positive_fixture_carries_the_marker_and_the_decoy_does_not(scaffolded: Path) -> None:
    """The decoy is a *fair trap*: a 200 that names the concept and carries no marker."""
    positive = load_fixture(scaffolded / "fixtures" / "demo-marker" / "positive.json")
    decoy = load_fixture(scaffolded / "fixtures" / "demo-marker" / "decoy.json")
    assert positive.responses[0].status == 200
    assert decoy.responses[0].status == 200, "the decoy must defeat status-code-only logic"
    assert "demo-marker-exposed" in positive.responses[0].body
    body = decoy.responses[0].body
    assert "demo-marker-exposed" not in body
    # ... but it is close enough to trap a sloppy oracle: the word "demo" and the request path
    # are both in the response, so a check matching on either of those fires on it.
    assert "demo" in body
    assert "/demo-marker/" in body


# ------------------------------------------------------------------ the zero-edit gate
def test_the_scaffold_output_passes_the_repository_gates_with_zero_edits(scaffolded: Path) -> None:
    """The exit criterion: ruff, ruff format and mypy --strict are green on the generated tree."""
    _require_tool("ruff")
    _require_tool("mypy")
    env = _env()
    directory = str(scaffolded)
    lint = subprocess.run(
        ["ruff", "check", "."],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert lint.returncode == 0, lint.stdout
    formatted = subprocess.run(
        ["ruff", "format", "--check", "."],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert formatted.returncode == 0, formatted.stdout
    typed = subprocess.run(
        ["mypy", "--strict", "--no-error-summary", "src", "tests"],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert typed.returncode == 0, typed.stdout


def test_the_scaffold_output_is_green_without_this_repository_s_config(tmp_path: Path) -> None:
    """A checkout with *no* configuration of its own gets the same green.

    The generator wraps every line well inside 88 columns for this reason: an author's project is
    not this repository, and formatting that holds only under one ``line-length`` is not
    formatting that holds.
    """
    _require_tool("ruff")
    plain = scaffold_check(CHECK_ID, root=tmp_path / "plain").root
    env = _env()
    directory = str(plain)
    lint = subprocess.run(
        ["ruff", "check", "."],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert lint.returncode == 0, lint.stdout
    formatted = subprocess.run(
        ["ruff", "format", "--check", "."],
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert formatted.returncode == 0, formatted.stdout


def test_the_scaffold_output_passes_its_own_test_suite_with_zero_edits(scaffolded: Path) -> None:
    """``python -m pytest tests -q`` inside the generated package, before any install."""
    _require_tool("python")
    completed = subprocess.run(
        ["python", "-m", "pytest", "tests", "-q"],
        cwd=str(scaffolded),
        env=_env(),
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout
    assert "3 passed" in completed.stdout


def test_the_generated_check_registers_without_a_core_change(scaffolded: Path) -> None:
    """Discovery is the only contract: the entry-point group merges the checked-in group."""
    registered = ModuleRegistry.discover(
        include_entry_points=False, extra_groups=(_plugin_group(scaffolded),)
    ).get(CHECK_ID)
    assert registered is not None, "the entry point's group did not register the check"
    # The metadata matches the file the kit loaded. The *class objects* differ because this test
    # loads the module twice under two names — which is the point: nothing depends on the import
    # name, only on the entry point and the metadata.
    assert registered.metadata == load_check(load_manifest(scaffolded)).metadata
    plain = ModuleRegistry.discover(include_entry_points=False).group(registered.metadata.module)
    assert plain is not None
    assert CHECK_ID not in [item.id for item in plain.metadata()], "a plugin must add, not replace"


# ------------------------------------------------------------------ determinism and refusal
def test_scaffolding_the_same_id_twice_is_byte_identical(tmp_path: Path) -> None:
    first = scaffold_check(CHECK_ID, root=tmp_path / "one")
    second = scaffold_check(CHECK_ID, root=tmp_path / "two")
    for path in first.files:
        twin = second.root / path.relative_to(first.root)
        assert path.read_bytes() == twin.read_bytes(), f"{path.name} is not deterministic"


def test_the_scaffold_refuses_to_overwrite_an_existing_tree(tmp_path: Path) -> None:
    root = tmp_path / "plugin"
    scaffold_check(CHECK_ID, root=root)
    with pytest.raises(ConfigurationError, match="refusing to overwrite"):
        scaffold_check(CHECK_ID, root=root)
    # The escape hatch is explicit, and it works.
    again = scaffold_check(CHECK_ID, root=root, force=True)
    assert again.written is True


@pytest.mark.parametrize(
    "bad",
    ["M4.Header", "m4", "m7.thing", "m4.Thing_Here", "header-missing", ""],
)
def test_a_malformed_check_id_is_refused_with_the_accepted_shape(bad: str) -> None:
    with pytest.raises(ConfigurationError) as excinfo:
        CheckId.parse(bad)
    assert "module" in str(excinfo.value)
    assert "m4.header-missing" in str(excinfo.value), "the message must show the accepted shape"


def test_an_unmapped_declaration_is_refused_at_scaffold_time(tmp_path: Path) -> None:
    """The scaffold builds its own metadata, so a self-contradictory request fails early."""
    with pytest.raises(ConfigurationError):
        author_metadata(CHECK_ID, title="t", description="d", framework=("WSTG-CONF-99",))
    with pytest.raises(ConfigurationError):
        scaffold_check(CHECK_ID, root=tmp_path / "bad", framework=("WSTG-CONF-99",))


def test_an_l2_declaration_through_the_sdk_is_opt_in() -> None:
    """``author_metadata`` derives the opt-in, so the pairing cannot be forgotten."""
    metadata = author_metadata(
        CHECK_ID,
        title="Out-of-band claim",
        description="Establishes a claim that needs an out-of-band callback.",
        framework=("CWE-693",),
        proof="L2",
    )
    assert metadata.enabled_by_default is False
    assert metadata.proof.value == "L2"


# ------------------------------------------------------------------ the authoring surface
def test_the_base_class_fills_the_defaults(scaffolded: Path) -> None:
    check = load_check(load_manifest(scaffolded))
    assert issubclass(check, AuthorCheck)
    metadata = check.metadata
    assert metadata.id == CHECK_ID
    assert metadata.module == "M4"
    assert metadata.name == "demo-marker"
    assert metadata.research_ref == "ch04#1"
    assert metadata.type == "hybrid"
    assert metadata.safe is True
    assert metadata.enabled_by_default is True


def test_a_fixture_gap_is_refused_rather_than_answered(scaffolded: Path) -> None:
    """A check that asks for an unrecorded URL is told so, instead of being given a 501."""
    check = load_check(load_manifest(scaffolded))
    fixture = scaffolded / "fixtures" / "demo-marker" / "positive.json"
    # Point the recording at a different path than the one the check requests.
    text = fixture.read_text(encoding="utf-8")
    fixture.write_text(
        text.replace("demo.example.test/demo-marker", "demo.example.test/elsewhere"),
        encoding="utf-8",
    )
    with pytest.raises(FixtureGapError, match="records no response"):
        run_fixture(check, fixture)


# ------------------------------------------------------------------ the CLI
def test_the_cli_scaffolds_and_conforms(tmp_path: Path) -> None:
    target = tmp_path / "cli"
    created = runner.invoke(app, ["plugin", "new-check", CHECK_ID, "--out", str(target)])
    assert created.exit_code == 0, created.output
    assert "green before you edit" in created.output
    conformed = runner.invoke(app, ["plugin", "conform", str(target / "conformance.yaml")])
    assert conformed.exit_code == 0, conformed.output
    assert "CONFORMANT" in conformed.output


def test_the_cli_refuses_an_id_that_replaces_a_builtin(tmp_path: Path) -> None:
    existing = ModuleRegistry.builtin().check_ids()[0]
    refused = runner.invoke(app, ["plugin", "new-check", existing, "--out", str(tmp_path / "x")])
    assert refused.exit_code == 2
    assert "already exists in the built-in catalogue" in refused.output


def test_the_cli_new_check_reports_json(tmp_path: Path) -> None:
    created = runner.invoke(
        app, ["plugin", "new-check", CHECK_ID, "--out", str(tmp_path / "j"), "--json"]
    )
    assert created.exit_code == 0, created.output
    output = created.output
    payload = json.loads(output[output.index("{") : output.rindex("}") + 1])
    assert payload["check"] == CHECK_ID
    assert "conformance.yaml" in payload["files"]
