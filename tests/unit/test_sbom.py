"""The CycloneDX SBOM generator's contract (S22, REQ-TRUST-002).

The SBOM is a release artefact, so its shape is pinned: CycloneDX 1.5, the root
application component, the transitive dependency set with purl refs, and — the
property reproducible builds need — byte-identical output for the same environment
and timestamp.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from arachne import __version__
from arachne.tools.sbom import (
    CYCLONEDX_SPEC_VERSION,
    SbomValidationError,
    generate_sbom,
    load_schema,
    main,
    validate_sbom,
)

STAMP = "2026-10-31T00:00:00+00:00"


@pytest.fixture
def sbom() -> dict[str, Any]:
    return generate_sbom(timestamp=STAMP)


def test_the_document_is_cyclonedx_1_5(sbom: dict[str, Any]) -> None:
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == CYCLONEDX_SPEC_VERSION == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["metadata"]["timestamp"] == STAMP


def test_the_root_component_is_the_arachne_application(sbom: dict[str, Any]) -> None:
    root = sbom["metadata"]["component"]
    assert root["type"] == "application"
    assert root["name"] == "arachne"
    assert root["version"] == __version__
    assert root["purl"] == f"pkg:pypi/arachne@{__version__}"


def test_the_dependency_set_is_transitive_and_purl_refed(sbom: dict[str, Any]) -> None:
    names = {component["name"] for component in sbom["components"]}
    # The declared runtime dependencies (pyproject) are all present…
    for expected in (
        "httpx",
        "pydantic",
        "fastapi",
        "uvicorn",
        "typer",
        "jinja2",
        "sqlalchemy",
        "alembic",
        "pyyaml",
    ):
        assert expected in names, expected
    # …and so is a second-level dependency no [project.dependencies] row names.
    assert "pydantic-core" in names or "anyio" in names
    for component in sbom["components"]:
        assert component["type"] == "library"
        assert component["purl"] == f"pkg:pypi/{component['name']}@{component['version']}"
        assert component["bom-ref"] == f"{component['name']}@{component['version']}"
    # Sorted, so a diff between two releases is a diff of dependency sets.
    refs = [component["bom-ref"] for component in sbom["components"]]
    assert refs == sorted(refs)


def test_marker_gated_backports_are_not_components(sbom: dict[str, Any]) -> None:
    """A ``python_version < "3.11"`` backport is not a component on a newer interpreter."""
    names = {component["name"] for component in sbom["components"]}
    assert "exceptiongroup" not in names
    assert "tomli" not in names


def test_the_same_environment_is_byte_identical(sbom: dict[str, Any]) -> None:
    again = generate_sbom(timestamp=STAMP)
    assert json.dumps(again, sort_keys=True) == json.dumps(sbom, sort_keys=True)


def test_a_changed_dependency_set_changes_the_serial() -> None:
    """The serial is derived from the component set, so two SBOMs are comparable."""
    from arachne.tools import sbom as sbom_module

    first = generate_sbom(timestamp=STAMP)
    real = sbom_module._components
    inflated = [
        *real(),
        {
            "type": "library",
            "bom-ref": "x@1",
            "name": "x",
            "version": "1",
            "purl": "pkg:pypi/x@1",
            "scope": "required",
        },
    ]
    sbom_module._components = lambda: inflated  # type: ignore[assignment]
    try:
        second = generate_sbom(timestamp=STAMP)
    finally:
        sbom_module._components = real  # type: ignore[assignment]
    assert first["serialNumber"] != second["serialNumber"]
    assert len(second["components"]) == len(first["components"]) + 1


def test_source_date_epoch_drives_the_timestamp(
    monkeypatch: pytest.MonkeyPatch, sbom: dict[str, Any]
) -> None:
    from datetime import UTC, datetime

    stamp = "2025-10-31T00:00:00+00:00"
    epoch = int(datetime(2025, 10, 31, tzinfo=UTC).timestamp())
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(epoch))
    document = generate_sbom()
    assert document["metadata"]["timestamp"] == stamp
    assert document["metadata"]["timestamp"] != sbom["metadata"]["timestamp"]


def test_a_malformed_source_date_epoch_falls_back_to_now(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not-a-number")
    document = generate_sbom()
    assert "T" in document["metadata"]["timestamp"]


def test_the_cli_writes_a_file(tmp_path: Any, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "sbom.cdx.json"
    assert main(["--output", str(target), "--timestamp", STAMP]) == 0
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert main(["--output", "-", "--timestamp", STAMP]) == 0
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"


def test_a_missing_dependency_is_a_loud_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib.metadata as metadata_module

    from arachne.tools import sbom as sbom_module

    real = metadata_module.distribution

    def missing(name: str, **kwargs: Any) -> Any:
        if name == "httpx":
            raise metadata_module.PackageNotFoundError(name)
        return real(name)

    monkeypatch.setattr(sbom_module.metadata, "distribution", missing)
    with pytest.raises(SystemExit, match="httpx"):
        generate_sbom(timestamp=STAMP)


def test_the_vendored_schema_is_the_official_cyclonedx_1_5_schema() -> None:
    """The shipped validator's schema is the published CycloneDX 1.5 document."""
    schema = load_schema()
    assert schema["$id"] == "http://cyclonedx.org/schema/bom-1.5.schema.json"
    assert schema["properties"]["bomFormat"]["enum"] == ["CycloneDX"]
    assert schema["required"] == ["bomFormat", "specVersion"]


def test_a_generated_document_is_schema_valid(sbom: dict[str, Any]) -> None:
    """REQ-TRUST-011: the release SBOM must pass CycloneDX schema validation."""
    validate_sbom(sbom)


def test_a_corrupted_document_fails_validation(sbom: dict[str, Any]) -> None:
    import copy

    corrupted = copy.deepcopy(sbom)
    corrupted["bomFormat"] = "SPDX"
    with pytest.raises(SbomValidationError, match="not valid CycloneDX"):
        validate_sbom(corrupted)


def test_a_wrongly_typed_reference_fails_validation(sbom: dict[str, Any]) -> None:
    import copy

    corrupted = copy.deepcopy(sbom)
    corrupted["components"][0]["version"] = 123  # a version is a string in CycloneDX
    with pytest.raises(SbomValidationError, match="not valid CycloneDX"):
        validate_sbom(corrupted)


def test_a_missing_validator_is_an_actionable_error(
    monkeypatch: pytest.MonkeyPatch, sbom: dict[str, Any]
) -> None:
    """An absent jsonschema must fail loudly, never report a silent pass."""
    from arachne.tools import sbom as sbom_module

    def unavailable(name: str, package: str | None = None) -> Any:
        raise ModuleNotFoundError(f"No module named {name!r}")

    monkeypatch.setattr(sbom_module.importlib, "import_module", unavailable)
    with pytest.raises(SbomValidationError, match="jsonschema"):
        validate_sbom(sbom)


def test_the_check_cli_validates_and_rejects(
    tmp_path: Any, sbom: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    good = tmp_path / "sbom.cdx.json"
    good.write_text(json.dumps(sbom), encoding="utf-8")
    assert main(["--check", str(good)]) == 0
    assert sbom["bomFormat"] in capsys.readouterr().out

    bad = tmp_path / "corrupt.cdx.json"
    bad.write_text(json.dumps({**sbom, "bomFormat": "SPDX"}), encoding="utf-8")
    assert main(["--check", str(bad)]) == 1
    assert "failed validation" in capsys.readouterr().err

    not_json = tmp_path / "not-json.cdx.json"
    not_json.write_text("{", encoding="utf-8")
    assert main(["--check", str(not_json)]) == 1


def test_a_file_output_is_validated_by_default(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, sbom: dict[str, Any]
) -> None:
    from arachne.tools import sbom as sbom_module

    validated: list[Any] = []
    real = sbom_module.validate_sbom
    monkeypatch.setattr(
        sbom_module, "validate_sbom", lambda document: (validated.append(document), real(document))
    )
    assert main(["--output", str(tmp_path / "s.json"), "--timestamp", STAMP]) == 0
    assert validated == [sbom]


def test_a_stdout_output_is_not_validated_by_default(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from arachne.tools import sbom as sbom_module

    validated: list[Any] = []
    monkeypatch.setattr(sbom_module, "validate_sbom", lambda document: validated.append(document))
    assert main(["--output", "-", "--timestamp", STAMP]) == 0
    assert validated == []
    assert json.loads(capsys.readouterr().out)["bomFormat"] == "CycloneDX"


def test_a_failed_validation_fails_the_cli(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from arachne.tools import sbom as sbom_module

    def reject(document: Any) -> None:
        raise SbomValidationError("nope")

    monkeypatch.setattr(sbom_module, "validate_sbom", reject)
    assert main(["--output", str(tmp_path / "s.json"), "--timestamp", STAMP]) == 1
    assert "failed validation" in capsys.readouterr().err
    assert main(["--output", str(tmp_path / "s2.json"), "--no-validate", "--timestamp", STAMP]) == 0
