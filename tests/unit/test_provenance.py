"""SLSA v1.2 provenance generator/verifier contract (REQ-TRUST-011).

The provenance is a release artefact, so two properties are pinned: the document is
the standard in-toto Statement v1 / ``https://slsa.dev/provenance/v1`` envelope with
the wheel, sdist and SBOM as sha256 subjects, and it is a pure function of the named
files and an explicit timestamp. The honesty rule is pinned too: a local run must not
claim GitHub's hosted-builder identity.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from arachne.tools.provenance import (
    BUILD_TYPE,
    GITHUB_ACTIONS_BUILDER_ID,
    IN_TOTO_STATEMENT_TYPE,
    LOCAL_BUILDER_ID,
    SLSA_PROVENANCE_V1,
    ProvenanceError,
    generate_provenance,
    main,
    render_provenance,
    verify_provenance,
)

STAMP = "2026-10-31T00:00:00+00:00"


@pytest.fixture
def artefacts(tmp_path: Path) -> tuple[Path, Path, Path]:
    wheel = tmp_path / "arachne-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"the wheel")
    sdist = tmp_path / "arachne-0.1.0.tar.gz"
    sdist.write_bytes(b"the sdist")
    sbom = tmp_path / "sbom.cdx.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.5"}', encoding="utf-8")
    return wheel, sdist, sbom


def test_the_envelope_is_an_intoto_statement_with_slsa_v1_predicate(
    artefacts: tuple[Path, Path, Path],
) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    assert document["_type"] == IN_TOTO_STATEMENT_TYPE == "https://in-toto.io/Statement/v1"
    assert document["predicateType"] == SLSA_PROVENANCE_V1 == "https://slsa.dev/provenance/v1"


def test_subjects_are_the_artefacts_and_the_sbom_with_sha256_digests(
    artefacts: tuple[Path, Path, Path],
) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    subjects = {entry["name"]: entry["digest"]["sha256"] for entry in document["subject"]}
    assert subjects == {
        "arachne-0.1.0-py3-none-any.whl": hashlib.sha256(b"the wheel").hexdigest(),
        "arachne-0.1.0.tar.gz": hashlib.sha256(b"the sdist").hexdigest(),
        "sbom.cdx.json": hashlib.sha256(
            b'{"bomFormat": "CycloneDX", "specVersion": "1.5"}'
        ).hexdigest(),
    }


def test_the_predicate_carries_the_build_definition_and_run_details(
    artefacts: tuple[Path, Path, Path],
) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    build_definition = document["predicate"]["buildDefinition"]
    assert build_definition["buildType"] == BUILD_TYPE
    assert build_definition["externalParameters"]["artifacts"]
    assert build_definition["externalParameters"]["sbom"]["name"] == "sbom.cdx.json"
    assert build_definition["internalParameters"]["generator"] == "arachne.tools.provenance"
    assert [entry["name"] for entry in build_definition["resolvedDependencies"]] == [
        "arachne-0.1.0-py3-none-any.whl",
        "arachne-0.1.0.tar.gz",
    ]
    run_details = document["predicate"]["runDetails"]
    assert run_details["metadata"]["startedOn"] == STAMP
    assert run_details["metadata"]["finishedOn"] == STAMP
    assert run_details["metadata"]["invocationId"].startswith("urn:arachne:invocation:")
    assert [byproduct["name"] for byproduct in run_details["byproducts"]] == ["sbom.cdx.json"]


def test_the_default_builder_is_local_and_never_github(
    artefacts: tuple[Path, Path, Path],
) -> None:
    """A local run cannot prove a hosted identity, so it must not claim one."""
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    builder = document["predicate"]["runDetails"]["builder"]["id"]
    assert builder == LOCAL_BUILDER_ID
    assert builder != GITHUB_ACTIONS_BUILDER_ID


def test_an_explicit_builder_id_is_recorded(
    artefacts: tuple[Path, Path, Path],
) -> None:
    """CI passes the platform it can actually prove; the tool records it verbatim."""
    wheel, sdist, sbom = artefacts
    document = generate_provenance(
        [wheel, sdist], sbom=sbom, timestamp=STAMP, builder_id=GITHUB_ACTIONS_BUILDER_ID
    )
    assert document["predicate"]["runDetails"]["builder"]["id"] == GITHUB_ACTIONS_BUILDER_ID


def test_the_document_is_a_pure_function_of_its_inputs(
    artefacts: tuple[Path, Path, Path],
) -> None:
    wheel, sdist, sbom = artefacts
    first = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    second = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    assert first == second
    assert render_provenance(first) == render_provenance(second)


def test_duplicate_subject_names_are_rejected(tmp_path: Path) -> None:
    first = tmp_path / "a" / "widget.whl"
    second = tmp_path / "b" / "widget.whl"
    first.parent.mkdir()
    second.parent.mkdir()
    first.write_bytes(b"one")
    second.write_bytes(b"two")
    with pytest.raises(ProvenanceError, match="duplicate subject"):
        generate_provenance([first, second], sbom=None, timestamp=STAMP)


def test_verification_accepts_a_matching_document(artefacts: tuple[Path, Path, Path]) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    verify_provenance(document, [wheel, sdist], sbom=sbom)


def test_verification_refuses_a_changed_artefact(artefacts: tuple[Path, Path, Path]) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    wheel.write_bytes(b"tampered")
    with pytest.raises(ProvenanceError, match="does not match"):
        verify_provenance(document, [wheel, sdist], sbom=sbom)


def test_verification_refuses_a_missing_subject_file(artefacts: tuple[Path, Path, Path]) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    with pytest.raises(ProvenanceError, match="no file supplied"):
        verify_provenance(document, [wheel])


def test_verification_refuses_an_extra_file(
    artefacts: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    extra = tmp_path / "extra.txt"
    extra.write_bytes(b"extra")
    with pytest.raises(ProvenanceError, match="not a subject"):
        verify_provenance(document, [wheel, sdist, sbom, extra])


def test_verification_refuses_a_foreign_envelope(artefacts: tuple[Path, Path, Path]) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    document["predicateType"] = "https://example.com/not-slsa"
    with pytest.raises(ProvenanceError, match="not SLSA provenance"):
        verify_provenance(document, [wheel, sdist], sbom=sbom)


def test_verification_refuses_a_statement_without_subjects(
    artefacts: tuple[Path, Path, Path],
) -> None:
    wheel, sdist, sbom = artefacts
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp=STAMP)
    del document["subject"]
    with pytest.raises(ProvenanceError, match="no subjects"):
        verify_provenance(document, [wheel, sdist], sbom=sbom)


def test_the_cli_generates_then_verifies(
    artefacts: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    wheel, sdist, sbom = artefacts
    output = tmp_path / "provenance.intoto.jsonl"
    assert (
        main(
            [
                "--output",
                str(output),
                "--artifact",
                str(wheel),
                "--artifact",
                str(sdist),
                "--sbom",
                str(sbom),
                "--timestamp",
                STAMP,
            ]
        )
        == 0
    )
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["predicateType"] == SLSA_PROVENANCE_V1
    assert (
        main(
            [
                "--verify",
                str(output),
                "--artifact",
                str(wheel),
                "--artifact",
                str(sdist),
                "--sbom",
                str(sbom),
            ]
        )
        == 0
    )
    # The gate refuses a document whose digest no longer matches the file.
    wheel.write_bytes(b"tampered after attestation")
    assert (
        main(
            [
                "--verify",
                str(output),
                "--artifact",
                str(wheel),
                "--artifact",
                str(sdist),
                "--sbom",
                str(sbom),
            ]
        )
        == 1
    )


def test_the_cli_requires_an_explicit_clock(
    artefacts: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    wheel, _, _ = artefacts
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    assert main(["--artifact", str(wheel)]) == 1
    assert "timestamp" in capsys.readouterr().err


def test_source_date_epoch_drives_the_clock(
    artefacts: tuple[Path, Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    wheel, sdist, sbom = artefacts
    from datetime import UTC, datetime

    monkeypatch.setenv(
        "SOURCE_DATE_EPOCH", str(int(datetime(2025, 10, 31, tzinfo=UTC).timestamp()))
    )
    document = generate_provenance([wheel, sdist], sbom=sbom, timestamp="2026-10-31T00:00:00+00:00")
    assert (
        document["predicate"]["runDetails"]["metadata"]["startedOn"] == "2026-10-31T00:00:00+00:00"
    )
    assert main(["--artifact", str(wheel), "--output", "-"]) == 0


def test_the_cli_rejects_a_non_json_document(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert main(["--verify", str(broken)]) == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_the_cli_rejects_a_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--verify", str(tmp_path / "absent.json")]) == 1
    assert "no such file" in capsys.readouterr().err
