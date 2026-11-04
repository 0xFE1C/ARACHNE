"""SLSA v1.2 build provenance for ARACHNE release artefacts (REQ-TRUST-011).

A release artefact is only useful if a third party can tell *what* produced it and
*where*. SLSA answers that with an in-toto attestation: an ``https://in-toto.io/Statement/v1``
envelope whose predicate is ``https://slsa.dev/provenance/v1``, binding a subject set
(name + sha256) to the build that produced it. This module writes that document for
ARACHNE's release artefacts (the wheel/sdist and the SBOM itself) and verifies it
offline, so the shape of the claim is a product artefact rather than a CI-only script.

Reproducibility is the same discipline the SBOM uses: the document is a pure function
of the named files and an explicit timestamp. Nothing reads the wall clock and the
invocation id is derived from the subjects, so the same inputs render byte-identical
bytes on any machine.

**Honesty about the builder.** Outside CI the default builder id is
:data:`LOCAL_BUILDER_ID` — the document says plainly that it was produced on a local
machine, and the docstring below records exactly which SLSA requirements that does and
does not meet. Only a platform that can *prove* the identity may pass
``--builder-id``: the release workflow passes :data:`GITHUB_ACTIONS_BUILDER_ID` because
GitHub's hosted runner plus ``actions/attest-build-provenance`` is the platform that
mints and signs the attestation.

**SLSA Build L3 coverage.** L3's two load-bearing requirements are (a) a hardened,
isolated build platform that user-controlled build steps cannot tamper with, and
(b) provenance that the build platform itself generates and signs, so the build user
cannot forge it. The local path below does **not** satisfy either: the document is
written by the same user on the same machine that built the artefact, and nothing
prevents that user from editing the file after the fact. What the local path does
provide is the *document shape* of the higher levels: it names the builder, the build
type, the external and internal parameters, the resolved dependencies, the invocation
id, the start/finish times, and the SBOM as a byproduct. The CI path supplies the L3
platform: the wheel/sdist and image are built on a GitHub-hosted runner, and
``actions/attest-build-provenance`` signs the provenance with the workflow's OIDC
identity and pushes it to the registry — see ``docs/slsa-provenance.md``.

Usage::

    python -m arachne.tools.provenance --output provenance.intoto.jsonl \\
        --artifact dist/arachne-0.1.0-py3-none-any.whl \\
        --artifact dist/arachne-0.1.0.tar.gz \\
        --sbom sbom.cdx.json --timestamp 2026-10-31T00:00:00+00:00

    python -m arachne.tools.provenance --verify provenance.intoto.jsonl \\
        --artifact dist/arachne-0.1.0-py3-none-any.whl --sbom sbom.cdx.json

Exit code is 0 on success; ``--verify`` is the CI gate and returns non-zero when a
subject digest does not match the named file or a subject is missing.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from arachne import __version__

__all__ = [
    "BUILD_TYPE",
    "GITHUB_ACTIONS_BUILDER_ID",
    "IN_TOTO_STATEMENT_TYPE",
    "LOCAL_BUILDER_ID",
    "SLSA_PROVENANCE_V1",
    "ProvenanceError",
    "generate_provenance",
    "main",
    "render_provenance",
    "verify_provenance",
]

IN_TOTO_STATEMENT_TYPE: Final = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_V1: Final = "https://slsa.dev/provenance/v1"

#: The build described is ARACHNE's own release assembly of an artefact set.
BUILD_TYPE: Final = "https://arachne.dev/buildtypes/python-release/v1"

#: An honest builder id for a run outside a hosted build platform. It makes no claim
#: of isolation or signing, which a local run cannot provide.
LOCAL_BUILDER_ID: Final = "https://arachne.dev/builders/local/v1"

#: GitHub's hosted runner. Passed explicitly (never inferred) by the release workflow,
#: where the platform really is what signs the attestation.
GITHUB_ACTIONS_BUILDER_ID: Final = "https://github.com/actions/runner"

_CHUNK = 1 << 20


class ProvenanceError(RuntimeError):
    """A provenance document could not be generated or verified."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _descriptor(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ProvenanceError(f"artefact not found: {path}")
    return {"name": path.name, "digest": {"sha256": _sha256(path)}}


def _named_paths(artifacts: Sequence[Path], sbom: Path | None) -> list[tuple[str, Path]]:
    """The subject set: artefacts plus the SBOM, sorted by name for determinism."""
    named = [(path.name, path) for path in artifacts]
    if sbom is not None:
        named.append((sbom.name, sbom))
    if not named:
        raise ProvenanceError("at least one artefact (or the SBOM) is required")
    seen: set[str] = set()
    for name, _ in named:
        if name in seen:
            raise ProvenanceError(f"duplicate subject name {name!r}: names must be unique")
        seen.add(name)
    return sorted(named, key=lambda item: item[0])


def generate_provenance(
    artifacts: Sequence[Path],
    *,
    sbom: Path | None,
    timestamp: str,
    builder_id: str = LOCAL_BUILDER_ID,
    invocation_id: str | None = None,
) -> dict[str, Any]:
    """Build the SLSA v1.2 provenance statement for ``artifacts`` (and ``sbom``).

    ``timestamp`` is mandatory — provenance without an explicit clock is not
    reproducible — and ``builder_id`` defaults to the honest local id.
    """
    named = _named_paths(artifacts, sbom)
    subjects = [{"name": name, "digest": {"sha256": _sha256(path)}} for name, path in named]
    resolved = [_descriptor(path) for path in artifacts]
    byproducts = [_descriptor(sbom)] if sbom is not None else []
    external: dict[str, Any] = {
        "artifacts": [_descriptor(path) for path in artifacts],
        "sbom": _descriptor(sbom) if sbom is not None else None,
    }
    internal: dict[str, Any] = {
        "generator": "arachne.tools.provenance",
        "generatorVersion": __version__,
    }
    resolved_invocation = invocation_id or _invocation_id(timestamp, subjects)
    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": SLSA_PROVENANCE_V1,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": external,
                "internalParameters": internal,
                "resolvedDependencies": resolved,
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": resolved_invocation,
                    "startedOn": timestamp,
                    "finishedOn": timestamp,
                },
                "byproducts": byproducts,
            },
        },
    }


def _invocation_id(timestamp: str, subjects: Sequence[Mapping[str, Any]]) -> str:
    """A deterministic invocation id: same inputs, same id, no random UUID."""
    material = json.dumps({"timestamp": timestamp, "subjects": subjects}, sort_keys=True)
    return f"urn:arachne:invocation:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def render_provenance(document: Mapping[str, Any]) -> str:
    """Canonical bytes for a provenance document (sorted keys, trailing newline)."""
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def verify_provenance(
    document: Mapping[str, Any],
    artifacts: Sequence[Path],
    *,
    sbom: Path | None = None,
) -> None:
    """Re-derive every subject digest from the named files and refuse a mismatch.

    Every subject the document claims must be backed by a file supplied here; a
    subject with no file, or a digest that does not match, raises
    :class:`ProvenanceError`. This is the gate a consumer runs before trusting an
    artefact set.
    """
    declared = _declared_subjects(document)
    supplied = {path.name: _sha256(path) for path in [*artifacts, *([sbom] if sbom else [])]}
    for name in sorted(declared):
        if name not in supplied:
            raise ProvenanceError(f"no file supplied for subject {name!r}")
        if declared[name] != supplied[name]:
            raise ProvenanceError(
                f"subject {name!r} digest does not match the named file "
                f"(document {declared[name]}, file {supplied[name]})"
            )
    for name in sorted(supplied):
        if name not in declared:
            raise ProvenanceError(f"file {name!r} is not a subject of this document")


def _declared_subjects(document: Mapping[str, Any]) -> dict[str, str]:
    _check_envelope(document)
    subjects = document["subject"]
    declared: dict[str, str] = {}
    for entry in subjects:
        if not isinstance(entry, Mapping):
            raise ProvenanceError(f"subject entry is not an object: {entry!r}")
        name = entry.get("name")
        digest = entry.get("digest")
        if not isinstance(name, str) or not isinstance(digest, Mapping):
            raise ProvenanceError(f"subject is missing a name/digest: {entry!r}")
        sha256 = digest.get("sha256")
        if not isinstance(sha256, str):
            raise ProvenanceError(f"subject {name!r} has no sha256 digest")
        declared[name] = sha256
    return declared


def _check_envelope(document: Mapping[str, Any]) -> None:
    if document.get("_type") != IN_TOTO_STATEMENT_TYPE:
        raise ProvenanceError(
            f"not an in-toto statement: _type is {document.get('_type')!r}, "
            f"expected {IN_TOTO_STATEMENT_TYPE!r}"
        )
    if document.get("predicateType") != SLSA_PROVENANCE_V1:
        raise ProvenanceError(
            f"not SLSA provenance: predicateType is {document.get('predicateType')!r}, "
            f"expected {SLSA_PROVENANCE_V1!r}"
        )
    if not isinstance(document.get("predicate"), Mapping):
        raise ProvenanceError("the statement has no provenance predicate")
    if not isinstance(document.get("subject"), list) or not document["subject"]:
        raise ProvenanceError("the statement has no subjects")


def _resolve_timestamp(explicit: str | None) -> str:
    """An explicit clock, then ``SOURCE_DATE_EPOCH``; never ``now()``."""
    if explicit:
        return explicit
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), tz=UTC).isoformat()
        except (ValueError, OSError, OverflowError):
            pass
    raise ProvenanceError(
        "a timestamp is required for reproducible provenance: pass --timestamp "
        "or set SOURCE_DATE_EPOCH"
    )


def main(argv: list[str] | None = None) -> int:
    """Generate (default) or verify (``--verify``) SLSA v1.2 provenance."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m arachne.tools.provenance",
        description="Generate or verify SLSA v1.2 provenance for ARACHNE release artefacts.",
    )
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        dest="artifacts",
        metavar="PATH",
        help="a release artefact to bind (repeatable; the wheel/sdist)",
    )
    parser.add_argument("--sbom", metavar="PATH", default=None, help="the CycloneDX SBOM")
    parser.add_argument(
        "--output",
        "-o",
        default="-",
        help="write the provenance here ('-' = stdout)",
    )
    parser.add_argument(
        "--timestamp",
        default=None,
        help="ISO-8601 build timestamp (default: SOURCE_DATE_EPOCH; never now())",
    )
    parser.add_argument(
        "--builder-id",
        default=LOCAL_BUILDER_ID,
        help=(
            "SLSA builder id; defaults to the honest local id. Only a platform that "
            "can prove the identity may pass its own (the release workflow passes "
            f"{GITHUB_ACTIONS_BUILDER_ID})"
        ),
    )
    parser.add_argument(
        "--verify",
        metavar="PATH",
        default=None,
        help="re-derive subjects from --artifact/--sbom and exit non-zero on a mismatch",
    )
    args = parser.parse_args(argv)
    artifacts = [Path(path) for path in args.artifacts]
    sbom = Path(args.sbom) if args.sbom else None

    if args.verify is not None:
        return _verify(Path(args.verify), artifacts, sbom)
    try:
        document = generate_provenance(
            artifacts,
            sbom=sbom,
            timestamp=_resolve_timestamp(args.timestamp),
            builder_id=args.builder_id,
        )
    except ProvenanceError as exc:
        sys.stderr.write(f"provenance: {exc}\n")
        return 1
    rendered = render_provenance(document)
    if args.output == "-":
        sys.stdout.write(rendered)
    else:
        Path(args.output).write_text(rendered, encoding="utf-8")
    return 0


def _verify(path: Path, artifacts: Sequence[Path], sbom: Path | None) -> int:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        sys.stderr.write(f"provenance: no such file: {path}\n")
        return 1
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"provenance: {path} is not valid JSON: {exc}\n")
        return 1
    try:
        verify_provenance(document, artifacts, sbom=sbom)
    except ProvenanceError as exc:
        sys.stderr.write(f"provenance: rejected {path}: {exc}\n")
        return 1
    sys.stdout.write(f"provenance: {path} matches the named artefacts\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    sys.exit(main())
