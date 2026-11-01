"""The CycloneDX SBOM generator (S22, REQ-TRUST-002).

Every release publishes a Software Bill of Materials in CycloneDX 1.5 JSON. The
generator is part of ARACHNE (not a CI-only script) because the SBOM is a product
artefact: an operator can run it against their own installed environment — the exact
dependency set *they* will attest to — and a test can pin its shape.

Two properties matter more than the feature list:

* **Reproducible.** The document is a pure function of the installed environment and
  an explicit timestamp: sorted keys, sorted components, a deterministic
  ``serialNumber`` derived from the component set, and the clock taken from
  ``SOURCE_DATE_EPOCH`` (see ``docs/reproducible-builds.md``) rather than
  ``now()``. Two machines with the same environment produce byte-identical SBOMs.
* **Honest.** Components come from the installed distributions actually reachable from
  ARACHNE's declared dependencies (``importlib.metadata``), transitively — not from
  whatever the build machine happens to have cached. A dependency that is not
  installed is a loud error, never a silent omission.

Usage::

    python -m arachne.tools.sbom [--output PATH]

Exit code is 0 on success. ``--output -`` writes to stdout.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import uuid
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

__all__ = ["CYCLONEDX_SPEC_VERSION", "generate_sbom", "main"]

CYCLONEDX_SPEC_VERSION = "1.5"

#: ARACHNE's declared runtime dependencies (pyproject ``[project.dependencies]``),
#: normalised the way ``importlib.metadata`` reports them.
ROOT_DISTRIBUTION = "arachne"


def generate_sbom(*, timestamp: str | None = None) -> dict[str, Any]:
    """Build the CycloneDX 1.5 document for the installed ARACHNE environment.

    ``timestamp`` (ISO-8601) overrides the clock; without it, ``SOURCE_DATE_EPOCH`` is
    honoured, and only then the current time — the order a reproducible build needs.
    """
    root = _root_component()
    components = _components()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": _serial_number(root, components),
        "version": 1,
        "metadata": {
            "timestamp": _resolve_timestamp(timestamp),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "arachne",
                        "version": _distribution_version(ROOT_DISTRIBUTION),
                        "bom-ref": _bom_ref("arachne", _distribution_version(ROOT_DISTRIBUTION)),
                    }
                ]
            },
            "component": root,
        },
        "components": components,
    }


def _root_component() -> dict[str, Any]:
    version = _distribution_version(ROOT_DISTRIBUTION)
    return {
        "type": "application",
        "bom-ref": _bom_ref(ROOT_DISTRIBUTION, version),
        "name": ROOT_DISTRIBUTION,
        "version": version,
        "description": (
            "ARACHNE — defensive automated vulnerability-detection and reporting system"
        ),
        "purl": _purl(ROOT_DISTRIBUTION, version),
        "scope": "required",
    }


def _components() -> list[dict[str, Any]]:
    """Every distribution transitively reachable from ARACHNE's dependencies, sorted.

    A requirement whose environment marker excludes this interpreter (``python_version
    < "3.11"``, ``extra == ...``, …) is skipped — the SBOM describes what *is*
    installed. A dependency that is missing with **no** marker is a broken environment
    and a loud error, never a silent omission.
    """
    seen: dict[str, dict[str, Any]] = {}
    visiting: set[str] = set()

    def visit(name: str, *, requirement: str | None) -> None:
        canonical = _canonical(name)
        if canonical in seen or canonical in visiting:
            return
        dist = _distribution(canonical, requirement=requirement)
        visiting.add(canonical)
        version = dist.version
        seen[canonical] = {
            "type": "library",
            "bom-ref": _bom_ref(canonical, version),
            "name": canonical,
            "version": version,
            "purl": _purl(canonical, version),
            "scope": "required",
        }
        for child_requirement in dist.requires or ():
            child = _requirement_name(child_requirement)
            if child is None or _is_extra(child_requirement):
                continue
            if not _marker_applies(child_requirement):
                continue
            visit(child, requirement=child_requirement)
        visiting.discard(canonical)

    root_dist = _distribution(_canonical(ROOT_DISTRIBUTION), requirement=None)
    for requirement in root_dist.requires or ():
        child = _requirement_name(requirement)
        if child is None or _is_extra(requirement) or not _marker_applies(requirement):
            continue
        visit(child, requirement=requirement)
    return sorted(seen.values(), key=lambda component: component["bom-ref"])


def _distribution(canonical: str, *, requirement: str | None) -> Any:
    try:
        return metadata.distribution(canonical)
    except metadata.PackageNotFoundError as exc:
        if requirement is not None and ";" in requirement:
            # Not installed because its environment marker excludes this interpreter
            # (a Python-version or platform gate) — correct to skip, not an error.
            return _MarkedOut(canonical)
        msg = (
            f"the installed environment is missing {canonical!r}, which ARACHNE depends "
            "on — generate the SBOM from a complete environment "
            "(pip install -e .) rather than a partial one"
        )
        raise SystemExit(msg) from exc


class _MarkedOut:
    """A stand-in for a distribution whose marker excludes this environment."""

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def version(self) -> str:
        return "not-installed"

    @property
    def requires(self) -> list[str]:  # pragma: no cover - a marker-out dep has no children here
        return []


_NAME_PATTERN = None


def _requirement_name(requirement: str) -> str | None:
    """``pydantic>=2.7,<3`` → ``pydantic``; ``uvicorn[standard]>=0.30`` → ``uvicorn``."""
    global _NAME_PATTERN
    if _NAME_PATTERN is None:
        import re

        _NAME_PATTERN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?")
    match = _NAME_PATTERN.match(requirement.split(";", 1)[0])
    return _canonical(match.group(1)) if match else None


def _is_extra(requirement: str) -> bool:
    """An ``extra == ...`` marker: optional extras are not SBOM-required components."""
    return "extra ==" in requirement


_PYTHON_MARKER: re.Pattern[str] | None = None


def _version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """PEP 440-style release-segment comparison (missing segments are zero)."""
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _marker_applies(requirement: str) -> bool:
    """Whether a requirement's environment marker selects this interpreter.

    Only the ``python_version <op> "X.Y"`` family is evaluated — the marker every
    dependency in ARACHNE's tree actually uses to gate a backport package. A more
    complex marker applies (conservative include: an SBOM lists what could be loaded,
    and an unparsed marker must not silently hide a component).
    """
    global _PYTHON_MARKER
    if ";" not in requirement:
        return True
    marker = requirement.split(";", 1)[1].strip()
    if _PYTHON_MARKER is None:
        _PYTHON_MARKER = re.compile(
            r'python_version\s*(==|!=|<=|>=|<|>|~=)\s*["\']?([0-9]+(?:\.[0-9]+)*)["\']?'
        )
    match = _PYTHON_MARKER.fullmatch(marker)
    if match is None:
        return True
    operator, bound = match.group(1), match.group(2)
    current = (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)
    ordering = _compare(current, _version_tuple(bound))
    verdicts: dict[str, bool] = {
        "==": ordering == 0,
        "!=": ordering != 0,
        "<": ordering < 0,
        "<=": ordering <= 0,
        ">": ordering > 0,
        ">=": ordering >= 0,
        # A compatible-release bound is an inclusive floor for our purposes.
        "~=": ordering >= 0,
    }
    return verdicts[operator]


def _canonical(name: str) -> str:
    """PEP 503 normalisation: case-insensitive, runs of ``-``/``_``/``.`` → ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{_canonical(name)}@{version}"


def _bom_ref(name: str, version: str) -> str:
    return f"{_canonical(name)}@{version}"


def _distribution_version(canonical: str) -> str:
    return str(_distribution(canonical, requirement=None).version)


def _serial_number(root: dict[str, Any], components: list[dict[str, Any]]) -> str:
    """A deterministic UUID (RFC 4122 name-based) over the component set.

    Same environment → same serial → byte-identical documents; a changed dependency
    set gets a new serial, which is what makes two SBOMs comparable in an audit.
    """
    material = json.dumps(
        [root["bom-ref"], [component["bom-ref"] for component in components]],
        sort_keys=True,
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, digest)}"


def _resolve_timestamp(timestamp: str | None) -> str:
    if timestamp:
        return timestamp
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            return datetime.fromtimestamp(int(epoch), tz=UTC).isoformat()
        except (ValueError, OSError, OverflowError):
            pass  # a malformed SOURCE_DATE_EPOCH is not a build breaker
    return datetime.now(UTC).isoformat()


def main(argv: list[str] | None = None) -> int:
    """Write the SBOM to ``--output`` (default stdout); used by the release workflow."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m arachne.tools.sbom",
        description="Generate the CycloneDX 1.5 SBOM for the installed ARACHNE environment.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="-",
        help="write the SBOM here ('-' = stdout)",
    )
    parser.add_argument(
        "--timestamp",
        default=None,
        help="ISO-8601 build timestamp (default: SOURCE_DATE_EPOCH, else now)",
    )
    args = parser.parse_args(argv)
    document = generate_sbom(timestamp=args.timestamp)
    rendered = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output == "-":
        sys.stdout.write(rendered)
    else:
        Path(args.output).write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    sys.exit(main())
