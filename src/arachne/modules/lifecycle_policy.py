"""Check lifecycle policy: the deprecated state, its successor and its removal horizon.

152 checks with no retirement mechanism become 400 unmaintainable ones (REQ-DET-008). The
policy is deliberately small: **one table**, appended to by a human, that says a check id is
deprecated, who replaces it, and in which minor release that happened. From it three things
follow, and nothing else does:

* a deprecated check keeps running — compatibility is the point of deprecating rather than
  deleting — but its state travels with it into the registry summary (plan output) and into
  the coverage ledger (reports);
* a check that has been deprecated for more than :data:`REMOVAL_HORIZON_MINORS` minor releases
  fails the ledger's ``--check`` gate, which CI already runs. That is the "retire it or undeprecate
  it" alarm: nothing is removed silently, and nothing is kept for ever;
* the successor must be a registered check, and the deprecation must not be in the future or
  dated in a format the version can be read from.

The table is **empty today**, and that is a statement rather than an omission: no shipped check
is deprecated. The horizon's behaviour is therefore proven by tests that drive synthetic
tables through :func:`problems` — a gate that has never been exercised is a gate nobody trusts.

Usage::

    python -m arachne.modules.lifecycle_policy --check
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from typing import Any, Final

from arachne import __version__

__all__ = [
    "DEPRECATED_CHECKS",
    "LIFECYCLE_VERSION",
    "REMOVAL_HORIZON_MINORS",
    "Deprecation",
    "annotate",
    "horizon_expired",
    "ledger_section",
    "main",
    "problems",
]

#: Bumped when the policy's shape changes: the ledger records it.
LIFECYCLE_VERSION: Final = "1.0"

#: A deprecation's removal horizon, in minor releases (REQ-DET-008). A check deprecated in
#: ``0.1`` may still run in ``0.2`` and ``0.3``; from ``0.4`` it fails the gate.
REMOVAL_HORIZON_MINORS: Final = 2

_MINOR = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?$")


@dataclass(frozen=True, slots=True)
class Deprecation:
    """One deprecated check: who replaces it, when, and why."""

    check_id: str
    successor: str
    deprecated_in: str
    reason: str

    @property
    def horizon(self) -> str:
        """The first minor release in which this check must be gone."""
        major, minor = _minor_parts(self.deprecated_in)
        return f"{major}.{minor + REMOVAL_HORIZON_MINORS}"


#: Every deprecated check. Empty: no shipped check is deprecated as of this work package.
DEPRECATED_CHECKS: tuple[Deprecation, ...] = ()


def _minor_parts(version: str) -> tuple[int, int]:
    match = _MINOR.match(version.strip())
    if match is None:
        raise ValueError(f"{version!r} is not a major.minor version")
    return int(match.group(1)), int(match.group(2))


def _minor_index(version: str) -> int:
    major, minor = _minor_parts(version)
    return major * 1000 + minor


def horizon_expired(deprecation: Deprecation, *, current_version: str) -> bool:
    """True when ``deprecation`` has been in force for **more than** the horizon.

    "More than two minors" is the requirement's wording: deprecated in ``0.1`` and running on
    ``0.3`` is still within the horizon (two minors have elapsed), and ``0.4`` is not.
    """
    elapsed = _minor_index(current_version) - _minor_index(deprecation.deprecated_in)
    return elapsed > REMOVAL_HORIZON_MINORS


def annotate(check_id: str) -> dict[str, object]:
    """The lifecycle fields for one check, for the registry summary (plan output)."""
    for deprecation in DEPRECATED_CHECKS:
        if deprecation.check_id == check_id:
            return {
                "deprecated": True,
                "successor": deprecation.successor,
                "removal_horizon": deprecation.horizon,
                "deprecation_reason": deprecation.reason,
            }
    return {"deprecated": False, "successor": None, "removal_horizon": None}


def ledger_section(*, current_version: str | None = None) -> dict[str, Any]:
    """The ledger's ``deprecations`` section: the state, the successor and the horizon."""
    version = current_version if current_version is not None else __version__
    return {
        "lifecycle_version": LIFECYCLE_VERSION,
        "current_version": version,
        "removal_horizon_minors": REMOVAL_HORIZON_MINORS,
        "deprecated": [
            {
                "check_id": deprecation.check_id,
                "successor": deprecation.successor,
                "deprecated_in": deprecation.deprecated_in,
                "removal_horizon": deprecation.horizon,
                "reason": deprecation.reason,
            }
            for deprecation in DEPRECATED_CHECKS
        ],
    }


def problems(
    *,
    current_version: str | None = None,
    deprecations: tuple[Deprecation, ...] | None = None,
    registry_check_ids: frozenset[str] | set[str] | None = None,
) -> tuple[str, ...]:
    """Every defect in the deprecation table, as a sentence. Empty means conforming.

    This is the CI gate (REQ-DET-008): the ledger's ``--check`` mode calls it, so a table entry
    that has outlived its horizon, points at a check that does not exist, or is dated in the
    future fails the build. ``current_version`` defaults to the running product version, read
    at call time so a caller (and a test) can ask about another release.
    """
    version = current_version if current_version is not None else __version__
    table = DEPRECATED_CHECKS if deprecations is None else deprecations
    found: list[str] = []
    try:
        current_index = _minor_index(version)
    except ValueError as exc:
        return (f"the running version is unusable: {exc}",)
    seen: set[str] = set()
    for deprecation in table:
        if deprecation.check_id in seen:
            found.append(f"check {deprecation.check_id!r} is deprecated twice")
        seen.add(deprecation.check_id)
        try:
            deprecated_index = _minor_index(deprecation.deprecated_in)
        except ValueError as exc:
            found.append(f"check {deprecation.check_id!r}: {exc}")
            continue
        if deprecated_index > current_index:
            found.append(
                f"check {deprecation.check_id!r} is deprecated in {deprecation.deprecated_in}, "
                f"which is later than the running version {current_version}"
            )
        if horizon_expired(deprecation, current_version=version):
            found.append(
                f"check {deprecation.check_id!r} has been deprecated since "
                f"{deprecation.deprecated_in} and must be removed by {deprecation.horizon}: "
                f"the running version is {current_version}. Remove it, or supersede the "
                "deprecation with a recorded decision."
            )
        if deprecation.successor == deprecation.check_id:
            found.append(
                f"check {deprecation.check_id!r} names itself as its successor: a deprecation "
                "must point at the check that replaces it"
            )
        if not deprecation.reason.strip():
            found.append(f"check {deprecation.check_id!r} has no recorded deprecation reason")
        if registry_check_ids is not None:
            if deprecation.check_id not in registry_check_ids:
                found.append(
                    f"deprecated check {deprecation.check_id!r} is not registered: a removed "
                    "check has no deprecation to record"
                )
            if deprecation.successor not in registry_check_ids:
                found.append(
                    f"check {deprecation.check_id!r} names successor "
                    f"{deprecation.successor!r}, which is not a registered check"
                )
    return tuple(found)


def main(argv: list[str] | None = None) -> int:
    """``python -m arachne.modules.lifecycle_policy --check``."""
    parser = argparse.ArgumentParser(
        description="Validate the check deprecation table (REQ-DET-008)."
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero when a deprecation has outlived its horizon or is malformed",
    )
    parser.add_argument("--version", default=__version__, help="the running product version")
    arguments = parser.parse_args(argv)
    from arachne.modules.registry import ModuleRegistry

    found = problems(
        current_version=arguments.version,
        registry_check_ids=set(ModuleRegistry.discover().check_ids()),
    )
    # ``sys.stdout`` rather than ``print``: this module is domain logic, not the CLI package
    # (where ``print`` is the sanctioned output path), and one line per problem is the whole
    # report.
    for problem in found:
        sys.stdout.write(f"FAIL {problem}\n")
    if found:
        return 1
    sys.stdout.write(
        f"OK {len(DEPRECATED_CHECKS)} deprecated check(s) within the "
        f"{REMOVAL_HORIZON_MINORS}-minor horizon\n"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - the module entry point
    sys.exit(main())
