"""``python -m arachne.tools.compliance`` — generate the published control maps (REQ-TRUST-009).

The four map files under ``templates/compliance/`` are **generated artifacts**, not sources.
The source of truth is each check's :attr:`~arachne.modules.base.CheckMetadata.compliance`
declaration, validated at import against the pinned inventories
(:mod:`arachne.modules.compliance_map`); this tool inverts that declaration into
``control -> checks`` and writes the framework's own YAML. Two consequences, both of them the
point of the requirement:

* **No drift.** Editing a map by hand is a change the ``--check`` mode reports, and the schema
  test runs ``--check`` — so "generated from check metadata" is enforced rather than promised.
  A check that gains or loses a control changes the map in the same commit.
* **The gap is named.** The map carries the framework's own control total *and* an explicit
  ``outside_assessed_set``: every control no check maps onto, with the reason drawn from its
  group. Nothing is omitted, so a report can never read the assessed set as the whole
  framework — the honesty the old hand-written files documented in prose is now a value.

Usage::

    python -m arachne.tools.compliance            # print the ratios
    python -m arachne.tools.compliance --write    # rewrite the four map files
    python -m arachne.tools.compliance --check    # exit 1 when a committed file is stale
    python -m arachne.tools.compliance --json     # machine-readable ratios
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Final

from arachne.core.errors import ConfigurationError
from arachne.modules.compliance_map import (
    COMPLIANCE_FRAMEWORKS,
    TARGET_RATIOS,
    ComplianceInventory,
    inventories,
    split_qualified,
)

__all__ = [
    "MAP_VERSION",
    "generate_all",
    "generate_document",
    "main",
    "ratios",
    "render_map",
]

#: The generated map's own format version. 2.0 introduced generation and the
#: ``outside_assessed_set`` block; 1.0 was the hand-maintained file it replaced.
MAP_VERSION: Final = "2.0"

#: Where the maps are written, relative to the repository root.
_MAP_DIR: Final = ("src", "arachne", "templates", "compliance")


def _repo_root() -> Path:
    """``<repo>/`` — ``parents[3]`` is the checkout (tools -> arachne -> src -> root)."""
    return Path(__file__).resolve().parents[3]


def _registry() -> Any:
    from arachne.modules.registry import ModuleRegistry

    return ModuleRegistry.discover()


def control_assignments() -> dict[str, dict[str, tuple[str, ...]]]:
    """``{framework: {control id (unqualified): (check ids)}}`` from the registry.

    Inverted from ``CheckMetadata.compliance``, sorted, and deduplicated: the same check may
    name a control once, and the order of a check's own tuple never leaks into the file.
    """
    out: dict[str, dict[str, list[str]]] = {framework: {} for framework in COMPLIANCE_FRAMEWORKS}
    for metadata in _registry().metadata():
        for qualified in metadata.compliance:
            split = split_qualified(qualified)
            if split is None:  # pragma: no cover - validated at construction
                msg = f"unrecognised compliance control {qualified!r} on {metadata.id}"
                raise ConfigurationError(msg)
            framework, bare = split
            entry = out[framework].setdefault(bare, [])
            if metadata.id not in entry:
                entry.append(metadata.id)
    return {
        framework: {control: tuple(sorted(checks)) for control, checks in sorted(controls.items())}
        for framework, controls in out.items()
    }


def _order(control_id: str) -> tuple[int, tuple[int, ...], str]:
    """A stable, human ordering: numeric ids by number, then anything else alphabetically."""
    numbers = tuple(int(part) for part in re.findall(r"\d+", control_id))
    return (0 if numbers else 1, numbers, control_id)


def generate_document(inventory: ComplianceInventory) -> dict[str, Any]:
    """The map for one framework: the assessed controls plus the named outside set."""
    assigned = control_assignments()[inventory.framework]
    controls = [
        {"id": control.id, "title": control.title, "checks": list(assigned[control.id])}
        for control in sorted(inventory.controls, key=lambda item: _order(item.id))
        if control.id in assigned
    ]
    outside = [
        {"id": control.id, "title": control.title, "reason": inventory.reason(control)}
        for control in sorted(inventory.controls, key=lambda item: _order(item.id))
        if control.id not in assigned
    ]
    return {
        "framework": inventory.framework,
        "name": inventory.name,
        "edition": inventory.edition,
        "kind": inventory.kind,
        "total_controls": inventory.total,
        "map_version": MAP_VERSION,
        "controls": controls,
        "outside_assessed_set": outside,
    }


def _quote(value: str) -> str:
    """A YAML scalar that cannot be mistyped: JSON's double-quoted form is valid YAML.

    Quoting is not cosmetic — a PCI id is ``1``, which an unquoted emitter would write as the
    integer 1, and the loader would then refuse its own map (or, worse, match it as a number).
    """
    return json.dumps(value, ensure_ascii=False)


def render_map(document: Mapping[str, Any], inventory: ComplianceInventory) -> str:
    """The committed file's exact bytes: a provenance header, then the data."""
    assessed = document["controls"]
    outside = document["outside_assessed_set"]
    target, total = TARGET_RATIOS[inventory.framework]
    header = [
        "# GENERATED FILE — do not edit by hand.",
        "#",
        "# `python -m arachne.tools.compliance --write` regenerates it from every check's",
        "# `compliance=` declaration (REQ-TRUST-009); `--check` fails when this file and the",
        "# registry disagree, which is what makes 'generated, not maintained' enforceable.",
        "#",
        f"# {inventory.name} {inventory.edition} — {inventory.total} {inventory.kind}s.",
        f"# Assessed: {len(assessed)} {inventory.kind}(s) reached by at least one check "
        f"(target {target} of {total}).",
        f"# Outside the assessed set: {len(outside)} {inventory.kind}(s), each named below with a",
        "# reason — an unmapped control is reported, never omitted.",
        "#",
        f"# Source: {inventory.source}",
        f"# Retrieved: {inventory.retrieved}. Cross-check: {inventory.cross_check}",
        "#",
        "# A control id is a real control of this edition (validated against the pinned",
        "# inventory), and every `checks:` entry is a registered check id, so neither direction",
        "# of the join can be a typo. A check's evidence is *about* a control; it is never proof",
        "# of conformity.",
    ]
    lines = [*header]
    lines.append(f"framework: {_quote(inventory.framework)}")
    lines.append(f"name: {_quote(inventory.name)}")
    lines.append(f"edition: {_quote(inventory.edition)}")
    lines.append(f"kind: {_quote(inventory.kind)}")
    lines.append(f"total_controls: {inventory.total}")
    lines.append(f"map_version: {_quote(MAP_VERSION)}")
    lines.append("controls:")
    for control in assessed:
        lines.append(f"  - id: {_quote(control['id'])}")
        lines.append(f"    title: {_quote(control['title'])}")
        lines.append("    checks:")
        lines.extend(f"      - {check}" for check in control["checks"])
    lines.append("outside_assessed_set:")
    for control in outside:
        lines.append(f"  - id: {_quote(control['id'])}")
        lines.append(f"    title: {_quote(control['title'])}")
        lines.append(f"    reason: {_quote(control['reason'])}")
    return "\n".join(lines) + "\n"


def generate_all() -> dict[str, str]:
    """``{framework: rendered map}`` for every framework, without touching the disk."""
    return {
        inventory.framework: render_map(generate_document(inventory), inventory)
        for inventory in inventories()
    }


def ratios() -> dict[str, dict[str, Any]]:
    """The assessed ratio per framework, counted from the registry (REQ-TRUST-009).

    The denominator is the *pinned inventory's* total, and it is checked against the number the
    requirement states: if a future release adds a control to a framework, the two disagree and
    this refuses rather than reporting a ratio against a stale denominator.
    """
    out: dict[str, dict[str, Any]] = {}
    for inventory in inventories():
        assessed = len(generate_document(inventory)["controls"])
        target, stated_total = TARGET_RATIOS[inventory.framework]
        if stated_total != inventory.total:
            msg = (
                f"{inventory.framework}: the requirement's denominator ({stated_total}) does "
                f"not match the pinned inventory's total ({inventory.total}) — one of the two "
                "is out of date"
            )
            raise ConfigurationError(msg)
        out[inventory.framework] = {
            "name": inventory.name,
            "edition": inventory.edition,
            "assessed": assessed,
            "total": inventory.total,
            "target": target,
            "meets_target": assessed >= target,
            "ratio": round(assessed / inventory.total, 4) if inventory.total else 0.0,
        }
    return out


def _write(documents: Mapping[str, str]) -> list[str]:
    root = _repo_root()
    written: list[str] = []
    for framework, text in documents.items():
        target = root.joinpath(*_MAP_DIR, f"{framework}.yaml")
        if target.is_file() and target.read_text(encoding="utf-8") == text:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        written.append(str(target.relative_to(root)))
    return written


def _stale(documents: Mapping[str, str]) -> list[str]:
    root = _repo_root()
    stale: list[str] = []
    for framework, text in documents.items():
        target = root.joinpath(*_MAP_DIR, f"{framework}.yaml")
        if not target.is_file():
            stale.append(f"{framework}: {target} is missing")
            continue
        if target.read_text(encoding="utf-8") != text:
            stale.append(
                f"{framework}: {target.name} disagrees with the check metadata — run "
                "`python -m arachne.tools.compliance --write`"
            )
    return stale


def _print_ratios(table: Mapping[str, Mapping[str, Any]]) -> None:
    for framework, row in table.items():
        mark = "ok " if row["meets_target"] else "UNDER"
        sys.stdout.write(
            f"{mark} {framework:9} {row['assessed']:3}/{row['total']:<4} "
            f"({row['ratio']:.1%}) against a target of {row['target']} — {row['name']} "
            f"{row['edition']}\n"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m arachne.tools.compliance",
        description="Generate and verify the compliance maps from check metadata (REQ-TRUST-009).",
    )
    parser.add_argument("--write", action="store_true", help="rewrite the committed map files")
    parser.add_argument("--check", action="store_true", help="exit 1 when a map is stale")
    parser.add_argument("--json", action="store_true", help="print the ratios as JSON")
    args = parser.parse_args(argv)

    documents = generate_all()
    table = ratios()
    if args.json:
        sys.stdout.write(
            json.dumps({"ratios": table, "map_version": MAP_VERSION}, indent=2, sort_keys=True)
            + "\n"
        )
    else:
        _print_ratios(table)
    if args.write:
        written = _write(documents)
        detail = f": {', '.join(written)}" if written else ""
        sys.stdout.write(f"wrote {len(written)} file(s){detail}\n")
    if args.check:
        stale = _stale(documents)
        for problem in stale:
            sys.stderr.write(f"stale: {problem}\n")
        return 1 if stale else 0
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry point
    sys.exit(main())
