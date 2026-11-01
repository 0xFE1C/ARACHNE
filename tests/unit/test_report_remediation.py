"""Remediation catalog coverage and verification-of-fix (docs/spec/06- §6, F-06-04).

S8 owns the catalog QA gate: every CWE a shipped check or rule can emit must resolve to an
entry, and every entry must carry the four parts the spec names (summary, numbered steps,
verification of fix, references). The stage prompt also asks for a starter set covering the
top 40 CWEs, which is asserted here so the corpus cannot quietly shrink.
"""

from __future__ import annotations

import pathlib
from typing import Any

import yaml

from arachne.analyzer.remediation import load_remediation_catalog
from arachne.modules.registry import ModuleRegistry

RULES_FILE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "src"
    / "arachne"
    / "templates"
    / "rules"
    / "heuristic-rules.yaml"
)


def _emitted_cwes() -> set[str]:
    cwes: set[str] = set()
    for group in ModuleRegistry.discover().groups:
        for metadata in group.metadata():
            if metadata.cwe:
                cwes.add(metadata.cwe)
    data: Any = yaml.safe_load(RULES_FILE.read_text(encoding="utf-8"))
    for rule in data["rules"]:
        if rule.get("cwe"):
            cwes.add(str(rule["cwe"]))
    return cwes


def test_every_emitted_cwe_resolves_to_a_catalog_entry() -> None:
    catalog = load_remediation_catalog()
    covered = {entry.cwe for entry in catalog.entries if entry.cwe}
    missing = sorted(_emitted_cwes() - covered)
    assert missing == [], (
        f"these CWEs can be emitted by a shipped check/rule but have no remediation entry: "
        f"{missing}"
    )


def test_the_catalog_covers_at_least_forty_cwes() -> None:
    catalog = load_remediation_catalog()
    covered = {entry.cwe for entry in catalog.entries if entry.cwe}
    assert len(covered) >= 40


def test_every_entry_carries_summary_steps_verification_and_references() -> None:
    catalog = load_remediation_catalog()
    problems: list[str] = []
    for entry in catalog.entries:
        if not entry.summary.strip():
            problems.append(f"{entry.id}: no summary")
        if not entry.steps:
            problems.append(f"{entry.id}: no numbered steps")
        if not entry.verify:
            problems.append(f"{entry.id}: no verification-of-fix steps")
        if not entry.references:
            problems.append(f"{entry.id}: no references")
        for reference in entry.references:
            if not reference.startswith(("https://", "http://")):
                problems.append(f"{entry.id}: reference is not a URL: {reference}")
        for step in entry.steps:
            if not step.strip():
                problems.append(f"{entry.id}: empty step")
    assert problems == []


def test_the_entry_ids_are_unique_and_stable() -> None:
    catalog = load_remediation_catalog()
    ids = [entry.id for entry in catalog.entries]
    assert len(ids) == len(set(ids))
    assert "env-file-exposure" in ids


def test_verification_flows_into_the_resolved_remediation() -> None:
    catalog = load_remediation_catalog()
    entry = catalog.by_id("env-file-exposure")
    assert entry is not None
    remediation = entry.to_remediation()
    assert remediation.verification
    assert remediation.steps
    assert remediation.references
    assert remediation.to_dict()["verification"] == list(remediation.verification)


def test_an_entry_without_verification_gets_the_documented_fallback() -> None:
    from arachne.analyzer.remediation import parse_remediation_catalog

    catalog = parse_remediation_catalog(
        {
            "version": "test",
            "entries": [
                {
                    "id": "custom-entry",
                    "cwe": "CWE-200",
                    "summary": "Do the thing that fixes the exposure.",
                    "steps": ["1. Fix it."],
                    "references": ["https://cwe.mitre.org/data/definitions/200.html"],
                }
            ],
        }
    )
    remediation = catalog.by_id("custom-entry").to_remediation()  # type: ignore[union-attr]
    assert remediation.verification


def test_every_catalog_cwe_has_an_owasp_top10_category() -> None:
    from arachne.report.owasp import load_owasp_map

    catalog = load_remediation_catalog()
    mapping = load_owasp_map()
    missing = sorted(
        {
            entry.cwe
            for entry in catalog.entries
            if entry.cwe and mapping.category_for(entry.cwe) is None
        }
    )
    assert missing == [], f"CWEs without an OWASP Top-10 category: {missing}"
