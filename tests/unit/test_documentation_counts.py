"""The documented counts match the system (REQ-DOC-002).

The claim under test is narrow and checkable: every number a shipped document states about
the system is the number the artefact that owns it currently produces. If a check is added,
a rule is deleted or a test file appears, these tests fail until the documentation is updated
— which is the only mechanism that has ever kept this repository's counts honest.

The generator is the source of truth; these tests only compare it with what is committed.
"""

from __future__ import annotations

from pathlib import Path

from arachne.tools.counts import claims, collect, module_rows, report, stale

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_every_documented_number_matches_the_generator() -> None:
    """REQ-DOC-002's accept criterion, in one assertion."""
    values = collect()
    assert stale(values) == [], "\n".join(stale(values))


def test_the_readme_badge_and_the_registry_agree() -> None:
    values = collect()
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"checks-{int(values['checks.total'])}-" in readme
    assert f"tests-{int(values['tests.collected']):,}-" in readme


def test_the_readme_module_table_matches_the_registry() -> None:
    values = collect()
    expected = {
        key.removeprefix("checks."): int(value)
        for key, value in values.items()
        if key.startswith("checks.M")
    }
    assert module_rows() == expected


def test_the_generator_is_idempotent() -> None:
    assert collect() == collect()


def test_the_report_renders_every_metric() -> None:
    values = collect()
    rendered = report(values)
    for key in values:
        assert key in rendered


def test_every_claim_names_a_document_in_the_repository() -> None:
    for claim in claims(collect()):
        assert (REPO_ROOT / claim.path).is_file(), claim.path
