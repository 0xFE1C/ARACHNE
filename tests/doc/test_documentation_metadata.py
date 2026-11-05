"""Documentation ownership and freshness (REQ-DOC-004).

The gate has two halves, and both are asserted here: the *tree* (every shipped page carries an
owner and a date, and the pages that exist today are current) and the *mechanism* (a page past one
interval merely warns; past two it fails). Asserting only the first would pass just as well if the
mechanism never fired, which is the failure mode REQ-DOC-004 is about.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from arachne.tools import docmeta

REPO_ROOT = Path(__file__).resolve().parents[2]
TODAY = date(2026, 11, 5)


def _page(
    root: Path,
    name: str,
    *,
    verified: str,
    interval: int = 180,
    owner: str = "Documentation owners",
) -> Path:
    path = root / "docs" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        f"# {name}\n\n> **Owner:** {owner} · **Last verified:** {verified} · "
        f"**Review interval:** {interval} days\n\nbody\n",
        encoding="utf-8",
    )
    return path


def test_every_shipped_page_has_an_owner_and_a_last_verified_date() -> None:
    report = docmeta.check(REPO_ROOT, TODAY)
    assert report.failures == (), "\n".join(report.failures)
    assert len(report.pages) >= 50, "the gate must cover the documentation surface, not a sample"
    for page in report.pages:
        assert page.owner in docmeta.OWNER_GROUPS
        assert page.verified <= TODAY


def test_a_page_past_one_interval_warns_and_past_two_fails(tmp_path: Path) -> None:
    """The escalation the requirement names, both sides of it, on real dates."""
    (tmp_path / "docs").mkdir()
    _page(tmp_path, "fresh.md", verified="2026-10-01")
    _page(tmp_path, "due.md", verified="2026-01-01")  # 308 days: past 180, below 360
    due = docmeta.check(tmp_path, TODAY)
    assert due.ok, "one interval past is a warning, not a failure"
    assert len(due.warnings) == 1 and "due for review" in due.warnings[0]

    _page(tmp_path, "stale.md", verified="2025-01-01")  # 673 days: past two intervals
    stale = docmeta.check(tmp_path, TODAY)
    assert not stale.ok
    assert len(stale.failures) == 1 and "STALE" in stale.failures[0]
    assert "stale.md" in stale.failures[0]


def test_a_longer_declared_interval_is_honoured(tmp_path: Path) -> None:
    """A frozen record (an ADR) legitimately reviews less often than a living page."""
    (tmp_path / "docs").mkdir()
    _page(tmp_path, "record.md", verified="2022-01-01", interval=1825)
    report = docmeta.check(tmp_path, date(2026, 6, 1))
    assert report.ok and not report.warnings


def test_the_owner_must_be_a_group_the_project_actually_has(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    _page(tmp_path, "orphan.md", verified="2026-10-01", owner="The internet")
    report = docmeta.check(tmp_path, TODAY)
    assert not report.ok
    assert "not a known group" in report.failures[0]


def test_a_missing_header_is_a_failure_not_a_warning(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "bare.md").write_text("# bare\n\nno metadata here\n", encoding="utf-8")
    report = docmeta.check(tmp_path, TODAY)
    assert not report.ok
    assert "no owner/date header" in report.failures[0]


def test_the_header_must_sit_above_the_body(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "late.md").write_text(
        "# late\n\n## A section\n\n> **Owner:** Documentation owners · "
        "**Last verified:** 2026-10-01 · **Review interval:** 180 days\n",
        encoding="utf-8",
    )
    report = docmeta.check(tmp_path, TODAY)
    assert not report.ok
    assert "above the first section heading" in report.failures[0]


@pytest.mark.parametrize("interval", [5, 5000])
def test_an_interval_outside_the_bounds_is_refused(tmp_path: Path, interval: int) -> None:
    (tmp_path / "docs").mkdir()
    _page(tmp_path, "odd.md", verified="2026-10-01", interval=interval)
    report = docmeta.check(tmp_path, TODAY)
    assert not report.ok
    assert "outside" in report.failures[0]


def test_generated_pages_are_excluded_with_a_stated_reason() -> None:
    assert docmeta.GENERATED_PAGES, "the exclusion must be explicit, not a silent skip"
    for page, reason in docmeta.GENERATED_PAGES.items():
        assert reason.strip(), f"{page} is excluded without saying why"
        assert (REPO_ROOT / page).is_file(), f"{page} is excluded but does not exist"


def test_the_gate_self_test_passes() -> None:
    assert docmeta.main(["--self-test"]) == 0


def test_the_gate_is_wired_into_ci_and_not_a_manual_step() -> None:
    """REQ-DOC-004: "the check is part of the docs job, not a manual review step"."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "python -m arachne.tools.docmeta --check" in workflow
    assert "python -m arachne.tools.changelog --check" in workflow
