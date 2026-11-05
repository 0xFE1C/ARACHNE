"""One changelog source and a generated release-notes index (REQ-DOC-004).

The property under test is "typed twice is impossible". A test that only compared the committed
files would pass on a hand-edited pair that happened to agree today, so the mechanism itself is
driven here: a source edit with the index left alone must fail, and so must a source whose shape
the generator cannot read.
"""

from __future__ import annotations

from pathlib import Path

from arachne.tools import changelog

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_the_committed_notes_are_what_the_source_produces() -> None:
    report = changelog.check(REPO_ROOT)
    assert report.failures == (), "\n".join(report.failures)
    assert changelog.BEGIN in report.generated and changelog.END in report.generated


def test_the_release_notes_reference_the_single_source() -> None:
    """REQ-DOC-004: "the other references it rather than duplicating"."""
    notes = (REPO_ROOT / changelog.NOTES).read_text(encoding="utf-8")
    assert changelog.CHANGELOG in notes
    assert "generated" in notes.lower()
    # The index is a *block*, not the whole page: the prose around it is hand-written and the
    # change entries inside it are generated.
    block = notes[notes.index(changelog.BEGIN) : notes.index(changelog.END)]
    assert "Change index" in block


def test_the_source_records_a_release_with_a_date_and_a_status() -> None:
    releases, problems = changelog.parse(
        (REPO_ROOT / changelog.CHANGELOG).read_text(encoding="utf-8")
    )
    assert problems == []
    dated = [release for release in releases if not release.unreleased]
    assert dated, "the changelog must record at least one dated release entry"
    for release in dated:
        assert release.date and release.status
        assert release.total > 0


def test_an_index_left_behind_a_source_edit_fails(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    source = "# Changelog\n\n## [2.0.0] — 2026-02-03 — released\n\n### Added\n\n- one thing\n\n"
    (tmp_path / changelog.CHANGELOG).write_text(source, encoding="utf-8")
    releases, _ = changelog.parse(source)
    index = changelog.render(releases)
    (tmp_path / changelog.NOTES).write_text(f"# Notes\n\n{index}", encoding="utf-8")
    assert changelog.check(tmp_path).ok

    edited = source.replace("- one thing", "- one thing\n- a second thing")
    (tmp_path / changelog.CHANGELOG).write_text(edited, encoding="utf-8")
    report = changelog.check(tmp_path)
    assert not report.ok
    assert "stale" in report.failures[0]


def test_a_source_the_generator_cannot_read_is_refused(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / changelog.CHANGELOG).write_text(
        "## [1.0.0]\n\n### Nonsense\n\n- x\n", encoding="utf-8"
    )
    (tmp_path / changelog.NOTES).write_text("# Notes\n", encoding="utf-8")
    report = changelog.check(tmp_path)
    assert not report.ok
    joined = "\n".join(report.failures)
    assert "YYYY-MM-DD" in joined, "an undated release must be refused"
    assert "is not one of" in joined, "an unknown section name must be refused"


def test_the_notes_must_name_the_source_at_all(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    source = "## [1.0.0] — 2026-01-02 — released\n\n### Fixed\n\n- a bug\n"
    (tmp_path / changelog.CHANGELOG).write_text(source, encoding="utf-8")
    (tmp_path / changelog.NOTES).write_text("# Notes\n\nno changelog here\n", encoding="utf-8")
    report = changelog.check(tmp_path)
    assert not report.ok
    assert any("does not name" in failure for failure in report.failures)


def test_a_missing_source_is_named_as_the_defect(tmp_path: Path) -> None:
    report = changelog.check(tmp_path)
    assert not report.ok
    assert "single changelog source" in report.failures[0]


def test_the_generator_is_idempotent() -> None:
    text = (REPO_ROOT / changelog.CHANGELOG).read_text(encoding="utf-8")
    releases, _ = changelog.parse(text)
    assert changelog.render(releases) == changelog.render(releases)


def test_the_gate_self_test_passes() -> None:
    assert changelog.main(["--self-test"]) == 0
