"""The shared-preamble sync gate (REQ-QUAL-014).

The acceptance criteria are exercised directly: an exact copy passes, a one-character edit
to a single block fails and names the block, and a block added without the preamble fails.
The real ``PROMPT.md`` is checked too, so the gate cannot pass on a fixture while the shipped
library has drifted.
"""

from __future__ import annotations

from pathlib import Path

from arachne.tools.preamble_check import (
    CANONICAL_MARKER,
    check_repository,
    check_text,
    extract_canonical,
    extract_copies,
    main,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _prompt(*, blocks: int = 2, drift: int | None = None, bare: int | None = None) -> str:
    """Build a synthetic PROMPT.md with ``blocks`` work-package blocks."""
    preamble = (
        f"{CANONICAL_MARKER}\n"
        "access. Read the code before you change it; run the commands before you claim a result.\n"
    )
    parts = ["## 1. How to use this file\n", "## 2. The shared preamble\n", f"```\n{preamble}```\n"]
    parts.append("## 3. Work-package prompts\n")
    for index in range(1, blocks + 1):
        body = "" if index == bare else preamble
        if index == drift:
            body = body.replace("Read the code", "Read code")
        parts.append(f"### WP-{index:02d} — block\n\n▼▼▼ COPY FROM HERE ▼▼▼\n\n```\n{body}\n")
        parts.append(f"WORK PACKAGE: WP-{index:02d} — block\n```\n\n▲▲▲ END OF COPY ▲▲▲\n\n")
    parts.append("## 4. Mapping table\n")
    return "".join(parts)


def test_the_shipped_prompt_library_is_in_sync() -> None:
    assert check_repository(REPO_ROOT) == []
    assert main([str(REPO_ROOT)]) == 0


def test_a_one_character_edit_to_one_block_fails_and_names_the_block() -> None:
    violations = check_text(_prompt(blocks=3, drift=2))
    assert len(violations) == 1
    assert "WP-02" in violations[0].block
    assert "differs" in violations[0].detail


def test_a_block_added_without_the_preamble_fails() -> None:
    violations = check_text(_prompt(blocks=3, bare=3))
    assert len(violations) == 1
    assert "WP-03" in violations[0].block


def test_a_second_source_of_the_preamble_is_reported(tmp_path: Path) -> None:
    prompt = _prompt(blocks=1)
    (tmp_path / "PROMPT.md").write_text(prompt, encoding="utf-8")
    # A stray copy anywhere else is a second source and must be reported.
    (tmp_path / "NOTES.md").write_text(f"copied rules:\n{CANONICAL_MARKER}\n", encoding="utf-8")
    violations = check_repository(tmp_path)
    assert [v.block for v in violations] == ["NOTES.md"]


def test_the_canonical_text_and_copies_are_byte_identical_in_the_real_file() -> None:
    text = (REPO_ROOT / "PROMPT.md").read_text(encoding="utf-8")
    canonical = extract_canonical(text)
    assert canonical is not None
    copies = extract_copies(text)
    assert len(copies) == 23, "one copy per work-package block"
    for label, region in copies:
        assert region == canonical + "\n", label


def test_the_self_test_passes() -> None:
    assert main(["--self-test"]) == 0
