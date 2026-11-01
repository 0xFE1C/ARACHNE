"""The documentation integrity gate (REQ-DOC-001, REQ-DOC-003).

Two kinds of test:

* **Behavioural** — the checker is driven against purpose-built trees (a good link, a dangling
  link, a glob, a URL path, a labelled historical citation) so that "the gate works" is
  demonstrated rather than asserted. REQ-DOC-001's acceptance criterion is explicit: *a
  deliberately dangling link fails the build in a self-test*.
* **The repository's own tree** — the gate's real subject. The last test is the acceptance
  test for the work package: the shipped tree carries no dangling reference at all.

These tests never shell out to git except through the checker's own ``git cat-file`` call, and
they do not depend on the working directory.
"""

from __future__ import annotations

from pathlib import Path

from arachne.tools.doccheck import (
    ALLOWLIST,
    HISTORICAL_MARKER,
    Roots,
    Violation,
    check_tree,
    main,
    path_candidate,
    scan_file,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _tree(tmp_path: Path) -> Roots:
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "real.md").write_text("# real\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    return Roots.for_repo(tmp_path)


# ------------------------------------------------------------------ markdown
def test_a_resolving_link_and_a_resolving_backticked_path_pass(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text("See [real](docs/real.md) and `docs/real.md`.\n", encoding="utf-8")
    assert scan_file(page, roots) == []


def test_a_dangling_link_fails(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text("See [gone](docs/gone.md).\n", encoding="utf-8")
    assert [violation.token for violation in scan_file(page, roots)] == ["docs/gone.md"]


def test_a_dangling_backticked_path_fails(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text("The contract lives in `docs/contract.md`.\n", encoding="utf-8")
    assert [violation.token for violation in scan_file(page, roots)] == ["docs/contract.md"]


def test_a_fenced_code_block_is_not_prose_and_is_not_checked(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text("Example:\n\n```\ncat docs/nowhere.md\n```\n", encoding="utf-8")
    assert scan_file(page, roots) == []


def test_a_glob_and_a_url_path_are_not_path_claims(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text("`tests/test_*_safety.py` and `/.well-known/security.txt`\n", encoding="utf-8")
    assert scan_file(page, roots) == []


def test_an_external_link_is_not_checked(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text("See [site](https://example.test/docs/nope.md).\n", encoding="utf-8")
    assert scan_file(page, roots) == []


def test_a_path_is_resolved_against_the_src_tree_shorthand(tmp_path: Path) -> None:
    """``core/http.py`` in prose means ``src/arachne/core/http.py``."""
    (tmp_path / "src" / "arachne" / "core").mkdir(parents=True)
    (tmp_path / "src" / "arachne" / "core" / "http.py").write_text("", encoding="utf-8")
    roots = Roots.for_repo(tmp_path)
    assert check_tree([tmp_path], roots=roots) == []


# ------------------------------------------------------------------ python
def test_a_path_in_a_docstring_is_checked(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    module = tmp_path / "mod.py"
    module.write_text('"""Module citing `docs/absent.md`."""\n', encoding="utf-8")
    assert [violation.token for violation in scan_file(module, roots)] == ["docs/absent.md"]


def test_a_path_in_a_code_string_is_not_a_citation(tmp_path: Path) -> None:
    """A runtime path in code is a value, not a claim about this repository."""
    roots = _tree(tmp_path)
    module = tmp_path / "mod.py"
    module.write_text('CONFIG = "etc/arachne/branding.yaml"\n', encoding="utf-8")
    assert scan_file(module, roots) == []


def test_a_path_in_a_comment_is_checked(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    module = tmp_path / "mod.py"
    module.write_text("# see docs/absent.md\nx = 1\n", encoding="utf-8")
    assert [violation.token for violation in scan_file(module, roots)] == ["docs/absent.md"]


# ------------------------------------------------------------------ commits
def test_a_cited_commit_that_is_not_in_the_repository_fails(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text("The fix landed in commit 0123456789ab.\n", encoding="utf-8")
    kinds = {violation.kind for violation in scan_file(page, roots)}
    assert kinds == {"unreachable-commit"}


def test_a_hex_string_that_is_not_a_commit_citation_is_ignored(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text(
        "The digest is 3b1f0a9c4d2e5f60718293a4b5c6d7e8 in this example.\n", encoding="utf-8"
    )
    assert scan_file(page, roots) == []


# ------------------------------------------------------------------ the rules themselves
def test_a_line_labelled_historical_is_exempt(tmp_path: Path) -> None:
    roots = _tree(tmp_path)
    page = tmp_path / "page.md"
    page.write_text(
        "Gate: G3 (`historical` spec path `docs/03-delivery-plan.md` §5).\n", encoding="utf-8"
    )
    assert HISTORICAL_MARKER in page.read_text(encoding="utf-8")
    assert scan_file(page, roots) == []


def test_every_allowlist_entry_carries_a_reason() -> None:
    assert ALLOWLIST, "the allowlist is empty or justified; this test pins the second case"
    for prefix, reason in ALLOWLIST:
        assert prefix.endswith("/"), prefix
        assert len(reason) > 40, f"allowlist entry {prefix!r} needs a real justification"


def test_the_candidate_rule_admits_the_repository_shapes_only(tmp_path: Path) -> None:
    (tmp_path / "tests").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "real.md").write_text("# real\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
    roots = Roots.for_repo(tmp_path)
    # a top-level entry this repository has, and the extension rule for the src/ shorthand
    assert path_candidate("tests/helpers.py", roots) == "tests/helpers.py"
    assert path_candidate("core/http.py", roots) == "core/http.py"
    # not candidates: an absolute URL path, a full URL, a bare hostname, a bare word
    assert path_candidate("/etc/passwd", roots) is None
    assert path_candidate("https://example.test/a/b.md", roots) is None
    assert path_candidate("github.com/org/repo/blob/main/README.md", roots) is None
    assert path_candidate("NaN", roots) is None
    # a glob is reported as a candidate here and filtered by the scanner's span rule
    assert path_candidate("tests/test_", roots) == "tests/test_"


def test_the_violation_renders_with_a_location_and_a_kind() -> None:
    rendered = Violation("a.md", 7, "dangling-path", "docs/x.md", "no such file").render()
    assert rendered.startswith("a.md:7: dangling-path: docs/x.md")


# ------------------------------------------------------------------ the gate itself
def test_the_self_test_passes() -> None:
    assert main(["--self-test"]) == 0


def test_the_allowlist_is_printable() -> None:
    assert main(["--list-allowlist"]) == 0


def test_a_missing_path_is_a_usage_error() -> None:
    assert main(["/nonexistent-path-for-doccheck"]) == 2


def test_the_shipped_tree_carries_no_dangling_reference() -> None:
    """The work package's acceptance test: the gate passes on this repository."""
    violations = check_tree([REPO_ROOT], roots=Roots.for_repo(REPO_ROOT))
    assert violations == [], "\n".join(violation.render() for violation in violations)
