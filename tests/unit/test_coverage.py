"""The coverage matrix tool and its CLI surface (G-01).

G-01 is "≥ 90% of research methods mapped to checks", tracked in a generated
``coverage_matrix.md``. The tool's job is to be *trustworthy*: it has to count the right
universe (175 numbered methods across six chapters), attribute a reference to the check that
declares it, and handle reference ranges like ``ch01#14-16`` without silently losing two
methods. These tests use the real corpus and the real source tree, because a coverage number
computed over fixtures would prove nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.errors import ConfigurationError
from arachne.modules.coverage import (
    CoverageReport,
    RefHit,
    build_coverage,
    default_research_dir,
    default_source_roots,
    expand_ref,
    hits_by_check,
    parse_research_methods,
    render_coverage_markdown,
    render_coverage_text,
    scan_sources_for_refs,
    write_coverage_markdown,
)

RESEARCH = default_research_dir()


# ------------------------------------------------------------------ the universe
def test_the_corpus_is_present_so_these_tests_run(tmp_path: Path) -> None:
    """The module-level ``skipif`` that used to disable this module is gone (REQ-QUAL-011).

    A gate that can disable itself is not a gate: the corpus ships with the repository, so a
    missing one is an error (asserted below), never a reason to stop checking the drift.
    """
    assert RESEARCH is not None, "the research corpus must ship beside the code"
    assert RESEARCH.is_dir()


def test_the_corpus_has_the_175_methods_g_01_counts() -> None:
    methods = parse_research_methods(RESEARCH)  # type: ignore[arg-type]
    assert len(methods) == 175
    chapters: dict[str, int] = {}
    for method in methods:
        chapters[method.chapter] = chapters.get(method.chapter, 0) + 1
    assert chapters == {
        "ch01": 30,
        "ch02": 30,
        "ch03": 35,
        "ch04": 30,
        "ch05": 25,
        "ch06": 25,
    }
    assert all(method.title for method in methods)
    assert methods[0].ref == "ch01#1"


def test_an_absent_research_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        parse_research_methods(tmp_path / "nope")


def test_a_chapter_without_numbered_methods_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "01-empty.md").write_text("# Nothing here\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="no numbered methods"):
        parse_research_methods(tmp_path)


# ------------------------------------------------------------------ the grep
def test_source_scan_finds_refs_and_attributes_them_to_a_check() -> None:
    hits = scan_sources_for_refs(default_source_roots())
    by_ref = {hit.ref: hit for hit in hits}
    assert by_ref["ch01#1"].check_id == "dork-sweep"
    assert by_ref["ch01#8"].check_id == "ct-lookup"
    assert by_ref["ch01#14-16"].check_id == "webarchive-harvest"
    assert all(hit.path.endswith(".py") for hit in hits)


def test_source_scan_can_include_the_templates(tmp_path: Path) -> None:
    template = tmp_path / "catalog.yaml"
    template.write_text(
        "checks:\n  - module: M9\n    name: fake\n    research_ref: ch02#2\n", encoding="utf-8"
    )
    hits = scan_sources_for_refs((tmp_path,))
    assert [(hit.ref, hit.check_id) for hit in hits] == [("ch02#2", "fake")]


def test_source_scan_ignores_unreadable_files(tmp_path: Path) -> None:
    (tmp_path / "binary.py").write_bytes(b"\xff\xfe\x00research_ref: ch01#1")
    assert scan_sources_for_refs((tmp_path,)) == ()


def test_reference_ranges_expand() -> None:
    assert expand_ref("ch04#1") == ("ch04#1",)
    assert expand_ref("ch01#14-16") == ("ch01#14", "ch01#15", "ch01#16")
    assert expand_ref("ch01#16-14") == ("ch01#14", "ch01#15", "ch01#16")
    assert expand_ref("ch01#x") == ("ch01#x",)


# ------------------------------------------------------------------ the report
def test_build_coverage_reports_the_m1_m2_m3_and_m4_rows() -> None:
    report = build_coverage()
    assert report.total == 175
    # S13 adds 25 checks that lift the mapped total from 119 to 144 (see ADR-180.1); S18's
    # three intel checks map four more methods (Shodan #3, Censys #4, WHOIS/RDAP #9, breach
    # lookups #18), closing part of the paid-feed OSINT gap -> 148.
    assert report.mapped == 148
    assert report.percent > 0

    ch01 = next(chapter for chapter in report.chapters if chapter.chapter == "ch01")
    assert ch01.total == 30
    assert ch01.mapped == 19

    ch02 = next(chapter for chapter in report.chapters if chapter.chapter == "ch02")
    assert ch02.total == 30
    assert ch02.mapped == 28
    mapped_m2 = {item.method.ref: item.checks for item in ch02.methods if item.mapped}
    assert mapped_m2["ch02#1"] == ("host-discovery",)
    # WP-09's mutual-TLS observation cites the same TLS chapter method as the deep scan: both
    # are handshake observations of the same endpoint (REQ-DET-011).
    assert set(mapped_m2["ch02#14"]) == {"tls-deep-scan", "tls-mutual-auth"}
    assert mapped_m2["ch02#29"] == ("cve-correlate",)
    assert "ch02#11" in report.unmapped  # masscan-scale sweeping is not implemented
    ch03 = next(chapter for chapter in report.chapters if chapter.chapter == "ch03")
    assert ch03.total == 35
    assert ch03.mapped == 34
    mapped_m3 = {item.method.ref: item.checks for item in ch03.methods if item.mapped}
    assert mapped_m3["ch03#1"] == (
        "sqli-oob",
        "sqli-oracle",
        "state-marker",
        "xpath-injection",
    )
    # ch03#3 is now mapped by three checks: the reflection oracle, the L2 client-secret
    # verification and WP-11's DOM-sink browser check (REQ-DET-015) — both halves of the
    # method plus the client-side half of ch03#33.
    assert mapped_m3["ch03#3"] == ("client-secret-verify", "dom-xss", "xss-oracle")
    assert mapped_m3["ch03#11"] == ("traversal-oracle",)
    assert mapped_m3["ch03#24"] == ("security-headers",)
    # S10's extended families are mapped too.
    assert mapped_m3["ch03#5"] == ("ssrf-probe",)
    assert mapped_m3["ch03#16"] == ("smuggling-oracle",)
    assert mapped_m3["ch03#32"] == ("graphql-audit", "graphql-depth-abuse", "graphql-resolver-auth")
    assert mapped_m3["ch03#34"] == ("subdomain-takeover",)
    assert mapped_m3["ch03#12"] == ("directory-traversal",)  # S13
    ch06 = next(chapter for chapter in report.chapters if chapter.chapter == "ch06")
    assert ch06.total == 25
    assert ch06.mapped == 16
    mapped_m6 = {item.method.ref: item.checks for item in ch06.methods if item.mapped}
    assert mapped_m6["ch06#7"] == ("cve-epss-correlation",)
    assert mapped_m6["ch06#24"] == ("webshell-yara",)
    assert "sigma-hunt-rules" in mapped_m6["ch06#19"]  # range + the AD check both map it
    assert "ch06#13" not in mapped_m6  # autonomous agentic hacking is not implemented
    ch04 = next(chapter for chapter in report.chapters if chapter.chapter == "ch04")
    assert ch04.total == 30
    assert ch04.mapped == 30
    mapped_m4 = {item.method.ref: item.checks for item in ch04.methods if item.mapped}
    assert mapped_m4["ch04#1"] == ("env-file-probe",)
    assert mapped_m4["ch04#2"] == ("vcs-exposure",)
    assert mapped_m4["ch04#13"] == ("bucket-exposure",)
    # S13 additions
    assert mapped_m4["ch04#23"] == ("robots-sitemap",)
    assert mapped_m4["ch04#6"] == ("verbose-errors",)
    assert "ch04#3" in mapped_m4  # backup-file-hunt
    mapped = {item.method.ref: item.checks for item in ch01.methods if item.mapped}
    assert mapped["ch01#1"] == ("dork-sweep",)
    assert mapped["ch01#5"] == ("internetdb-triage",)
    assert mapped["ch01#8"] == ("ct-lookup", "ct-surprise")
    assert mapped["ch01#26"] == ("js-asset-scan", "mobile-artifact")
    assert mapped["ch01#23"] == ("favicon-hash",)  # S13
    assert mapped["ch01#25"] == ("dns-txt-mining",)  # S13
    # A method the M1 checks do not cover is reported as unmapped, with no guesswork.
    assert "ch01#6" in report.unmapped  # WHOIS/registration archaeology: no check reads it
    assert not [item for item in ch01.methods if item.method.ref == "ch01#7" and item.mapped]


def test_an_explicitly_named_corpus_that_is_missing_is_an_error(tmp_path: Path) -> None:
    """A typo in --research-dir must be loud, not a silent 0/0 report."""
    with pytest.raises(ConfigurationError, match="does not exist"):
        build_coverage(tmp_path / "absent", source_roots=[tmp_path])


def test_a_report_without_a_corpus_still_lists_what_is_mapped() -> None:
    report = CoverageReport(
        chapters=(),
        hits=(RefHit("ch01#1", "src/arachne/modules/m1/exposure.py", 145, "dork-sweep"),),
        source_roots=("src/arachne/modules",),
    )
    assert report.mapped == 0 and report.percent == 0.0
    assert "not found" in render_coverage_text(report)


def test_text_rendering_lists_every_method_and_the_totals() -> None:
    text = render_coverage_text(build_coverage())
    assert "coverage matrix" in text
    assert "ch01" in text and "ch06" in text
    assert "148/175" in text
    assert "[x] ch01#1" in text
    assert "[ ] ch02#11" in text


def test_markdown_rendering_is_a_report() -> None:
    markdown = render_coverage_markdown(build_coverage())
    assert markdown.startswith("# ARACHNE coverage matrix (G-01)")
    assert "| Chapter | Mapped | Total | Percent | Title |" in markdown
    assert "| ch01 | 19 | 30 | 63.3% |" in markdown
    assert "| ch02 | 28 | 30 | 93.3% |" in markdown
    assert "| ch03 | 34 | 35 | 97.1% |" in markdown
    assert "| ch04 | 30 | 30 | 100.0% |" in markdown
    assert "| ch05 | 21 | 25 | 84.0% |" in markdown
    assert "| ch06 | 16 | 25 | 64.0% |" in markdown
    assert "### ch01 —" in markdown
    assert "## Unmapped methods" in markdown
    assert "`dork-sweep`" in markdown
    assert "`ch02#11`" in markdown  # an unmapped method is listed by reference


def test_markdown_rendering_without_a_corpus_lists_the_raw_hits(tmp_path: Path) -> None:
    report = CoverageReport(chapters=(), hits=(RefHit("ch01#1", str(tmp_path / "a.py"), 3, "x"),))
    markdown = render_coverage_markdown(report)
    assert "method universe is unknown" in markdown
    assert "| `ch01#1` | x |" in markdown


def test_writing_the_matrix_creates_parents(tmp_path: Path) -> None:
    target = write_coverage_markdown(build_coverage(), tmp_path / "docs" / "coverage_matrix.md")
    assert target.is_file()
    assert "coverage matrix" in target.read_text(encoding="utf-8")


def test_hits_by_check_inverts_the_view() -> None:
    inverted = hits_by_check(scan_sources_for_refs(default_source_roots()))
    assert inverted["ct-lookup"] == ("ch01#8",)
    assert "ch01#14-16" in inverted["webarchive-harvest"]


def test_the_json_view_round_trips() -> None:
    import json

    payload = json.loads(build_coverage().to_json())
    assert payload["total"] == 175
    assert payload["mapped"] == 148
    assert isinstance(payload["chapters"], list)
    assert payload["chapters"][0]["methods"][0]["ref"] == "ch01#1"


# ------------------------------------------------------------------ CLI
def test_cli_reports_the_matrix() -> None:
    result = CliRunner().invoke(app, ["coverage", "matrix"])
    assert result.exit_code == 0, result.output
    assert "coverage matrix" in result.output
    assert "148/175" in result.output
    assert "ch01#1" in result.output


def test_cli_reports_the_matrix_as_json() -> None:
    import json

    result = CliRunner().invoke(app, ["coverage", "matrix", "--json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["total"] == 175


def test_cli_writes_the_markdown_matrix(tmp_path: Path) -> None:
    target = tmp_path / "coverage_matrix.md"
    result = CliRunner().invoke(app, ["coverage", "matrix", "--write", str(target)])
    assert result.exit_code == 0, result.output
    assert f"wrote {target}" in result.output
    assert "coverage matrix" in target.read_text(encoding="utf-8")


def test_cli_can_count_the_planning_catalogue_too() -> None:
    result = CliRunner().invoke(app, ["coverage", "matrix", "--include-templates", "--json"])
    assert result.exit_code == 0, result.output
    import json

    payload = json.loads(result.output)
    assert payload["mapped"] > 47, "the planned M4-M6 rows add references"


def test_cli_accepts_an_explicit_root(tmp_path: Path) -> None:
    (tmp_path / "check.py").write_text('research_ref = "ch03#1"\n', encoding="utf-8")
    result = CliRunner().invoke(app, ["coverage", "matrix", "--root", str(tmp_path), "--json"])
    import json

    payload = json.loads(result.output)
    assert payload["mapped"] == 1


def test_the_committed_matrix_is_current() -> None:
    """``coverage_matrix.md`` is a tracked artefact (G-01): it must not go stale.

    Regenerating it is one command (``arachne coverage --write coverage_matrix.md``), so a
    failing test here means "a check was added or re-referenced; refresh the matrix", which
    is exactly the reminder a tracked metric should give.
    """
    committed = Path(__file__).resolve().parents[2] / "coverage_matrix.md"
    assert committed.is_file(), "coverage_matrix.md is a tracked artefact and must ship"
    assert committed.read_text(encoding="utf-8") == render_coverage_markdown(build_coverage())
