"""The executable quickstart (REQ-DOC-005).

Two things are asserted: the committed page still describes the corridor (the static half), and
the runner really fails when a documented command fails (the half that makes the CI job a gate
rather than a demonstration). The full corridor itself is executed by the `quickstart` CI job in
a clean container; running it here would install a virtualenv inside a unit test.

The runner control flow is exercised with tiny shell commands in a temporary repository, so the
test does not depend on the product, the network, or the optional extras.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from arachne.tools import quickstart

REPO_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _doc(blocks: str, *, version: str = "9.9.9") -> str:
    return f"# Quickstart\n\nVerified against ARACHNE **{version}**.\n\n{blocks}\n"


def test_the_committed_page_declares_the_version_and_the_whole_corridor() -> None:
    failures, blocks = quickstart.check_page(REPO_ROOT)
    assert failures == [], "\n".join(failures)
    assert len(blocks) >= 7, "the corridor is install, migrate, plan, scan, reports, serve, health"
    assert any(block.kind == quickstart.SERVICE for block in blocks), (
        "the serve step must be a service block, or the corridor would block forever"
    )


def test_the_page_states_the_version_it_was_verified_against() -> None:
    text = (REPO_ROOT / quickstart.DEFAULT_DOC).read_text(encoding="utf-8")
    declared = quickstart.declared_version(text)
    assert declared is not None
    assert declared == quickstart._project_version(REPO_ROOT)


def test_a_failing_documented_command_fails_the_run(tmp_path: Path) -> None:
    """The exit criterion: a documented command that fails must fail the job."""
    (tmp_path / "docs").mkdir()
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        _doc(
            "```bash quickstart\necho installing\n```\n\n"
            "```bash quickstart\necho about to fail\nexit 3\n```\n\n"
            "```bash quickstart\necho never reached\n```\n"
        ),
        encoding="utf-8",
    )
    report = quickstart.run(tmp_path, verify_version=False)
    assert not report.ok
    assert any("exited 3" in failure for failure in report.failures)
    assert [step.returncode for step in report.steps] == [0, 3], (
        "the run must stop at the failing step rather than continuing past it"
    )
    assert "never reached" not in [step.command for step in report.steps]


def test_a_good_corridor_passes_and_reports_its_measurement(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        _doc(
            "```bash quickstart\necho install\n```\n\n"
            "```bash quickstart\nara_scan=1; echo scan $ara_scan\n```\n"
        ),
        encoding="utf-8",
    )
    report = quickstart.run(tmp_path, verify_version=False)
    assert report.ok, report.failures
    assert report.total_seconds >= 0
    assert report.first_finding_seconds is None, "no live `arachne scan` block, so no measurement"
    assert report.target_seconds == quickstart.DEFAULT_TARGET_SECONDS


def test_the_time_to_first_finding_stops_at_the_live_scan(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        _doc(
            "```bash quickstart\necho install\n```\n\n"
            "```bash quickstart\necho planning --dry-run\n```\n\n"
            # The line must look like a live scan to the measurement, and must succeed in a
            # repository that has no `arachne` installed.
            "```bash quickstart\narachne scan --target nowhere || true\n```\n\n"
            "```bash quickstart\necho report\n```\n"
        ),
        encoding="utf-8",
    )
    report = quickstart.run(tmp_path, verify_version=False)
    assert report.ok, report.failures
    assert report.first_finding_seconds is not None
    assert report.first_finding_seconds <= report.total_seconds


def test_a_service_block_is_started_waited_for_and_stopped(tmp_path: Path) -> None:
    """The service half of the convention: background, wait for the named port, stop afterwards."""
    port = _free_port()
    (tmp_path / "serve_for_test.py").write_text(
        "import http.server, socketserver, sys\n"
        "port = int(sys.argv[sys.argv.index('--port') + 1])\n"
        "handler = http.server.SimpleHTTPRequestHandler\n"
        "with socketserver.TCPServer(('127.0.0.1', port), handler) as server:\n"
        "    server.serve_forever()\n",
        encoding="utf-8",
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        _doc(
            "```bash quickstart service\n"
            f"python3 serve_for_test.py --port {port}\n"
            "```\n\n"
            f"```bash quickstart\ncurl -fsS http://127.0.0.1:{port}/\n```\n"
        ),
        encoding="utf-8",
    )
    report = quickstart.run(tmp_path, verify_version=False)
    assert report.ok, report.failures
    assert [step.kind for step in report.steps] == ["service", "quickstart"]
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass


def test_a_service_that_dies_before_listening_is_reported(tmp_path: Path) -> None:
    port = _free_port()
    (tmp_path / "docs").mkdir()
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        _doc(f"```bash quickstart service\necho cannot bind on --port {port}\nexit 4\n```\n"),
        encoding="utf-8",
    )
    report = quickstart.run(tmp_path, verify_version=False)
    assert not report.ok
    assert "before it served anything" in " ".join(report.failures)


def test_a_missing_step_fails_the_static_check(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        _doc("```bash quickstart\necho hello\n```\n"), encoding="utf-8"
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
    failures, _ = quickstart.check_page(tmp_path)
    assert failures
    assert any("no install step" in failure for failure in failures)
    assert any("no health step" in failure for failure in failures)


def test_a_version_disagreement_fails_the_static_check(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n', encoding="utf-8")
    text = (REPO_ROOT / quickstart.DEFAULT_DOC).read_text(encoding="utf-8")
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        text.replace("Verified against ARACHNE 0.1.0", "Verified against ARACHNE 0.0.1"),
        encoding="utf-8",
    )
    failures, _ = quickstart.check_page(tmp_path)
    assert any("declares version 0.0.1" in failure for failure in failures)


def test_a_page_without_a_version_statement_fails_the_static_check(tmp_path: Path) -> None:
    (tmp_path / "docs").mkdir()
    (tmp_path / quickstart.DEFAULT_DOC).write_text(
        _doc("```bash quickstart\necho hi\n```\n").replace(
            "Verified against ARACHNE **9.9.9**.\n\n", ""
        ),
        encoding="utf-8",
    )
    failures, _ = quickstart.check_page(tmp_path)
    assert any("must say which version" in failure for failure in failures)


def test_an_unterminated_fence_is_refused() -> None:
    blocks, problems = quickstart.parse_blocks("# T\n\n```bash quickstart\necho hi\n")
    assert problems and "unterminated" in problems[0]
    assert blocks == []


def test_an_unknown_info_token_is_refused() -> None:
    blocks, problems = quickstart.parse_blocks(
        "# T\n\n```bash quickstart --with-typos\necho hi\n```\n"
    )
    assert problems and "unknown info token" in problems[0]
    assert blocks == []


def test_an_illustrative_block_is_never_executed() -> None:
    blocks, problems = quickstart.parse_blocks(
        "# T\n\n```bash\nrm -rf /tmp/this-is-never-run\n```\n\n```bash quickstart\necho hi\n```\n"
    )
    assert problems == []
    assert [block.body for block in blocks] == ["echo hi"]


def test_the_gate_self_test_passes() -> None:
    assert quickstart.main(["--self-test"]) == 0


def test_the_quickstart_job_runs_in_a_clean_container() -> None:
    """A warm runner measures nothing, so the job must declare a fresh container."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "quickstart:" in workflow
    assert "container: python:3.12-slim" in workflow
    assert "python -m arachne.tools.quickstart --target-seconds 600" in workflow
    # The measurement is tee'd into the job summary, and a pipe's status is the *last*
    # command's: without `pipefail` a failed corridor would exit 0 through tee.
    assert "set -o pipefail" in workflow
