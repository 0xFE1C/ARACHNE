"""Acceptance: ``arachne scan`` plans completely, performs zero requests, and refuses.

The stage's headline requirement (F-01-10, Phase 0) is checked here through
the *real* entry point (``arachne.cli.main.run``), not by calling the Typer app directly,
so what is verified is what an operator gets — including the process exit code.

Zero requests is asserted two ways: every egress path raises if touched, and the audit
trail contains no request event. The dry run also never opens the database, which is why
it works before ``arachne db upgrade`` and why the fixture DB is asserted absent.
"""

from __future__ import annotations

import json
import socket
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from sqlalchemy import create_engine, text
from tests.conftest import EXAMPLES_DIR, plain

from arachne.browser.driver import browser_available
from arachne.cli.main import run
from arachne.core.config import reset_settings_cache
from arachne.core.http import ScopedHttpClient

FIXTURE = EXAMPLES_DIR / "lab-fixture.yaml"
#: Recorded target responses (example.com and its JavaScript bundle), so a live CLI scan
#: exercises the real request path without any network.
REPLAY_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "http"


@dataclass(frozen=True, slots=True)
class CliResult:
    """Outcome of one end-to-end CLI invocation."""

    code: int
    stdout: str
    stderr: str


@pytest.fixture(autouse=True)
def _isolated_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Isolate every invocation from the developer's environment and database."""
    for variable in (
        "ARACHNE_SCOPE_HOSTS",
        "ARACHNE_SCOPE_DOMAINS",
        "ARACHNE_SCOPE_NETWORKS",
        "ARACHNE_SCOPE_URL_PREFIXES",
        "ARACHNE_SCOPE_EXCLUDE_HOSTS",
        "ARACHNE_SCOPE_EXCLUDE_DOMAINS",
        "ARACHNE_SCOPE_EXCLUDE_NETWORKS",
        "ARACHNE_ALLOW_PRIVATE_IPS",
        "ARACHNE_ALLOW_LOOPBACK",
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'scan.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.setenv("ARACHNE_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    # Every CLI test replays recorded target responses: a live scan reads them instead of
    # opening a socket, so no test in this module can reach the network .
    monkeypatch.setenv("ARACHNE_HTTP_FIXTURES", str(REPLAY_FIXTURES))
    # A live scan of the replay fixture runs every module's probes. Replayed responses are
    # instant, so the per-host rate limit (5/s in production) is what would make the test
    # slow; rate limiting has its own suite. The probe bounds are reduced for the same
    # reason (these tests exercise the CLI and persistence, not a module's probe count).
    for variable, value in (
        ("ARACHNE_RATE_LIMIT_PER_HOST", "1000000"),
        ("ARACHNE_RATE_LIMIT_PER_HOST_BURST", "1000000"),
        ("ARACHNE_RATE_LIMIT_GLOBAL", "1000000"),
        ("ARACHNE_RATE_LIMIT_GLOBAL_BURST", "1000000"),
        ("ARACHNE_WEB_MAX_PAGES", "5"),
        ("ARACHNE_WEB_MAX_DEPTH", "1"),
        ("ARACHNE_WEB_MAX_PARAMS", "2"),
        ("ARACHNE_M4_MAX_PATHS", "4"),
        ("ARACHNE_M4_MAX_FINDINGS", "2"),
        ("ARACHNE_M5_MAX_PATHS", "4"),
        ("ARACHNE_M5_MAX_FINDINGS", "2"),
    ):
        monkeypatch.setenv(variable, value)
    monkeypatch.delenv("ARACHNE_OSINT_ENABLED", raising=False)
    monkeypatch.delenv("ARACHNE_OSINT_FIXTURES", raising=False)
    monkeypatch.delenv("ARACHNE_OSINT_SEARCH_URL", raising=False)
    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def cli(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> Callable[..., CliResult]:
    """Invoke the console entry point and capture its exit code and output."""

    def invoke(*args: str) -> CliResult:
        monkeypatch.setattr(sys, "argv", ["arachne", *args])
        code = 0
        try:
            run()
        except SystemExit as exit_request:  # the entry point's clean failure path
            code = exit_request.code if isinstance(exit_request.code, int) else 1
        captured = capsys.readouterr()
        return CliResult(code=code, stdout=captured.out, stderr=captured.err)

    return invoke


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Make every egress path raise, and record any attempt."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("a zero-request operation attempted network access")

    monkeypatch.setattr(ScopedHttpClient, "request", forbidden)
    monkeypatch.setattr(httpx.AsyncClient, "request", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    return attempts


@pytest.fixture
def socket_sentinel(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record (and refuse) any attempt to open a real connection."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("a replayed scan attempted real network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    return attempts


def audit_lines(tmp_path: Path) -> list[dict[str, object]]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def upgrade(cli: Callable[..., CliResult]) -> None:
    result = cli("db", "upgrade")
    assert result.code == 0, result.stderr
    reset_settings_cache()


# ---------------------------------------------------------------- dry run (F-01-10)
def test_the_network_sentinel_has_teeth(no_network: list[str]) -> None:
    """Guard against a vacuous zero-request assertion: the sentinel must actually fire."""
    import asyncio

    from arachne.core.config import Settings
    from arachne.core.safety import Scope

    client = ScopedHttpClient(
        settings=Settings(database_url="sqlite:///:memory:"),
        scope=Scope(allowed_hosts=("example.com",)),
    )
    try:
        with pytest.raises(AssertionError, match="zero-request operation"):
            asyncio.run(client.get("https://example.com/"))
    finally:
        asyncio.run(client.aclose())
    assert no_network, "the sentinel recorded the attempt"


def test_dry_run_prints_a_complete_plan_and_makes_zero_requests(
    cli: Callable[..., CliResult], no_network: list[str], tmp_path: Path
) -> None:
    result = cli("scan", "--target", str(FIXTURE), "--dry-run")

    assert result.code == 0, result.stderr
    assert no_network == [], "the dry run touched the network"

    output = result.stdout
    # Identity, scope, attestation, assets, pipeline, checks, totals: a complete plan.
    assert "ARACHNE dry run" in output
    assert "lab-fixture" in output
    assert "domains:" in output and "example.com" in output
    assert "networks:" in output and "192.0.2.0/30" in output
    assert "excluded domains:" in output and "admin.example.com" in output
    assert "authorization: Jane Operator" in output
    assert "live-ready: yes" in output
    assert "1. recon" in output and "2. discovery" in output and "3. checks" in output
    assert "[M1] dork-sweep" in output
    assert "[M4] env-file-probe" in output
    assert "estimated request(s)" in output
    assert "no request was made and no database was opened" in output

    # The database was never opened: the dry run needs no migrated schema.
    assert not (tmp_path / "scan.db").exists()

    # The plan is in the audit trail; no request is.
    actions = [entry["action"] for entry in audit_lines(tmp_path)]
    assert "target.loaded" in actions
    assert "scan.planned" in actions
    assert "http.request" not in actions


def test_the_browser_crawl_is_visible_in_the_plan_when_it_is_enabled(
    cli: Callable[..., CliResult],
    no_network: list[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """REQ-DET-015: the crawl's budget is part of the plan, and so is its absence.

    The plan needs its own target: the shared fixture's attestation authorizes no active
    checks, and ``m3.dom-xss`` is active, so it would be withheld for an unrelated reason and
    the plan would say nothing about the browser either way.

    This installation has no browser driver (the extra is not installed), so the honest plan is
    the one that says so: the checks step carries **no** budget — nothing is advertised that
    cannot happen — and the warning names the extra to install. On an installation with the
    extra, the same plan prints the budget line under ``3. checks``; the model-level half of
    that assertion is ``tests/unit/test_browser_hardening.py``, which does not need a browser.
    """
    target = tmp_path / "browser-target.yaml"
    target.write_text(
        "target:\n"
        "  name: browser-plan\n"
        "  targets:\n"
        "    - kind: url\n"
        "      value: http://127.0.0.1:8080/\n"
        "  attestation:\n"
        '    attested_by: "Jane Operator <jane.operator@example.com>"\n'
        '    attested_at: "2026-11-01T00:00:00Z"\n'
        '    expires_at: "2027-11-01T00:00:00Z"\n'
        '    authorization_ref: "TEST-BROWSER"\n'
        "    scope_statement: Loopback only.\n"
        "    allowed_targets:\n"
        "      - http://127.0.0.1:8080/\n"
        "    active_checks_authorized: true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ARACHNE_WEB_BROWSER_CRAWL", "true")
    monkeypatch.setenv("ARACHNE_WEB_BROWSER_MAX_PAGES", "7")
    monkeypatch.setenv("ARACHNE_WEB_BROWSER_TIME_BUDGET_S", "9")
    reset_settings_cache()
    try:
        result = cli("scan", "--target", str(target), "--dry-run", "--active-checks", "--json")
    finally:
        reset_settings_cache()

    assert result.code == 0, result.stderr
    assert no_network == [], "the dry run touched the network"
    document = json.loads(result.stdout)
    checks_step = next(step for step in document["steps"] if step["step"] == "checks")
    assert any(check["name"] == "dom-xss" and check["included"] for check in document["checks"])
    if browser_available():  # pragma: no cover - the extra is not installed in CI
        assert (checks_step["budget_pages"], checks_step["budget_seconds"]) == (7, 9.0)
    else:
        assert checks_step["budget_pages"] is None
        assert checks_step["budget_seconds"] is None
        assert any("no browser driver is installed" in warning for warning in document["warnings"])


def test_dry_run_json_output_is_machine_readable(
    cli: Callable[..., CliResult], no_network: list[str]
) -> None:
    result = cli("scan", "--target", str(FIXTURE), "--dry-run", "--json")

    assert result.code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["dry_run"] is True
    assert document["target_name"] == "lab-fixture"
    assert document["totals"]["included_checks"] > 0
    assert document["totals"]["estimated_requests"] > 0
    assert [step["step"] for step in document["steps"]][:3] == ["recon", "discovery", "checks"]
    assert any(check["requires_active_checks"] for check in document["checks"])
    assert any(not check["included"] for check in document["checks"])
    assert {
        "module-not-selected",
        "no-applicable-target",
        "active-checks-not-opted-in",
        "active-checks-not-authorized",
        # S15: the L3/L4 proof checks are planned only when named (REQ-PROOF-001).
        "proof-not-opted-in",
        None,
    } >= {check["skip_code"] for check in document["checks"]}


def test_dry_run_without_attestation_warns_but_still_plans(
    cli: Callable[..., CliResult], no_network: list[str], tmp_path: Path
) -> None:
    fixture = tmp_path / "no-attestation.yaml"
    fixture.write_text(
        "target:\n  name: un-attested\n  targets:\n    - {kind: domain, value: example.com}\n",
        encoding="utf-8",
    )
    result = cli("scan", "--target", str(fixture), "--dry-run")

    assert result.code == 0, result.stderr
    assert "live-ready: NO" in result.stdout
    assert "no authorization attestation" in result.stdout
    assert no_network == []


# ----------------------------------------------------------------- refusals (F-01-02)
def test_dry_run_against_an_out_of_scope_target_is_blocked_and_audited(
    cli: Callable[..., CliResult], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ARACHNE_SCOPE_HOSTS", "only-this.example")
    reset_settings_cache()

    result = cli("scan", "--target", str(FIXTURE), "--dry-run")

    assert result.code == 2
    assert "out of scope" in result.stderr
    assert "Traceback" not in result.stderr

    rejected = [entry for entry in audit_lines(tmp_path) if entry["action"] == "scope.rejected"]
    assert rejected, "the blocked target must be in the audit log (F-01-08)"
    assert rejected[0]["outcome"] == "blocked"
    assert "deployment scope" in str(rejected[0]["reason"])


def test_live_scan_without_an_authorization_attestation_is_refused(
    cli: Callable[..., CliResult], tmp_path: Path
) -> None:
    fixture = tmp_path / "unattested.yaml"
    fixture.write_text(
        "target:\n  name: unattested\n  targets:\n    - {kind: domain, value: example.com}\n",
        encoding="utf-8",
    )
    upgrade(cli)

    result = cli("scan", "--target", str(fixture))

    assert result.code == 2
    assert "not authorized" in result.stderr
    assert "auth.rejected" in [entry["action"] for entry in audit_lines(tmp_path)]


def test_missing_fixture_is_a_clean_error(cli: Callable[..., CliResult], tmp_path: Path) -> None:
    result = cli("scan", "--target", str(tmp_path / "absent.yaml"), "--dry-run")
    assert result.code == 2
    assert "does not exist" in result.stderr
    assert "Traceback" not in result.stderr


def test_live_scan_without_a_migrated_database_explains_what_to_do(
    cli: Callable[..., CliResult],
) -> None:
    result = cli("scan", "--target", str(FIXTURE))
    assert result.code == 2
    assert "arachne db upgrade" in result.stderr


def test_dry_run_and_resume_together_are_refused(cli: Callable[..., CliResult]) -> None:
    result = cli("scan", "--target", str(FIXTURE), "--dry-run", "--resume", "1")
    assert result.code != 0
    assert "mutually exclusive" in (result.stdout + result.stderr)


# ------------------------------------------------------------------- live scan (F-01-04)
def test_a_live_scan_persists_state_and_audits_every_step(
    cli: Callable[..., CliResult], tmp_path: Path
) -> None:
    upgrade(cli)

    result = cli("scan", "--target", str(FIXTURE))

    assert result.code == 0, result.stderr
    assert "scan 1: completed" in result.stdout

    engine = create_engine(f"sqlite:///{tmp_path / 'scan.db'}")
    try:
        with engine.connect() as connection:
            scan = connection.execute(text("SELECT status, engine, plan_json FROM scans")).one()
            steps = connection.execute(
                text("SELECT step, status, attempts FROM scan_steps ORDER BY id")
            ).all()
            assets = connection.execute(text("SELECT kind, value FROM assets ORDER BY id")).all()
            audit_actions = {
                row[0] for row in connection.execute(text("SELECT action FROM audit_log")).all()
            }
    finally:
        engine.dispose()

    assert scan[0] == "completed"
    assert scan[1] == "heuristic"
    assert json.loads(scan[2])["target_name"] == "lab-fixture"

    # Every pipeline step has a durable row: the two with a handler completed, the four
    # without one are recorded as skipped (S3 adds the module-backed handlers).
    assert [row[0] for row in steps] == [
        "recon",
        "discovery",
        "checks",
        "analysis",
        "correlation",
        "reporting",
    ]
    statuses = {row[0]: row[1] for row in steps}
    assert statuses["recon"] == "completed"
    assert statuses["discovery"] == "completed"
    assert statuses["reporting"] == "skipped"

    # The declared targets became the asset inventory.
    assert {row[0] for row in assets} == {"domain", "url", "network", "git", "cloud"}
    assert {"scan.created", "scan.started", "scan.step_completed", "scan.finished"} <= audit_actions


def test_a_live_scan_replays_recorded_responses_without_a_socket(
    cli: Callable[..., CliResult], socket_sentinel: list[str], tmp_path: Path
) -> None:
    """S3 runs M1: a live scan now works, against recordings, with no egress at all.

    The point of the assertion is that the *only* thing that changed about the network story
    is that there is real work to do: every request still goes through the scoped, audited
    client, and with OSINT off (the default) all of it is target-scoped.
    """
    upgrade(cli)
    result = cli("scan", "--target", str(FIXTURE))
    assert result.code == 0, result.stderr
    assert socket_sentinel == []

    requests = [line for line in audit_lines(tmp_path) if line["action"] == "http.request"]
    assert requests, "the replayed scan should have recorded its requests"
    for line in requests:
        target = str(line["target"])
        # Every request stays on the declared host. Since S6 the checks step also crawls the
        # endpoints the discovery step derived for the declared domain, so the plaintext
        # ``http://example.com/`` twin is probed alongside the recorded ``https://`` one —
        # which is why the assertion is on the host and not on the scheme.
        assert target.startswith(("https://example.com/", "http://example.com/")), target
    # No third-party source was consulted (OSINT is off by default).
    assert not [line for line in audit_lines(tmp_path) if line["action"] == "osint.query"]


def test_resume_after_a_live_scan_is_a_no_op(cli: Callable[..., CliResult]) -> None:
    upgrade(cli)
    assert cli("scan", "--target", str(FIXTURE)).code == 0

    result = cli("scan", "--target", str(FIXTURE), "--resume", "1")

    assert result.code == 0, result.stderr
    assert "scan 1: completed" in result.stdout
    assert "already complete:" in result.stdout


# ---------------------------------------------------------------------- overrides
def test_engine_and_module_overrides_are_applied_to_the_plan(cli: Callable[..., CliResult]) -> None:
    result = cli(
        "scan",
        "--target",
        str(FIXTURE),
        "--dry-run",
        "--json",
        "--engine",
        "hybrid",
        "--enable",
        "M4",
    )
    assert result.code == 0, result.stderr
    document = json.loads(result.stdout)
    assert document["engine"] == "hybrid"
    assert document["totals"]["modules"] == ["M4"]


def test_active_checks_flag_without_attestation_authorization_is_reported(
    cli: Callable[..., CliResult],
) -> None:
    result = cli("scan", "--target", str(FIXTURE), "--dry-run", "--active-checks")
    assert result.code == 0, result.stderr
    assert "does not authorize them" in result.stdout
    assert "live-ready: NO" in result.stdout


def test_scan_help_lists_the_s2_flags(cli: Callable[..., CliResult]) -> None:
    result = cli("scan", "--help")
    assert result.code == 0
    for flag in ("--target", "--dry-run", "--resume", "--engine", "--active-checks"):
        assert flag in plain(result.stdout)
