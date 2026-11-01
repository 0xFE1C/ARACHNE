"""The compose-equivalent end-to-end scan, offline (DONE criterion S14-1).

`docker compuse up` runs `docker/demo/run-demo-scan.sh`, which is exactly the sequence this
file executes against a local database: migrate, run the heuristic scan of the bundled demo
target with replayed responses, render the Markdown and HTML reports. Docker is not required
to run the *commands* — only to build the image — so this proves the demo path end to end
and asserts the offline promise (no socket is ever opened).

It also covers the two S14 surfaces a deployment drives through the CLI: a project-scoped
scan (whose scope refusal is the tenancy gate) and a white-labelled report.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import get_settings, reset_settings_cache

CODE_ROOT = Path(__file__).resolve().parents[2]
DEMO = CODE_ROOT / "docker" / "demo"
SEARCH_URL = "https://search.example.net/search?q={query}&limit={limit}&format=json"

runner = CliRunner()


@pytest.fixture
def demo_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """The environment the compose `scan` service builds, pointed at a temp database."""
    database = tmp_path / "demo.db"
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{database}")
    monkeypatch.setenv("ARACHNE_HTTP_FIXTURES", str(DEMO / "http"))
    monkeypatch.setenv("ARACHNE_OSINT_ENABLED", "true")
    monkeypatch.setenv("ARACHNE_OSINT_FIXTURES", str(DEMO / "osint"))
    monkeypatch.setenv("ARACHNE_OSINT_PROVIDERS", "crtsh,circl,wayback,commoncrawl,internetdb")
    monkeypatch.setenv("ARACHNE_OSINT_SEARCH_URL", SEARCH_URL)
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    reset_settings_cache()
    try:
        upgraded = runner.invoke(app, ["db", "upgrade"])
        assert upgraded.exit_code == 0, upgraded.output
        yield tmp_path
    finally:
        reset_settings_cache()


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """The demo scan must be offline: any real connection fails the test."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("the demo scan attempted real network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == [], f"unexpected socket use: {attempts}"


def test_the_compose_scan_sequence_produces_findings_and_reports(demo_env: Path) -> None:
    scan = runner.invoke(app, ["scan", "--target", str(DEMO / "target.yaml"), "--json"])
    assert scan.exit_code == 0, scan.output
    payload = json.loads(scan.output[scan.output.index("{") :])
    scan_id = payload["scan_id"]
    assert payload["status"] == "completed"
    assert payload["steps"]["executed"], "the scan ran no step"
    assert sum(payload["severities"].values()) > 0, "the offline demo found nothing"

    markdown_path = demo_env / "demo-report.md"
    html_path = demo_env / "demo-report.html"
    md = runner.invoke(
        app, ["report", "--scan", str(scan_id), "--format", "md", "--output", str(markdown_path)]
    )
    assert md.exit_code == 0, md.output
    html = runner.invoke(
        app,
        ["report", "--scan", str(scan_id), "--format", "html", "--output", str(html_path)],
    )
    assert html.exit_code == 0, html.output

    document = markdown_path.read_text()
    assert document.startswith("# Security Assessment Report")
    assert "## 1. Executive summary" in document
    assert "## 2. Scope" in document
    assert html_path.read_text().startswith("<!doctype html>")


def test_a_project_scope_can_refuse_the_demo_target(demo_env: Path) -> None:
    created = runner.invoke(
        app,
        ["project", "create", "globex", "--scope-domains", "globex.example"],
    )
    assert created.exit_code == 0, created.output
    refused = runner.invoke(
        app,
        ["scan", "--target", str(DEMO / "target.yaml"), "--project", "globex"],
    )
    assert refused.exit_code != 0
    assert "project scope" in str(refused.exception)


def test_a_matching_project_scope_runs_the_scan(demo_env: Path) -> None:
    created = runner.invoke(
        app,
        [
            "project",
            "create",
            "acme",
            "--scope-domains",
            "example.com",
            "--scope-hosts",
            "93.184.216.34,93.184.216.35",
        ],
    )
    assert created.exit_code == 0, created.output
    scan = runner.invoke(
        app,
        ["scan", "--target", str(DEMO / "target.yaml"), "--project", "acme", "--json"],
    )
    assert scan.exit_code == 0, scan.output
    payload = json.loads(scan.output[scan.output.index("{") :])
    assert payload["scan_id"]


def test_a_white_labelled_report_carries_the_tenant_branding(demo_env: Path) -> None:
    created = runner.invoke(
        app,
        [
            "project",
            "create",
            "acme",
            "--scope-domains",
            "example.com",
            "--scope-hosts",
            "93.184.216.34,93.184.216.35",
            "--branding",
            str(_branding_file(demo_env)),
        ],
    )
    assert created.exit_code == 0, created.output
    scan = runner.invoke(
        app, ["scan", "--target", str(DEMO / "target.yaml"), "--project", "acme", "--json"]
    )
    assert scan.exit_code == 0, scan.output
    scan_id = json.loads(scan.output[scan.output.index("{") :])["scan_id"]
    report = runner.invoke(
        app, ["report", "--scan", str(scan_id), "--project", "acme", "--format", "md"]
    )
    assert report.exit_code == 0, report.output
    assert "**CONFIDENTIAL**" in report.output
    assert "Acme Security" in report.output


def test_feeds_import_is_used_by_the_next_scan(demo_env: Path) -> None:
    feed = demo_env / "epss.csv"
    feed.write_text("cve,epss,percentile\nCVE-2021-44228,0.97,0.999\n")
    imported = runner.invoke(app, ["feeds", "import", str(feed), "--name", "epss-demo"])
    assert imported.exit_code == 0, imported.output
    listed = runner.invoke(app, ["feeds", "list"])
    assert listed.exit_code == 0
    assert "epss-demo" in listed.output
    lookup = runner.invoke(app, ["feeds", "lookup", "CVE-2021-44228"])
    assert lookup.exit_code == 0
    assert "0.97" in lookup.output
    # The active feed is what the composition root hands to M6.
    from arachne.data.services import build_services

    services = build_services(get_settings())
    try:
        assert services.feeds.effective_path("epss") is not None
    finally:
        services.close()


def test_plugin_commands_list_the_environment(demo_env: Path) -> None:
    listed = runner.invoke(app, ["plugin", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    payload = json.loads(listed.output)
    assert set(payload) == {"checks", "report_formats"}
    formats = runner.invoke(app, ["plugin", "formats", "--json"])
    assert formats.exit_code == 0
    names = {item["name"] for item in json.loads(formats.output)}
    assert {"md", "html", "json", "pdf"} <= names
    marketplace = runner.invoke(app, ["plugin", "marketplace", "--search", "example"])
    assert marketplace.exit_code == 0
    assert "arachne-example-check-plugin" in marketplace.output


def _branding_file(directory: Path) -> Path:
    path = directory / "branding.yaml"
    path.write_text(
        "company_name: Acme Security\n"
        "tagline: Managed detection\n"
        "classification: CONFIDENTIAL\n"
        "contact: soc@acme.example\n"
        "show_arachne_branding: false\n"
    )
    return path
