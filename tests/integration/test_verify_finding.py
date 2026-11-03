"""``arachne verify-finding`` end to end (WP-13, REQ-PROOF-016).

The command's whole value is that its answer is produced the way a scan produces one: the
same scope gate, the same attestation gate, the same check, the same scoped client. This suite
proves the three things that could go wrong with that:

* **the verdict is real** — a scan finds a planted SQL injection, ``verify-finding`` says
  ``still-verified``, the fixture is fixed, and the next ``verify-finding`` says
  ``no-longer-verified``;
* **a refusal touches nothing** — with the stored attestation expired the command returns
  ``refused`` and a non-zero exit while every socket entry point is armed, and no
  re-verification scan row is created;
* **it never escalates** — a finding recorded at a lower level than the check now declares is
  refused rather than re-run up a rung (PD-7). That half is a unit test
  (``tests/unit/test_verification_record.py``), because it is about the guard, not the
  network.

Everything runs against loopback: a purpose-built HTTP sink the test can *fix* mid-run, which
is what makes the "no longer verified" case honest rather than asserted.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import get_settings, reset_settings_cache
from arachne.core.target import ModuleSelection, ScanOptions, ScanRequest, TargetDefinition
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.models import Scan
from arachne.data.services import build_orchestrator, build_services

runner = CliRunner()

#: The check under test. One check keeps the re-scan fast and the verdict unambiguous.
CHECK_ID = "m3.sqli-oracle"

_BENIGN = (
    "<html><body><h1>catalog</h1>"
    + '<li class="record">anchor-product</li>'
    + '<li class="record">second-product</li>'
    + '<a href="/search?category=1">search</a></body></html>'
)
_SQL_ERROR = (
    "<html><body><p>You have an error in your SQL syntax; check the manual that corresponds "
    "to your MySQL server version for the right syntax to use near ''' at line 1</p></body></html>"
)
_NOT_FOUND = "<html><body><p>no matching records</p></body></html>"


class _SinkState:
    """The sink's mutable state: the test fixes the vulnerability between invocations."""

    vulnerable = True


class _SinkHandler(BaseHTTPRequestHandler):
    """A tiny loopback SQL sink: an error on a quote while ``vulnerable``, benign after."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args: Any) -> None:  # keep the test output clean
        return None

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        value = parse_qs(parts.query, keep_blank_values=True).get("category", [""])[0]
        status, body = 200, _BENIGN
        if _SinkState.vulnerable:
            if "'" in value or '"' in value or "\\" in value:
                status, body = 500, _SQL_ERROR
            elif "1=2" in value or "='2" in value:
                status, body = 200, _NOT_FOUND
        self._respond(status, body)

    def _respond(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture
def sink() -> Iterator[str]:
    """A loopback SQL sink; yields its parameterised URL, and always restores the flag."""
    _SinkState.vulnerable = True
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SinkHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/search?category=1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        _SinkState.vulnerable = True


@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A real SQLite deployment the CLI and the test share (the command reads the same DB)."""
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'wp13.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    # The lab is loopback: the deployment allowlist must name it, and the URL policy must
    # permit a loopback dial. This is the test harness's scope, not a relaxation of the gate.
    monkeypatch.setenv("ARACHNE_SCOPE_HOSTS", "127.0.0.1")
    monkeypatch.setenv("ARACHNE_ALLOW_LOOPBACK", "true")
    monkeypatch.setenv("ARACHNE_ALLOW_PRIVATE_IPS", "true")
    reset_settings_cache()
    try:
        upgraded = runner.invoke(app, ["db", "upgrade"])
        assert upgraded.exit_code == 0, upgraded.output
        yield get_settings().database_url
    finally:
        reset_settings_cache()


def _definition(url: str, *, expires_at: str | None = None) -> TargetDefinition:
    attestation: dict[str, Any] = {
        "attested_by": "WP-13 builder <wp13@arachne.test>",
        "attested_at": "2026-11-01T00:00:00Z",
        "scope_statement": (
            "Local vulnerable-by-design lab fixture on loopback, owned by the test suite"
        ),
        "allowed_targets": ["127.0.0.1", url],
        "authorization_ref": "TEST-WP13",
        "active_checks_authorized": True,
    }
    if expires_at is not None:
        attestation["expires_at"] = expires_at
    return TargetDefinition(
        name="wp13-lab",
        targets=({"kind": "url", "value": url},),
        attestation=attestation,
    )


def _scan_once(url: str) -> tuple[int, int]:
    """Run the planted scan through the real orchestrator; return ``(scan_id, finding_id)``."""
    import asyncio

    settings = get_settings()
    services = build_services(settings)
    try:
        definition = _definition(url)
        request = ScanRequest(
            target=definition,
            options=ScanOptions(
                active_checks=True,
                modules=ModuleSelection(enabled=("M3",), only=(CHECK_ID,)),
            ),
        )
        orchestrator = build_orchestrator(services)
        session = asyncio.run(orchestrator.scan(request))
        scan_id = int(session.scan_id or 0)
        assert scan_id, "the scan produced no id"
        candidates = services.findings.list_candidates(scan_id)
        assert candidates, "the planted SQL injection was not found by the scan"
        finding = candidates[0]
        assert finding.verification is not None, "a finding must persist a verification record"
        return scan_id, int(finding.id or 0)
    finally:
        services.close()


def _expire_the_stored_attestation(scan_id: int) -> None:
    """Rewrite the admitted request so its attestation has since expired (drift)."""
    services = build_services(get_settings())
    try:
        factory = create_session_factory(create_db_engine(settings=get_settings()))
        with factory() as session:
            row = session.get(Scan, scan_id)
            assert row is not None
            document = dict(row.request_json or {})
            attestation = dict(document["target"]["attestation"])
            attestation["attested_at"] = "2020-01-01T00:00:00Z"
            attestation["expires_at"] = "2020-01-02T00:00:00Z"
            document["target"] = {**document["target"], "attestation": attestation}
            row.request_json = document
            session.commit()
    finally:
        services.close()


def _scan_rows() -> int:
    factory = create_session_factory(create_db_engine(settings=get_settings()))
    with factory() as session:
        return len(session.query(Scan).all())


# --------------------------------------------------------------------------- the verdict
def test_a_scan_then_two_reverifications_report_the_drift(sink: str, cli_env: str) -> None:
    """scan → verify-finding (still-verified) → fix the fixture → verify-finding (gone)."""
    _scan_id, finding_id = _scan_once(sink)

    first = runner.invoke(app, ["verify-finding", str(finding_id), "--json"])
    assert first.exit_code == 0, first.output
    payload = json.loads(first.output)
    assert payload["outcome"] == "still-verified", first.output
    assert payload["parent_record_id"] is not None
    assert payload["record_id"] is not None
    assert payload["record_id"] != payload["parent_record_id"]

    # The fixture is fixed: the same check against the same asset now finds nothing.
    _SinkState.vulnerable = False

    second = runner.invoke(app, ["verify-finding", str(finding_id), "--json"])
    assert second.exit_code == 0, second.output
    payload = json.loads(second.output)
    assert payload["outcome"] == "no-longer-verified", second.output
    # The chain moves forward: the second record's parent is the first one, never itself.
    assert payload["parent_record_id"] not in (None, payload["record_id"])


def test_the_audit_chain_is_still_green_after_the_migration(sink: str, cli_env: str) -> None:
    """REQ-PROOF-015's last criterion: ``verify-chain`` stays green after the migration.

    A scan that writes findings *and* their verification records, plus two re-verifications,
    still leaves a walkable hash chain — which is what proves 0015 changed no existing
    column's contents and no chaining behaviour.
    """
    _scan_id, finding_id = _scan_once(sink)
    assert runner.invoke(app, ["verify-finding", str(finding_id)]).exit_code == 0

    result = runner.invoke(app, ["verify-chain", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output[result.output.index("{") :])
    assert payload["ok"] is True, result.output
    assert sum(payload["checked"].values()) > 0, "the chain verified something"


def test_the_reverification_record_is_linked_and_both_are_audited(sink: str, cli_env: str) -> None:
    """REQ-PROOF-016: the new record names its parent, and both get an audit line."""
    _scan_id, finding_id = _scan_once(sink)
    assert runner.invoke(app, ["verify-finding", str(finding_id)]).exit_code == 0

    from arachne.data.verification import SqlVerificationStore

    factory = create_session_factory(create_db_engine(settings=get_settings()))
    store = SqlVerificationStore(factory)
    history = store.history(finding_id)
    assert len(history) == 2, [item.to_dict() for item in history]
    original, reverified = history
    assert reverified.parent_id == original.id
    assert reverified.outcome == "still-verified"
    # The record the finding points at is the newest one.
    assert store.current(finding_id) is not None
    assert store.current(finding_id).id == reverified.id  # type: ignore[union-attr]

    from arachne.data.report_store import SqlAuditReader

    reader = SqlAuditReader(factory)
    # The new record's line lives on the verification scan; the parent's on the original one,
    # so each scan's own trail answers "what did this run record?".
    new_events = reader.events_for_scan(int(reverified.scan_id or 0))
    recorded = [event for event in new_events if event.action == "finding.reverified"]
    assert recorded, [event.action for event in new_events]
    assert recorded[0].event_meta.get("parent_record_id") == original.id
    assert recorded[0].event_meta.get("role") == "new"
    parent_events = reader.events_for_scan(int(original.scan_id or 0))
    parent_lines = [
        event for event in parent_events if event.action == "finding.verification_recorded"
    ]
    assert parent_lines, [event.action for event in parent_events]
    assert parent_lines[0].event_meta.get("record_id") == original.id
    assert parent_lines[0].event_meta.get("rechecked_by_record_id") == reverified.id


# --------------------------------------------------------------------------- the refusal
def test_an_expired_attestation_refuses_with_no_network_access(
    sink: str, cli_env: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """REQ-PROOF-016's most important clause: refused, non-zero, and *no* socket touched.

    The socket entry points are armed, so any dial — a scope probe, a DNS lookup, the check's
    own request — fails the test rather than being asserted about after the fact. The scan
    count is also compared, because "no network" and "no re-verification scan row" are two
    different claims and the second is the observable one.
    """
    import socket

    scan_id, finding_id = _scan_once(sink)
    _expire_the_stored_attestation(scan_id)
    before = _scan_rows()

    attempts: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        attempts.append(str(args[:1]))
        msg = "an armed socket was reached during a refused re-verification"
        raise AssertionError(msg)

    for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyname_ex"):
        monkeypatch.setattr(socket, name, forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)

    result = runner.invoke(app, ["verify-finding", str(finding_id)])
    assert result.exit_code == 1, result.output
    assert "REFUSED" in result.output
    assert "expired" in result.output.lower(), result.output
    assert attempts == [], f"the refusal touched the network: {attempts}"
    assert _scan_rows() == before, "a refused re-verification created a scan row"


def test_a_finding_without_a_record_is_refused(cli_env: str) -> None:
    """Nothing to re-verify is a refusal with a non-zero exit, not a silent success."""
    from arachne.data.db import create_db_engine, create_session_factory
    from arachne.data.models import Finding, Target

    factory = create_session_factory(create_db_engine(settings=get_settings()))
    with factory() as session:
        # A pre-WP-13 row: the finding exists and carries no verification record.
        target = Target(name="legacy", scope_json={"targets": []})
        session.add(target)
        session.commit()
        scan = Scan(target_id=int(target.id), status="completed")
        session.add(scan)
        session.commit()
        row = Finding(scan_id=int(scan.id), title="legacy row", status="open")
        session.add(row)
        session.commit()
        finding_id = int(row.id)

    result = runner.invoke(app, ["verify-finding", str(finding_id)])
    assert result.exit_code == 1, result.output
    assert "REFUSED" in result.output
    assert "no verification record" in result.output


def test_an_unknown_finding_is_a_clean_error(cli_env: str) -> None:
    """An id that does not exist is an error (exit 2), not a verdict."""
    result = runner.invoke(app, ["verify-finding", "999999"])
    assert result.exit_code == 2, result.output
    assert "does not exist" in result.output
