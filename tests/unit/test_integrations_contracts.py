"""Integration contract tests against recorded payloads (S22, REQ-OPS-001/002).

The fixtures in ``tests/fixtures/integrations/`` are receiver-side documents: the
shape each receiving system's own API defines for the call ARACHNE makes. A contract
test renders the payload ARACHNE actually produces and asserts it carries **every key
the recorded document carries** — so a field a receiver expects that we stop sending
fails the suite here instead of failing silently in someone's SIEM or ticket queue.

The receiver-side documents are deliberately written from the receivers' published
schemas (Jira REST v2 create-issue, ServiceNow Table API incident, DefectDojo
import-scan generic-parser findings, and a newline-delimited HTTP collector), not from
our code — the point of the fixture is that it does not move when we refactor.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.api import StubPoster
from tests.helpers.report import synthetic_report

from arachne.api.webhooks import (
    WebhookNotifier,
    build_webhook_sender,
    render_payloads,
    siem_records,
    webhook_scope,
)
from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import ApiSettings, Settings, WebhookSettings
from arachne.report.defectdojo import render_defectdojo
from arachne.report.model import ReportData

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "integrations"


def _recorded(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _recorded_lines(name: str) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (FIXTURES / name).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _settings(**overrides: Any) -> Settings:
    from pydantic import SecretStr

    kwargs: dict[str, Any] = {
        "enabled": True,
        "jira_url": SecretStr("https://jira.example"),
        "jira_project": "SEC",
        "jira_token": SecretStr("jira-token"),
        "servicenow_url": SecretStr("https://acme.service-now.example"),
        "servicenow_user": SecretStr("svc-arachne"),
        "servicenow_password": SecretStr("snow-password"),
        "defectdojo_url": SecretStr("https://dojo.example"),
        "defectdojo_token": SecretStr("dojo-token"),
        "siem_url": SecretStr("https://siem.example/collector"),
        "siem_token": SecretStr("siem-token"),
        "min_severity": "info",
    }
    kwargs.update(overrides)
    hooks = WebhookSettings(**kwargs)
    return Settings(
        webhooks=hooks,
        api=ApiSettings(base_url="https://arachne.example", require_tls=False),
    )


@pytest.fixture
def report() -> ReportData:
    return synthetic_report()  # type: ignore[return-value]


# --------------------------------------------------------------------- ServiceNow
def test_servicenow_matches_the_recorded_incident_shape(report: ReportData) -> None:
    payloads = [p for p in render_payloads(report, _settings()) if p.name == "servicenow"]
    assert payloads, "a configured ServiceNow instance must receive incidents"
    recorded = _recorded("servicenow-incident.json")
    body = payloads[0].body
    for key in recorded:
        assert key in body, f"the incident is missing the recorded field {key!r}"
    assert payloads[0].url == "https://acme.service-now.example/api/now/table/incident"
    assert payloads[0].headers["Authorization"].startswith("Basic ")
    assert payloads[0].headers["Accept"] == "application/json"
    # Impact/urgency are ServiceNow's own 1..3 scale, mapped from the severity.
    assert body["impact"] in (1, 2, 3) and body["urgency"] in (1, 2, 3)


def test_servicenow_one_incident_per_finding_above_the_threshold() -> None:
    report = synthetic_report()
    settings = _settings(min_severity="high")
    expected = sum(1 for f in report.findings if f.severity in {"high", "critical"})
    payloads = [p for p in render_payloads(report, settings) if p.name == "servicenow"]
    assert len(payloads) == expected


def test_a_servicenow_url_without_credentials_is_refused() -> None:
    from pydantic import SecretStr

    with pytest.raises(Exception, match="servicenow"):
        WebhookSettings(servicenow_url=SecretStr("https://acme.service-now.example"))


def test_the_service_account_never_appears_outside_the_auth_header(report: ReportData) -> None:
    payloads = render_payloads(report, _settings())
    for payload in payloads:
        body_text = json.dumps(payload.body, default=str)
        assert "snow-password" not in body_text
        assert "svc-arachne" not in body_text
        assert payload.to_dict()["headers"] == dict.fromkeys(payload.headers, "<redacted>")


# --------------------------------------------------------------------------- SIEM
def test_siem_export_is_ndjson_with_findings_and_the_audit_trail(
    report: ReportData,
) -> None:
    audit_events = [
        {
            "action": "http.request",
            "outcome": "allowed",
            "target": "https://target.example/",
            "reason": None,
            "meta": {"method": "GET"},
        },
        {
            "action": "scope.rejected",
            "outcome": "blocked",
            "target": "https://elsewhere.example/",
            "reason": "host outside the scan scope",
            "meta": {},
        },
    ]
    payloads = [
        p
        for p in render_payloads(report, _settings(), audit_events=audit_events)
        if p.name == "siem"
    ]
    assert payloads, "a configured SIEM collector must receive the export"
    payload = payloads[0]
    assert payload.raw_body is not None and payload.content_type == "application/x-ndjson"
    lines = [json.loads(line) for line in payload.raw_body.splitlines()]
    # One summary, one per confirmed finding, one per audit event — in that order.
    assert lines[0]["event"] == "scan.summary"
    findings = [line for line in lines if line["event"] == "finding"]
    audits = [line for line in lines if line["event"] == "audit"]
    assert len(findings) == report.counts.total
    assert len(audits) == len(audit_events)
    assert audits[0]["action"] == "http.request" and audits[1]["outcome"] == "blocked"


def test_siem_records_match_the_recorded_collector_shape(report: ReportData) -> None:
    audit_events = [
        {
            "action": "http.request",
            "outcome": "allowed",
            "target": "https://t.example/",
            "reason": None,
            "meta": {"method": "GET"},
        },
    ]
    records = siem_records(report, audit_events)
    recorded = _recorded_lines("siem-events.jsonl")
    by_event: dict[str, dict[str, Any]] = {}
    for line in recorded:
        by_event.setdefault(str(line["event"]), line)
    summary_keys = set(by_event["scan.summary"])
    finding_keys = set(by_event["finding"])
    audit_keys = set(by_event["audit"])
    assert set(records[0]) >= summary_keys, "the summary is missing recorded fields"
    assert set(records[1]) >= finding_keys, "a finding record is missing recorded fields"
    assert set(records[-1]) >= audit_keys, "an audit record is missing recorded fields"


async def test_the_siem_body_is_posted_verbatim_and_audited(report: ReportData) -> None:
    from pydantic import SecretStr

    hooks = WebhookSettings(
        enabled=True,
        siem_url=SecretStr("https://siem.example/collector"),
        siem_token=SecretStr("siem-token"),
    )
    settings = Settings(
        webhooks=hooks,
        api=ApiSettings(base_url="https://arachne.example", require_tls=False),
    )
    poster = StubPoster()
    sink = MemoryAuditSink()
    notifier = WebhookNotifier(settings, auditor=Auditor(sink, actor="pytest"), post_json=poster)
    results = await notifier.notify(synthetic_report())
    assert all(result.ok for result in results)
    ((_url, body, headers),) = poster.calls
    assert isinstance(body, str) and body.endswith("\n")
    assert headers["Authorization"] == "Bearer siem-token"
    delivered = [event for event in sink.events if event.action.value == "webhook.delivered"]
    assert delivered, "the delivery is audited like every other egress"


# -------------------------------------------------------------------- DefectDojo
def test_defectdojo_matches_the_recorded_import_shape(report: ReportData) -> None:
    payloads = [p for p in render_payloads(report, _settings()) if p.name == "defectdojo"]
    assert payloads and payloads[0].url == "https://dojo.example/api/v2/import-scan/"
    recorded = _recorded("defectdojo-import.json")
    body = payloads[0].body
    for key in recorded:
        assert key in body, f"the import is missing the recorded field {key!r}"
    assert body["scan_type"] == recorded["scan_type"]
    recorded_finding = recorded["findings"][0]
    for finding in body["findings"]:
        for key in recorded_finding:
            assert key in finding, f"an import finding is missing {key!r}"


def test_the_report_format_and_the_webhook_send_the_same_defectdojo_document(
    report: ReportData,
) -> None:
    """DefectDojo-first: one document builder, two delivery paths (REQ-OPS-001).

    The webhook import and `arachne report --format defectdojo` are byte-equal
    documents: an operator can hand the file over or let the scan push it, and
    DefectDojo sees the same import either way.
    """
    webhook = next(p for p in render_payloads(report, _settings()) if p.name == "defectdojo")
    document = json.loads(render_defectdojo(report))
    assert webhook.body == document
    assert document["findings"][0]["description"], (
        "the narrative (or remediation) is the description"
    )


def test_the_defectdojo_format_is_a_registered_builtin(report: ReportData) -> None:
    from arachne.report.formats import default_registry

    fmt = default_registry().require("defectdojo")
    rendered = fmt.to_text(report)
    document = json.loads(rendered)
    assert document["scan_type"] == "ARACHNE Scan"
    assert document["product_name"] == report.target_name
    assert len(document["findings"]) == report.counts.total


# ------------------------------------------------------------------------ Jira
def test_jira_matches_the_recorded_issue_shape(report: ReportData) -> None:
    payloads = [
        p for p in render_payloads(report, _settings(min_severity="info")) if p.name == "jira"
    ]
    assert payloads
    recorded = _recorded("jira-issue.json")
    body = payloads[0].body
    for key in recorded["fields"]:
        assert key in body["fields"], f"the issue is missing the recorded field {key!r}"
    assert body["fields"]["project"] == {"key": "SEC"}
    assert body["fields"]["issuetype"] == {"name": "Bug"}


# ----------------------------------------------------------------------- scope
def test_the_new_integrations_are_inside_the_egress_scope() -> None:
    scope = webhook_scope(_settings().webhooks)
    hosts = set(scope.allowed_hosts)
    assert {
        "jira.example",
        "acme.service-now.example",
        "dojo.example",
        "siem.example",
    } <= hosts


async def test_a_failed_servicenow_delivery_is_audited_and_never_raises(
    report: ReportData,
) -> None:
    settings = _settings()
    poster = StubPoster(ok=False, status_code=500)
    sink = MemoryAuditSink()
    notifier = WebhookNotifier(settings, auditor=Auditor(sink, actor="pytest"), post_json=poster)
    results = await notifier.notify(report)
    assert results
    failed = [result for result in results if result.name == "servicenow"]
    assert failed and all(not result.ok for result in failed)
    audited = [event for event in sink.events if event.action.value == "webhook.failed"]
    assert audited, "the failure is audited"
    # And the audit line carries no credential material.
    assert all("snow-password" not in json.dumps(event.to_dict(), default=str) for event in audited)


async def test_a_poster_that_raises_leaves_the_scan_alive(report: ReportData) -> None:
    settings = _settings()

    class Exploding:
        async def __call__(self, url: str, body: Any, headers: Any) -> Any:
            raise RuntimeError("collector unreachable")

    notifier = WebhookNotifier(settings, post_json=Exploding())  # type: ignore[arg-type]
    results = await notifier.notify(report)  # must not raise
    assert results and all(not result.ok for result in results)


def test_the_sender_posts_the_raw_siem_body_through_the_real_seam(
    monkeypatch: pytest.MonkeyPatch, report: ReportData
) -> None:
    """The default sender posts the NDJSON verbatim (the seam is the shared client)."""
    captured: dict[str, Any] = {}

    class FakeExchange:
        status_code = 200

    class FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured["client"] = kwargs

        async def request(self, *args: Any, **kwargs: Any) -> FakeExchange:
            captured["kwargs"] = kwargs
            return FakeExchange()

        async def aclose(self) -> None:
            return None

    import arachne.core.http as http_module

    monkeypatch.setattr(http_module, "ScopedHttpClient", FakeClient)
    from pydantic import SecretStr

    hooks = WebhookSettings(enabled=True, siem_url=SecretStr("https://siem.example/collector"))
    settings = Settings(
        webhooks=hooks,
        api=ApiSettings(base_url="https://arachne.example", require_tls=False),
    )
    post = build_webhook_sender(settings)
    import asyncio

    result = asyncio.run(post("https://siem.example/collector", '{"a": 1}\n', {}))
    assert result.ok
    assert captured["kwargs"]["content"] == '{"a": 1}\n'
    assert captured["kwargs"]["headers"]["Content-Type"] == "application/x-ndjson"
