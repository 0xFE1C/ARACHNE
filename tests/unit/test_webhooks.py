"""Unit tests for the F-06-06 webhooks (S12).

The payload mapping is a pure function of a report DTO, so it is tested without a socket:
what each integration's body contains, that the Jira cap is honoured, that the DefectDojo
mapping uses the documented field names, and that a failed delivery is audited and returned
rather than raised.
"""

from __future__ import annotations

import json

import pytest
from tests.helpers.api import StubPoster
from tests.helpers.report import synthetic_report

from arachne.api.webhook_schemas import SCHEMA_VERSION
from arachne.api.webhooks import (
    WebhookNotifier,
    build_webhook_sender,
    render_payloads,
    webhook_scope,
)
from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import ApiSettings, Settings, WebhookSettings
from arachne.report.model import ReportData


def _settings(*, min_severity: str = "high", max_findings: int = 25) -> Settings:
    from pydantic import SecretStr

    from arachne.core.config import ApiSettings

    hooks = WebhookSettings(
        enabled=True,
        slack_url=SecretStr("https://hooks.slack.example/T/B/X"),
        teams_url=SecretStr("https://teams.example/webhook"),
        jira_url=SecretStr("https://jira.example"),
        jira_project="SEC",
        jira_token=SecretStr("jira-token"),
        defectdojo_url=SecretStr("https://dojo.example"),
        defectdojo_token=SecretStr("dojo-token"),
        min_severity=min_severity,
        max_findings=max_findings,
    )
    return Settings(
        webhooks=hooks,
        api=ApiSettings(base_url="https://arachne.example", require_tls=False),
    )


@pytest.fixture
def report() -> ReportData:
    return synthetic_report()  # type: ignore[return-value]


def test_disabled_webhooks_render_nothing(report: ReportData) -> None:
    settings = _settings()
    object.__setattr__(settings, "webhooks", WebhookSettings(enabled=False))
    assert render_payloads(report, settings) == ()


def test_a_disabled_deployment_reports_no_targets() -> None:
    assert WebhookSettings().configured_targets() == ()
    assert WebhookSettings().endpoint_urls() == ()


def test_all_four_integrations_render_their_documented_shapes(report: ReportData) -> None:
    settings = _settings()
    payloads = render_payloads(report, settings)
    assert [item.name for item in payloads][:2] == ["slack", "teams"]
    assert "jira" in [item.name for item in payloads]
    assert payloads[-1].name == "defectdojo"

    slack = payloads[0]
    # The Slack card is the rendered text plus the versioned envelope every payload carries
    # (REQ-ECOS-009): this is a shape a receiver can recognise, not an anonymous message.
    assert set(slack.body) == {"text", "event", "schema_version"}
    assert slack.event == "scan.slack"
    assert slack.schema_version == SCHEMA_VERSION
    assert slack.headers["X-Arachne-Event"] == "scan.slack"
    assert report.target_name in slack.body["text"]
    assert "/scans/" in slack.body["text"]  # the report link

    teams = payloads[1]
    assert teams.body["@type"] == "MessageCard"
    assert teams.body["title"].startswith("ARACHNE scan")

    dojo = payloads[-1]
    assert dojo.url == "https://dojo.example/api/v2/import-scan/"
    assert dojo.body["scan_type"] == "ARACHNE Scan"
    assert dojo.body["product_name"] == report.target_name
    assert dojo.body["findings"], "the import must carry the findings"


def test_the_report_link_uses_the_configured_base_url(report: ReportData) -> None:
    payloads = render_payloads(report, _settings())
    assert f"https://arachne.example/scans/{report.scan_id}" in payloads[0].body["text"]


def test_jira_creates_one_issue_per_finding_at_or_above_the_threshold() -> None:
    report = synthetic_report()
    severity_counts: dict[str, int] = {}
    for finding in report.findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
    expected = sum(count for name, count in severity_counts.items() if name in {"high", "critical"})
    payloads = render_payloads(report, _settings())
    jira = [item for item in payloads if item.name == "jira"]
    assert len(jira) == expected
    if jira:
        fields = jira[0].body["fields"]
        assert fields["project"] == {"key": "SEC"}
        assert fields["issuetype"] == {"name": "Bug"}
        assert fields["summary"].startswith("[")


def test_the_jira_issue_count_is_capped(report: ReportData) -> None:
    payloads = render_payloads(report, _settings(max_findings=1, min_severity="info"))
    jira = [item for item in payloads if item.name == "jira"]
    assert len(jira) == 1


def test_jira_auth_is_a_bearer_or_basic_header() -> None:
    from pydantic import SecretStr

    from arachne.core.config import WebhookSettings

    bearer = WebhookSettings(
        enabled=True,
        jira_url=SecretStr("https://jira.example"),
        jira_project="SEC",
        jira_token=SecretStr("tok"),
    )
    assert _jira_header(bearer) == "Bearer tok"
    basic = WebhookSettings(
        enabled=True,
        jira_url=SecretStr("https://jira.example"),
        jira_project="SEC",
        jira_user=SecretStr("user@example.com"),
        jira_token=SecretStr("tok"),
    )
    header = _jira_header(basic)
    assert header.startswith("Basic ")


def _jira_header(hooks: WebhookSettings) -> str:
    from arachne.api.webhooks import _jira_headers

    return _jira_headers(hooks).get("Authorization", "")


def test_defectdojo_maps_cwe_severity_and_status(report: ReportData) -> None:
    payloads = render_payloads(report, _settings(min_severity="info"))
    dojo = payloads[-1]
    first = dojo.body["findings"][0]
    assert first["severity"] in {"Critical", "High", "Medium", "Low", "Info"}
    assert isinstance(first["cwe"], int)
    assert "unique_id_from_tool" in first and "file_path" in first


def test_the_scope_is_exactly_the_configured_hosts() -> None:
    scope = webhook_scope(_settings().webhooks)
    assert set(scope.allowed_hosts) == {
        "hooks.slack.example",
        "teams.example",
        "jira.example",
        "dojo.example",
    }


def test_payloads_are_json_serializable_and_carry_no_raw_url_secrets(
    report: ReportData,
) -> None:
    for payload in render_payloads(report, _settings()):
        json.dumps(payload.body)  # must not raise
        # to_dict() redacts header values (tokens) — the body itself never holds them.
        assert "jira-token" not in json.dumps(payload.body)
        assert "dojo-token" not in json.dumps(payload.body)


# --------------------------------------------------------------------------- notifier
@pytest.mark.asyncio
async def test_the_notifier_delivers_and_audits_each_target(report: ReportData) -> None:
    sink = MemoryAuditSink()
    poster = StubPoster()
    notifier = WebhookNotifier(_settings(), auditor=Auditor(sink), post_json=poster)
    results = await notifier.notify(report)
    assert poster.calls, "the stub must have been called"
    assert all(item.ok for item in results)
    actions = [event.action for event in sink.events]
    assert actions and all(action is AuditAction.WEBHOOK_DELIVERED for action in actions)


@pytest.mark.asyncio
async def test_a_failed_delivery_is_audited_and_never_raises(report: ReportData) -> None:
    sink = MemoryAuditSink()
    poster = StubPoster(ok=False, status_code=500, error="server error")
    notifier = WebhookNotifier(_settings(), auditor=Auditor(sink), post_json=poster)
    results = await notifier.notify(report)
    assert results and not any(item.ok for item in results)
    assert all(event.action is AuditAction.WEBHOOK_FAILED for event in sink.events)


@pytest.mark.asyncio
async def test_a_poster_that_raises_is_caught(report: ReportData) -> None:
    async def exploding(url, body, headers):  # type: ignore[no-untyped-def]
        raise RuntimeError("boom")

    notifier = WebhookNotifier(_settings(), post_json=exploding)
    results = await notifier.notify(report)
    assert results and all(not item.ok for item in results)
    assert all("boom" in (item.error or "") for item in results)


@pytest.mark.asyncio
async def test_a_disabled_notifier_sends_nothing(report: ReportData) -> None:
    poster = StubPoster()
    settings = _settings()
    object.__setattr__(settings, "webhooks", WebhookSettings(enabled=False))
    notifier = WebhookNotifier(settings, post_json=poster)
    assert await notifier.notify(report) == ()
    assert poster.calls == []
    assert not notifier.enabled


def test_the_default_sender_is_built_without_a_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default sender is an async callable; building it opens no connection."""
    sender = build_webhook_sender(_settings())
    assert callable(sender)
    # It is a coroutine function: calling it returns an awaitable that nobody awaits here.
    import inspect

    assert inspect.iscoroutinefunction(sender)


# ------------------------------------------------------------------ S22: six destinations
def test_all_six_integrations_render_their_shapes_and_the_order_is_stable(
    report: ReportData,
) -> None:
    """Slack, Teams, Jira, ServiceNow, DefectDojo, SIEM — one list, one order."""
    from pydantic import SecretStr

    hooks = WebhookSettings(
        enabled=True,
        slack_url=SecretStr("https://hooks.slack.example/T/B/X"),
        teams_url=SecretStr("https://teams.example/webhook"),
        jira_url=SecretStr("https://jira.example"),
        jira_project="SEC",
        jira_token=SecretStr("jira-token"),
        servicenow_url=SecretStr("https://acme.service-now.example"),
        servicenow_user=SecretStr("svc-arachne"),
        servicenow_password=SecretStr("snow-password"),
        defectdojo_url=SecretStr("https://dojo.example"),
        defectdojo_token=SecretStr("dojo-token"),
        siem_url=SecretStr("https://siem.example/collector"),
        siem_token=SecretStr("siem-token"),
        min_severity="info",
    )
    settings = Settings(
        webhooks=hooks,
        api=ApiSettings(base_url="https://arachne.example", require_tls=False),
    )
    names = [payload.name for payload in render_payloads(report, settings)]
    assert names[0] == "slack" and names[1] == "teams"
    # jira and servicenow open one item per at-or-above-threshold finding, then the two
    # bulk exports close the list, in the documented order.
    assert names.count("jira") >= 1 and names.count("servicenow") == names.count("jira")
    first = names.index("jira")
    assert names[first : first + names.count("jira")] == ["jira"] * names.count("jira")
    assert names[-2] == "defectdojo" and names[-1] == "siem"
    assert hooks.configured_targets() == (
        "slack",
        "teams",
        "jira",
        "servicenow",
        "defectdojo",
        "siem",
    )


async def test_a_secret_never_reaches_a_payload_an_audit_line_or_the_log(
    report: ReportData,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """REQ-OPS-002's no-secrets-in-logs test, over the whole integration path.

    Every configured token (Jira, DefectDojo, ServiceNow password, SIEM bearer) is
    rendered into an auth header, delivered through the notifier, audited, and mirrored
    into the structured logger. None of them may survive anywhere except the header
    the request itself carries.
    """
    import logging

    from pydantic import SecretStr
    from tests.helpers.api import StubPoster

    secrets = ("jira-token", "dojo-token", "snow-password", "svc-arachne", "siem-token")
    hooks = WebhookSettings(
        enabled=True,
        slack_url=SecretStr("https://hooks.slack.example/T/B/X"),
        teams_url=SecretStr("https://teams.example/webhook"),
        jira_url=SecretStr("https://jira.example"),
        jira_project="SEC",
        jira_token=SecretStr("jira-token"),
        servicenow_url=SecretStr("https://acme.service-now.example"),
        servicenow_user=SecretStr("svc-arachne"),
        servicenow_password=SecretStr("snow-password"),
        defectdojo_url=SecretStr("https://dojo.example"),
        defectdojo_token=SecretStr("dojo-token"),
        siem_url=SecretStr("https://siem.example/collector"),
        siem_token=SecretStr("siem-token"),
        min_severity="info",
    )
    settings = Settings(
        webhooks=hooks,
        api=ApiSettings(base_url="https://arachne.example", require_tls=False),
    )
    # 1) The rendered payloads: secrets live only in the auth headers, and to_dict()
    #    redacts every header value.
    payloads = render_payloads(report, settings)
    for payload in payloads:
        body_text = json.dumps(payload.body, default=str)
        for secret in secrets:
            assert secret not in body_text, f"{payload.name} body carries {secret}"
            assert secret not in payload.url
        redacted = payload.to_dict()
        assert redacted["headers"] == dict.fromkeys(payload.headers, "<redacted>")
        assert all(secret not in json.dumps(redacted["body"], default=str) for secret in secrets)
    # 2) The delivery + audit trail.
    poster = StubPoster()
    sink = MemoryAuditSink()
    notifier = WebhookNotifier(settings, auditor=Auditor(sink, actor="pytest"), post_json=poster)
    results = await notifier.notify(report)
    assert results and all(result.ok for result in results)
    trail = json.dumps([event.to_dict() for event in sink.events], default=str)
    for secret in secrets:
        assert secret not in trail
    # 3) The structured log mirror of the same trail.
    with caplog.at_level(logging.DEBUG, logger="core.audit"):
        for event in sink.events:
            logging.getLogger("core.audit").info("audit", extra={"event": event.to_dict()})
    for secret in secrets:
        assert secret not in caplog.text
