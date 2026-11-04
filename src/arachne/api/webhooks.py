"""Outbound scan-completion integrations (F-06-06, S12/S22).

Six destinations, one shape. A :class:`WebhookPayload` is a fully-rendered
``(name, url, headers, body)`` tuple; ``render_payloads`` produces them from an immutable
:class:`~arachne.report.model.ReportData`, and :class:`WebhookNotifier` posts them. The
split matters: the payload mapping is a pure function (unit-testable with no socket), and
the posting is one injectable callable (``post_json``).

* **Slack / Teams** — one summary card: severity counts, the top findings, and a link to the
  report in the web UI. The prose comes from a managed-data template
  (``templates/webhooks/*.txt.j2``, ADR-04).
* **Jira** — one issue per at-or-above-threshold finding, template-driven (summary and
  description are templates), capped by ``webhooks.max_findings`` so a scan cannot open
  hundreds of tickets in one call.
* **ServiceNow** (S22, REQ-OPS-002) — one incident per at-or-above-threshold finding via
  the Table API (``/api/now/table/incident``), Basic-authenticated with a SecretStr
  service account, capped like Jira.
* **SIEM export** (S22, REQ-OPS-002) — the scan's findings **and audit events** as
  newline-delimited JSON (``application/x-ndjson``) to the configured collector:
  one ``scan.summary`` record, one record per finding, one per audit event. The audit
  records are the trail's own (already redacted) dicts.
* **DefectDojo** (S22, REQ-OPS-001) — a JSON import built by
  :mod:`arachne.report.defectdojo`, the same builder ``arachne report --format
  defectdojo`` uses for the offline handoff, posted to ``/api/v2/import-scan/`` with the
  standard engagement mapping.

Three properties are non-negotiable:

* **A webhook never fails a scan.** Delivery errors are caught, audited
  (``webhook.failed``) and returned as a result the caller may report; they are never raised.
* **No secrets in a payload.** Every value comes from the already-redacted report DTO
  (F-08-04); the endpoint URLs and tokens live in :class:`~pydantic.SecretStr` and are
  only read to build the request and its auth header — never logged, never audited, and
  pinned out of the trail by ``tests/unit/test_webhooks.py``.
* **Egress is the shared client.** Posting goes through :class:`ScopedHttpClient`
  (ADR-05), scoped to exactly the configured webhook hosts, so rate limits and the audit
  trail apply to ARACHNE's own outbound integrations too.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from importlib.resources import files
from typing import Any

import jinja2

from arachne import __version__
from arachne.api.webhook_schemas import (
    EVENT_HEADER,
    SCHEMA_VERSION,
    VERSION_HEADER,
    require_event,
)
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import SEVERITY_LEVELS, Settings, WebhookSettings
from arachne.core.errors import ConfigurationError
from arachne.core.safety import Scope
from arachne.report.defectdojo import defectdojo_document
from arachne.report.model import ReportData, ReportFinding

__all__ = [
    "WEBHOOK_TEMPLATE_DIR",
    "PostJson",
    "WebhookNotifier",
    "WebhookPayload",
    "WebhookResult",
    "build_webhook_sender",
    "load_webhook_environment",
    "render_payloads",
    "siem_records",
    "webhook_scope",
]

#: Bundled template directory, relative to the ``arachne.templates`` package.
WEBHOOK_TEMPLATE_DIR = "webhooks"

#: The single egress seam: ``(url, body, headers) -> (status_code, error)``. The body is
#: a JSON mapping, or a pre-encoded string (the SIEM's NDJSON) posted verbatim.
PostJson = Callable[
    [str, "Mapping[str, Any] | str", Mapping[str, str]], Awaitable["WebhookPostResult"]
]


@dataclass(frozen=True, slots=True)
class WebhookPostResult:
    """What the sender returns for one delivery attempt."""

    status_code: int | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code is not None and 200 <= self.status_code < 300


@dataclass(frozen=True, slots=True)
class WebhookPayload:
    """One fully-rendered delivery: where to post it, what, and which event shape it is.

    ``event`` and ``schema_version`` are **required** (REQ-ECOS-009): every outbound payload names
    the event it carries and the version of that event's shape, so a receiver can tell "a shape I
    do not understand" from "a message I cannot parse". An unknown pair is refused *here*, at emit
    time — a schema change that forgot to mint a version fails in ARACHNE's own process instead
    of in a customer's ingest pipeline.
    """

    name: str
    url: str
    body: dict[str, Any]
    event: str
    schema_version: str = SCHEMA_VERSION
    headers: Mapping[str, str] = field(default_factory=dict)
    summary: str = ""
    #: When set, posted verbatim instead of ``json.dumps(body)`` (the SIEM's NDJSON:
    #: one JSON object per line, which is not a JSON document).
    raw_body: str | None = None
    content_type: str = "application/json"

    def __post_init__(self) -> None:
        # The emit-time gate: refuse an event/version this build does not have a schema for.
        schema = require_event(self.event, self.schema_version)
        if schema.destination != self.name:
            msg = (
                f"webhook event {schema.pair!r} belongs to the {schema.destination!r} "
                f"destination but was rendered as {self.name!r}; the two must agree or a "
                "receiver gets a payload whose event name lies about its shape"
            )
            raise ConfigurationError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "event": self.event,
            "schema_version": self.schema_version,
            "headers": dict.fromkeys(self.headers, "<redacted>"),
            "body": self.body if self.raw_body is None else f"<{self.content_type}>",
        }


@dataclass(frozen=True, slots=True)
class WebhookResult:
    """The outcome of one delivery, for the caller and the audit trail."""

    name: str
    ok: bool
    status_code: int | None = None
    error: str | None = None
    items: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "status_code": self.status_code,
            "error": self.error,
            "items": self.items,
        }


# --------------------------------------------------------------------------- templates
def load_webhook_environment(templates_dir: str | None = None) -> jinja2.Environment:
    """A Jinja environment over the bundled webhook templates (+ an optional override dir).

    The custom directory (``webhooks.templates_dir``, F-09-04) is consulted first, so a
    deployment can restyle its cards without touching the package; the bundled templates are
    always the fallback. Loading is ``autoescape=False`` because the output is not HTML — but
    every payload is JSON-encoded by Python afterwards, so a target-derived title cannot
    break out of the envelope.
    """
    bundled = files("arachne.templates").joinpath(WEBHOOK_TEMPLATE_DIR)
    loaders: list[jinja2.BaseLoader] = []
    if templates_dir:
        loaders.append(jinja2.FileSystemLoader(templates_dir))
    try:
        # Only files are templates: the directory also holds ``schemas/``, the published JSON
        # Schema of each event (REQ-ECOS-009). Reading that subdirectory as a template would make
        # an unrelated addition break every webhook, which is the kind of coupling that turns a
        # data directory into a trap.
        contents = {
            item.name: item.read_text(encoding="utf-8")
            for item in bundled.iterdir()
            if item.is_file()
        }
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled webhook templates are missing: {exc}"
        raise ConfigurationError(msg) from exc
    loaders.append(jinja2.DictLoader(contents))
    return jinja2.Environment(
        loader=jinja2.ChoiceLoader(loaders),
        autoescape=False,  # noqa: S701 - JSON, not HTML; Python json-encodes the payload
        keep_trailing_newline=False,
        trim_blocks=True,
        lstrip_blocks=True,
        undefined=jinja2.StrictUndefined,
    )


# --------------------------------------------------------------------------- egress
def webhook_scope(settings: WebhookSettings) -> Scope:
    """The scope a webhook may reach: exactly the hosts of the configured endpoints."""
    hosts: list[str] = []
    for url in settings.endpoint_urls():
        from urllib.parse import urlsplit

        host = urlsplit(url).hostname
        if host:
            hosts.append(host)
    return Scope(allowed_hosts=tuple(dict.fromkeys(hosts)))


def build_webhook_sender(
    settings: Settings,
    *,
    auditor: Auditor | None = None,
    transport: object | None = None,
    client: object | None = None,
    resolver: object | None = None,
    policy: object | None = None,
    scope: Scope | None = None,
) -> PostJson:
    """Build the default :data:`PostJson` over a scope-bound :class:`ScopedHttpClient`.

    The keyword seams (``transport``/``client``/``resolver``/``policy``/``scope``) exist for
    tests: they let a caller point the real client at a loopback stub or a mock transport
    without teaching this module about ``httpx`` (which only ``core/http.py`` may import).

    A fresh client is built per delivery and closed afterwards. A scan's webhooks are a
    handful of requests (bounded by ``max_findings``), so the connection-pool reuse a shared
    client would buy is not worth keeping an open pool alive between two scans.
    """
    import json

    from arachne.core.http import ScopedHttpClient

    effective_scope = scope if scope is not None else webhook_scope(settings.webhooks)

    async def post(
        url: str, body: Mapping[str, Any] | str, headers: Mapping[str, str]
    ) -> WebhookPostResult:
        content = body if isinstance(body, str) else json.dumps(body, default=str)
        content_type = "application/x-ndjson" if isinstance(body, str) else "application/json"
        request_headers = {"Content-Type": content_type, **dict(headers)}
        client_obj = ScopedHttpClient(
            settings=settings,
            scope=effective_scope,
            policy=policy,  # type: ignore[arg-type]
            resolver=resolver,  # type: ignore[arg-type]
            auditor=auditor,
            transport=transport,  # type: ignore[arg-type]
            client=client,  # type: ignore[arg-type]
        )
        try:
            exchange = await client_obj.request(
                "POST",
                url,
                headers=request_headers,
                content=content,
                follow_redirects=False,
            )
        except Exception as exc:  # a delivery failure is data, never an exception upstream
            return WebhookPostResult(status_code=None, error=f"{exc.__class__.__name__}: {exc}")
        finally:
            await client_obj.aclose()
        return WebhookPostResult(status_code=exchange.status_code)

    return post


# --------------------------------------------------------------------------- payloads
def _severity_at_or_above(finding: ReportFinding, minimum: str) -> bool:
    floor = SEVERITY_LEVELS.index(minimum)
    level = SEVERITY_LEVELS.index(finding.severity) if finding.severity in SEVERITY_LEVELS else 0
    return level >= floor


def _finding_view(finding: ReportFinding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "module": finding.module,
        "check_id": finding.check_id,
        "cwe": finding.classification.cwe,
        "cve": finding.classification.cve,
        "confidence": finding.score.confidence,
        "asset": finding.asset.value,
        "asset_kind": finding.asset.kind,
        "cvss": finding.score.cvss_base,
        "remediation": finding.remediation.summary,
        "remediation_id": finding.remediation.id,
        "status": finding.status,
    }


def _report_context(report: ReportData, settings: Settings) -> dict[str, Any]:
    findings = [_finding_view(item) for item in report.findings]
    at_or_above = [
        item
        for item in findings
        if item["severity"] in SEVERITY_LEVELS
        and SEVERITY_LEVELS.index(item["severity"])
        >= SEVERITY_LEVELS.index(settings.webhooks.min_severity)
    ]
    ordered = sorted(
        findings,
        key=lambda item: (
            SEVERITY_LEVELS.index(item["severity"]) if item["severity"] in SEVERITY_LEVELS else -1
        ),
        reverse=True,
    )
    return {
        "target": report.target_name,
        "scan_id": report.scan_id,
        "engine": report.cover.engine,
        "arachne_version": report.cover.arachne_version or __version__,
        "generated_at": (report.cover.generated_at or datetime.now(UTC)).isoformat(),
        "counts": {name: report.counts.for_severity(name) for name in reversed(SEVERITY_LEVELS)},
        "total": report.counts.total,
        "findings": findings,
        "at_or_above": at_or_above,
        "top": ordered[:3],
        "threshold": settings.webhooks.min_severity,
        "report_url": _report_url(report.scan_id, settings),
        "low_confidence": len(report.low_confidence),
    }


def _report_url(scan_id: str | int, settings: Settings) -> str:
    base = (settings.api.base_url or "").rstrip("/")
    path = f"/scans/{scan_id}"
    return f"{base}{path}" if base else path


def _envelope(
    body: Mapping[str, Any],
    event: str,
    headers: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    """Stamp the event envelope onto a body and into the headers (REQ-ECOS-009).

    Both, because the two destinations ARACHNE posts to that own their field set (Jira's issue
    API, ServiceNow's table API) may drop a property they do not recognise: a receiver that keeps
    the body's ``event``/``schema_version`` reads them there, and one that drops unknown body
    properties can still read the headers. Nothing about the destination's own fields changes.
    """
    schema = require_event(event)
    stamped = dict(body) | {"event": schema.name, "schema_version": schema.version}
    merged = dict(headers or {}) | {
        EVENT_HEADER: schema.name,
        VERSION_HEADER: schema.version,
    }
    return stamped, merged


def render_payloads(
    report: ReportData,
    settings: Settings,
    *,
    templates: jinja2.Environment | None = None,
    audit_events: Sequence[Mapping[str, Any]] = (),
) -> tuple[WebhookPayload, ...]:
    """Render every configured destination's payload for ``report``.

    Pure apart from reading the templates: no socket, no store, no clock beyond the report's
    own ``generated_at``. The order is stable (slack, teams, jira, servicenow, defectdojo,
    siem) so a test can assert on it. ``audit_events`` (already redacted audit dicts) feed
    the SIEM export only; every other destination is a function of the report alone.
    """
    hooks = settings.webhooks
    if not hooks.enabled:
        return ()
    environment = templates or load_webhook_environment(hooks.templates_dir)
    context = _report_context(report, settings)
    payloads: list[WebhookPayload] = []

    if hooks.slack_url is not None:
        text = environment.get_template("slack.txt.j2").render(**context)
        body, headers = _envelope({"text": text}, "scan.slack")
        payloads.append(
            WebhookPayload(
                name="slack",
                url=hooks.slack_url.get_secret_value(),
                body=body,
                event="scan.slack",
                headers=headers,
                summary=_first_line(text),
            )
        )

    if hooks.teams_url is not None:
        text = environment.get_template("teams.txt.j2").render(**context)
        card, teams_headers = _envelope(
            {
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": _first_line(text),
                "themeColor": _theme_color(context["counts"]),
                "title": f"ARACHNE scan {report.scan_id}: {report.target_name}",
                "text": text,
            },
            "scan.teams",
        )
        payloads.append(
            WebhookPayload(
                name="teams",
                url=hooks.teams_url.get_secret_value(),
                body=card,
                event="scan.teams",
                headers=teams_headers,
                summary=_first_line(text),
            )
        )

    if hooks.jira_url is not None and hooks.jira_project:
        base = hooks.jira_url.get_secret_value().rstrip("/")
        endpoint = f"{base}/rest/api/2/issue"
        headers = _jira_headers(hooks)
        selected = context["at_or_above"][: hooks.max_findings]
        for finding in selected:
            summary = environment.get_template("jira_summary.txt.j2").render(
                finding=finding, scan_id=report.scan_id, target=report.target_name
            )
            description = environment.get_template("jira_description.txt.j2").render(
                finding=finding, **context
            )
            issue, issue_headers = _envelope(
                {
                    "fields": {
                        "project": {"key": hooks.jira_project},
                        "summary": summary.strip(),
                        "description": description.strip(),
                        "issuetype": {"name": "Bug"},
                        "priority": {"name": _jira_priority(str(finding["severity"]))},
                        "labels": ["arachne", finding["severity"]],
                    }
                },
                "finding.jira",
                headers,
            )
            payloads.append(
                WebhookPayload(
                    name="jira",
                    url=endpoint,
                    headers=issue_headers,
                    summary=_first_line(summary.strip()),
                    body=issue,
                    event="finding.jira",
                )
            )

    if hooks.servicenow_url is not None:
        payloads.extend(_servicenow_payloads(report, hooks, environment, context))

    if hooks.defectdojo_url is not None:
        base = hooks.defectdojo_url.get_secret_value().rstrip("/")
        dd_headers: dict[str, str] = {}
        if hooks.defectdojo_token is not None:
            token = hooks.defectdojo_token.get_secret_value()
            dd_headers["Authorization"] = f"Token {token}"
        document, dd_headers = _envelope(defectdojo_document(report), "scan.defectdojo", dd_headers)
        payloads.append(
            WebhookPayload(
                name="defectdojo",
                url=f"{base}/api/v2/import-scan/",
                headers=dd_headers,
                summary=f"{report.counts.total} finding(s) for scan {report.scan_id}",
                body=document,
                event="scan.defectdojo",
            )
        )

    if hooks.siem_url is not None:
        records = siem_records(report, audit_events)
        # The NDJSON payload's own envelope describes the export; every *record* inside it
        # carries its own event name and version, because a SIEM collector indexes records, not
        # HTTP bodies.
        body, siem_headers = _envelope(
            {"records": len(records), "event_types": sorted({item["event"] for item in records})},
            "scan.export.siem",
            _siem_headers(hooks),
        )
        payloads.append(
            WebhookPayload(
                name="siem",
                url=hooks.siem_url.get_secret_value(),
                body=body,
                event="scan.export.siem",
                headers=siem_headers,
                summary=f"{len(records)} record(s) for scan {report.scan_id}",
                raw_body="".join(
                    json.dumps(record, default=str, sort_keys=True) + "\n" for record in records
                ),
                content_type="application/x-ndjson",
            )
        )

    return tuple(payloads)


def _servicenow_payloads(
    report: ReportData,
    hooks: WebhookSettings,
    environment: jinja2.Environment,
    context: Mapping[str, Any],
) -> list[WebhookPayload]:
    """One ServiceNow incident per at-or-above-threshold finding (S22, REQ-OPS-002).

    The Table API (``POST /api/now/table/incident``) with Basic auth over a SecretStr
    service account (``user``/``password`` — enforced together by the settings). Capped
    by ``max_findings`` exactly like Jira: a scan cannot open hundreds of incidents in
    one fan-out.
    """
    assert hooks.servicenow_url is not None  # the caller checked
    assert hooks.servicenow_user is not None and hooks.servicenow_password is not None
    base = hooks.servicenow_url.get_secret_value().rstrip("/")
    endpoint = f"{base}/api/now/table/incident"
    raw = (
        f"{hooks.servicenow_user.get_secret_value()}:{hooks.servicenow_password.get_secret_value()}"
    ).encode()
    headers = {
        "Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}",
        "Accept": "application/json",
    }
    selected = context["at_or_above"][: hooks.max_findings]
    payloads: list[WebhookPayload] = []
    for finding in selected:
        short = environment.get_template("servicenow_summary.txt.j2").render(
            finding=finding, scan_id=report.scan_id, target=report.target_name
        )
        description = environment.get_template("servicenow_description.txt.j2").render(
            finding=finding, **context
        )
        impact, urgency = _servicenow_priority(str(finding.get("severity") or "info"))
        incident, incident_headers = _envelope(
            {
                "short_description": short.strip(),
                "description": description.strip(),
                "impact": impact,
                "urgency": urgency,
                "category": "vulnerability",
                "subcategory": "arachne",
                "comments": (
                    f"Opened by ARACHNE scan {report.scan_id} · check "
                    f"{finding.get('check_id') or 'n/a'} · report: {context['report_url']}"
                ),
            },
            "finding.servicenow",
            headers,
        )
        payloads.append(
            WebhookPayload(
                name="servicenow",
                url=endpoint,
                headers=incident_headers,
                summary=_first_line(short.strip()),
                body=incident,
                event="finding.servicenow",
            )
        )
    return payloads


def _jira_priority(severity: str) -> str:
    """Severity → the default Jira priority scheme's name."""
    return {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    }.get(severity, "Medium")


def _servicenow_priority(severity: str) -> tuple[int, int]:
    """Severity → ServiceNow ``(impact, urgency)`` (1 = highest, 3 = lowest)."""
    return {
        "critical": (1, 1),
        "high": (1, 2),
        "medium": (2, 2),
        "low": (3, 3),
        "info": (3, 3),
    }.get(severity, (2, 2))


def _siem_headers(hooks: WebhookSettings) -> dict[str, str]:
    """The SIEM collector's auth header — a bearer token only when one is configured."""
    if hooks.siem_token is None:
        return {}
    return {"Authorization": f"Bearer {hooks.siem_token.get_secret_value()}"}


def siem_records(
    report: ReportData,
    audit_events: Sequence[Mapping[str, Any]] = (),
) -> list[dict[str, Any]]:
    """The SIEM export's records: one summary, one per finding, one per audit event.

    The records are the deployment's SIEM view of a scan (REQ-OPS-002: "findings +
    audit events as JSONL/webhook"). Every value is already-redacted report data or the
    audit trail's own dict — this function never touches a credential, and the
    no-secrets-in-logs test pins that a token cannot reach a record.
    """
    generated = report.cover.generated_at or datetime.now(UTC)
    summary_version = require_event("scan.summary").version
    finding_version = require_event("finding").version
    audit_version = require_event("audit").version
    records: list[dict[str, Any]] = [
        {
            "event": "scan.summary",
            "schema_version": summary_version,
            "ts": generated.isoformat(),
            "scan_id": str(report.scan_id),
            "target": report.target_name,
            "engine": report.cover.engine,
            "arachne_version": report.cover.arachne_version or __version__,
            "counts": {
                name: report.counts.for_severity(name) for name in reversed(SEVERITY_LEVELS)
            },
            "total": report.counts.total,
        }
    ]
    for finding in report.findings:
        records.append(
            {
                "event": "finding",
                "schema_version": finding_version,
                "ts": (finding.timestamps.last_seen or generated).isoformat(),
                "scan_id": str(report.scan_id),
                "finding_id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "check_id": finding.check_id,
                "module": finding.module,
                "cwe": finding.classification.cwe,
                "cve": finding.classification.cve,
                "asset": finding.asset.value,
                "asset_kind": finding.asset.kind,
                "cvss": finding.score.cvss_base,
                "confidence": finding.score.confidence,
                "status": finding.status,
                "remediation": finding.remediation.summary,
            }
        )
    for event in audit_events:
        record = dict(event)
        record.setdefault("event", "audit")
        record.setdefault("schema_version", audit_version)
        record.setdefault("ts", generated.isoformat())
        record["scan_id"] = str(record.get("scan_id") or report.scan_id)
        records.append(record)
    return records


def _jira_headers(hooks: WebhookSettings) -> dict[str, str]:
    """Jira auth: a bearer token (Server/PAT), else Basic ``user:token`` (Cloud)."""
    if hooks.jira_token is None:
        return {}
    token = hooks.jira_token.get_secret_value()
    if hooks.jira_user is None:
        return {"Authorization": f"Bearer {token}"}
    import base64

    raw = f"{hooks.jira_user.get_secret_value()}:{token}".encode()
    return {"Authorization": f"Basic {base64.b64encode(raw).decode('ascii')}"}


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip().lstrip("#").strip()
        if stripped:
            return stripped[:250]
    return ""


def _theme_color(counts: Mapping[str, int]) -> str:
    if counts.get("critical"):
        return "b60205"
    if counts.get("high"):
        return "d93f0b"
    if counts.get("medium"):
        return "fbca04"
    if counts.get("low"):
        return "0e8a16"
    return "0075ca"


# --------------------------------------------------------------------------- notifier
class WebhookNotifier:
    """Render and deliver the configured integrations for a scan report."""

    def __init__(
        self,
        settings: Settings,
        *,
        auditor: Auditor | None = None,
        post_json: PostJson | None = None,
        templates: jinja2.Environment | None = None,
    ) -> None:
        self.settings = settings
        self.auditor = auditor
        self._templates = templates
        self._post = post_json

    # ------------------------------------------------------------------ inspection
    @property
    def enabled(self) -> bool:
        return self.settings.webhooks.enabled and bool(self.settings.webhooks.configured_targets())

    def payloads_for(
        self, report: ReportData, audit_events: Sequence[Mapping[str, Any]] = ()
    ) -> tuple[WebhookPayload, ...]:
        """Render the payloads without sending anything (used by tests and ``--dry-run``)."""
        return render_payloads(
            report, self.settings, templates=self._templates, audit_events=audit_events
        )

    # ------------------------------------------------------------------ delivery
    async def notify(
        self, report: ReportData, audit_events: Sequence[Mapping[str, Any]] = ()
    ) -> tuple[WebhookResult, ...]:
        """Deliver ``report`` to every configured target; never raises.

        ``audit_events`` (already-redacted audit dicts) reach the SIEM export only; a
        caller without the trail still delivers findings everywhere else.
        """
        payloads = self.payloads_for(report, audit_events=audit_events)
        if not payloads:
            return ()
        poster = self._post or build_webhook_sender(self.settings, auditor=self.auditor)
        results: list[WebhookResult] = []
        for payload in payloads:
            result = await self._deliver(poster, payload, report.scan_id)
            results.append(result)
        return tuple(results)

    async def _deliver(
        self, poster: PostJson, payload: WebhookPayload, scan_id: str | int
    ) -> WebhookResult:
        body = payload.raw_body if payload.raw_body is not None else payload.body
        try:
            outcome = await poster(payload.url, body, payload.headers)
        except Exception as exc:  # belt and braces: the client already swallows transport errors
            outcome = WebhookPostResult(error=f"{exc.__class__.__name__}: {exc}")
        result = WebhookResult(
            name=payload.name,
            ok=outcome.ok,
            status_code=outcome.status_code,
            error=outcome.error,
            items=1,
        )
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.WEBHOOK_DELIVERED if result.ok else AuditAction.WEBHOOK_FAILED,
                outcome=AuditOutcome.ALLOWED if result.ok else AuditOutcome.ERROR,
                target=payload.url,
                reason=result.error,
                scan_id=scan_id,
                meta={
                    "integration": payload.name,
                    "status_code": result.status_code,
                    "summary": payload.summary[:200],
                },
            )
        return result
