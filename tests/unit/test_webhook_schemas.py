"""Every webhook payload is versioned, published and pinned by a golden (REQ-ECOS-009).

The requirement is short and every clause is asserted here:

* **every payload includes ``event`` and ``schema_version``** — in the JSON body *and* in the
  ``X-Arachne-Event`` / ``X-Arachne-Schema-Version`` headers, because Jira's issue API and
  ServiceNow's table API own their field sets and may drop a property they do not recognise;
* **the versioned schema is published and tested with a golden fixture per event type** — the
  schemas in ``templates/webhooks/schemas/`` are compared byte-for-byte with the code that emits
  them, and each event's rendered payload is compared with a committed golden, so a shape change
  is a reviewed diff rather than a surprise in somebody's ingest pipeline;
* **an unknown event version is rejected at emit time, not at the receiver** — constructing a
  payload with a version this build does not know raises in ARACHNE's own process.

The payloads are rendered from the fixed synthetic report the report tests share and one fixed
audit event, so the goldens are deterministic; regenerate them with
``ARACHNE_UPDATE_WEBHOOK_GOLDENS=1 python -m pytest tests/unit/test_webhook_schemas.py -q`` after
an *intentional* shape change (which also means a version bump).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from pydantic import SecretStr
from tests.helpers.report import synthetic_report
from typer.testing import CliRunner

from arachne.api.webhook_schemas import (
    ENVELOPE_KEYS,
    EVENT_HEADER,
    EVENTS,
    SCHEMA_RESOURCE,
    SCHEMA_VERSION,
    VERSION_HEADER,
    event_schema,
    event_versions,
    known_events,
    publish,
    require_event,
    schema_directory,
    schema_filename,
)
from arachne.api.webhooks import (
    WebhookPayload,
    render_payloads,
    siem_records,
)
from arachne.cli.main import app
from arachne.core.config import ApiSettings, Settings, WebhookSettings
from arachne.core.errors import ConfigurationError

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "webhooks" / "golden"
runner = CliRunner()

#: One fixed audit event, so the ``audit`` record's golden is deterministic.
AUDIT = (
    {
        "action": "scan.finished",
        "outcome": "allowed",
        "target": "target.example",
        "reason": None,
        "actor": "pytest",
    },
)


def _settings() -> Settings:
    """Every destination configured, with placeholder endpoints and no reachable secret."""
    return Settings(
        webhooks=WebhookSettings(
            enabled=True,
            slack_url=SecretStr("https://hooks.slack.example/T/B/X"),
            teams_url=SecretStr("https://teams.example/webhook"),
            jira_url=SecretStr("https://jira.example"),
            jira_project="SEC",
            defectdojo_url=SecretStr("https://dojo.example"),
            servicenow_url=SecretStr("https://acme.service-now.example"),
            servicenow_user=SecretStr("svc-arachne"),
            servicenow_password=SecretStr("not-a-real-password"),
            siem_url=SecretStr("https://siem.example/collector"),
            min_severity="info",
            max_findings=25,
        ),
        api=ApiSettings(base_url="https://arachne.example", require_tls=False),
    )


def payloads() -> tuple[WebhookPayload, ...]:
    return render_payloads(synthetic_report(), _settings(), audit_events=AUDIT)


def bodies() -> dict[str, dict[str, Any]]:
    """One rendered body per event: the payload's own, or the first record of its kind."""
    rendered: dict[str, dict[str, Any]] = {}
    for payload in payloads():
        rendered.setdefault(payload.event, payload.body)
    for record in siem_records(synthetic_report(), AUDIT):
        rendered.setdefault(str(record["event"]), record)
    return rendered


# ------------------------------------------------------------------ the envelope
def test_every_payload_carries_an_event_name_and_a_schema_version() -> None:
    for payload in payloads():
        assert payload.event, f"{payload.name} has no event name"
        assert payload.schema_version, f"{payload.name} has no schema version"
        for key in ENVELOPE_KEYS:
            assert key in payload.body, f"{payload.name}'s body has no {key}"
        # The same two values travel in the headers, where a receiver that drops unknown body
        # properties (Jira's issue API, ServiceNow's table API) can still read them.
        assert payload.headers[EVENT_HEADER] == payload.event
        assert payload.headers[VERSION_HEADER] == payload.schema_version


def test_every_record_of_the_siem_export_is_versioned() -> None:
    """A collector indexes records, not HTTP bodies, so each record carries the envelope."""
    for record in siem_records(synthetic_report(), AUDIT):
        assert record["event"] in known_events()
        assert record["schema_version"] == SCHEMA_VERSION
        schema = require_event(str(record["event"]), str(record["schema_version"]))
        assert schema.problems(record) == ()


def test_every_registered_event_is_actually_emitted() -> None:
    """A registered event nothing emits is a schema that will rot; say so."""
    emitted = set(bodies())
    assert emitted == set(known_events()), (
        "the registry and the emitter disagree; "
        f"registered but never rendered: {sorted(set(known_events()) - emitted)}, "
        f"rendered but not registered: {sorted(emitted - set(known_events()))}"
    )


def test_all_six_destinations_are_covered() -> None:
    destinations = {EVENTS[key].destination for key in EVENTS}
    assert destinations == {"slack", "teams", "jira", "servicenow", "defectdojo", "siem"}


# ------------------------------------------------------------------ the emit-time gate
def test_an_unknown_event_version_is_refused_at_emit_time() -> None:
    """The interesting case: a shape change that forgot to mint a version."""
    with pytest.raises(ConfigurationError) as excinfo:
        WebhookPayload(
            name="slack",
            url="https://hooks.slack.example/T/B/X",
            body={"text": "hi", **dict.fromkeys(ENVELOPE_KEYS, "")},
            event="scan.slack",
            schema_version="99.0",
        )
    message = str(excinfo.value)
    assert "unknown version" in message
    assert "NEW event version" in message, "the refusal must say how to change a shape"
    assert SCHEMA_VERSION in message


def test_an_unknown_event_name_is_refused_at_emit_time() -> None:
    with pytest.raises(ConfigurationError, match="unknown webhook event"):
        WebhookPayload(
            name="slack",
            url="https://hooks.slack.example/T/B/X",
            body={"text": "hi"},
            event="scan.nonexistent",
        )


def test_an_event_rendered_for_the_wrong_destination_is_refused() -> None:
    """A payload whose event name lies about its shape is refused, not sent."""
    with pytest.raises(ConfigurationError, match="destination"):
        WebhookPayload(
            name="teams",
            url="https://teams.example/webhook",
            body={"text": "hi"},
            event="scan.slack",
        )


def test_a_breaking_change_is_a_new_version_not_a_new_shape() -> None:
    """The registry keys on ``name@version``, so a second version coexists with the first."""
    assert event_versions("scan.slack") == (SCHEMA_VERSION,)
    assert event_schema("scan.slack", "2.0") is None
    # Every key is the pair it claims to be, so registering 2.0 is an addition, not a mutation.
    for key, schema in EVENTS.items():
        assert key == schema.pair


# ------------------------------------------------------------------ the published schemas
def test_the_published_schema_files_match_the_registry() -> None:
    """The committed documents are the ones the code emits — a drift gate, not a copy."""
    node = schema_directory()
    committed = sorted(item.name for item in node.iterdir() if item.is_file())
    expected = sorted(publish())
    assert committed == expected, (
        "the published schema documents and the registry disagree; regenerate them with "
        "`arachne events catalogue --write src/arachne/templates/webhooks/schemas`"
    )
    for name, text in publish().items():
        on_disk = (node / name).read_text(encoding="utf-8")
        assert on_disk == text, f"{name} on disk differs from the registry"


def test_each_published_schema_is_a_valid_json_schema() -> None:
    for name, text in publish().items():
        schema = json.loads(text)
        jsonschema.Draft202012Validator.check_schema(schema)
        assert set(ENVELOPE_KEYS) <= set(schema["required"]), f"{name}: the envelope is required"


def test_the_schema_resource_lives_under_the_templates_package() -> None:
    assert SCHEMA_RESOURCE[0] == "webhooks"


# ------------------------------------------------------------------ the goldens
@pytest.mark.parametrize("key", sorted(EVENTS))
def test_the_golden_fixture_matches_the_rendered_payload(key: str) -> None:
    """One golden per event type: a shape change is a diff a reviewer sees."""
    schema = EVENTS[key]
    golden = FIXTURES / schema_filename(schema)
    rendered = bodies()[schema.name]
    if not golden.exists():
        if os.environ.get("ARACHNE_UPDATE_WEBHOOK_GOLDENS") == "1":
            FIXTURES.mkdir(parents=True, exist_ok=True)
            golden.write_text(_dump(rendered), encoding="utf-8")
        else:
            pytest.fail(
                f"the golden fixture {golden} is missing; create it with "
                "ARACHNE_UPDATE_WEBHOOK_GOLDENS=1 python -m pytest "
                "tests/unit/test_webhook_schemas.py -q"
            )
    assert json.loads(golden.read_text(encoding="utf-8")) == rendered, (
        f"{schema.pair} changed shape; if that is intentional it needs a NEW event version, "
        "and then a regenerated golden"
    )


def test_every_registered_event_has_a_golden_and_no_golden_is_orphaned() -> None:
    expected = {schema_filename(schema) for schema in EVENTS.values()}
    committed = {path.name for path in FIXTURES.glob("*.json")}
    assert committed == expected, (
        f"missing goldens: {sorted(expected - committed)}, "
        f"orphaned goldens: {sorted(committed - expected)}"
    )


def test_each_golden_validates_against_its_published_schema() -> None:
    """The published document is not decoration: it accepts the payload it describes."""
    for key, schema in EVENTS.items():
        document = json.loads((FIXTURES / schema_filename(schema)).read_text(encoding="utf-8"))
        jsonschema.validate(document, schema.json_schema())
        assert schema.problems(document) == ()
        del key


def _dump(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, default=str) + "\n"


# ------------------------------------------------------------------ the CLI
def test_the_cli_publishes_the_event_catalogue(tmp_path: Path) -> None:
    written = tmp_path / "schemas"
    published = runner.invoke(app, ["events", "catalogue", "--write", str(written)])
    assert published.exit_code == 0, published.output
    assert len(list(written.glob("*.json"))) == len(EVENTS)
    assert "schema version" in published.output


def test_the_cli_prints_json_for_a_consumer(tmp_path: Path) -> None:
    emitted = runner.invoke(app, ["events", "catalogue", "--json"])
    assert emitted.exit_code == 0, emitted.output
    output = emitted.output
    payload = json.loads(output[output.index("{") : output.rindex("}") + 1])
    assert payload["schema_version"] == SCHEMA_VERSION
    assert len(payload["events"]) == len(EVENTS)
    assert all(item["schema"]["type"] == "object" for item in payload["events"])


def test_the_cli_validates_a_recorded_payload(tmp_path: Path) -> None:
    record = FIXTURES / schema_filename(require_event("scan.slack"))
    accepted = runner.invoke(app, ["events", "check", str(record)])
    assert accepted.exit_code == 0, accepted.output
    assert "valid" in accepted.output

    tampered = json.loads(record.read_text(encoding="utf-8"))
    tampered["schema_version"] = "9.9"
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(tampered), encoding="utf-8")
    refused = runner.invoke(app, ["events", "check", str(path)])
    assert refused.exit_code == 1
    assert "INVALID" in refused.output
    assert "unknown version" in refused.output
