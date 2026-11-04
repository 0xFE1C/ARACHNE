"""Versioned webhook event schemas (REQ-ECOS-009).

Six outbound payload shapes went out with no version at all, so a change to any of them silently
broke a customer integration: the receiver had no way to say "this is a shape I do not
understand". This module is the fix, and it is deliberately small:

* **a name and a version on every payload.** The event *name* says what happened; the *version*
  says which shape the receiver is being sent. Both travel in the JSON body and in the
  ``X-Arachne-Event`` / ``X-Arachne-Schema-Version`` headers, because a receiver that drops
  unknown body properties (Jira's issue API, ServiceNow's table API) would otherwise lose them.
* **an unknown version is refused at emit time, not at the receiver.** A payload is a
  :class:`~arachne.api.webhooks.WebhookPayload`, and constructing one with a pair this registry
  does not know raises — so a schema change that forgets to bump the version fails in ARACHNE's
  own process rather than in somebody's ingest pipeline.
* **a breaking change is a new version of the event**, not a new shape under the old version.
  The registry holds ``(name, version)`` pairs, so ``finding.jira@1.0`` and a future
  ``finding.jira@2.0`` coexist and a receiver can subscribe to what it understands.
* **the schema is published as data.** ``src/arachne/templates/webhooks/schemas/<event>.v<n>.json``
  holds the JSON Schema of each event, committed and compared byte-for-byte with this registry by
  ``tests/unit/test_webhook_schemas.py`` — so the published document cannot drift from the code
  that emits, and a consumer can validate against a file rather than a wiki page.

The schema is descriptive, not a second implementation: it names the properties a payload of that
event carries and which of them are always present. It deliberately does not try to describe the
*content* of a destination's own fields (Jira's ``fields`` mapping, a DefectDojo import
document), because those are the destination's contract, not ARACHNE's — what ARACHNE promises is
the envelope plus the keys it fills.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = [
    "ENVELOPE_KEYS",
    "EVENTS",
    "EVENT_HEADER",
    "SCHEMA_RESOURCE",
    "SCHEMA_VERSION",
    "VERSION_HEADER",
    "EventSchema",
    "event_schema",
    "event_versions",
    "known_events",
    "publish",
    "require_event",
    "schema_directory",
    "schema_filename",
]

#: The version of every event schema currently emitted. A breaking change mints a new version
#: (``2.0``) and registers it next to this one rather than replacing it.
SCHEMA_VERSION: Final = "1.0"

#: The two keys every payload carries, whatever the destination (REQ-ECOS-009's first criterion).
ENVELOPE_KEYS: Final[tuple[str, str]] = ("event", "schema_version")

#: Where the published schema documents live, relative to the ``arachne.templates`` package.
SCHEMA_RESOURCE: Final = ("webhooks", "schemas")

#: The header names, which carry the same two values outside the body.
EVENT_HEADER: Final = "X-Arachne-Event"
VERSION_HEADER: Final = "X-Arachne-Schema-Version"


@dataclass(frozen=True, slots=True)
class EventSchema:
    """One event at one version: what it is called, what it carries, and what must be there."""

    name: str
    version: str
    description: str
    #: The destination the event is rendered for (``slack``, ``siem``, ...).
    destination: str
    #: Properties a payload of this event always carries, including the envelope.
    required: tuple[str, ...]
    #: Every property, with a short human description. ``additionalProperties`` is left open for
    #: destinations whose own API adds fields it owns (ServiceNow, DefectDojo).
    properties: Mapping[str, str]

    @property
    def pair(self) -> str:
        return f"{self.name}@{self.version}"

    def json_schema(self) -> dict[str, Any]:
        """The JSON Schema document published for this event."""
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://arachne.invalid/schemas/webhooks/{self.name}.v{self.version}.json",
            "title": f"ARACHNE webhook event {self.name} {self.version}",
            "description": self.description,
            "type": "object",
            "required": list(self.required),
            "properties": {
                key: (
                    {"type": "string", "description": text}
                    if key in ENVELOPE_KEYS
                    else {"description": text}
                )
                for key, text in self.properties.items()
            },
            # Left open on purpose: a destination's own API adds fields it owns, and a payload is
            # rendered for that API. What ARACHNE promises is the envelope plus these keys.
            "additionalProperties": True,
        }

    def problems(self, document: Mapping[str, Any]) -> tuple[str, ...]:
        """Every way ``document`` fails this schema: missing keys, or a mismatched envelope."""
        problems: list[str] = []
        if document.get("event") != self.name:
            problems.append(
                f"event is {document.get('event')!r}, expected {self.name!r}: a payload must "
                "declare the event it is"
            )
        if str(document.get("schema_version")) != self.version:
            problems.append(
                f"schema_version is {document.get('schema_version')!r}, expected "
                f"{self.version!r}: bump the version when the shape changes"
            )
        missing = [key for key in self.required if key not in document]
        if missing:
            problems.append(f"missing required propert(ies): {sorted(missing)}")
        return tuple(problems)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.name,
            "schema_version": self.version,
            "destination": self.destination,
            "description": self.description,
            "required": list(self.required),
            "properties": dict(self.properties),
            "schema": self.json_schema(),
        }


def _schema(
    name: str, destination: str, description: str, properties: Mapping[str, str]
) -> EventSchema:
    """One event at :data:`SCHEMA_VERSION`, with the envelope always present and required."""
    complete: dict[str, str] = {
        "event": "the event name (REQ-ECOS-009)",
        "schema_version": "the version of this event's shape",
        **properties,
    }
    return EventSchema(
        name=name,
        version=SCHEMA_VERSION,
        description=description,
        destination=destination,
        required=tuple(sorted(complete)),
        properties=complete,
    )


#: Every ``(name, version)`` the emitter knows. The key is ``name@version`` so a second version
#: of one event is an addition, never an overwrite (REQ-ECOS-009: a breaking change is a new
#: event version).
EVENTS: Final[dict[str, EventSchema]] = {
    schema.pair: schema
    for schema in (
        _schema(
            "scan.slack",
            "slack",
            "A scan-completion summary card posted to a Slack incoming webhook.",
            {"text": "the rendered card, one message"},
        ),
        _schema(
            "scan.teams",
            "teams",
            "A scan-completion MessageCard posted to a Teams incoming webhook.",
            {"title": "the card title", "text": "the rendered card body"},
        ),
        _schema(
            "finding.jira",
            "jira",
            "One Jira issue for one at-or-above-threshold finding.",
            {"fields": "the Jira issue fields (project, summary, description, priority)"},
        ),
        _schema(
            "finding.servicenow",
            "servicenow",
            "One ServiceNow incident for one at-or-above-threshold finding.",
            {"short_description": "the incident summary", "description": "the incident body"},
        ),
        _schema(
            "scan.defectdojo",
            "defectdojo",
            "A DefectDojo import document for a whole scan (the offline handoff, posted).",
            {"scan_type": "the DefectDojo scan type", "findings": "the imported findings"},
        ),
        _schema(
            "scan.export.siem",
            "siem",
            (
                "The envelope of the newline-delimited SIEM export. Each *record* inside it "
                "carries its own event name and version, because a collector indexes records, "
                "not HTTP bodies."
            ),
            {"records": "how many records follow", "event_types": "the record events present"},
        ),
        _schema(
            "scan.summary",
            "siem",
            "One SIEM record summarising a scan (the first record of the NDJSON export).",
            {"scan_id": "the scan identifier", "counts": "findings per severity"},
        ),
        _schema(
            "finding",
            "siem",
            "One SIEM record per finding.",
            {"finding_id": "the finding identifier", "severity": "the finding's severity"},
        ),
        _schema(
            "audit",
            "siem",
            "One SIEM record per audit event, already redacted.",
            {"action": "the audit action", "outcome": "the audit outcome"},
        ),
    )
}


def known_events() -> tuple[str, ...]:
    """Every registered event name, sorted."""
    return tuple(sorted({schema.name for schema in EVENTS.values()}))


def event_versions(name: str) -> tuple[str, ...]:
    """Every registered version of ``name``, newest last."""
    return tuple(sorted(schema.version for schema in EVENTS.values() if schema.name == name))


def event_schema(name: str, version: str = SCHEMA_VERSION) -> EventSchema | None:
    """The schema for ``name`` at ``version``, or ``None`` when there is no such pair."""
    return EVENTS.get(f"{name}@{version}")


def require_event(name: str, version: str = SCHEMA_VERSION) -> EventSchema:
    """The schema, or a refusal naming what is registered — the emit-time gate (REQ-ECOS-009).

    Called wherever a payload is built. An unknown *version* is the interesting case: it means
    somebody changed a shape without minting a version, which would break receivers silently, so
    the refusal says exactly that.
    """
    found = event_schema(name, version)
    if found is not None:
        return found
    if name not in known_events():
        msg = (
            f"unknown webhook event {name!r}; registered events are {list(known_events())}. "
            "Register the event in arachne.api.webhook_schemas before emitting it"
        )
        raise ConfigurationError(msg)
    msg = (
        f"unknown version {version!r} of webhook event {name!r} (registered: "
        f"{list(event_versions(name))}). A breaking change to a payload uses a NEW event "
        "version, never a new shape under the old one; otherwise every receiver breaks silently"
    )
    raise ConfigurationError(msg)


def schema_filename(schema: EventSchema) -> str:
    """The published file name for one event: ``<name>.v<version>.json``."""
    return f"{schema.name}.v{schema.version}.json"


def publish() -> dict[str, str]:
    """``{filename: document text}`` for every published schema — what the tree must contain."""
    documents: dict[str, str] = {}
    for schema in sorted(EVENTS.values(), key=lambda item: item.pair):
        documents[schema_filename(schema)] = (
            json.dumps(schema.json_schema(), indent=2, sort_keys=False) + "\n"
        )
    return documents


def schema_directory() -> Any:
    """The ``importlib.resources`` node holding the committed schema documents."""
    node = files("arachne.templates")
    for part in SCHEMA_RESOURCE:
        node = node.joinpath(part)
    return node
