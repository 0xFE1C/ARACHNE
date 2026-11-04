"""``arachne events`` — the versioned outbound event catalogue (REQ-ECOS-009).

A receiver of ARACHNE's webhooks needs two things this command publishes: the list of events
this build emits, and the JSON Schema of each one. ``catalogue`` prints them (``--json`` for a
machine), and ``--write DIR`` drops the schema documents into a directory so a consumer can
validate against a file rather than a wiki page.

The same documents ship inside the package
(``src/arachne/templates/webhooks/schemas/``) and are compared byte-for-byte with the code that
emits by ``tests/unit/test_webhook_schemas.py``; this command is how they reach a third party
without that third party reading the source.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from arachne.api.webhook_schemas import (
    ENVELOPE_KEYS,
    EVENT_HEADER,
    EVENTS,
    SCHEMA_VERSION,
    VERSION_HEADER,
    publish,
)
from arachne.core.errors import ConfigurationError

__all__ = ["events_app"]

events_app = typer.Typer(
    name="events",
    help="The versioned catalogue of outbound webhook events (REQ-ECOS-009).",
    no_args_is_help=True,
)


@events_app.command("catalogue")
def events_catalogue(
    write: Annotated[
        Path | None,
        typer.Option("--write", help="Write each event's JSON Schema into this directory."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List every webhook event, its version and the properties its payload carries."""
    documents = publish()
    if write is not None:
        target = write.expanduser()
        target.mkdir(parents=True, exist_ok=True)
        for name, text in documents.items():
            (target / name).write_text(text, encoding="utf-8")
        typer.echo(f"wrote {len(documents)} schema document(s) to {target}")
    if json_output:
        payload = {
            "format": "arachne-webhook-events/1",
            "schema_version": SCHEMA_VERSION,
            "headers": {EVENT_HEADER: "<event>", VERSION_HEADER: "<schema_version>"},
            "envelope": list(ENVELOPE_KEYS),
            "events": [EVENTS[key].to_dict() for key in sorted(EVENTS)],
        }
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo(f"{len(EVENTS)} webhook event(s), schema version {SCHEMA_VERSION}")
    typer.echo(f"  every payload carries {list(ENVELOPE_KEYS)} in the body, and the same two")
    typer.echo(f"  values in the {EVENT_HEADER} / {VERSION_HEADER} headers")
    for key in sorted(EVENTS):
        schema = EVENTS[key]
        typer.echo(f"  {schema.pair:<24} {schema.destination:<12} {schema.description}")
        typer.echo(f"      requires: {', '.join(schema.required)}")
        if write is None:
            typer.echo(f"      schema:   {schema.name}.v{schema.version}.json")


@events_app.command("check")
def events_check(
    emitted: Annotated[Path, typer.Argument(help="A JSON payload (or NDJSON file) to validate.")],
) -> None:
    """Validate a recorded payload against its own event's schema.

    The event is read from the document itself (``event``/``schema_version``), so this answers
    the question a receiver asks — "is this the shape I was promised?" — for a payload captured
    from the wire. Exit code 1 on a failure, so a CI job can gate a consumer on it.
    """
    resolved = emitted.expanduser()
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        typer.echo(f"error: cannot read {resolved}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    documents: list[dict[str, object]] = []
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError:
            loaded = None
        if isinstance(loaded, dict):
            documents.append(loaded)
    if not documents:
        for line in stripped.splitlines():
            if line.strip():
                documents.append(json.loads(line))
    problems: list[str] = []
    for document in documents:
        name = str(document.get("event") or "")
        version = str(document.get("schema_version") or "")
        if not name or not version:
            problems.append(
                f"a record carries no event/schema_version: {sorted(document)[:6]}. Every "
                "payload names the event it is and the version of that event's shape"
            )
            continue
        try:
            from arachne.api.webhook_schemas import require_event

            schema = require_event(name, version)
        except ConfigurationError as exc:
            problems.append(str(exc))
            continue
        problems.extend(f"{schema.pair}: {item}" for item in schema.problems(document))
    if problems:
        for problem in problems:
            typer.echo(f"INVALID: {problem}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"valid: {len(documents)} document(s) match the schema they declare")
