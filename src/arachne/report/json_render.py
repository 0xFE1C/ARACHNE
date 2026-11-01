"""JSON renderer and the versioned report schema (F-06-02).

The JSON format is the machine/CI view: the *full* :class:`~arachne.report.model.ReportData`
DTO, every finding and every evidence payload, with a stable, versioned schema. Two
properties are deliberate:

* **It is the same DTO the Markdown renderer reads.** There is no second assembly path, so
  the two formats cannot disagree about a severity or an evidence reference.
* **The schema ships as data** (``templates/report/report-schema-1.0.json``) and is the
  versioned contract. ``schema_version`` is both a document field and a constant in the
  schema, so a consumer can accept exactly the version it understands. The schema is
  generated from the pydantic model (``ReportData.model_json_schema()``) and committed;
  ``tests/report_qa`` validates a rendered report against it.

The renderer itself has no third-party dependency: serialisation is ``json.dumps`` over
``model_dump(mode="json")``. Validation is a test/CI concern, so the ``jsonschema`` package
lives in the ``dev`` extra rather than the runtime dependencies.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, Final

from arachne.core.errors import ReportError
from arachne.report.model import REPORT_SCHEMA_VERSION, ReportData

__all__ = [
    "REPORT_SCHEMA_RESOURCE",
    "load_report_schema",
    "render_json",
    "report_payload",
]

REPORT_SCHEMA_RESOURCE: Final = ("report", f"report-schema-{REPORT_SCHEMA_VERSION}.json")


def report_payload(report: ReportData) -> dict[str, Any]:
    """The JSON-ready document (tuples become lists, datetimes ISO-8601)."""
    return report.model_dump(mode="json")


def render_json(report: ReportData) -> str:
    """Render ``report`` as deterministic, indented JSON."""
    return (
        json.dumps(
            report_payload(report), indent=2, sort_keys=False, ensure_ascii=False, default=str
        )
        + "\n"
    )


def load_report_schema() -> dict[str, Any]:
    """Load the shipped, versioned JSON Schema for the report document."""
    resource = files("arachne.templates")
    for part in REPORT_SCHEMA_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled report schema is missing: {exc}"
        raise ReportError(msg) from exc
    try:
        schema = json.loads(text)
    except json.JSONDecodeError as exc:  # pragma: no cover - shipped file is valid
        msg = f"bundled report schema is not valid JSON: {exc}"
        raise ReportError(msg) from exc
    if not isinstance(schema, dict):  # pragma: no cover - defended by the file
        raise ReportError("bundled report schema is not an object")
    return schema
