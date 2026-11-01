"""SARIF 2.1.0 output for a report (S26, REQ-ECOS-003).

A CI pipeline does not want prose. It wants a document the forge can read and turn into
pull-request annotations: GitHub Code Scanning ingests SARIF directly, and *every* forge
speaks it. This module is the static-analysis half of the delivery surface — the same
:class:`~arachne.report.model.ReportData` every other renderer consumes, emitted as a
SARIF run with one ``result`` per finding.

Three decisions worth stating, because they are where a SARIF emitter usually goes wrong:

* **One rule per check id, results referencing them.** SARIF wants the rule catalogue in
  ``tool.driver.rules`` and results naming a ``ruleId``; repeating the description on every
  result is what makes a code-scanning UI unreadable. Rule order is sorted, and so is the
  result order (severity, then id), so the document is byte-deterministic.
* **``region`` starts at line 1, column 1, on the *asset*.** ARACHNE's findings are about
  network assets, not source lines, so there is no honest line to point at. A SARIF result
  with *no* ``locations`` is dropped by GitHub's uploader, so the asset URI is the location
  and the region is a constant 1:1 — a real, reviewable annotation that does not pretend to
  a line number the scanner never learned. The asset kind rides along in ``properties`` and
  the logical location so a rule can filter on it.
* **The severity ladder maps onto SARIF's three levels**, and the ARACHNE severity is also
  preserved verbatim in ``properties.severity`` so no information is lost to the mapping.

The document is validated in tests against the shipped, minimal SARIF schema
(``templates/report/sarif-schema-2.1.0.json``) — not the full OASIS schema, which is a
megabyte of JSON, but the constraints this emitter actually relies on.
"""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, Final

from arachne.core.errors import ReportError
from arachne.report.model import ReportData, ReportFinding

__all__ = [
    "SARIF_SCHEMA_RESOURCE",
    "SARIF_VERSION",
    "load_sarif_schema",
    "render_sarif",
    "sarif_document",
]

#: The SARIF revision this emitter targets.
SARIF_VERSION: Final = "2.1.0"

#: Bundled minimal schema, relative to ``templates/``.
SARIF_SCHEMA_RESOURCE: Final = ("report", "sarif-schema-2.1.0.json")

#: ARACHNE severity → SARIF result level. SARIF has exactly three; the mapping is lossy on
#: purpose and the original is kept in ``properties.severity``.
_LEVELS: Final[dict[str, str]] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_INFO_URI: Final = "https://github.com/arachne-project/arachne"


def sarif_document(report: ReportData) -> dict[str, Any]:
    """The SARIF 2.1.0 document for ``report`` (deterministic)."""
    rules: dict[str, dict[str, Any]] = {}
    for finding in report.findings:
        rules.setdefault(finding.check_id, _rule(finding))
    ordered_rules = [rules[key] for key in sorted(rules)]
    results = [_result(finding) for finding in _ordered(report.findings)]
    driver: dict[str, Any] = {
        "name": "ARACHNE",
        "informationUri": _INFO_URI,
        "version": _tool_version(report),
        "rules": ordered_rules,
    }
    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
            "sarif-schema-2.1.0.json"
        ),
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": driver},
                "results": results,
                "properties": {
                    "scanId": report.scan_id,
                    "targetName": report.target_name,
                    "schemaVersion": report.schema_version,
                },
            }
        ],
    }


def render_sarif(report: ReportData) -> str:
    """Render ``report`` as deterministic, indented SARIF JSON."""
    return (
        json.dumps(sarif_document(report), indent=2, sort_keys=False, ensure_ascii=False) + "\n"
    )


def load_sarif_schema() -> dict[str, Any]:
    """Load the shipped, minimal SARIF schema this emitter is validated against."""
    resource = files("arachne.templates")
    for part in SARIF_SCHEMA_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled SARIF schema is missing: {exc}"
        raise ReportError(msg) from exc
    schema = json.loads(text)
    if not isinstance(schema, dict):  # pragma: no cover - defended by the file
        msg = "bundled SARIF schema is not an object"
        raise ReportError(msg)
    return schema


# --------------------------------------------------------------------------- internals
def _ordered(findings: tuple[ReportFinding, ...]) -> list[ReportFinding]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda item: (order.get(item.severity, 9), item.id))


def _rule(finding: ReportFinding) -> dict[str, Any]:
    described = bool(finding.description.strip())
    rule: dict[str, Any] = {
        "id": finding.check_id,
        "name": _rule_name(finding.check_id),
        "shortDescription": {"text": finding.title},
    }
    if described:
        rule["fullDescription"] = {"text": finding.description}
    rule["defaultConfiguration"] = {"level": _LEVELS.get(finding.severity, "warning")}
    properties: dict[str, Any] = {
        "module": finding.module,
        "security-severity": _security_severity(finding),
    }
    if finding.classification.cwe:
        properties["cwe"] = finding.classification.cwe
    if finding.research_ref:
        properties["researchRef"] = finding.research_ref
    rule["properties"] = properties
    return rule


def _result(finding: ReportFinding) -> dict[str, Any]:
    asset = finding.asset
    message = finding.title
    if finding.description:
        message = f"{finding.title}: {finding.description}"
    return {
        "ruleId": finding.check_id,
        "level": _LEVELS.get(finding.severity, "warning"),
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _asset_uri(asset.kind, asset.value)},
                    "region": {"startLine": 1, "startColumn": 1},
                },
                "logicalLocations": [
                    {"name": asset.value, "kind": asset.kind, "fullyQualifiedName": asset.value}
                ],
            }
        ],
        "partialFingerprints": {"arachneFinding/v1": f"{finding.check_id}:{asset.value}"},
        "properties": {
            "severity": finding.severity,
            "confidence": finding.score.confidence,
            "status": finding.status,
            "findingId": finding.id,
            "evidenceRefs": list(finding.evidence_refs),
            "assetKind": asset.kind,
        },
    }


def _asset_uri(kind: str, value: str) -> str:
    """A stable, reviewable ``artifactLocation.uri`` for a non-file asset.

    A URI, not a path: the asset is a host or a URL, and a bare ``example.com`` would be
    resolved as a *relative file* by a code-scanning UI. A custom scheme keeps it honest
    and still groups per asset.
    """
    cleaned = value.strip() or "unknown"
    scheme = "asset" if kind not in {"url", "web"} else "url"
    return f"{scheme}://{cleaned}"


def _rule_name(check_id: str) -> str:
    """A camel-case rule *name* (SARIF wants one when ``id`` is kebab-case)."""
    parts = [part for part in check_id.replace(".", "-").split("-") if part]
    if not parts:
        return "check"
    return parts[0] + "".join(part[:1].upper() + part[1:] for part in parts[1:])


def _security_severity(finding: ReportFinding) -> str:
    """GitHub's numeric ``security-severity`` (0.0-10.0), from CVSS when present."""
    if finding.score.cvss_base is not None:
        return f"{finding.score.cvss_base:.1f}"
    fallback = {"critical": "9.0", "high": "7.0", "medium": "5.0", "low": "3.0", "info": "1.0"}
    return fallback.get(finding.severity, "0.0")


def _tool_version(report: ReportData) -> str:
    return report.cover.arachne_version or "0.0.0"
