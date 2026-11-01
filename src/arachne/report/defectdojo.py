"""The DefectDojo document — one builder, two delivery paths (S22, REQ-OPS-001).

DefectDojo is the first integration target, so "DefectDojo-first" is a structural
statement rather than a feature list: **one** document builder produces the
``import-scan`` payload, and both delivery paths consume it —

* the webhook path (``webhooks.defectdojo_url``) posts it to
  ``/api/v2/import-scan/`` when a scan completes; and
* ``arachne report --format defectdojo`` renders it as a file, for the offline
  handoff (an operator imports it through DefectDojo's UI or its own tooling, or a
  deployment that cannot egress to DefectDojo still produces the artefact).

Every value comes from the already-redacted report DTO (F-08-04): the document cannot
contain more than the report does. ``close_old_findings`` is set so a re-import of the
same target retires findings the latest scan no longer reports — the same semantics the
diff's ``fixed`` state reports, expressed in DefectDojo's model.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from arachne.report.model import ReportData

__all__ = ["DEFECTDOJO_SCAN_TYPE", "defectdojo_document", "render_defectdojo"]

#: The scan type the DefectDojo generic parser registers for ARACHNE imports.
DEFECTDOJO_SCAN_TYPE: Final = "ARACHNE Scan"


def defectdojo_document(report: ReportData) -> dict[str, Any]:
    """The DefectDojo ``import-scan`` body for ``report``.

    One builder, one source: the report DTO alone. The webhook import and the
    ``--format defectdojo`` file are therefore byte-equal documents. The field names
    are DefectDojo's own (the generic parser's finding schema): a drift here is a
    contract break, and ``tests/unit/test_integrations_contracts.py`` pins it against
    the recorded payload shape.
    """
    findings: list[dict[str, Any]] = []
    scan_date = (report.cover.generated_at or datetime.now(UTC)).date().isoformat()
    for finding in report.findings:
        findings.append(
            _finding_document(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description or finding.remediation.summary,
                    "remediation": finding.remediation.summary,
                    "remediation_id": finding.remediation.id,
                    "cwe": finding.classification.cwe,
                    "cve": finding.classification.cve,
                    "references": tuple(finding.remediation.references),
                    "module": finding.module,
                    "check_id": finding.check_id,
                    "asset": finding.asset.value,
                    "status": finding.status,
                },
                scan_date,
            )
        )
    return {
        "scan_type": DEFECTDOJO_SCAN_TYPE,
        "engagement_name": f"ARACHNE · {report.target_name}",
        "product_name": report.target_name,
        "scan_date": scan_date,
        "minimum_severity": "Info",
        "active": True,
        "verified": False,
        "close_old_findings": True,
        "findings": findings,
    }


def _finding_document(item: Mapping[str, Any], scan_date: str) -> dict[str, Any]:
    severity = str(item.get("severity") or "info")
    remediation = str(item.get("remediation") or "")
    references = item.get("references") or ()
    return {
        "title": str(item.get("title") or ""),
        "severity": severity.capitalize() if severity else "Info",
        "description": str(item.get("description") or remediation or item.get("title") or ""),
        "mitigation": remediation,
        "date": scan_date,
        "cwe": _cwe_number(item.get("cwe")),
        "references": [str(reference) for reference in references],
        "active": item.get("status") != "fp",
        "verified": item.get("status") == "verified",
        "false_p": item.get("status") == "fp",
        "unique_id_from_tool": str(item.get("id") or ""),
        "file_path": str(item.get("asset") or ""),
        "severity_justification": str(item.get("remediation_id") or ""),
        "component_name": str(item.get("module") or ""),
        "vuln_id_from_tool": str(item.get("check_id") or ""),
        "tags": [
            str(item.get("module") or "arachne"),
            severity or "info",
        ],
    }


def _cwe_number(value: Any) -> int:
    if isinstance(value, str) and value.upper().startswith("CWE-"):
        digits = value[4:]
        if digits.isdigit():
            return int(digits)
    return 0


def render_defectdojo(report: ReportData) -> str:
    """Render the report as a DefectDojo ``import-scan`` JSON document (REQ-OPS-001)."""
    return json.dumps(defectdojo_document(report), indent=2, ensure_ascii=False, default=str) + "\n"
