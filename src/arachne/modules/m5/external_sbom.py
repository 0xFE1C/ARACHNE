"""The opt-in external scanner path: ingest a report produced out of band (REQ-DET-016).

The native scanner in :mod:`arachne.modules.m5.image` is the default and needs nothing
installed. This module keeps the previous external-scanner path available for deployments
that already run Trivy or Grype, but it **reads their JSON report** rather than executing
them:

* no process is started, so the scanner cannot escape the scope gate or the audit trail;
* no network is used, so an air-gapped deployment can import a report produced elsewhere;
* the report is an operator-supplied file, read through the same bounded reader as the other
  local-artifact checks and never written to.

That is the honest reading of "the external-scanner path remains available and is no longer
the default": the native path always runs, and a configured report is merged into its
findings. A path that executed the tool itself would be a second, unaudited network client.

Supported shapes:

``trivy``
    ``{"Results": [{"Vulnerabilities": [{"VulnerabilityID", "PkgName",
    "InstalledVersion", "FixedVersion", "Severity"}]}]}``. An *SBOM* result (``"Class":
    "lang-pkgs"`` and no ``Vulnerabilities``) contributes nothing, by construction.
``grype``
    ``{"matches": [{"artifact": {"name", "version"}, "vulnerability": {"id", "severity"},
    "fix": {"versions": [...]}}]}``.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

__all__ = ["EXTERNAL_REPORT_TOOLS", "load_external_report"]

#: The tool names whose report shapes this module understands.
EXTERNAL_REPORT_TOOLS: Final[tuple[str, ...]] = ("trivy", "grype")


def load_external_report(
    tool: str | None, path: str | Path | None, *, max_bytes: int = 8_388_608
) -> tuple[list[dict[str, str]], str]:
    """Read one external report; return ``(findings, note)``.

    ``([], reason)`` means the report could not be used and the caller should say so. The
    note never contains report content, only the reason.
    """
    if tool is None or tool not in EXTERNAL_REPORT_TOOLS:
        return [], f"external scanner {tool!r} is not one of {', '.join(EXTERNAL_REPORT_TOOLS)}"
    if path is None or str(path).strip() == "":
        return [], "ARACHNE_M5_SBOM_REPORT names no report file"
    report = Path(str(path)).expanduser()
    try:
        if report.stat().st_size > max_bytes:
            return [], f"the external report is above the {max_bytes}-byte read cap"
        text = report.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except OSError as exc:
        return [], f"the external report could not be read: {exc.strerror or 'unreadable'}"
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [], "the external report is not JSON"
    return _findings(tool, document), ""


def _findings(tool: str, document: Any) -> list[dict[str, str]]:
    if not isinstance(document, Mapping):
        return []
    entries: list[dict[str, str]] = []
    if tool == "trivy":
        results = document.get("Results")
        if isinstance(results, list):
            for result in results:
                if not isinstance(result, Mapping):
                    continue
                vulnerabilities = result.get("Vulnerabilities")
                if not isinstance(vulnerabilities, list):
                    continue
                for item in vulnerabilities:
                    if isinstance(item, Mapping):
                        entries.append(_trivy_entry(item))
    elif tool == "grype":
        matches = document.get("matches")
        if isinstance(matches, list):
            for match in matches:
                if isinstance(match, Mapping):
                    entries.append(_grype_entry(match))
    return [
        entry
        for entry in entries
        if entry.get("package") and entry.get("advisory") and entry.get("installed")
    ]


def _trivy_entry(item: Mapping[str, Any]) -> dict[str, str]:
    return {
        "package": str(item.get("PkgName", "")),
        "installed": str(item.get("InstalledVersion", "")),
        "fixed": str(item.get("FixedVersion", "")),
        "advisory": str(item.get("VulnerabilityID", "")),
        "severity": str(item.get("Severity", "")),
    }


def _grype_entry(match: Mapping[str, Any]) -> dict[str, str]:
    artifact = match.get("artifact")
    vulnerability = match.get("vulnerability")
    fix = match.get("fix")
    if not isinstance(artifact, Mapping) or not isinstance(vulnerability, Mapping):
        return {}
    fixed = fix.get("versions") if isinstance(fix, Mapping) else None
    return {
        "package": str(artifact.get("name", "")),
        "installed": str(artifact.get("version", "")),
        "fixed": str(fixed[0]) if isinstance(fixed, list) and fixed else "",
        "advisory": str(vulnerability.get("id", "")),
        "severity": str(vulnerability.get("severity", "")),
    }
