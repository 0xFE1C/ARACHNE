"""Compliance framework maps and per-scan control coverage (S22, REQ-TRUST-001).

Three jobs, one module:

* **The maps are data** (ADR-04). ``templates/compliance/<framework>.yaml`` maps check
  ids onto the controls of CIS Controls v8.1, PCI DSS v4.0, ISO/IEC 27001:2022
  Annex A and NIST CSF 2.0 — the four frameworks area TRUST names. A deployment can
  point :func:`load_compliance_framework` at its own file and add or restyle a
  framework without a code change.
* **The no-dangling-id guarantee.** :func:`load_compliance_framework` validates the
  file's structure (unique control ids, well-formed check ids) and, when a
  ``known_checks`` set is supplied, refuses a check id the catalogue does not know.
  ``tests/unit/test_compliance_map.py`` supplies the shipped catalogue, which is what
  makes "a control can never claim coverage from a typo" a schema test rather than a
  hope.
* **Per-scan coverage.** :func:`compute_framework_coverage` joins a map with what a
  scan actually did — which mapped checks ran, which were withheld, which produced
  confirmed findings — into the :class:`~arachne.report.model.FrameworkCoverage`
  block the renderers and the evidence export speak. Three per-control states:
  ``fail`` (a mapped check found something), ``pass`` (mapped checks ran and found
  nothing), ``gap`` (mapped checks did not run). A framework's own control count is
  carried so the report can state the unmapped remainder explicitly — a framework
  report that silently showed only the controls ARACHNE can speak to would read as
  coverage it does not have.

An unmapped control is not a clean result. Nothing here ever renders a framework as
"compliant" — only per-control states with the reasons and the gaps named.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Final, Literal

import yaml

from arachne.core.errors import ConfigurationError
from arachne.report.model import (
    CheckRun,
    ControlCoverage,
    FrameworkCoverage,
    ReportData,
    ReportFinding,
)

__all__ = [
    "BUNDLED_FRAMEWORKS",
    "COMPLIANCE_RESOURCE_DIR",
    "FRAMEWORK_ALIASES",
    "ComplianceMap",
    "ControlMapping",
    "available_frameworks",
    "canonical_framework",
    "compute_framework_coverage",
    "export_control_evidence",
    "load_compliance_framework",
]

#: Bundled map directory, relative to the ``arachne.templates`` package.
COMPLIANCE_RESOURCE_DIR: Final = "compliance"

#: The frameworks shipped in ``templates/compliance/`` (canonical names).
BUNDLED_FRAMEWORKS: Final = ("cis", "iso27001", "nist-csf", "pci-dss")

#: Accepted spellings per canonical name (the CLI's and the report setting's vocabulary).
FRAMEWORK_ALIASES: Final[dict[str, str]] = {
    "cis": "cis",
    "cis-controls": "cis",
    "cis_v8": "cis",
    "iso27001": "iso27001",
    "iso-27001": "iso27001",
    "iso_27001": "iso27001",
    "nist-csf": "nist-csf",
    "nist_csf": "nist-csf",
    "csf": "nist-csf",
    "pci-dss": "pci-dss",
    "pci_dss": "pci-dss",
    "pcidss": "pci-dss",
}

#: The per-control status vocabulary (also the report schema's enum).
CONTROL_STATUSES: Final = ("pass", "fail", "gap")

# Pattern of a check id as findings and maps write it: ``m3.sqli-oracle``.
_EXPECTED_CHECK = ("m1", "m2", "m3", "m4", "m5", "m6")


@dataclass(frozen=True, slots=True)
class ControlMapping:
    """One control of a framework and the checks that evidence it."""

    id: str
    title: str
    checks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ComplianceMap:
    """A loaded framework map: which checks speak to which controls."""

    framework: str
    name: str
    edition: str
    kind: str
    total_controls: int
    map_version: str
    controls: tuple[ControlMapping, ...]
    source: str

    def by_check(self) -> dict[str, tuple[ControlMapping, ...]]:
        """Check id → the controls it evidences (the finding→control join)."""
        out: dict[str, list[ControlMapping]] = {}
        for control in self.controls:
            for check in control.checks:
                out.setdefault(check, []).append(control)
        return {check: tuple(controls) for check, controls in out.items()}


def canonical_framework(name: str) -> str | None:
    """The canonical framework id for a CLI/report-setting spelling."""
    return FRAMEWORK_ALIASES.get(name.strip().lower())


def available_frameworks() -> tuple[str, ...]:
    """The bundled framework names, in ``BUNDLED_FRAMEWORKS`` order."""
    return BUNDLED_FRAMEWORKS


def load_compliance_framework(
    name: str,
    *,
    path: str | None = None,
    maps_dir: str | None = None,
    known_checks: set[str] | None = None,
) -> ComplianceMap:
    """Load a framework map by name (bundled), a ``maps_dir`` override, or explicit ``path``.

    ``maps_dir`` is the managed-data override (ADR-04): a deployment can ship its own
    ``<framework>.yaml`` and add or restyle frameworks without a code change. With
    ``known_checks``, a ``checks:`` entry outside the set is a :class:`ConfigurationError`
    — the no-dangling-id contract. Report-time loading omits it (a stale map must not
    fail a report); the schema test supplies it.
    """
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"compliance map {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return _parse(text, source=str(resolved), known_checks=known_checks)

    canonical = canonical_framework(name)
    if canonical is None:
        msg = (
            f"unknown compliance framework {name!r}; this build ships "
            f"{', '.join(BUNDLED_FRAMEWORKS)}"
        )
        raise ConfigurationError(msg)

    if maps_dir:
        from pathlib import Path

        for suffix in (".yaml", ".yml"):
            candidate = Path(maps_dir).expanduser() / f"{canonical}{suffix}"
            if candidate.is_file():
                try:
                    text = candidate.read_text(encoding="utf-8")
                except OSError as exc:
                    raise ConfigurationError(f"cannot read {candidate}: {exc}") from exc
                return _parse(text, source=str(candidate), known_checks=known_checks)

    resource = files("arachne.templates").joinpath(COMPLIANCE_RESOURCE_DIR)
    data: dict[str, object] | None = None
    source = ""
    try:
        for item in resource.iterdir():
            if item.name in {f"{canonical}.yaml", f"{canonical}.yml"}:
                data = yaml.safe_load(item.read_text(encoding="utf-8"))
                source = f"{COMPLIANCE_RESOURCE_DIR}/{item.name}"
                break
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled compliance maps are missing: {exc}"
        raise ConfigurationError(msg) from exc
    if data is None:
        msg = f"bundled compliance map for {canonical!r} is missing"
        raise ConfigurationError(msg)  # pragma: no cover - shipped file exists
    return _parse_data(data, source=source, known_checks=known_checks)


# --------------------------------------------------------------------------- parsing
def _parse(text: str, *, source: str, known_checks: set[str] | None) -> ComplianceMap:
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError(f"{source}: expected a mapping")
    return _parse_data(data, source=source, known_checks=known_checks)


def _parse_data(
    data: dict[str, object], *, source: str, known_checks: set[str] | None
) -> ComplianceMap:
    framework = data.get("framework")
    controls = data.get("controls")
    if not isinstance(framework, str) or not framework:
        raise ConfigurationError(f"{source}: `framework` must be a non-empty string")
    if not isinstance(controls, list) or not controls:
        raise ConfigurationError(f"{source}: `controls` must be a non-empty list")
    total = data.get("total_controls")
    if not isinstance(total, int) or total < 1:
        raise ConfigurationError(f"{source}: `total_controls` must be a positive integer")
    if isinstance(data.get("checks"), list):  # a legacy/nested shape is a data mistake
        raise ConfigurationError(f"{source}: `checks` belongs inside each control, not the top")
    seen: set[str] = set()
    parsed: list[ControlMapping] = []
    for entry in controls:
        if not isinstance(entry, dict):
            raise ConfigurationError(f"{source}: each control must be a mapping")
        control_id = entry.get("id")
        title = entry.get("title")
        checks = entry.get("checks")
        if not isinstance(control_id, str) or not control_id:
            raise ConfigurationError(f"{source}: every control needs a non-empty string id")
        if control_id in seen:
            raise ConfigurationError(f"{source}: duplicate control id {control_id!r}")
        seen.add(control_id)
        if not isinstance(title, str) or not title:
            raise ConfigurationError(f"{source}: control {control_id!r} needs a title")
        if not isinstance(checks, list) or not checks:
            raise ConfigurationError(f"{source}: control {control_id!r} needs a checks list")
        known_ids: list[str] = []
        for check in checks:
            if not isinstance(check, str) or not _wellformed_check(check):
                msg = f"{source}: control {control_id!r} has a malformed check id {check!r}"
                raise ConfigurationError(msg)
            if known_checks is not None and check not in known_checks:
                msg = f"{source}: control {control_id!r} maps unknown check {check!r}"
                raise ConfigurationError(msg)
            known_ids.append(check)
        parsed.append(
            ControlMapping(id=control_id, title=title, checks=tuple(known_ids))
        )
    if total < len(parsed):
        msg = (
            f"{source}: total_controls ({total}) is smaller than the mapped control count "
            f"({len(parsed)})"
        )
        raise ConfigurationError(msg)
    return ComplianceMap(
        framework=str(data.get("framework") or framework),
        name=str(data.get("name") or framework),
        edition=str(data.get("edition") or ""),
        kind=str(data.get("kind") or "control"),
        total_controls=total,
        map_version=str(data.get("map_version") or "0"),
        controls=tuple(parsed),
        source=source,
    )


def _wellformed_check(value: str) -> bool:
    """``m<1..6>.<kebab-name>`` — the id form every finding carries."""
    module, _, name = value.partition(".")
    return (
        module in _EXPECTED_CHECK
        and bool(name)
        and name.replace("-", "").isalnum()
        and name == name.lower()
    )


# --------------------------------------------------------------------------- coverage
def compute_framework_coverage(
    map_data: ComplianceMap,
    checks: Sequence[CheckRun],
    findings: Sequence[ReportFinding],
) -> FrameworkCoverage:
    """Join a framework map with what the scan actually did, per control.

    * **fail** — a confirmed finding from a mapped check. The control is *not*
      operating as intended; the finding ids travel with the row.
    * **pass** — at least one mapped check ran and no mapped check found anything.
    * **gap** — none of the control's mapped checks ran (opt-in withheld, module not
      enabled, target not applicable). The skip reasons are the report's business.
    """
    # The plan's check rows carry (module, bare name); findings carry the qualified
    # `m3.sqli-oracle` id — so the join key is the qualified form (M1 and M2 both ship a
    # `favicon-hash`, which a bare-name join would conflate).
    ran_checks = {
        f"{check.module.lower()}.{check.name}" for check in checks if check.ran
    }
    finding_by_check: dict[str, list[str]] = {}
    evidence_by_check: dict[str, tuple[str, ...]] = {}
    for finding in findings:
        if not finding.check_id:
            continue
        finding_by_check.setdefault(finding.check_id, []).append(finding.id)
        if finding.evidence_refs:
            evidence_by_check[finding.check_id] = tuple(
                {*evidence_by_check.get(finding.check_id, ()), *finding.evidence_refs}
            )

    rows: list[ControlCoverage] = []
    for control in map_data.controls:
        finding_ids: tuple[str, ...] = ()
        ran: list[str] = []
        not_run: list[str] = []
        for check in control.checks:
            hits = finding_by_check.get(check)
            if hits:
                finding_ids = tuple({*finding_ids, *hits})
            if check in ran_checks:
                ran.append(check)
            else:
                not_run.append(check)
        if finding_ids:
            status: Literal["pass", "fail", "gap"] = "fail"
        elif ran:
            status = "pass"
        else:
            status = "gap"
        refs: tuple[str, ...] = ()
        for check in control.checks:
            refs = tuple({*refs, *evidence_by_check.get(check, ())})
        # Sorted like a finding's own refs (and the report's finding ids), so a golden
        # file is stable regardless of the dedup fold's set order.
        rows.append(
            ControlCoverage(
                control=control.id,
                title=control.title,
                status=status,
                findings=tuple(sorted(finding_ids)),
                checks_run=tuple(ran),
                checks_not_run=tuple(not_run),
                evidence_refs=tuple(sorted(refs)),
            )
        )
    return FrameworkCoverage(
        framework=map_data.framework,
        name=map_data.name,
        edition=map_data.edition,
        kind=map_data.kind,
        total_controls=map_data.total_controls,
        map_version=map_data.map_version,
        controls=tuple(rows),
    )


# --------------------------------------------------------------------------- export
def export_control_evidence(
    map_data: ComplianceMap, report: ReportData, *, generated_at: str | None = None
) -> dict[str, object]:
    """The audit-ready per-control evidence document (REQ-TRUST-001).

    One JSON document, self-contained on purpose: an auditor gets the framework's
    identity, the scan's identity, every assessed control with its state, the failing
    findings **and their evidence payloads** (the same redacted payloads the report
    appendix carries — never more), and the audit-trail summary. Nothing here is
    fetched later: an export that must be re-derived from a live database months later
    is not evidence.

    ``status`` per control is pass/fail/gap exactly as the report renders it, and the
    framework's unmapped remainder is stated in ``coverage`` so the document cannot be
    read as a conformity claim.
    """
    coverage = compute_framework_coverage(map_data, report.scope.checks, report.findings)
    controls: list[dict[str, object]] = []
    for row in coverage.controls:
        finding_docs: list[dict[str, object]] = []
        for finding in report.findings:
            if finding.id not in row.findings:
                continue
            evidence: list[dict[str, object]] = []
            for ref in finding.evidence_refs:
                entry = report.evidence_by_id(ref)
                if entry is None:
                    continue
                evidence.append(
                    {
                        "id": entry.id,
                        "kind": entry.kind,
                        "summary": entry.summary,
                        "payload": entry.payload,
                        "sha256": entry.sha256,
                        "redacted": entry.redacted,
                        "captured_at": entry.captured_at.isoformat()
                        if entry.captured_at
                        else None,
                    }
                )
            finding_docs.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "asset": finding.asset.value,
                    "check_id": finding.check_id,
                    "cwe": finding.classification.cwe,
                    "cvss": finding.score.cvss_base,
                    "confidence": finding.score.confidence,
                    "description": finding.description,
                    "remediation": finding.remediation.summary,
                    "status": finding.status,
                    "proof": finding.proof.model_dump(mode="json")
                    if finding.proof is not None
                    else None,
                    "evidence": evidence,
                }
            )
        controls.append(
            {
                "control": row.control,
                "title": row.title,
                "status": row.status,
                "checks_run": list(row.checks_run),
                "checks_not_run": list(row.checks_not_run),
                "findings": finding_docs,
            }
        )
    audit = report.appendix.audit
    return {
        "document": "arachne-control-evidence",
        "version": "1.0",
        "generated_at": generated_at,
        "framework": {
            "framework": map_data.framework,
            "name": map_data.name,
            "edition": map_data.edition,
            "kind": map_data.kind,
            "map_version": map_data.map_version,
            "source": map_data.source,
        },
        "scan": {
            "scan_id": report.scan_id,
            "target": report.target_name,
            "engine": report.cover.engine,
            "arachne_version": report.cover.arachne_version,
            "generated_at": report.cover.generated_at.isoformat(),
            "started_at": report.scope.started_at.isoformat() if report.scope.started_at else None,
            "finished_at": report.scope.finished_at.isoformat()
            if report.scope.finished_at
            else None,
            "requested_by": report.scope.requested_by,
            "authorization": report.cover.authorization,
        },
        "coverage": {
            "total_controls": coverage.total_controls,
            "mapped": coverage.mapped,
            "unmapped": coverage.unmapped,
            "fail": coverage.count("fail"),
            "pass": coverage.count("pass"),
            "gap": coverage.count("gap"),
            "note": (
                f"{coverage.mapped} of {coverage.total_controls} {coverage.kind}s mapped to "
                f"ARACHNE's check catalogue; {coverage.unmapped} {coverage.kind}(s) outside it "
                "cannot be assessed by any scan. Technical findings are evidence about a "
                "control's operation, not proof of conformity."
            ),
        },
        "audit": {
            "total_events": audit.total_events,
            "blocked_events": audit.blocked_events,
            "actions": dict(sorted(audit.actions.items())),
            "first_event_at": audit.first_event_at.isoformat() if audit.first_event_at else None,
            "last_event_at": audit.last_event_at.isoformat() if audit.last_event_at else None,
        },
        "controls": controls,
    }
