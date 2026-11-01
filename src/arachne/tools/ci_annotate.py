"""``python -m arachne.tools.ci_annotate`` — the CI delivery-surface entry point (S26).

This is the one command the shipped GitHub Action and GitLab CI component call. It runs
the offline IaC/CI gate over a tree (or reads a pre-computed report) and emits the review
artefacts — GitHub annotations, a GitLab Code Quality report, SARIF, or the gate's own JSON
summary — then exits with the F-07-05 gate code (``0`` clean / ``1`` below threshold /
``2`` at or above) so the pipeline can act on it.

Two properties matter for a CI tool:

* **It is the gate.** The scan is the same local, offline ``repo:`` review ``arachne iac
  gate`` runs (it mirrors that command's request builder exactly), the findings are read
  through the project's own store API, and the verdict comes from :mod:`arachne.cli.ci` —
  never a second implementation of the policy.
* **stdout is the annotation stream.** GitHub renders workflow commands from stdout, so the
  annotations go there and everything a human reads (the summary, errors) goes to stderr.

Usage::

    python -m arachne.tools.ci_annotate --path . --format github --fail-on high
    python -m arachne.tools.ci_annotate --report report.json --format sarif -o report.sarif
    python -m arachne.tools.ci_annotate --path . --format all --output-dir .arachne-ci

Exit code: the gate's (0/1/2). The emitted artefacts never change it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arachne import __version__
from arachne.cli.ci import gate_exit_code, parse_threshold
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.core.target import (
    AuthorizationAttestation,
    EngineName,
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetKind,
    TargetSelector,
)
from arachne.data.api_store import ApiQueryStore
from arachne.data.report_store import SqlAuditReader
from arachne.data.services import ScanServices, build_orchestrator, build_services
from arachne.ecos.ci_gate import (
    DEFAULT_MAX_ANNOTATIONS,
    GateFinding,
    findings_from_report,
    render_github_annotations,
    render_gitlab_code_quality,
    sarif_report,
    severity_counts,
    summary,
)
from arachne.report import build_report_for_scan, module_versions_for, not_run_checks
from arachne.report.model import ReportData

__all__ = ["FORMATS", "RunResult", "emit", "main", "run_gate_scan"]

#: Statuses the gate ignores, matching ``ApiQueryStore.severity_counts`` (F-07-05's input).
_IGNORED_STATUSES = frozenset({"fp", "merged"})

#: The severity ladder, most-severe first (the order a review reads).
_SEVERITIES = ("critical", "high", "medium", "low", "info")

FORMATS = ("github", "gitlab", "sarif", "json", "all")


@dataclass(frozen=True, slots=True)
class RunResult:
    """The annotatable findings, the gate counts, the threshold and the verdict."""

    findings: tuple[GateFinding, ...]
    counts: dict[str, int]
    threshold: str
    exit_code: int
    scan_id: int | None = None


# ------------------------------------------------------------------ the gate scan (mirrors cli/iac)
def _self_attestation(path: Path) -> AuthorizationAttestation:
    """The local-review attestation a CI job's own invocation stands for (mirrors cli/iac)."""
    return AuthorizationAttestation(
        attested_by="arachne iac gate (local pre-deploy review)",
        attested_at=datetime.now(UTC),
        scope_statement=(
            f"Local pre-deploy IaC/CI review of {path}; the scan reads local artifacts only "
            "and makes no network requests."
        ),
        allowed_targets=(f"repo:{path}",),
        authorization_ref=f"iac-gate:{path.name}",
    )


def _scan_request(path: Path) -> ScanRequest:
    """The offline local-review request — identical to ``arachne iac gate``'s (S23)."""
    selector = TargetSelector(kind=TargetKind.CLOUD, value="repo:" + str(path))
    definition = TargetDefinition(
        name=f"iac:{path.name}",
        targets=(selector,),
        attestation=_self_attestation(path),
    )
    options = ScanOptions(
        engine=EngineName.HEURISTIC,
        active_checks=False,
        modules=ModuleSelection(enabled=("M5",)),
        notes="arachne iac gate: local pre-deploy review (offline by construction)",
    )
    return ScanRequest(target=definition, options=options)


def _asset_path(value: str, *, root: Path) -> str:
    """A usable path from a finding asset value (``repo:/abs/path`` → ``relative``)."""
    cleaned = value.strip()
    if cleaned.startswith("repo:"):
        cleaned = cleaned[len("repo:") :]
    if not cleaned:
        return "."
    candidate = Path(cleaned)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(root).as_posix()
        except ValueError:
            return candidate.name or cleaned
    return cleaned


def _location_of(payload: Any) -> str | None:
    """The artefact a check recorded in its evidence payload, if any."""
    if not isinstance(payload, dict):
        return None
    location = payload.get("location")
    if isinstance(location, str) and location.strip():
        return location.strip()
    locations = payload.get("locations")
    if isinstance(locations, (list, tuple)):
        for entry in locations:
            if isinstance(entry, str) and entry.strip():
                return entry.strip()
    return None


def _findings_from_scan(
    services: ScanServices, scan_id: int, *, root: Path
) -> tuple[GateFinding, ...]:
    """The gate's confirmed findings, anchored to their artefact where known.

    The row filter (not ``fp``/``merged``, with a severity) is exactly the one
    ``ApiQueryStore.severity_counts`` applies, so the annotations and the verdict describe
    the same finding set. The artefact path comes from the check's evidence payload when it
    recorded one, and falls back to the finding's asset value otherwise.
    """
    store = ApiQueryStore(services.session_factory)
    findings: list[GateFinding] = []
    for row in store.finding_rows(scan_id=scan_id, limit=10000):
        severity = (row.severity or "").strip().lower()
        if row.status in _IGNORED_STATUSES or not severity:
            continue
        path: str | None = None
        if row.id is not None:
            for evidence in store.evidence_rows(row.id):
                path = _location_of(evidence.get("payload"))
                if path:
                    break
        findings.append(
            GateFinding(
                check_id=row.check_id or "unknown",
                title=row.title,
                severity=severity,
                path=path or _asset_path(row.asset_value or "", root=root),
            )
        )
    return tuple(findings)


def _report_for_scan(services: ScanServices, scan_id: int) -> ReportData:
    """Build the full :class:`ReportData` for a scan (the SARIF emitter's input)."""
    record = services.store.get_scan(scan_id)
    if record is None:  # pragma: no cover - the scan we just ran exists
        raise ArachneError(f"scan {scan_id} vanished before the report was built")
    return build_report_for_scan(
        scan_id=scan_id,
        scans=services.store,
        findings=services.findings,
        analyses=services.analyses,
        audit_events=SqlAuditReader(services.session_factory).events_for_scan(
            scan_id, started_at=record.started_at, finished_at=record.finished_at
        ),
        module_versions=module_versions_for(services.registry, record.plan),
        arachne_version=__version__,
        settings=services.settings,
        generated_at=record.finished_at or record.created_at or datetime.now(UTC),
        not_run_checks=not_run_checks(
            services.registry, services.findings.list_candidates(scan_id)
        ),
    )


def run_gate_scan(
    path: Path, *, threshold: str = "high", with_report: bool = False
) -> tuple[RunResult, ReportData | None]:
    """Run the offline IaC gate over ``path``; return findings, counts, verdict and report.

    ``with_report`` additionally builds the full report document (needed only for SARIF),
    within the same services block so nothing is reopened.
    """
    root = path.expanduser().resolve()
    services = build_services(get_settings())
    try:
        orchestrator = build_orchestrator(services)
        session = asyncio.run(orchestrator.scan(_scan_request(root)))
        scan_id = session.scan_id
        assert scan_id is not None
        findings = _findings_from_scan(services, scan_id, root=root)
        report = _report_for_scan(services, scan_id) if with_report else None
    finally:
        services.close()
    counts = severity_counts(findings)
    result = RunResult(
        findings=findings,
        counts=counts,
        threshold=threshold,
        exit_code=gate_exit_code(counts, threshold),
        scan_id=scan_id,
    )
    return result, report


def _result_from_report(report: ReportData, threshold: str) -> RunResult:
    """The gate verdict for a pre-computed report (counts from its findings)."""
    findings = findings_from_report(report)
    counts = {
        severity: sum(1 for item in findings if item.severity == severity)
        for severity in _SEVERITIES
    }
    return RunResult(
        findings=findings,
        counts=counts,
        threshold=threshold,
        exit_code=gate_exit_code(counts, threshold),
    )


# ------------------------------------------------------------------ emission
def emit(
    fmt: str,
    result: RunResult,
    *,
    max_annotations: int = DEFAULT_MAX_ANNOTATIONS,
    report: ReportData | None = None,
) -> str:
    """Render one artefact (``github``/``gitlab``/``sarif``/``json``) for ``result``."""
    if fmt == "github":
        return render_github_annotations(
            result.findings,
            severity_threshold=result.threshold,
            max_annotations=max_annotations,
        )
    if fmt == "gitlab":
        return render_gitlab_code_quality(result.findings)
    if fmt == "sarif":
        if report is None:
            raise ArachneError("SARIF output needs a report; use --path or --report")
        return sarif_report(report)
    if fmt == "json":
        return json.dumps(summary(result.counts, result.threshold), indent=2) + "\n"
    raise ArachneError(f"unknown format {fmt!r}")  # pragma: no cover - argparse constrains it


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run_all(
    result: RunResult,
    *,
    max_annotations: int,
    report: ReportData | None,
    output_dir: Path,
) -> list[Path]:
    """Write every artefact into ``output_dir`` and return the paths written."""
    written: list[tuple[Path, str]] = [
        (
            output_dir / "github-annotations.txt",
            emit("github", result, max_annotations=max_annotations),
        ),
        (output_dir / "codequality.json", emit("gitlab", result, max_annotations=max_annotations)),
        (output_dir / "summary.json", emit("json", result, max_annotations=max_annotations)),
    ]
    if report is not None:
        written.append((output_dir / "report.sarif", sarif_report(report)))
    for path, text in written:
        _write(path, text)
    return [path for path, _ in written]


# ------------------------------------------------------------------ CLI
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m arachne.tools.ci_annotate",
        description="Emit CI review artefacts for ARACHNE's IaC gate (REQ-ECOS-003).",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--path", help="IaC/CI tree to review (the offline gate scan).")
    source.add_argument("--report", help="A pre-computed ARACHNE report JSON to read instead.")
    parser.add_argument(
        "--fail-on",
        default="high",
        help="Gate threshold: info|low|medium|high|critical|none (default: high).",
    )
    parser.add_argument(
        "--format",
        default="github",
        choices=FORMATS,
        help="Artefact(s): github (annotations), gitlab (Code Quality), sarif, json, all.",
    )
    parser.add_argument("--output", "-o", help="Write the artefact here (default: stdout).")
    parser.add_argument(
        "--output-dir",
        help="Directory for --format all (default: .arachne-ci).",
    )
    parser.add_argument(
        "--max-annotations",
        type=int,
        default=DEFAULT_MAX_ANNOTATIONS,
        help=f"Cap on GitHub annotations, worst-first (default: {DEFAULT_MAX_ANNOTATIONS}).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the tool; return the gate's exit code (0/1/2)."""
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        threshold = parse_threshold(args.fail_on)
    except ValueError as exc:
        parser.error(str(exc))
        raise AssertionError("unreachable") from exc  # pragma: no cover - parser.error exits

    report: ReportData | None = None
    try:
        if args.report is not None:
            report = ReportData.model_validate(json.loads(Path(args.report).read_text("utf-8")))
            result = _result_from_report(report, threshold)
        else:
            path = Path(args.path)
            if not path.exists():
                sys.stderr.write(f"ci-annotate: path does not exist: {path}\n")
                return 2
            result, report = run_gate_scan(
                path, threshold=threshold, with_report=args.format in {"sarif", "all"}
            )
    except (ArachneError, ValueError) as exc:
        sys.stderr.write(f"ci-annotate: {exc}\n")
        return 2

    if args.format == "all":
        output_dir = Path(args.output_dir or ".arachne-ci")
        written = _run_all(
            result,
            max_annotations=args.max_annotations,
            report=report,
            output_dir=output_dir,
        )
        sys.stderr.write(
            f"ci-annotate: {len(result.findings)} finding(s); threshold {result.threshold}; "
            f"exit {result.exit_code}; wrote " + ", ".join(str(item) for item in written) + "\n"
        )
        return result.exit_code

    rendered = emit(args.format, result, max_annotations=args.max_annotations, report=report)
    if args.output:
        _write(Path(args.output), rendered)
        sys.stderr.write(
            f"ci-annotate: wrote {args.format} to {args.output} "
            f"({len(result.findings)} finding(s); exit {result.exit_code})\n"
        )
    else:
        sys.stdout.write(rendered)
    return result.exit_code


if __name__ == "__main__":  # pragma: no cover - exercised as a CI step / Action entry
    sys.exit(main())
