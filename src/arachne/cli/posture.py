"""``arachne posture`` — continuous exposure management (S23, area POSTURE).

The operator verbs of the continuous mode:

- ``verify-fix <finding-id>`` — the fix-verification loop's front door: a targeted
  re-scan of only the affected checks; the finding auto-closes on verified absence and
  stays open (with the act recorded) when the check still present (REQ-POSTURE-003).
  Exit codes: ``0`` verified and closed, ``1`` still present, ``2`` refused (unknown
  finding, already closed, analyzer-closed status).
- ``reconcile --scan <id>`` — the regression half, runnable on demand: reopen closed
  findings a completed scan of the same target reports again (the scheduler runs the
  same reconciliation after every scheduled scan).
- ``report`` — the estate posture & trend report (REQ-POSTURE-004), executive-facing,
  rendered from stored data only.
- ``cmdb import <file>`` — asset criticality from a CMDB export (CSV/JSON), feeding
  attack-path ranking (REQ-POSTURE-006).
- ``admission-check`` — the admission webhook's evaluation, locally and with zero
  cluster: the staged-rollout rehearsal (risk R-15's "dry-run policy evaluation").
  Exit ``0`` when the objects would be allowed, ``2`` when denied, ``3`` when the mode
  is off.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError, ConfigurationError
from arachne.posture.cmdb import CriticalityEntry, parse_cmdb
from arachne.posture.iac import rules_from_corpus
from arachne.posture.trend import (
    estate_payload,
    render_estate_markdown,
)

__all__ = ["app"]

app = typer.Typer(help="Continuous exposure management (S23).")

cmdb_app = typer.Typer(help="CMDB asset-criticality imports (REQ-POSTURE-006).")
app.add_typer(cmdb_app, name="cmdb")


# ------------------------------------------------------------------ verify-fix
@app.command(name="verify-fix")
def verify_fix_command(
    finding_id: Annotated[int, typer.Argument(help="The finding to re-verify.")],
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable result.")] = False,
) -> None:
    """Targeted re-scan of the affected checks; auto-close on verified absence."""
    from arachne.data.services import build_services
    from arachne.posture.verify import FixVerificationService

    settings = get_settings()
    services = build_services(settings)
    try:
        result = asyncio.run(FixVerificationService(services).verify(finding_id))
    except ArachneError as exc:
        typer.secho(f"verify-fix: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    finally:
        services.close()
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "finding_id": result.finding_id,
                    "outcome": "closed" if result.closed else "still-open",
                    "verification_scan_id": result.verification_scan_id,
                    "original_scan_id": result.original_scan_id,
                    "detail": result.detail,
                },
                indent=2,
            )
        )
    else:
        typer.echo(result.detail)
    raise typer.Exit(code=0 if result.closed else 1)


# ------------------------------------------------------------------ reconcile
@app.command(name="reconcile")
def reconcile_command(
    scan_id: Annotated[int, typer.Option("--scan", help="The completed scan to reconcile.")],
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable result.")] = False,
) -> None:
    """Reopen closed findings this scan reports again (regression → auto-reopen)."""
    from arachne.data.services import build_services
    from arachne.posture.verify import FixVerificationService

    settings = get_settings()
    services = build_services(settings)
    try:
        reopens = FixVerificationService(services).reconcile(scan_id)
    except ArachneError as exc:
        typer.secho(f"reconcile: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    finally:
        services.close()
    if json_output:
        typer.echo(
            json.dumps(
                {
                    "scan_id": scan_id,
                    "reopened": [
                        {
                            "finding_id": item.finding_id,
                            "check": item.check_key,
                            "asset": item.asset_value,
                        }
                        for item in reopens
                    ],
                },
                indent=2,
            ),
        )
    else:
        if not reopens:
            typer.echo(f"scan {scan_id}: no regression to reopen")
        for item in reopens:
            typer.echo(
                f"reopened finding {item.finding_id}: {item.check_key} on {item.asset_value}"
            )
    raise typer.Exit(code=0)


# ------------------------------------------------------------------ report
@app.command(name="report")
def report_command(
    project: Annotated[
        str | None, typer.Option("--project", "-p", help="The estate (project slug).")
    ] = None,
    limit: Annotated[
        int, typer.Option("--limit", min=1, max=50, help="Scans to consider (newest first).")
    ] = 12,
    json_output: Annotated[
        bool, typer.Option("--json", help="JSON payload instead of markdown.")
    ] = False,
) -> None:
    """The estate posture & trend report (drift, trend, fix loop, inventory)."""
    from arachne.data.services import build_services

    settings = get_settings()
    services = build_services(settings)
    try:
        posture = _build_estate(services, project=project, limit=limit)
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(estate_payload(posture), indent=2, sort_keys=True))
    else:
        typer.echo(render_estate_markdown(posture))


def _build_estate(services: Any, *, project: str | None, limit: int) -> Any:
    """Assemble the estate report from stored data (S26: the shared assembler).

    The join itself lives in :func:`arachne.posture.estate.assemble_estate`, so this command and
    the executive dashboard at ``GET /ui/posture`` answer "what is our posture?" from the same
    code rather than from two implementations that drift.
    """
    from arachne.posture.estate import assemble_estate

    project_id: int | None = None
    name = project or "default"
    if project:
        record = services.projects.resolve(project)
        project_id = record.id
        name = record.name
    return assemble_estate(services, project_id=project_id, name=name, limit=limit)


# ------------------------------------------------------------------ cmdb
@cmdb_app.command(name="import")
def cmdb_import_command(
    path: Annotated[
        Path, typer.Argument(exists=True, readable=True, help="CMDB export (CSV or JSON).")
    ],
    source: Annotated[
        str, typer.Option("--source", help="Provenance label recorded with the rows.")
    ] = "import",
) -> None:
    """Import asset criticality (host,tier) — feeds attack-path ranking."""
    from arachne.data.services import build_services

    settings = get_settings()
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text.encode("utf-8")) > settings.posture.cmdb_max_bytes:
        typer.secho(
            "cmdb import: file exceeds ARACHNE_POSTURE_CMDB_MAX_BYTES "
            f"({settings.posture.cmdb_max_bytes})",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    try:
        entries = parse_cmdb(text, source=str(path), max_rows=settings.posture.cmdb_max_rows)
    except ConfigurationError as exc:
        typer.secho(f"cmdb import: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    services = build_services(settings)
    try:
        store = services.posture
        if store is None:
            typer.secho("cmdb import: no posture store wired", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        rows = store.import_criticality(

                CriticalityEntry(
                    host=entry.host,
                    tier=entry.tier,
                    name=entry.name,
                    note=entry.note,
                    source=source,
                )
                for entry in entries

        )
    finally:
        services.close()
    typer.echo(f"imported {rows} criticality row(s) from {path}")


# ------------------------------------------------------------------ admission-check
@app.command(name="admission-check")
def admission_check_command(
    manifests: Annotated[
        list[Path],
        typer.Argument(exists=True, readable=True, help="Manifest files to evaluate."),
    ],
    mode: Annotated[
        str, typer.Option("--mode", help="The admission posture to apply (monitor|enforce|off).")
    ] = "monitor",
    fail_on: Annotated[
        str, typer.Option("--fail-on", help="The enforce threshold (severity).")
    ] = "high",
) -> None:
    """Dry-run the admission decision on local manifests (staged-rollout rehearsal)."""
    from arachne.modules.m5.corpus import load_corpus
    from arachne.posture.admission import (
        AdmissionSettings,
        evaluate_admission_review,
        parse_admission_review,
    )

    settings = get_settings()
    effective = AdmissionSettings(
        mode=mode,
        enforce_namespaces=(*settings.posture.enforce_namespaces, "default")
        if mode == "enforce"
        else settings.posture.enforce_namespaces,
        deny_on=fail_on,
    )
    rules = rules_from_corpus(load_corpus())
    allowed = True
    off = False
    for manifest in manifests:
        for document in _documents_of(manifest):
            review = parse_admission_review(
                {
                    "request": {
                        "uid": f"local:{manifest.name}",
                        "kind": {"kind": str(document.get("kind", ""))},
                        "name": str(
                            document.get("metadata", {}).get("name", manifest.name)
                        ),
                        "namespace": str(
                            document.get("metadata", {}).get("namespace", "default")
                        ),
                        "operation": "CREATE",
                        "object": document,
                    }
                },
                source=str(manifest),
            )
            decision, _response = evaluate_admission_review(review, effective, rules)
            allowed = allowed and decision.allowed
            off = off or decision.mode == "off"
            typer.echo(
                f"{manifest.name}: {decision.mode} → "
                f"{'allow' if decision.allowed else 'deny'}"
                + (f" ({len(decision.violations)} finding(s))" if decision.violations else "")
            )
            for violation in decision.violations:
                typer.echo(f"  - {violation.describe()}")
    if off:
        raise typer.Exit(code=3)
    raise typer.Exit(code=0 if allowed else 2)


def _documents_of(path: Path) -> list[dict[str, Any]]:
    """Parsed YAML/JSON documents of one manifest file (multi-document aware)."""
    import yaml

    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        parsed = [document for document in yaml.safe_load_all(text) if document is not None]
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{path}: not valid YAML: {exc}") from exc
    return [document for document in parsed if isinstance(document, dict)]
