"""``arachne retention`` — per-project retention, storage quotas and the pruning job (S20).

Four verbs, in the order an operator uses them:

``status``   what each tenant holds and what policy applies to it (plus the quota ratio);
``plan``     what a pruning run *would* delete, per project and per category — read-only;
``prune``    the same plan, applied — but only with ``--apply``. Without it this is ``plan``.
``policy``   set a tenant's retention days, disable retention for a legal hold, or clear it;
``quota``    set or clear a tenant's storage quota.

The dry run is not a flag on a dangerous default: ``prune`` without ``--apply`` deletes
nothing, and the plan is what the operator reads before deciding. Both paths record an audit
line (``retention.planned`` / ``retention.pruned``) with the per-category counts.
"""

from __future__ import annotations

import asyncio
import json
from typing import Annotated, Any

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.data.services import build_retention_pruner, build_services

__all__ = ["retention_app"]

retention_app = typer.Typer(
    name="retention",
    help="Retention policies, storage quotas and the pruning job (S20, REQ-DATA-001/003).",
    no_args_is_help=True,
)


@retention_app.command("status")
def retention_status(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show every project's effective policy and storage usage."""
    services = build_services(get_settings())
    try:
        pruner = build_retention_pruner(services)
        usage = {entry["slug"]: entry for entry in _overview(services)}
        rows = []
        for project_id, slug, policy in pruner.policies():
            record = usage.get(slug, {})
            rows.append(
                {
                    "project": slug,
                    "project_id": project_id,
                    "policy": policy.to_dict(),
                    "used_bytes": record.get("used_bytes", 0),
                    "limit_bytes": record.get("limit_bytes"),
                    "ratio": record.get("ratio", 0.0),
                }
            )
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps({"projects": rows}, indent=2, default=str))
        return
    typer.echo(f"{'project':<20} {'scans':>7} {'findings':>9} {'evidence':>9} {'audit':>7}  used")
    for row in rows:
        policy = row["policy"]
        used = _bytes(row["used_bytes"])
        limit = "none" if row["limit_bytes"] is None else _bytes(row["limit_bytes"])
        marker = " (legal hold)" if not policy["enabled"] else ""
        typer.echo(
            f"{row['project']:<20} {_days(policy['scans_days']):>7} "
            f"{_days(policy['findings_days']):>9} {_days(policy['evidence_days']):>9} "
            f"{_days(policy['audit_days']):>7}  {used} / {limit}{marker}"
        )


@retention_app.command("plan")
def retention_plan(
    project: Annotated[
        str | None, typer.Option("--project", help="Limit to one project (slug or id).")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Report what a pruning run would delete (read-only; records a plan audit line)."""
    report = _run_prune(dry_run=True, project=project)
    _emit(report, json_output)


@retention_app.command("prune")
def retention_prune(
    apply: Annotated[
        bool, typer.Option("--apply", help="Actually delete. Without it this is a dry run.")
    ] = False,
    project: Annotated[
        str | None, typer.Option("--project", help="Limit to one project (slug or id).")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Plan a pruning run; with ``--apply``, carry it out."""
    report = _run_prune(dry_run=not apply, project=project)
    _emit(report, json_output)


@retention_app.command("policy")
def retention_policy(
    project: Annotated[str, typer.Option("--project", help="Project slug or id.")],
    findings_days: Annotated[int | None, typer.Option("--findings-days", min=0)] = None,
    evidence_days: Annotated[int | None, typer.Option("--evidence-days", min=0)] = None,
    scans_days: Annotated[int | None, typer.Option("--scans-days", min=0)] = None,
    audit_days: Annotated[int | None, typer.Option("--audit-days", min=0)] = None,
    hold: Annotated[
        bool, typer.Option("--hold", help="Legal hold: plan and delete nothing for this project.")
    ] = False,
    clear: Annotated[
        bool, typer.Option("--clear", help="Remove the override; inherit the defaults.")
    ] = False,
) -> None:
    """Set a project's retention policy (``0`` days keeps a category for ever)."""
    given = (findings_days, evidence_days, scans_days, audit_days)
    if clear and (hold or any(value is not None for value in given)):
        msg = "--clear cannot be combined with a policy value"
        raise typer.BadParameter(msg)
    services = build_services(get_settings())
    try:
        record = services.projects.resolve(project, create_default=False)
        declared: dict[str, Any] | None
        if clear:
            declared = None
        else:
            current = dict(record.retention or {})
            defaults = services.settings.retention
            declared = {
                "enabled": False if hold else current.get("enabled", True),
                "findings_days": findings_days
                if findings_days is not None
                else current.get("findings_days", defaults.findings_days),
                "evidence_days": evidence_days
                if evidence_days is not None
                else current.get("evidence_days", defaults.evidence_days),
                "scans_days": scans_days
                if scans_days is not None
                else current.get("scans_days", defaults.scans_days),
                "audit_days": audit_days
                if audit_days is not None
                else current.get("audit_days", defaults.audit_days),
            }
        try:
            updated = services.projects.set_retention(record.id, declared)
        except ArachneError as exc:
            raise typer.BadParameter(str(exc)) from exc
    finally:
        services.close()
    typer.echo(
        json.dumps(
            {
                "project": record.slug,
                "declared": dict(updated.retention) if updated and updated.retention else None,
            },
            indent=2,
        )
    )


@retention_app.command("quota")
def retention_quota(
    project: Annotated[str, typer.Option("--project", help="Project slug or id.")],
    bytes_limit: Annotated[
        int | None, typer.Option("--bytes", min=0, help="Quota in bytes.")
    ] = None,
    clear: Annotated[bool, typer.Option("--clear", help="Remove the quota.")] = False,
) -> None:
    """Set (or clear) a project's storage quota (REQ-DATA-003)."""
    if clear and bytes_limit is not None:
        msg = "--clear cannot be combined with --bytes"
        raise typer.BadParameter(msg)
    if not clear and bytes_limit is None:
        msg = "pass --bytes <n> or --clear"
        raise typer.BadParameter(msg)
    services = build_services(get_settings())
    try:
        record = services.projects.resolve(project, create_default=False)
        limit = None if clear else bytes_limit
        services.projects.set_quota(record.id, limit)
        state = services.quota.state(record.id) if services.quota is not None else None
        payload = {
            "project": record.slug,
            "limit_bytes": limit,
            "used_bytes": state.used_bytes if state else 0,
            "ratio": round(state.ratio, 4) if state else 0.0,
        }
    finally:
        services.close()
    typer.echo(json.dumps(payload, indent=2))


# --------------------------------------------------------------------------- helpers
def _run_prune(*, dry_run: bool, project: str | None) -> dict[str, Any]:
    services = build_services(get_settings())
    try:
        pruner = build_retention_pruner(services)
        project_id = None
        if project is not None:
            project_id = services.projects.resolve(project, create_default=False).id
        plan = asyncio.run(pruner.prune(dry_run=dry_run, project_id=project_id))
        return plan.to_dict()
    finally:
        services.close()


def _overview(services: Any) -> tuple[dict[str, Any], ...]:
    quota = getattr(services, "quota", None)
    return quota.overview() if quota is not None else ()


def _emit(report: dict[str, Any], json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(report, indent=2, default=str))
        return
    verb = "would be deleted" if report["dry_run"] else "deleted"
    typer.echo(f"retention {'plan (dry run)' if report['dry_run'] else 'run'}: {verb}")
    totals = report["totals"]
    for category in ("scans", "findings", "evidence", "audit"):
        entry = totals[category]
        if not entry["rows"]:
            continue
        detail = f" (+{entry['cascaded_rows']} cascaded rows)" if entry["cascaded_rows"] else ""
        typer.echo(f"  {category:<9} {entry['rows']:>7} rows{detail}  {_bytes(entry['bytes'])}")
    typer.echo(f"  total     {report['total_rows']:>7} rows  {_bytes(report['total_bytes'])}")
    _emit_pii(report.get("pii") or {}, dry_run=bool(report.get("dry_run")))
    for project in report["projects"]:
        rows = sum(
            entry["rows"] + entry["cascaded_rows"] for entry in project["categories"].values()
        )
        if rows:
            typer.echo(f"    {project['slug']}: {rows} rows")


def _emit_pii(pii: dict[str, Any], *, dry_run: bool) -> None:
    """The re-mask half of a run: counts by category, and what could not be re-masked.

    Printed even when it is zero: "nothing was re-masked" is the answer an operator
    checking a privacy control came for, and omitting the line would leave them guessing
    whether the run looked at it at all (REQ-DATA-005).
    """
    blobs = int(pii.get("blobs") or 0)
    verb = "would be re-masked" if dry_run else "re-masked"
    if blobs:
        categories = ", ".join(
            f"{name} {count}" for name, count in (pii.get("categories") or {}).items()
        )
        typer.echo(f"  pii       {blobs:>7} blob(s) {verb}  ({categories})")
    else:
        typer.echo(f"  pii       {0:>7} blob(s) {verb}")
    unsupported = pii.get("unsupported") or {}
    for reason, count in unsupported.items():
        typer.echo(f"    not re-maskable: {count} blob(s) — {reason}")


def _days(value: int) -> str:
    return "keep" if value == 0 else str(value)


def _bytes(value: int | None) -> str:
    if value is None:
        return "none"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if size < 1024 or unit == "TiB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"  # pragma: no cover - unreachable
