"""``arachne dr`` — disaster recovery (S25, REQ-RESIL-005) and the HA status view.

``backup``   write a complete, signed DR bundle: every table (findings, evidence, keys'
             provenance, the audit chain), the offloaded evidence objects, the operator's
             encrypted key sidecars and the deployment's non-secret configuration, with the
             RPO/RTO the procedure supports.
``restore``  verify a bundle and load it back, refusing a database that already holds scans
             unless ``--allow-existing`` says the overwrite is intended. It re-measures the
             RTO and prints it, so the documented number has evidence behind it.
``status``   the HA view: the leader leases (which replica holds each singleton job) and the
             queue depth with the replica count the autoscaler's arithmetic wants.
``rehearse`` the whole procedure, unattended (WP-18, REQ-OPS-010): back up, restore into a
             scratch database, compare row counts, verify the restored audit chain, and
             record the measured RTO and RPO — so "the restore works" is a measurement per
             run rather than an assumption. A broken stage names itself and exits non-zero.

The bundle is verified before it is used — signature, artifact digests and per-table row
counts — so a truncated or edited bundle is refused rather than half-restored.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.audit import AuditAction
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.core.signing import build_signer
from arachne.data.services import build_services
from arachne.resil.autoscale import ScaleToZeroPolicy, queue_depth_source
from arachne.resil.backup import create_bundle, read_bundle, restore_bundle
from arachne.resil.migrations import check_expand_only
from arachne.resil.rehearsal import (
    RehearsalError,
    record_rehearsal,
    recorded_runs,
    rehearse,
)

__all__ = ["dr_app"]

dr_app = typer.Typer(
    name="dr",
    help="Disaster recovery: backup, restore and the HA status view.",
    no_args_is_help=True,
)


@dr_app.command("backup")
def dr_backup(
    out: Annotated[Path, typer.Option("--out", help="A fresh directory for the bundle.")],
    key: Annotated[
        list[Path],
        typer.Option("--key", help="An operator key sidecar to include (repeatable)."),
    ] = [],  # noqa: B006 - typer requires a list default for a repeatable option
    rpo_seconds: Annotated[
        int, typer.Option("--rpo-seconds", min=0, help="Recovery point objective.")
    ] = 86400,
    rto_seconds: Annotated[
        int, typer.Option("--rto-seconds", min=0, help="Recovery time objective.")
    ] = 3600,
    no_evidence: Annotated[
        bool, typer.Option("--no-evidence", help="Skip the offloaded evidence objects.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Write a complete, signed DR bundle."""
    settings = get_settings()
    services = build_services(settings)
    try:
        report = create_bundle(
            session_factory=services.session_factory,
            settings=settings,
            out_dir=out,
            signer=build_signer(settings),
            evidence_dir=settings.evidence_dir,
            keys=key,
            rpo_seconds=rpo_seconds,
            rto_seconds=rto_seconds,
            include_evidence=not no_evidence,
        )
        services.auditor.record(
            AuditAction.BACKUP_CREATED,
            target=str(report.directory),
            meta={
                "rows": report.rows,
                "objects": report.evidence_objects,
                "signed": report.signed,
                "rpo_seconds": report.rpo_seconds,
                "rto_seconds": report.rto_seconds,
            },
        )
    except ArachneError as exc:
        services.close()
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    finally:
        services.close()
    payload = report.to_dict()
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(f"bundle written to {report.directory}")
    typer.echo(
        f"  {report.rows} rows across {len(report.tables)} tables, "
        f"{report.evidence_objects} evidence objects ({report.evidence_bytes} bytes)"
    )
    typer.echo(f"  keys: {', '.join(report.keys) or '(none)'}")
    typer.echo(
        f"  RPO {report.rpo_seconds}s, RTO {report.rto_seconds}s, "
        f"signed: {'yes' if report.signed else 'NO KEY'}"
    )
    for note in report.notes:
        typer.echo(f"  note: {note}")


@dr_app.command("restore")
def dr_restore(
    bundle: Annotated[Path, typer.Argument(help="The bundle directory to restore.")],
    allow_existing: Annotated[
        bool,
        typer.Option("--allow-existing", help="Restore over a database that already has scans."),
    ] = False,
    allow_unsigned: Annotated[
        bool, typer.Option("--allow-unsigned", help="Accept a bundle with no signature.")
    ] = False,
    evidence_dir: Annotated[
        Path | None, typer.Option("--evidence-dir", help="Where to unpack evidence objects.")
    ] = None,
    keys_to: Annotated[
        Path | None, typer.Option("--keys-to", help="Where to restore the key sidecars.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Verify a bundle and restore it into this deployment's database."""
    settings = get_settings()
    signer = build_signer(settings)
    services = build_services(settings)
    try:
        verified = read_bundle(
            bundle, signer=signer, require_signature=not allow_unsigned and signer is not None
        )
        report = restore_bundle(
            verified,
            session_factory=services.session_factory,
            engine=services.engine,
            evidence_dir=evidence_dir or settings.evidence_dir,
            restore_keys_to=keys_to,
            allow_existing=allow_existing,
        )
        services.auditor.record(
            AuditAction.BACKUP_RESTORED,
            target=str(bundle),
            meta={
                "rows": report.rows,
                "objects": report.evidence_objects,
                "seconds": round(report.seconds, 3),
            },
        )
    except ArachneError as exc:
        typer.echo(f"REFUSED: {exc}\nnothing was restored", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        services.close()
    payload = report.to_dict()
    payload["rpo_seconds"] = verified.rpo_seconds
    payload["rto_seconds"] = verified.rto_seconds
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(
        f"restored {report.rows} rows across {len(report.tables)} tables in {report.seconds:.1f}s"
    )
    keys = ", ".join(report.keys) or "(none)"
    typer.echo(f"  {report.evidence_objects} evidence objects, keys: {keys}")
    typer.echo(
        f"  measured RTO {report.seconds:.1f}s against a declared {verified.rto_seconds}s; "
        f"RPO of the bundle is {verified.rpo_seconds}s"
    )
    for note in report.notes:
        typer.echo(f"  note: {note}")


@dr_app.command("rehearse")
def dr_rehearse(
    record: Annotated[
        Path,
        typer.Option(
            "--record",
            help="Append one JSON line per run to this file.",
        ),
    ] = Path("var/dr/rehearsals.jsonl"),
    rto_seconds: Annotated[
        int, typer.Option("--rto-seconds", min=0, help="The RTO objective to hold the run to.")
    ] = 3600,
    rpo_seconds: Annotated[
        int, typer.Option("--rpo-seconds", min=0, help="The RPO objective to hold the run to.")
    ] = 86400,
    keep_scratch: Annotated[
        bool, typer.Option("--keep-scratch", help="Keep the bundle and the scratch database.")
    ] = False,
    history: Annotated[
        bool, typer.Option("--history", help="Print the recorded runs instead of rehearsing.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Rehearse the restore into a scratch database and record the measured RTO and RPO."""
    if history:
        runs = recorded_runs(record)
        if json_output:
            typer.echo(json.dumps(list(runs), indent=2))
            return
        if not runs:
            typer.echo(f"no recorded rehearsals in {record}")
            return
        for run in runs:
            typer.echo(
                f"{run.get('finished_at')}  {run.get('verdict')}  "
                f"RTO {run.get('measured_rto_seconds')}s  RPO {run.get('measured_rpo_seconds')}s  "
                f"failed_stage={run.get('failed_stage')}"
            )
        return
    try:
        report = rehearse(
            rto_seconds=rto_seconds, rpo_seconds=rpo_seconds, keep_scratch=keep_scratch
        )
    except RehearsalError as exc:
        typer.echo(f"REFUSED: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    written = record_rehearsal(report, record)
    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
    else:
        for stage in report.stages:
            mark = "ok  " if stage.ok else "FAIL"
            typer.echo(f"  {mark} {stage.name:<12} {stage.seconds:6.2f}s  {stage.detail}")
        typer.echo(report.summary())
        typer.echo(f"recorded in {written}")
    if not report.ok:
        raise typer.Exit(code=1)


@dr_app.command("status")
def dr_status(
    depth: Annotated[
        int | None,
        typer.Option("--depth", help="Override the queue depth (a rehearsal without a queue)."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show the leader leases, the queue depth and the replica count the planner wants."""
    settings = get_settings()
    services = build_services(settings)
    try:
        leases = _leases(services)
        measured = depth if depth is not None else queue_depth_source(services).depth()
        policy = ScaleToZeroPolicy()
        decision = policy.decide(
            measured,
            per_replica=settings.resilience.queue_depth_per_replica,
            min_replicas=settings.resilience.min_replicas,
            max_replicas=settings.resilience.max_replicas,
        )
        migrations = check_expand_only(_migrations_dir())
        payload: dict[str, Any] = {
            "region": settings.resilience.region,
            "airgapped": settings.airgap.enabled,
            "leader_ttl_s": settings.resilience.leader_ttl_s,
            "leases": leases,
            "queue_depth": measured,
            "scaling": decision.to_dict(),
            "head_migration": migrations.to_dict(),
        }
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(f"region:      {payload['region'] or '(none declared)'}")
    typer.echo(f"leader TTL:  {payload['leader_ttl_s']}s")
    for lease in payload["leases"]:
        typer.echo(f"  lease {lease['name']:<18} holder={lease['holder'] or '(free)'}")
    typer.echo(f"queue depth: {payload['queue_depth']}")
    typer.echo(
        f"scan farm:   {payload['scaling']['desired']} replica(s) — {payload['scaling']['reason']}"
    )
    typer.echo(f"head migration: {migrations.summary()}")
    if not migrations.expand_only:
        for finding in migrations.findings:
            typer.echo(f"  [{finding.operation}] {finding.detail}")


def _leases(services: Any) -> list[dict[str, Any]]:
    """Every singleton lease this build knows about, with its current holder.

    The reads never acquire, so reporting the leases cannot steal one from the replica that
    legitimately holds it.
    """
    from arachne.data.leader_store import LeaderElector

    names = ("scheduler", "retention", "integrity-anchor")
    return [LeaderElector(services.session_factory, name=name).state().to_dict() for name in names]


def _migrations_dir() -> Path:
    """Locate ``migrations/`` from the CLI's project root, falling back to the cwd."""
    from arachne.cli.main import PROJECT_ROOT

    candidate = PROJECT_ROOT / "migrations" / "versions"
    return candidate if candidate.is_dir() else Path("migrations") / "versions"
