"""``arachne plugin`` — list, install and browse check/report-format plugins (F-09-01, S14).

Three verbs:

``list``
    what this interpreter can see — every check module and report format whose ``origin`` is
    not ``builtin``, with the entry point that supplied it.
``install <source>``
    install a plugin from a local path or a git URL, then re-run discovery and print what
    appeared. ``--dry-run`` shows the exact pip command without running it.
``marketplace``
    the versioned catalogue (bundled, or ``--index``/``ARACHNE_MARKETPLACE``), annotated
    with which entries are already installed.

Installing mutates the running environment, so the command ends by telling the operator to
restart long-lived processes (the API server, a scheduler loop) — discovery happens at
process start.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import get_settings
from arachne.data.services import build_services
from arachne.plugins import installed_plugins
from arachne.plugins.installer import install_and_verify
from arachne.plugins.marketplace import load_marketplace
from arachne.plugins.review import DECISION_LISTED

__all__ = ["plugin_app"]

plugin_app = typer.Typer(
    name="plugin",
    help="List, install, review and browse check and report-format plugins (F-09-01, S26).",
    no_args_is_help=True,
)


@plugin_app.command("list")
def list_plugins(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Installed check and report-format plugins (built-ins are not listed)."""
    payload = installed_plugins()
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    checks = payload["checks"]
    formats = payload["report_formats"]
    typer.echo(f"check plugins: {len(checks)}")
    for item in checks:
        typer.echo(
            f"  {item['module']} · {item['title']} v{item['version']} "
            f"(origin {item['origin']}): {', '.join(item['checks'])}"
        )
    typer.echo(f"report-format plugins: {len(formats)}")
    for item in formats:
        typer.echo(f"  {item['name']} ({item['media_type']}, origin {item['origin']})")
    if not checks and not formats:
        typer.echo(
            "no third-party plugins installed; `arachne plugin marketplace` lists candidates"
        )


@plugin_app.command("formats")
def list_formats(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Every report format this build can render (built-ins and plugins)."""
    from arachne.report import default_registry

    summary = default_registry().summary()
    if json_output:
        typer.echo(json.dumps(summary, indent=2))
        return
    typer.echo(f"{'NAME':<16} {'BINARY':<7} {'ORIGIN':<24} MEDIA TYPE")
    for item in summary:
        typer.echo(
            f"{item['name']:<16} {item['binary']!s:<7} {item['origin']:<24} {item['media_type']}"
        )


@plugin_app.command("marketplace")
def marketplace(
    index: Annotated[
        Path | None, typer.Option("--index", help="Catalogue file (default: bundled index).")
    ] = None,
    search: Annotated[str | None, typer.Option("--search", help="Filter by term.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List the plugin catalogue and whether each entry is installed.

    Each entry also carries its review status from the recorded pipeline runs (S26,
    REQ-ECOS-001): ``reviewed`` when a listing verdict exists for these exact bytes,
    ``rejected`` when the newest verdict refuses them, and ``unreviewed`` when nothing has
    been reviewed. Nothing is hidden — the flag is how "listed only after review" is made
    visible rather than enforced by omission.
    """
    settings = get_settings()
    catalogue = load_marketplace(index or settings.plugins.marketplace)
    rows = _with_review_status(catalogue.listing(term=search), settings)
    if json_output:
        typer.echo(json.dumps({**catalogue.to_dict(), "entries": rows}, indent=2))
        return
    typer.echo(
        f"marketplace {catalogue.version or '(unversioned)'} · {catalogue.source} · "
        f"{catalogue.updated or 'no date'}"
    )
    if not rows:
        typer.echo("no matching entries")
        return
    for row in rows:
        flag = "installed" if row["installed"] else "available"
        verified = "verified" if row["verified"] else "unverified"
        typer.echo(
            f"  {row['name']} ({row['kind']}, {row['version'] or '-'}) "
            f"[{flag}, {verified}, review={row['review']}]"
        )
        if row["description"]:
            typer.echo(f"    {row['description']}")
        typer.echo(f"    source: {row['source']}")


def _with_review_status(rows: list[dict[str, Any]], settings: Any) -> list[dict[str, Any]]:
    """Annotate marketplace rows with the recorded review verdict (S26, REQ-ECOS-001).

    The store is opened lazily and a failure to open it (no database configured, a read-only
    checkout) degrades to ``unreviewed`` rather than making the marketplace unreadable: the
    listing is an inventory, and the review flag is an annotation on it.
    """
    states: dict[tuple[str, str], str] = {}
    try:
        services = build_services(settings)
    except Exception:  # pragma: no cover - a deployment with no store configured
        services = None
    try:
        store = getattr(services, "pack_reviews", None) if services is not None else None
        if store is not None:
            for record in store.list_reviews(limit=1000):
                key = (record.name, record.version)
                states.setdefault(key, record.decision)
    finally:
        if services is not None:
            services.close()
    for row in rows:
        decision = states.get((str(row["name"]), str(row["version"])))
        row["review"] = decision or "unreviewed"
        row["reviewed"] = decision == DECISION_LISTED
    return rows


@plugin_app.command("review")
def review_plugin(
    pack: Annotated[Path, typer.Argument(help="The signed content pack (.tar.gz) to review.")],
    publish: Annotated[
        bool,
        typer.Option(
            "--publish", help="Record the verdict in this deployment's provenance store (S26)."
        ),
    ] = False,
    allow_unsigned: Annotated[
        bool, typer.Option("--allow-unsigned", help="Review an unsigned pack (a lab only).")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Run the marketplace review pipeline over a content pack (S26, REQ-ECOS-001).

    The three gates — signature, safety (AST scan + proof-ladder consistency) and parity
    (declared kind/group, and no collision with a built-in check or format) — are reported with
    their reasons. A pack is *listed* only when all three pass. **Nothing is installed here**,
    and the exit code is 2 for a rejection so a CI job can gate on it.
    """
    from arachne.core.signing import build_signer
    from arachne.plugins.review import review_json, review_pack_bytes

    settings = get_settings()
    signer = build_signer(settings)
    try:
        data = pack.expanduser().read_bytes()
    except OSError as exc:
        typer.echo(f"error: cannot read {pack}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    report = review_pack_bytes(
        data,
        signer=signer,
        allow_unsigned=allow_unsigned or settings.plugins.allow_unsigned_packs,
        source=str(pack),
    )
    if publish:
        services = build_services(settings)
        try:
            if services.pack_reviews is not None:
                services.pack_reviews.record(report, reviewed_by=settings.actor)
            services.auditor.record(
                AuditAction.PACK_REVIEWED,
                outcome=AuditOutcome.ALLOWED if report.listed else AuditOutcome.BLOCKED,
                target=report.name,
                reason=(
                    None
                    if report.listed
                    else "; ".join(item.message for item in report.blockers)
                ),
                meta={
                    "version": report.version,
                    "digest": report.digest,
                    "key_id": report.key_id,
                    "decision": report.decision,
                    "gates_passed": [gate.gate for gate in report.gates if gate.passed],
                },
            )
        finally:
            services.close()
    if json_output:
        typer.echo(review_json(report), nl=False)
    else:
        typer.echo(
            f"{report.decision.upper()}: {report.name} {report.version} "
            f"({(report.digest[:16] + '...') if report.digest else 'no digest'})"
        )
        for gate in report.gates:
            mark = "PASS" if gate.passed else "FAIL"
            typer.echo(f"  [{mark}] {gate.gate}: {gate.detail}")
        for finding in report.blockers:
            where = f" ({finding.path}:{finding.line})" if finding.path else ""
            typer.echo(f"    - {finding.code}{where}: {finding.message}", err=True)
        if not publish:
            typer.echo(
                "not recorded; pass --publish to store the verdict in the provenance store"
            )
    raise typer.Exit(code=0 if report.listed else 2)


@plugin_app.command("install")
def install_plugin(
    source: Annotated[str, typer.Argument(help="Local path or git URL.")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the pip command without running it.")
    ] = False,
    target: Annotated[
        Path | None,
        typer.Option("--target", help="Install into this directory instead of the environment."),
    ] = None,
    no_deps: Annotated[
        bool, typer.Option("--no-deps", help="Do not install dependencies (offline demo).")
    ] = False,
    no_build_isolation: Annotated[
        bool,
        typer.Option(
            "--no-build-isolation",
            help=(
                "Build a source plugin with the already-installed backend (needed offline; "
                "the container image ships hatchling/setuptools for this)."
            ),
        ),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Install a plugin and report which checks/formats became discoverable."""
    settings = get_settings()
    extra: list[str] = []
    if no_deps:
        extra.append("--no-deps")
    if no_build_isolation:
        extra.append("--no-build-isolation")
    result, appeared = install_and_verify(
        source,
        target=str(target) if target else None,
        dry_run=dry_run,
        timeout_s=settings.plugins.install_timeout_s,
        extra_args=extra,
    )
    payload: dict[str, Any] = {
        "install": result.to_dict(),
        "appeared": appeared,
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    if not result.executed:
        typer.echo("dry run; would execute:")
        typer.echo(f"  {result.stdout}")
        return
    typer.echo(f"installed {result.request.source} ({result.request.kind})")
    checks = appeared["checks"]
    formats = appeared["report_formats"]
    for item in checks:
        typer.echo(f"  + module {item['module']} ({item['origin']}): {', '.join(item['checks'])}")
    for item in formats:
        typer.echo(f"  + report format {item['name']} ({item['media_type']})")
    if not checks and not formats:
        typer.echo(
            "  no new check or report format appeared (a provider plugin may still be active)"
        )
    typer.echo("restart long-lived processes (arachne serve, a scheduler) to pick the plugin up")
