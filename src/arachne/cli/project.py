"""``arachne project`` — tenants/workspaces for MSSP deployments (F-07-06, S14).

A project declares the addresses its operator may scan and, optionally, the branding its
reports carry. Targets and scans are stored against it, and the API/CLI lists are filtered
by it. The ``default`` workspace always exists (it is created on demand), so a
single-tenant deployment never needs this command.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.data.services import build_services
from arachne.report.branding import load_branding

__all__ = ["project_app"]

project_app = typer.Typer(
    name="project",
    help="Create and inspect tenants/workspaces (F-07-06).",
    no_args_is_help=True,
)


@project_app.command("create")
def create_project(
    slug: Annotated[str, typer.Argument(help="URL-safe tenant id (e.g. acme).")],
    name: Annotated[str | None, typer.Option("--name", help="Display name.")] = None,
    description: Annotated[str | None, typer.Option("--description")] = None,
    hosts: Annotated[
        str | None, typer.Option("--scope-hosts", help="Comma-separated hosts.")
    ] = None,
    domains: Annotated[
        str | None, typer.Option("--scope-domains", help="Comma-separated domain suffixes.")
    ] = None,
    networks: Annotated[
        str | None, typer.Option("--scope-networks", help="Comma-separated CIDR ranges.")
    ] = None,
    urls: Annotated[
        str | None, typer.Option("--scope-urls", help="Comma-separated URL prefixes.")
    ] = None,
    exclude_hosts: Annotated[
        str | None, typer.Option("--exclude-hosts", help="Comma-separated excluded hosts.")
    ] = None,
    branding: Annotated[
        Path | None,
        typer.Option("--branding", help="Branding YAML/JSON for this tenant's reports."),
    ] = None,
) -> None:
    """Create a project with its scope and optional white-label branding."""
    scope = _scope_dict(hosts, domains, networks, urls, exclude_hosts)
    brand = load_branding(branding).model_dump() if branding is not None else {}
    services = build_services(get_settings())
    try:
        record = services.projects.create(
            slug, name, description=description, scope=scope, branding=brand
        )
    finally:
        services.close()
    typer.echo(_render(record.to_dict()))


@project_app.command("list")
def list_projects(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List every project (the default workspace is created if absent)."""
    services = build_services(get_settings())
    try:
        services.projects.ensure_default()
        records = [record.to_dict() for record in services.projects.list_projects()]
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(records, indent=2))
        return
    typer.echo(f"{'SLUG':<20} {'NAME':<28} ID")
    for row in records:
        typer.echo(f"{row['slug']:<20} {row['name'][:28]:<28} {row['id']}")


@project_app.command("show")
def show_project(
    reference: Annotated[str, typer.Argument(help="Project slug or id.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show one project, its scope and its branding."""
    services = build_services(get_settings())
    try:
        record = services.projects.resolve(reference)
    finally:
        services.close()
    payload = record.to_dict()
    typer.echo(json.dumps(payload, indent=2) if json_output else _render(payload))


@project_app.command("delete")
def delete_project(
    reference: Annotated[str, typer.Argument(help="Project slug or id.")],
    force: Annotated[bool, typer.Option("--force", help="Do not ask for confirmation.")] = False,
) -> None:
    """Delete a project (its scans become unassigned; the default project is protected)."""
    services = build_services(get_settings())
    try:
        record = services.projects.resolve(reference)
        if not force:
            typer.confirm(f"delete project {record.slug!r}?", abort=True)
        removed = services.projects.delete(record.id)
    finally:
        services.close()
    if not removed:
        raise ArachneError(f"project {reference!r} does not exist")
    typer.echo(f"deleted project {record.slug!r}")


@project_app.command("pii")
def project_pii(
    project: Annotated[str, typer.Option("--project", help="Project slug or id.")],
    enable: Annotated[
        bool, typer.Option("--enable", help="Turn PII masking on for this tenant.")
    ] = False,
    categories: Annotated[
        str | None,
        typer.Option("--categories", help="Comma-separated categories (default: all)."),
    ] = None,
    action: Annotated[str, typer.Option("--action", help="mask | hash | drop.")] = "mask",
    salt: Annotated[
        str | None,
        typer.Option("--salt", help="Salt for action=hash (or set ARACHNE_PII_SALT)."),
    ] = None,
    clear: Annotated[bool, typer.Option("--clear", help="Remove the policy.")] = False,
) -> None:
    """Set (or clear) a tenant's PII policy (S25, REQ-TRUST-006)."""
    if clear and enable:
        msg = "--clear cannot be combined with --enable"
        raise typer.BadParameter(msg)
    settings = get_settings()
    policy: dict[str, Any] | None = None
    if not clear:
        policy = {
            "enabled": enable,
            "categories": [item.strip() for item in (categories or "").split(",") if item.strip()]
            or list(settings.pii.categories),
            "action": action,
        }
        chosen_salt = salt or (
            settings.pii.salt.get_secret_value() if settings.pii.salt is not None else None
        )
        if chosen_salt:
            policy["salt"] = chosen_salt
    services = build_services(settings)
    try:
        record = services.projects.resolve(project, create_default=False)
        try:
            updated = services.projects.set_pii(record.id, policy)
        except ArachneError as exc:
            raise typer.BadParameter(str(exc)) from exc
    finally:
        services.close()
    payload = {
        "project": record.slug,
        "pii": updated.to_dict()["pii"] if updated is not None else None,
    }
    typer.echo(json.dumps(payload, indent=2))


@project_app.command("residency")
def project_residency(
    project: Annotated[str, typer.Option("--project", help="Project slug or id.")],
    region: Annotated[
        str | None, typer.Option("--region", help="The region this tenant's evidence stays in.")
    ] = None,
    clear: Annotated[bool, typer.Option("--clear", help="Remove the pin.")] = False,
) -> None:
    """Pin (or unpin) a tenant's evidence residency (S25, REQ-RESIL-004)."""
    if clear and region:
        msg = "--clear cannot be combined with --region"
        raise typer.BadParameter(msg)
    if not clear and not region:
        msg = "pass --region <name> or --clear"
        raise typer.BadParameter(msg)
    services = build_services(get_settings())
    try:
        deployment_region = services.settings.resilience.region
        record = services.projects.resolve(project, create_default=False)
        updated = services.projects.set_residency(record.id, None if clear else region)
    finally:
        services.close()
    payload = {
        "project": record.slug,
        "residency_region": updated.residency_region if updated is not None else None,
        "deployment_region": deployment_region,
    }
    typer.echo(json.dumps(payload, indent=2))


@project_app.command("locale")
def project_locale(
    project: Annotated[str, typer.Option("--project", help="Project slug or id.")],
    locale: Annotated[
        str | None,
        typer.Option("--locale", help="Report language for this tenant (e.g. fr, en, pt-BR)."),
    ] = None,
    clear: Annotated[bool, typer.Option("--clear", help="Inherit the deployment default.")] = False,
) -> None:
    """Set (or clear) a tenant's default report language (S26, REQ-ECOS-005).

    A tenant that sets one gets its reports in that language by default; a single report can
    still be rendered in another (`arachne report --locale`, `?locale=`). ``--clear`` returns
    the tenant to the deployment default (``ARACHNE_REPORT_LOCALE``). An unknown language is
    accepted here on purpose — the i18n catalogue falls back to English at render time, and
    refusing a tag would make a deployment unable to pre-configure a language it is about to
    ship a catalogue for.
    """
    if clear and locale:
        msg = "--clear cannot be combined with --locale"
        raise typer.BadParameter(msg)
    if not clear and not locale:
        msg = "pass --locale <tag> or --clear"
        raise typer.BadParameter(msg)
    services = build_services(get_settings())
    try:
        deployment_locale = services.settings.report.locale or "(i18n default)"
        record = services.projects.resolve(project, create_default=False)
        try:
            updated = services.projects.set_locale(record.id, None if clear else locale)
        except ArachneError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    finally:
        services.close()
    typer.echo(
        json.dumps(
            {
                "project": record.slug,
                "report_locale": updated.report_locale if updated is not None else None,
                "deployment_locale": deployment_locale,
            },
            indent=2,
        )
    )


def _scope_dict(
    hosts: str | None,
    domains: str | None,
    networks: str | None,
    urls: str | None,
    exclude_hosts: str | None,
) -> dict[str, Any]:
    return {
        "hosts": _csv(hosts),
        "domains": _csv(domains),
        "networks": _csv(networks),
        "url_prefixes": _csv(urls),
        "exclude_hosts": _csv(exclude_hosts),
    }


def _csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _render(payload: dict[str, Any]) -> str:
    lines = [
        f"slug:        {payload['slug']}",
        f"name:        {payload['name']}",
        f"id:          {payload['id']}",
        f"description: {payload.get('description') or '(none)'}",
    ]
    scope = payload.get("scope") or {}
    declared = {key: value for key, value in scope.items() if value}
    lines.append(f"scope:       {declared or '(no project-level restriction)'}")
    brand = payload.get("branding") or {}
    lines.append(f"branding:    {brand or '(none)'}")
    return "\n".join(lines)
