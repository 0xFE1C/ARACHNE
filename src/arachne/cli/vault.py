"""``arachne vault`` — manage the encrypted credential vault (S19, REQ-CREDS-002).

Four operator verbs over the node-local encrypted file:

``put``
    Store (or replace) a credential: its kind, the scope it may be used against, the account
    and the secret. The secret is read from an environment variable or from a prompt — **never
    from the command line**, so it cannot land in a shell history or a process list.
``list``
    The entries this node holds: labels, kinds and scopes. Metadata only.
``show``
    One entry's metadata. The material is never printed; there is no verb that prints it.
``revoke`` / ``remove``
    Revoke in place (the entry survives as a refusal, which is what a report should show) or
    delete the entry and its material outright.

A vault is a property of the node: the commands read ``ARACHNE_VAULT_PATH`` and
``ARACHNE_VAULT_KEY``, and an agent deployed inside a target network manages its own.
"""

from __future__ import annotations

import getpass
import json
import os
from typing import Annotated

import typer

from arachne.core.config import Settings, get_settings
from arachne.core.errors import ArachneError
from arachne.core.vault import CREDENTIAL_KINDS, CredentialScope, FileCredentialVault, build_vault

__all__ = ["vault_app"]

vault_app = typer.Typer(
    name="vault",
    help="Manage the encrypted credential vault.",
    no_args_is_help=True,
)

#: Where ``put`` looks for the secret when ``--secret-env`` does not name another variable.
SECRET_ENV = "ARACHNE_VAULT_SECRET"  # noqa: S105 - an environment variable *name*


def _open_vault(settings: Settings | None = None) -> FileCredentialVault:
    """The deployment's vault, or a clear refusal (never a plaintext fallback)."""
    effective = settings or get_settings()
    try:
        vault = build_vault(effective)
    except ArachneError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    if vault is None:
        typer.secho(
            "no vault is configured: set ARACHNE_VAULT_PATH (the encrypted file) and "
            "ARACHNE_VAULT_KEY (the passphrase) first",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    return vault


def _read_secret(*, secret_env: str | None, prompt: bool) -> str:
    """The secret from an environment variable or an interactive prompt (never argv)."""
    if secret_env:
        value = os.environ.get(secret_env, "")
        if not value:
            typer.secho(
                f"{secret_env} is not set in this environment", fg=typer.colors.RED, err=True
            )
            raise typer.Exit(code=1)
        return value
    value = os.environ.get(SECRET_ENV, "")
    if value:
        return value
    if not prompt:
        typer.secho(
            f"no secret: set {SECRET_ENV} (or pass --secret-env VAR)",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=1)
    return getpass.getpass("credential secret: ")


@vault_app.command("put")
def put_command(
    label: Annotated[str, typer.Argument(help="The label a scan names (letters, digits, . _ -).")],
    username: Annotated[str, typer.Option("--username", help="The account to authenticate as.")],
    kind: Annotated[
        str,
        typer.Option("--kind", help=f"Credential kind: {', '.join(CREDENTIAL_KINDS)}."),
    ] = "web-form",
    scope_host: Annotated[
        list[str] | None,
        typer.Option(
            "--scope-host",
            help="A host (or *.glob) this credential may be used against. Repeatable.",
        ),
    ] = None,
    scope_url: Annotated[
        list[str] | None,
        typer.Option("--scope-url", help="A URL prefix this credential may be used against."),
    ] = None,
    secret_env: Annotated[
        str | None,
        typer.Option(
            "--secret-env", help=f"Environment variable holding the secret ({SECRET_ENV})."
        ),
    ] = None,
    prompt: Annotated[
        bool, typer.Option("--prompt/--no-prompt", help="Ask when the environment has no secret.")
    ] = True,
    login_json: Annotated[
        str | None,
        typer.Option(
            "--login-json",
            help="The login-flow declaration as JSON (url, format, field names, logout_url, ...).",
        ),
    ] = None,
    extra: Annotated[
        list[str] | None,
        typer.Option("--extra", help="An additional field as NAME=VALUE (a SMB domain, say)."),
    ] = None,
) -> None:
    """Store (or replace) one credential, encrypted at rest."""
    vault = _open_vault()
    hosts = tuple(scope_host or ())
    urls = tuple(scope_url or ())
    if not hosts and not urls:
        typer.secho(
            "a credential needs a scope: pass --scope-host and/or --scope-url "
            "(an unscoped credential covers nothing and will be refused everywhere)",
            fg=typer.colors.YELLOW,
            err=True,
        )
    secret = _read_secret(secret_env=secret_env, prompt=prompt)
    if not secret:
        typer.secho("the secret must not be empty", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    declared: dict[str, object] | None = None
    if login_json:
        try:
            parsed = json.loads(login_json)
        except ValueError as exc:
            typer.secho(f"--login-json is not valid JSON: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2) from exc
        if not isinstance(parsed, dict):
            typer.secho("--login-json must be a JSON object", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        declared = parsed
    fields: dict[str, str] = {}
    for item in extra or ():
        name, separator, value = item.partition("=")
        if not separator or not name.strip():
            typer.secho(f"--extra expects NAME=VALUE, got {item!r}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)
        fields[name.strip()] = value
    try:
        entry = vault.put(
            label,
            kind=kind,
            username=username,
            secret=secret,
            scope=CredentialScope(hosts=hosts, url_prefixes=urls),
            extra=fields,
            login=declared,
            created_by=os.environ.get("USER") or None,
        )
    except ArachneError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"stored {entry.label!r} ({entry.kind}) scoped to {entry.scope.describe()} in {vault.path}"
    )


@vault_app.command("list")
def list_command(
    include_revoked: bool = typer.Option(
        False, "--all", help="Include revoked entries (they survive as refusals)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON (metadata only)."),
) -> None:
    """List the credentials this node holds (metadata only — never material)."""
    vault = _open_vault()
    records = vault.records(include_revoked=include_revoked)
    if as_json:
        typer.echo(json.dumps([record.to_dict() for record in records], indent=2))
        return
    if not records:
        typer.echo(f"the vault at {vault.path} holds no credential")
        return
    typer.echo(f"{len(records)} credential(s) in {vault.path}:")
    for record in records:
        state = "revoked" if not record.active else record.kind
        typer.echo(f"  {record.label:<24} {state:<10} {record.scope.describe()}")


@vault_app.command("show")
def show_command(
    label: str = typer.Argument(..., help="The credential label."),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON (metadata only)."),
) -> None:
    """Show one entry's metadata. There is deliberately no verb that prints its secret."""
    vault = _open_vault()
    record = vault.get(label)
    if record is None:
        typer.secho(f"no credential labelled {label!r}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    if as_json:
        typer.echo(json.dumps(record.to_dict(), indent=2))
        return
    typer.echo(f"label:       {record.label}")
    typer.echo(f"kind:        {record.kind}")
    typer.echo(f"scope:       {record.scope.describe()}")
    typer.echo(f"created:     {record.created_at.isoformat()} by {record.created_by or 'unknown'}")
    typer.echo(f"revoked:     {record.revoked_at.isoformat() if record.revoked_at else 'no'}")
    typer.echo(f"login flow:  {'declared' if record.has_login_spec else 'detected from the crawl'}")
    typer.echo("secret:      not shown (the vault never prints material)")


@vault_app.command("revoke")
def revoke_command(label: str = typer.Argument(..., help="The credential label.")) -> None:
    """Revoke an entry in place: it stays visible as a refusal and its material is dropped."""
    vault = _open_vault()
    record = vault.revoke(label)
    if record is None:
        typer.secho(f"no credential labelled {label!r}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"revoked {record.label!r}: a scan that names it now runs unauthenticated")


@vault_app.command("remove")
def remove_command(label: str = typer.Argument(..., help="The credential label.")) -> None:
    """Delete an entry and its material from the vault file."""
    vault = _open_vault()
    if not vault.remove(label):
        typer.secho(f"no credential labelled {label!r}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)
    typer.echo(f"removed {label!r} from {vault.path}")
