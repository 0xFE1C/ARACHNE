"""``arachne`` command-line interface (F-07-01).

``arachne --version``
    print the runtime version
``arachne scan --target FIXTURE [--dry-run|--resume ID]``
    plan a scan, run one, or resume an interrupted one (S2: F-01-03/04/10)
``arachne agent [--name NAME] [--api-url URL --api-key KEY] [--once]``
    run a worker of the scan fleet (S16): register, lease, execute, heartbeat, ack
``arachne db upgrade [REVISION]``
    apply Alembic migrations (``head`` by default)
``arachne db current``
    show the applied revision and whether it is up to date
``arachne fuzz run PLAN``
    run a bounded, attested fuzzing plan (S30, area FUZZ)
``arachne info``
    show effective configuration with secrets redacted
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer
from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from arachne import __version__
from arachne.cli.agent import agent_command
from arachne.cli.ai import ai_app
from arachne.cli.analyze import analyze_command
from arachne.cli.callback import callback_server_command
from arachne.cli.compliance import compliance_app
from arachne.cli.dr import dr_app
from arachne.cli.feeds import feeds_app
from arachne.cli.fix import app as fix_app
from arachne.cli.fp import fp_app
from arachne.cli.fuzz import app as fuzz_app
from arachne.cli.iac import app as iac_app
from arachne.cli.integrity import integrity_app, verify_chain_command
from arachne.cli.intel import intel_app
from arachne.cli.module import coverage_app, module_app
from arachne.cli.observability import metrics_command
from arachne.cli.packs import packs_app
from arachne.cli.plugin import plugin_app
from arachne.cli.posture import app as posture_app
from arachne.cli.project import project_app
from arachne.cli.purple import app as purple_app
from arachne.cli.quality import quality_app
from arachne.cli.reason import reason_app
from arachne.cli.report import report_command
from arachne.cli.retention import retention_app
from arachne.cli.scan import scan_command
from arachne.cli.schedule import schedule_app
from arachne.cli.serve import serve_command
from arachne.cli.simulate import app as simulate_app
from arachne.cli.synthesize import synthesize_app
from arachne.cli.vault import vault_app
from arachne.cli.verify import verify_finding_command
from arachne.core.config import Settings, get_settings
from arachne.core.errors import ArachneError
from arachne.core.logging import configure_logging, get_logger
from arachne.core.tracing import configure_tracing

__all__ = ["app", "run"]

_logger = get_logger("cli")


def _find_project_root() -> Path:
    """Locate the directory holding ``alembic.ini`` and ``migrations/``.

    Candidates, in order: ``ARACHNE_PROJECT_ROOT`` (used by the container image and by
    deployments that ship migrations outside the package), the source tree two levels
    above this file when running from a checkout or an editable install, then the working
    directory. Returns the first that actually contains ``alembic.ini``; falls back to the
    working directory so error messages stay meaningful.
    """
    candidates: list[Path] = []
    from_env = os.environ.get("ARACHNE_PROJECT_ROOT", "").strip()
    if from_env:
        candidates.append(Path(from_env).expanduser())
    candidates.append(Path(__file__).resolve().parents[3])
    candidates.append(Path.cwd())
    candidates.append(Path("/app"))  # the image's WORKDIR

    for candidate in candidates:
        if (candidate / "alembic.ini").is_file():
            return candidate
    return Path.cwd()


PROJECT_ROOT = _find_project_root()

app = typer.Typer(
    name="arachne",
    help="ARACHNE — defensive automated vulnerability detection and reporting.",
    no_args_is_help=True,
    add_completion=False,
)
db_app = typer.Typer(name="db", help="Evidence-store database commands.", no_args_is_help=True)
app.add_typer(ai_app, name="ai")
app.add_typer(db_app, name="db")
app.add_typer(module_app, name="module")
app.add_typer(fp_app, name="fp")
app.add_typer(schedule_app, name="schedule")
app.add_typer(project_app, name="project")
app.add_typer(feeds_app, name="feeds")
app.add_typer(intel_app, name="intel")
app.add_typer(vault_app, name="vault")
app.add_typer(plugin_app, name="plugin")
app.add_typer(retention_app, name="retention")
app.add_typer(compliance_app, name="compliance")
app.add_typer(quality_app, name="quality")
app.add_typer(reason_app, name="reason")
app.add_typer(synthesize_app, name="synthesize")
app.add_typer(posture_app, name="posture")
app.add_typer(purple_app, name="purple")
app.add_typer(iac_app, name="iac")
app.add_typer(integrity_app, name="integrity")
app.add_typer(packs_app, name="packs")
app.add_typer(dr_app, name="dr")
# S27: remediation as code — propose, approve, submit, verify (area FIX).
app.add_typer(fix_app, name="fix")
# S28: simulation & what-if modeling — the estate model, hypothetical states and the
# re-simulation trend (area SIM).
app.add_typer(simulate_app, name="simulate")
app.add_typer(fuzz_app, name="fuzz")
app.command("scan", help="Plan (--dry-run), run, or resume a scan (F-01-03/04/10).")(scan_command)
app.command(
    "verify-chain",
    help="Verify the audit hash chain, the row signatures and the scan seals (S25).",
)(verify_chain_command)
app.command("analyze", help="Analyse a stored scan's candidates with the heuristic engine.")(
    analyze_command
)
# WP-13: re-run one finding's proof and record the outcome (REQ-PROOF-016). Exits non-zero
# when the re-verification is refused, so a script can tell "not answered" from "answered".
app.command(
    "verify-finding",
    help="Re-run the proof behind one finding against the same asset (WP-13, REQ-PROOF-016).",
)(verify_finding_command)
app.command("report", help="Render a stored scan as a Markdown or JSON report (F-06-02).")(
    report_command
)
# `coverage` is registered twice on purpose: as `arachne module coverage` (next to the
# inventory it belongs to) and as top-level `arachne coverage`, which is the name the
# roadmap's G-01 asks for. Since WP-07 the top-level form is a command group: `coverage
# matrix` is the G-01 research-method matrix, `coverage ledger` is the generated framework
# coverage ledger (REQ-DET-001).
app.add_typer(coverage_app, name="coverage")
app.command("serve", help="Serve the REST API and web UI (F-07-02/03, F-08-02).")(serve_command)
app.command(
    "agent",
    help="Run a scan worker of the fleet (S16): register, lease, execute, heartbeat, ack.",
)(agent_command)
app.command(
    "metrics",
    help="Print the Prometheus metrics this deployment would expose (S20, REQ-OPS-003).",
)(metrics_command)
app.command(
    "callback-server",
    help="Run the out-of-band callback service (S15, REQ-PROOF-005): single-use "
    "tokens, hits matched to findings, never dials out.",
)(callback_server_command)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            help="Print the ARACHNE version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
    log_level: Annotated[
        str | None,
        typer.Option("--log-level", help="Override ARACHNE_LOG_LEVEL for this run."),
    ] = None,
) -> None:
    """ARACHNE command-line interface."""
    settings = get_settings()
    configure_logging(log_level or settings.log_level, json_output=settings.log_json)
    if settings.observability.tracing_enabled:
        # Opt-in only, and only when the deployment asked for it: a no-op tracer installed
        # over an injected one would silently discard the spans a caller wanted (S20).
        configure_tracing(settings)


def _alembic_config(database_url: str | None = None) -> Config:
    """Build an Alembic config pointing at the project's migrations."""
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    if database_url:
        config.set_main_option("sqlalchemy.url", database_url)
    return config


def _resolve_database_url(database_url: str | None) -> str:
    return database_url or get_settings().database_url


@db_app.command("upgrade")
def db_upgrade(
    revision: Annotated[str, typer.Argument(help="Target revision (default: head).")] = "head",
    database_url: Annotated[
        str | None, typer.Option("--database-url", help="Override ARACHNE_DATABASE_URL.")
    ] = None,
) -> None:
    """Apply migrations up to REVISION (default: head)."""
    url = _resolve_database_url(database_url)
    typer.echo(f"upgrading {url} to {revision}")
    command.upgrade(_alembic_config(url), revision)
    typer.echo("done")


@db_app.command("downgrade")
def db_downgrade(
    revision: Annotated[str, typer.Argument(help="Target revision (use 'base' for none).")],
    database_url: Annotated[
        str | None, typer.Option("--database-url", help="Override ARACHNE_DATABASE_URL.")
    ] = None,
) -> None:
    """Roll migrations back to REVISION."""
    url = _resolve_database_url(database_url)
    typer.echo(f"downgrading {url} to {revision}")
    command.downgrade(_alembic_config(url), revision)
    typer.echo("done")


@db_app.command("current")
def db_current(
    database_url: Annotated[
        str | None, typer.Option("--database-url", help="Override ARACHNE_DATABASE_URL.")
    ] = None,
) -> None:
    """Show the applied schema revision."""
    url = _resolve_database_url(database_url)
    engine = create_engine(url)
    try:
        with engine.connect() as connection:
            applied = MigrationContext.configure(connection).get_current_revision()
    finally:
        engine.dispose()
    head = ScriptDirectory.from_config(_alembic_config(url)).get_current_head()
    typer.echo(f"database: {url}")
    typer.echo(f"applied revision: {applied or '(none)'}")
    typer.echo(f"head revision:    {head}")
    if applied != head:
        typer.echo("status: out of date — run `arachne db upgrade`")
        raise typer.Exit(code=1)
    typer.echo("status: up to date")


@db_app.command("tables")
def db_tables(
    database_url: Annotated[
        str | None, typer.Option("--database-url", help="Override ARACHNE_DATABASE_URL.")
    ] = None,
) -> None:
    """List the evidence-store tables present in the database."""
    url = _resolve_database_url(database_url)
    engine = create_engine(url)
    try:
        names = sorted(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    for name in names:
        typer.echo(name)


@app.command("info")
def info() -> None:
    """Print effective configuration (no secrets are stored in settings)."""
    settings: Settings = get_settings()
    typer.echo(f"arachne version:   {__version__}")
    typer.echo(f"database url:      {settings.database_url}")
    typer.echo(f"log level/json:    {settings.log_level}/{settings.log_json}")
    typer.echo(f"audit log path:    {settings.audit_log_path or '(not configured)'}")
    typer.echo(
        f"rate limits:       {settings.rate_limit.per_host_rate}/s per host "
        f"(burst {settings.rate_limit.per_host_burst}), "
        f"{settings.rate_limit.global_rate}/s global "
        f"(burst {settings.rate_limit.global_burst})"
    )
    typer.echo(
        "scope:             "
        f"hosts={list(settings.safety.scope.allowed_hosts)} "
        f"domains={list(settings.safety.scope.allowed_domains)} "
        f"excluded={list(settings.safety.scope.excluded_hosts)}"
    )
    typer.echo(
        "url safety:        "
        f"allow_private_ips={settings.safety.policy.allow_private_ips} "
        f"allow_loopback={settings.safety.policy.allow_loopback} "
        f"allow_link_local={settings.safety.policy.allow_link_local}"
    )
    typer.echo(f"redaction enabled: {settings.safety.redaction_enabled}")


def run() -> None:
    """Console-script entry point: translate ARACHNE errors into a clean exit code.

    ``SystemExit`` rather than ``typer.Exit``: the entry point calls ``app()`` directly
    (there is no click-level handler above us), so a click ``Exit`` would surface as an
    uncaught exception with a traceback. ``SystemExit`` is what a shell needs anyway.
    """
    try:
        app()
    except ArachneError as exc:
        typer.echo(f"error: {exc}", err=True)
        _logger.error("cli error", extra={"event": "cli.error", "error": str(exc)})
        raise SystemExit(2) from exc


if __name__ == "__main__":  # pragma: no cover - manual invocation
    run()
