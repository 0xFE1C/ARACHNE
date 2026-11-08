"""``arachne plugin`` — list, install and browse check/report-format plugins (F-09-01, S14).

The verbs, in the order an author meets them:

``new-check <id>``
    scaffold a check, its test, its mapping entry, a positive fixture, a decoy fixture and a
    docs stub (REQ-ECOS-007) — the paved road from an empty directory to a green run;
``conform <manifest>``
    run the conformance kit over a candidate: the four refusal reasons a check has to clear
    before it can be merged (REQ-ECOS-007);
``list``
    what this interpreter can see — every check module and report format whose ``origin`` is
    not ``builtin``, with the entry point that supplied it.
``install <source>``
    install a plugin from a local path or a git URL, then re-run discovery and print what
    appeared. ``--dry-run`` shows the exact pip command without running it; ``--entry``
    resolves the source from the marketplace index instead, after that index and the pack it
    points at have been signature-verified (REQ-ECOS-008).
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
from arachne.core.errors import ConfigurationError
from arachne.core.signing import build_content_keyring
from arachne.data.services import build_services
from arachne.plugins import installed_plugins
from arachne.plugins.installer import install_and_verify
from arachne.plugins.marketplace import load_marketplace, require_verified_entry
from arachne.plugins.review import DECISION_LISTED

__all__ = ["plugin_app"]

plugin_app = typer.Typer(
    name="plugin",
    help="List, install, review and browse check and report-format plugins.",
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

    Each entry also carries its review status from the recorded pipeline runs: ``reviewed``
    when a listing verdict exists for these exact bytes, ``rejected`` when the newest verdict
    refuses them, and ``unreviewed`` when nothing has been reviewed. Nothing is hidden — the
    flag is how "listed only after review" is made visible rather than enforced by omission.
    """
    settings = get_settings()
    try:
        catalogue = _load_catalogue(settings, index)
    except ConfigurationError as exc:
        typer.echo(f"REFUSED: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    rows = _with_review_status(catalogue.listing(term=search), settings)
    if json_output:
        typer.echo(json.dumps({**catalogue.to_dict(), "entries": rows}, indent=2))
        return
    trust = {"signed": "signature-verified", "bundled": "bundled (package-trusted)"}.get(
        catalogue.trust, "UNSIGNED (not verified)"
    )
    typer.echo(
        f"marketplace {catalogue.version or '(unversioned)'} · {catalogue.source} · "
        f"{catalogue.updated or 'no date'} · {trust}"
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


def _load_catalogue(settings: Any, index: Path | None) -> Any:
    """Load the marketplace catalogue, fail-closed on its signature (REQ-ECOS-008).

    Every caller goes through here so that no path can read an index this deployment cannot
    verify: the bundled index is package-trusted, a signed one must verify against the content
    key set, and any other unsigned index is refused unless the operator set
    ``ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX`` — the one documented escape hatch.
    """
    return load_marketplace(
        index or settings.plugins.marketplace,
        keyring=build_content_keyring(settings),
        allow_unsigned=settings.plugins.allow_unsigned_index,
    )


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
        typer.Option("--publish", help="Record the verdict in this deployment's provenance store."),
    ] = False,
    allow_unsigned: Annotated[
        bool, typer.Option("--allow-unsigned", help="Review an unsigned pack (a lab only).")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Run the marketplace review pipeline over a content pack.

    The three gates — signature, safety (AST scan + proof-ladder consistency) and parity
    (declared kind/group, and no collision with a built-in check or format) — are reported with
    their reasons. A pack is *listed* only when all three pass. **Nothing is installed here**,
    and the exit code is 2 for a rejection so a CI job can gate on it.
    """
    from arachne.plugins.review import review_json, review_pack_bytes

    settings = get_settings()
    # The accepted key set: a pack signed by either key of a rotation overlap verifies
    # (REQ-ECOS-008), which is what makes re-signing a marketplace an overlap rather than a
    # flag day.
    keyring = build_content_keyring(settings)
    try:
        data = pack.expanduser().read_bytes()
    except OSError as exc:
        typer.echo(f"error: cannot read {pack}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    report = review_pack_bytes(
        data,
        keyring=keyring,
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
                    None if report.listed else "; ".join(item.message for item in report.blockers)
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
            typer.echo("not recorded; pass --publish to store the verdict in the provenance store")
    raise typer.Exit(code=0 if report.listed else 2)


@plugin_app.command("new-check")
def new_check(
    check_id: Annotated[
        str, typer.Argument(help="The check id to scaffold, e.g. m4.header-missing.")
    ],
    out: Annotated[
        Path | None,
        typer.Option("--out", help="Directory to write the plugin package into."),
    ] = None,
    title: Annotated[
        str | None, typer.Option("--title", help="What the check establishes (one line).")
    ] = None,
    framework: Annotated[
        list[str],
        typer.Option(
            "--framework",
            help=(
                "A framework item the check's evidence bears on, repeatable. "
                "Defaults to WSTG-CONF-07 and CWE-693."
            ),
        ),
    ] = [],  # noqa: B006 - typer requires a list default for a repeatable option
    force: Annotated[
        bool, typer.Option("--force", help="Overwrite an existing scaffold tree.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Scaffold a check, its test, its mapping entry, its fixtures and a docs stub.

    The output is a plugin package that is green in place: ``python -m pytest tests`` passes
    inside it with no edit and no install, because the whole point of a paved road is that the
    first thing an author runs tells them the truth about their own work. The four files an
    author must touch are named in the printed list; everything else is wiring.
    """
    from arachne.ecos.sdk import CheckId, scaffold_check
    from arachne.modules.registry import ModuleRegistry

    parsed = CheckId.parse(check_id)
    if parsed.id in ModuleRegistry.builtin().check_ids():
        typer.echo(
            f"error: check id {parsed.id!r} already exists in the built-in catalogue; a plugin "
            "adds checks, it never replaces one — choose a free id",
            err=True,
        )
        raise typer.Exit(code=2)
    destination = out or Path.cwd() / parsed.distribution
    try:
        result = scaffold_check(
            parsed.id,
            root=destination,
            title=title,
            framework=tuple(framework) if framework else ("WSTG-CONF-07", "CWE-693"),
            force=force,
        )
    except ConfigurationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2))
        return
    typer.echo(f"created {parsed.id} in {result.root}")
    for path in sorted(result.files):
        typer.echo(f"  {path.relative_to(result.root)}")
    typer.echo("")
    typer.echo("next:")
    typer.echo(f"  cd {result.root} && python -m pytest tests -q     # green before you edit")
    typer.echo("  edit the marker list in the check, and record the response that made you")
    typer.echo("  write it in fixtures/<name>/positive.json (the decoy must stay clean)")
    typer.echo("  arachne plugin conform conformance.yaml          # before opening a PR")


@plugin_app.command("conform")
def conform_check(
    manifest: Annotated[
        Path, typer.Argument(help="The candidate's conformance.yaml (or its directory).")
    ],
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Run the conformance kit over a candidate check.

    Four defect classes are refusals: no framework mapping, an L2+ declaration without its
    opt-in, no assigned decoy (or one the check fires on), and a finding with no
    verification-relevant evidence. The kit **imports the candidate**, so it scans the source
    first and refuses a check that uses a capability a plugin is not granted without importing
    it at all. The exit code is 2 for a refusal, so a CI job can gate on it.
    """
    from arachne.ecos.conformance import conform, conform_json

    try:
        report = conform(manifest)
    except ConfigurationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if json_output:
        typer.echo(conform_json(report), nl=False)
    else:
        verdict = "CONFORMANT" if report.conformant else "REFUSED"
        typer.echo(f"{verdict}: {report.check} ({report.source})")
        for gate in report.gates:
            mark = "PASS" if gate.passed else "FAIL"
            typer.echo(f"  [{mark}] {gate.gate}: {gate.detail}")
        for defect in report.blockers:
            where = f" ({defect.path}:{defect.line})" if defect.line else ""
            typer.echo(f"    - {defect.code} [{defect.defect_class}]{where}: {defect.message}")
    raise typer.Exit(code=0 if report.conformant else 2)


@plugin_app.command("install")
def install_plugin(
    source: Annotated[
        str | None,
        typer.Argument(help="Local path or git URL (omit it when using --entry)."),
    ] = None,
    entry: Annotated[
        str | None,
        typer.Option(
            "--entry",
            help=(
                "Install the pack a marketplace entry names, after verifying the index and the "
                "pack's signing key. Refuses before downloading anything."
            ),
        ),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print the pip command without running it.")
    ] = False,
    index: Annotated[
        Path | None, typer.Option("--index", help="Catalogue file (default: bundled index).")
    ] = None,
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
    """Install a plugin and report which checks/formats became discoverable.

    With ``--entry`` the source comes from the marketplace index instead of the command line, and
    the index (and the key the pack it points at is signed by) is verified **before** anything is
    downloaded: a compromised index is a trust-redirection document, so an entry from one this
    deployment cannot verify is refused rather than fetched. With a bare ``source`` nothing is
    verified here — installing a local path or a URL is the operator's own decision, and the pack
    is verified when it is reviewed or imported.
    """
    settings = get_settings()
    if entry:
        try:
            catalogue = _load_catalogue(settings, index)
        except ConfigurationError as exc:
            typer.echo(f"REFUSED: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        resolved = catalogue.get(entry)
        if resolved is None:
            typer.echo(
                f"error: no marketplace entry named {entry!r} in {catalogue.source}", err=True
            )
            raise typer.Exit(code=2)
        try:
            require_verified_entry(catalogue, resolved, keyring=build_content_keyring(settings))
        except ConfigurationError as exc:
            typer.echo(f"REFUSED: {exc}", err=True)
            raise typer.Exit(code=2) from exc
        source = resolved.source
    elif not source:
        typer.echo("error: name a source, or use --entry to install from the marketplace", err=True)
        raise typer.Exit(code=2)
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
