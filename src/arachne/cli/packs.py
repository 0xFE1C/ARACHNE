"""``arachne packs`` — signed offline content packs (S25, REQ-RESIL-001).

The air-gapped workflow, in the order it is performed:

``export``  on a **connected** build: pack the check catalogue, the M6 rules, the CVE index
            (and anything else the operator names) into one signed ``.tar.gz``;
``verify``  anywhere: check a pack's signature and every file digest without installing it —
            the step an operator runs on the machine that will import it, before it is
            trusted;
``import``  on the **air-gapped** estate: verify, unpack into the content directory and
            record the provenance in the ``content_packs`` table. Nothing is installed if
            anything fails to verify (fail closed).
``list``    what this deployment has imported, with the key that signed each pack.

The signature key is ``ARACHNE_INTEGRITY_KEY`` (the same deployment key the tamper-evidence
layer uses). ``--allow-unsigned`` exists for a lab, is refused by default, and is recorded
in the audit trail as the deliberate exception it is.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError, ContentPackError
from arachne.core.signing import build_signer
from arachne.data.services import build_services
from arachne.resil.packs import (
    install_pack,
    installed_packs,
    read_pack_file,
    write_pack,
)

__all__ = ["packs_app"]

packs_app = typer.Typer(
    name="packs",
    help="Signed offline content packs for air-gapped deployments (S25, REQ-RESIL-001).",
    no_args_is_help=True,
)


@packs_app.command("export")
def packs_export(
    out: Annotated[Path, typer.Option("--out", help="Where to write the .tar.gz pack.")],
    name: Annotated[str, typer.Option("--name", help="Pack name.")],
    version: Annotated[str, typer.Option("--version", help="Pack version.")],
    content: Annotated[
        Path | None,
        typer.Option(
            "--content",
            help="Root directory of check content (default: the packaged templates).",
        ),
    ] = None,
    rules: Annotated[
        Path | None, typer.Option("--rules", help="Root directory of Sigma rule content.")
    ] = None,
    feeds: Annotated[
        Path | None, typer.Option("--feeds", help="Root directory of feed artefacts.")
    ] = None,
    catalogue: Annotated[
        list[str], typer.Option("--check", help="Extra 'kind=path' roots to include.")
    ] = [],  # noqa: B006 - typer requires a list default for a repeatable option
    notes: Annotated[str | None, typer.Option("--notes", help="Free-form provenance note.")] = (
        None
    ),
    pack_kind: Annotated[
        str | None,
        typer.Option(
            "--pack-kind",
            help=(
                "What the pack is: check | module | report-format | provider (S26). The review "
                "pipeline's parity gate needs it; without a declaration a pack cannot be listed."
            ),
        ),
    ] = None,
    entry_point_group: Annotated[
        str | None,
        typer.Option(
            "--entry-point-group",
            help=(
                "Where the pack registers (e.g. arachne.modules, arachne.report_formats). Must "
                "agree with --pack-kind (S26)."
            ),
        ),
    ] = None,
    check_id: Annotated[
        list[str],
        typer.Option(
            "--check-id",
            help=(
                "A check id the pack adds, repeatable (S26). Declared ids must not collide with "
                "the built-in catalogue: declaring them is what lets the parity gate tell 'adds "
                "a check' from 'replaces one'."
            ),
        ),
    ] = [],  # noqa: B006 - typer requires a list default for a repeatable option
    format_name: Annotated[
        list[str],
        typer.Option("--format-name", help="A report format the pack adds, repeatable (S26)."),
    ] = [],  # noqa: B006 - typer requires a list default for a repeatable option
    unsigned: Annotated[
        bool,
        typer.Option("--unsigned", help="Write a pack with no signature (a lab only)."),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Build a signed content pack from the shipped content (and any named roots).

    ``--pack-kind``/``--entry-point-group``/``--check-id``/``--format-name`` are the pack's
    *declaration of itself* (S26, REQ-ECOS-001). ``arachne plugin review`` reads them for its
    parity gate: a pack that says what it is can be listed, and a pack that claims a built-in
    check id is refused, because that is a substitution rather than an addition. Omit them and
    the pack is still built and signed — it simply cannot pass review, which is the honest
    outcome for a pack that declares no provenance.
    """
    settings = get_settings()
    signer = None if unsigned else build_signer(settings)
    if signer is None and not unsigned:
        typer.echo(
            "error: no content key is configured; set ARACHNE_INTEGRITY_KEY "
            "(or pass --unsigned for a lab pack, which an importer will refuse by default)",
            err=True,
        )
        raise typer.Exit(code=2)
    roots = _default_roots(content, rules, feeds, catalogue)
    if not roots:
        typer.echo("error: no content roots found to pack", err=True)
        raise typer.Exit(code=2)
    meta: dict[str, object] = {"generator_version": _version()}
    if pack_kind:
        meta["kind"] = pack_kind.strip()
    if entry_point_group:
        meta["entry_point_group"] = entry_point_group.strip()
    if check_id:
        meta["checks"] = [item.strip() for item in check_id if item.strip()]
    if format_name:
        meta["formats"] = [item.strip() for item in format_name if item.strip()]
    try:
        path, manifest = write_pack(
            out,
            roots,
            name=name,
            version=version,
            signer=signer,
            notes=notes,
            meta=meta,
        )
    except ArachneError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    payload = {
        "pack": str(path),
        "name": manifest.name,
        "version": manifest.version,
        "digest": manifest.digest,
        "files": len(manifest.files),
        "kinds": manifest.kinds(),
        "signed": signer is not None,
        "key_id": signer.key_id if signer else None,
        "roots": {kind_name: str(root) for kind_name, root in roots.items()},
        "declared": {
            "kind": meta.get("kind"),
            "entry_point_group": meta.get("entry_point_group"),
            "checks": meta.get("checks", []),
            "formats": meta.get("formats", []),
        },
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(f"wrote {path}")
    kinds = manifest.kinds()
    typer.echo(f"  {manifest.name} {manifest.version}: {len(manifest.files)} files {kinds}")
    typer.echo(f"  digest {manifest.digest[:16]}…")
    typer.echo("  signature: " + (f"{signer.key_id}" if signer else "NONE (unsigned lab pack)"))
    typer.echo("carry this file to the air-gapped estate and run `arachne packs import` there")


@packs_app.command("verify")
def packs_verify(
    pack: Annotated[Path, typer.Argument(help="The pack to verify (no installation).")],
    allow_unsigned: Annotated[
        bool, typer.Option("--allow-unsigned", help="Accept a pack with no signature.")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Verify a pack's signature and every file digest without installing anything."""
    settings = get_settings()
    signer = build_signer(settings)
    require = settings.airgap.require_signature and not allow_unsigned
    try:
        verified = read_pack_file(pack, signer=signer, require_signature=require)
    except ArachneError as exc:
        typer.echo(f"REFUSED: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    payload = verified.to_dict()
    payload["verified"] = True
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(f"verified {pack}")
    typer.echo(
        f"  {verified.manifest.name} {verified.manifest.version}: "
        f"{len(verified.manifest.files)} files {verified.manifest.kinds()}"
    )
    signer_label = verified.key_id or "nobody"
    typer.echo(f"  digest {verified.manifest.digest[:16]}… signed by {signer_label}")


@packs_app.command("import")
def packs_import(
    pack: Annotated[Path, typer.Argument(help="The pack to import.")],
    allow_unsigned: Annotated[
        bool, typer.Option("--allow-unsigned", help="Accept a pack with no signature.")
    ] = False,
    content_dir: Annotated[
        Path | None, typer.Option("--content-dir", help="Override ARACHNE_CONTENT_DIR.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Verify and install a content pack; nothing is installed when anything fails.

    When the deployment requires review (``ARACHNE_PLUGIN_REQUIRE_REVIEW``, on by default since
    S26), the pack must also have a *listed* verdict recorded for these exact bytes (S26,
    REQ-ECOS-001). Verification alone answers "did the operator sign this?"; the review answers
    "and did the pipeline pass it?". Both are required before content reaches a scan.
    """
    settings = get_settings()
    signer = build_signer(settings)
    require = settings.airgap.require_signature and not allow_unsigned
    services = build_services(settings)
    try:
        verified = read_pack_file(pack, signer=signer, require_signature=require)
        _require_listed_review(services, settings, verified)
        destination = content_dir or settings.content_dir
        result = install_pack(verified, content_dir=destination)
        record = None
        if services.content_packs is not None:
            record = services.content_packs.record(
                name=result.name,
                version=result.version,
                digest=result.digest,
                key_id=result.key_id,
                contents=result.kinds,
                source=str(pack),
                imported_by=settings.actor,
                meta={"unsigned": verified.signature is None},
            )
        services.auditor.record(
            AuditAction.PACK_IMPORTED,
            target=result.name,
            meta={
                "version": result.version,
                "digest": result.digest,
                "key_id": result.key_id,
                "files": len(result.installed),
                "kinds": result.kinds,
                "unsigned": verified.signature is None,
            },
        )
    except ArachneError as exc:
        services.auditor.record(
            AuditAction.PACK_REJECTED,
            outcome=AuditOutcome.BLOCKED,
            target=str(pack),
            reason=str(exc),
        )
        services.close()
        typer.echo(f"REFUSED: {exc}\nnothing was installed", err=True)
        raise typer.Exit(code=1) from exc
    finally:
        services.close()
    payload = result.to_dict()
    payload["provenance_id"] = record.id if record else None
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(f"imported {result.name} {result.version} ({len(result.installed)} files)")
    typer.echo(f"  installed to {result.directory}")
    typer.echo(f"  signed by {result.key_id or 'nobody (unsigned)'}")


@packs_app.command("list")
def packs_list(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List the packs imported into this deployment (from the store and from disk)."""
    settings = get_settings()
    services = build_services(settings)
    try:
        rows = (
            [record.to_dict() for record in services.content_packs.list_packs()]
            if services.content_packs is not None
            else []
        )
        on_disk = [dict(entry) for entry in installed_packs(settings.content_dir)]
    finally:
        services.close()
    payload = {
        "content_dir": str(settings.content_dir),
        "imported": rows,
        "on_disk": on_disk,
    }
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    if not rows and not on_disk:
        typer.echo(f"no content packs imported (content dir: {settings.content_dir})")
        return
    for row in rows:
        typer.echo(
            f"{row['name']} {row['version']:<12} {row['digest'][:16]}… "
            f"key={row['key_id']} files={sum((row['contents'] or {}).values())}"
        )


def _require_listed_review(services: Any, settings: Any, pack: Any) -> None:
    """Refuse a pack that has not passed the review pipeline (S26, REQ-ECOS-001).

    The gate is on the *digest*, so re-signing the same content passes and rebuilding it with
    different content does not: the verdict is about bytes, not about a name. ``require_review``
    off (``ARACHNE_PLUGIN_REQUIRE_REVIEW=false``) is the documented escape hatch for a lab, and
    it is the only way past this — an operator who wants unreviewed content must say so.
    """
    if not settings.plugins.require_review:
        return
    store = getattr(services, "pack_reviews", None)
    if store is None:  # pragma: no cover - a deployment with no provenance store
        return
    manifest = pack.manifest
    if store.is_listed(manifest.name, manifest.version, manifest.digest):
        return
    msg = (
        f"pack {manifest.name} {manifest.version} has no listed review for digest "
        f"{manifest.digest[:16]}...; run `arachne plugin review <pack> --publish` first "
        "(or set ARACHNE_PLUGIN_REQUIRE_REVIEW=false for a lab)"
    )
    raise ContentPackError(msg)


def _default_roots(
    content: Path | None,
    rules: Path | None,
    feeds: Path | None,
    catalogue: list[str],
) -> dict[str, Path]:
    """The ``{kind: directory}`` mapping to pack: named roots win, else the shipped ones."""
    from importlib.resources import files as resource_files

    # ``arachne.templates`` has no ``__init__.py`` (it is a data namespace), so its
    # ``__file__`` is ``None``; ``importlib.resources`` is the accessor that works for both a
    # wheel and a checkout (the same one ``api/app.py`` uses for the web templates).
    templates = Path(str(resource_files("arachne.templates")))
    roots: dict[str, Path] = {}
    if content is not None:
        roots["content"] = content
    else:
        for kind, relative in (
            ("checks", "plan"),
            ("rules", "m6"),
            ("cve", "m2"),
            ("web", "m3"),
            ("cloud", "m5"),
        ):
            candidate = templates / relative
            if candidate.is_dir():
                roots[kind] = candidate
    if rules is not None:
        roots["rules"] = rules
    if feeds is not None:
        roots["feeds"] = feeds
    for entry in catalogue:
        kind, _, raw = entry.partition("=")
        if not raw.strip():
            raise typer.BadParameter(f"--check {entry!r} must be 'kind=path'")
        roots[kind.strip()] = Path(raw.strip()).expanduser()
    return {kind: root for kind, root in roots.items() if root.is_dir()}


def _version() -> str:
    from arachne import __version__

    return __version__
