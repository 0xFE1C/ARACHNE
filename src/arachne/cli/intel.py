"""``arachne intel`` — sync feeds, regenerate the CVE baseline, inspect freshness (S18).

Four operator verbs, all offline-capable:

``sync``
    Fetch the configured feeds, verify them against the pinned digests (or detached
    signature), and import what verifies. ``--fixtures DIR`` replays a recording instead of
    contacting anything — the same code path, so an air-gapped deployment can rehearse it.
``status``
    The freshness snapshot the report carries: which feed artefact is active per kind, its
    upstream version, age, TTL and verification state.
``build-index``
    Regenerate the CVE-index baseline from the synced NVD corpus.
``verify``
    Check a file on disk against a pinned digest or signature, without importing it.

``sync --pin`` is the one deliberately trust-on-first-use act: it fetches, records the digests
of what it got into the manifest, and then runs the normal verify-and-import pass against
those pins. Everything after that is fail-closed: a mirror that serves different bytes is
refused and audited (``intel.feed_rejected``), never imported.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.audit import AuditAction, build_auditor
from arachne.core.config import IntelSettings, Settings, get_settings
from arachne.core.errors import ArachneError
from arachne.data.feed_store import FeedStore
from arachne.data.services import build_services
from arachne.intel.freshness import intel_snapshot
from arachne.intel.index_builder import build_baseline, load_product_map, write_baseline
from arachne.intel.sources import source_for
from arachne.intel.sync import SyncOutcome, build_sync_service
from arachne.intel.verify import (
    VerificationPolicy,
    resolve_expectations,
    verify_payload,
)

__all__ = ["intel_app"]

intel_app = typer.Typer(
    name="intel",
    help="Live threat intel: feed sync, CVE-index baseline, freshness (S18).",
    no_args_is_help=True,
)

#: Entries read per query when walking a feed for the index builder (keeps memory bounded on a
#: 300k-row NVD corpus).
_ENTRY_CHUNK = 5000


def _intel_settings(
    settings: Settings, *, fixtures: Path | None, allow_disabled: bool
) -> IntelSettings:
    """Apply the one-off overrides a sync invocation may make."""
    intel = settings.intel
    if fixtures is not None:
        intel = replace(intel, enabled=True, fixtures_dir=str(fixtures))
    elif allow_disabled and not intel.enabled:
        intel = replace(intel, enabled=True)
    return intel


def _source_names(value: str | None, settings: IntelSettings) -> tuple[str, ...]:
    if not value:
        return settings.sources
    names = tuple(item.strip().lower() for item in value.split(",") if item.strip())
    for name in names:
        source_for(name)  # a clear error for a typo, before any service is built
    return names


@intel_app.command("sync")
def sync_command(
    source: Annotated[
        str | None,
        typer.Option("--source", help="Comma-separated sources: nvd, kev, epss (default all)."),
    ] = None,
    fixtures: Annotated[
        Path | None,
        typer.Option("--fixtures", help="Replay recorded responses from this directory."),
    ] = None,
    pin: Annotated[
        bool,
        typer.Option(
            "--pin",
            help="Trust this fetch: record its digests in the manifest, then verify against it.",
        ),
    ] = False,
    checksums: Annotated[
        Path | None,
        typer.Option(
            "--checksums", help="Pin manifest to read/write (default the configured one)."
        ),
    ] = None,
    allow_disabled: Annotated[
        bool,
        typer.Option(
            "--allow-disabled",
            help="Run this one sync even though ARACHNE_INTEL_ENABLED is not set.",
        ),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Fetch, verify and import the configured threat-intel feeds."""
    settings = get_settings()
    intel = _intel_settings(settings, fixtures=fixtures, allow_disabled=allow_disabled)
    names = _source_names(source, intel)
    if checksums is not None:
        intel = replace(intel, checksums_file=str(checksums))
    if pin and intel.checksums_file and not Path(intel.checksums_file).expanduser().is_file():
        # Pinning is how a deployment creates its manifest: an absent one means "nothing
        # pinned yet", not "the configured manifest is missing".
        intel = replace(intel, checksums_file=None)
    services = build_services(settings)
    outcomes: tuple[SyncOutcome, ...] = ()
    pins: dict[str, str] = {}
    manifest_path = _manifest_path(intel, services.feeds, explicit=checksums)
    try:
        service = build_sync_service(
            services.feeds,
            intel,
            auditor=services.auditor,
            imported_by=settings.actor,
        )
        try:
            if pin:
                pins, pinned = asyncio.run(service.fetch_and_pin(names))
                _write_manifest(manifest_path, pins)
                # The run that follows is verified against the manifest just written, which is
                # what makes "--pin" a decision rather than a bypass. A signature deployment
                # keeps its signature policy: pinning records provenance, it does not downgrade
                # the check.
                if service.policy.mode == "checksum":
                    service.policy = VerificationPolicy(mode="checksum", digests=dict(pins))
                outcomes = asyncio.run(service.sync(names)) if pins else pinned
            else:
                outcomes = asyncio.run(service.sync(names))
        finally:
            asyncio.run(service.aclose())
    finally:
        services.close()

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "outcomes": [item.to_dict() for item in outcomes],
                    "pins": pins,
                    "manifest": str(manifest_path) if pin else None,
                },
                indent=2,
            )
        )
    else:
        for item in outcomes:
            typer.echo(_render_outcome(item))
        if pin:
            typer.echo(f"pinned {len(pins)} source digest(s) in {manifest_path}")
    failures = [item for item in outcomes if item.status in {"rejected", "error"}]
    if failures:
        raise typer.Exit(code=1)


@intel_app.command("status")
def status_command(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show feed freshness: the snapshot a report carries, plus provider opt-in state."""
    settings = get_settings()
    services = build_services(settings)
    try:
        snapshot = intel_snapshot(services.feeds, settings=settings)
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(snapshot, indent=2))
        return
    typer.echo(f"intel enabled: {'yes' if settings.intel.enabled else 'no'}")
    typer.echo(f"freshness as of {snapshot['generated_at']}:")
    for feed in snapshot["feeds"]:
        if not feed["imported_at"]:
            typer.echo(f"  {feed['kind']:<5} not ingested")
            continue
        state = "STALE" if feed["stale"] else "fresh"
        verified = "verified" if feed["verified"] else "UNVERIFIED"
        age = feed["age_hours"]
        typer.echo(
            f"  {feed['kind']:<5} {feed['version'] or '-':<28} "
            f"{'n/a' if age is None else f'{age:.1f}h':>8}  {state:<5} {verified:<10} "
            f"{feed['record_count']:>7} row(s)"
        )
    providers = snapshot["providers"]
    typer.echo(f"providers enabled: {', '.join(providers['enabled']) or '(none)'}")
    typer.echo(f"opt-in providers: {', '.join(providers['opted_in']) or '(none)'}")


@intel_app.command("build-index")
def build_index_command(
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", help="Where to write the baseline (default ARACHNE_CVE_INDEX_BASELINE)."
        ),
    ] = None,
    products: Annotated[
        Path | None,
        typer.Option("--products", help="Product map to generate from (default the packaged one)."),
    ] = None,
    max_entries: Annotated[
        int, typer.Option("--max-entries", help="Cap the generated entries.")
    ] = 500,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Regenerate the CVE-index baseline from the synced NVD corpus."""
    settings = get_settings()
    services = build_services(settings)
    try:
        feed = services.feeds.active("nvd")
        if feed is None:
            typer.echo(
                "no NVD corpus is stored; run `arachne intel sync --source nvd` first",
                err=True,
            )
            raise typer.Exit(code=2)
        records = _all_entries(services.feeds, feed.id)
        epss = _scores(services.feeds, "epss")
        kev = _kev_cves(services.feeds)
        index = build_baseline(
            records,
            products=load_product_map(products or settings.intel.index_products),
            epss=epss,
            kev=kev,
            source=f"nvd@{feed.version or 'unknown'}",
            max_entries=max_entries,
        )
        target = _baseline_path(settings, services.feeds, explicit=output)
        written = write_baseline(index, target)
        build_auditor(settings).record(
            AuditAction.INTEL_INDEX_BUILT,
            target=str(written),
            meta={
                "entries": index.count,
                "index_version": index.index_version,
                "source_feeds": {"nvd": feed.id, "epss": bool(epss), "kev": len(kev)},
            },
        )
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps({**index.to_document(), "path": str(written)}, indent=2))
        return
    typer.echo(
        f"wrote {index.count} baseline entr(ies) from nvd feed #{feed.id} "
        f"({feed.version or 'no version'}) -> {written}"
    )


@intel_app.command("verify")
def verify_command(
    path: Annotated[Path, typer.Argument(help="The feed file to verify.")],
    source: Annotated[str, typer.Option("--source", help="nvd | kev | epss.")] = "kev",
    checksums: Annotated[
        Path | None, typer.Option("--checksums", help="Pin manifest (default the configured one).")
    ] = None,
    digest: Annotated[
        str | None,
        typer.Option("--sha256", help="A digest to check against instead of a manifest."),
    ] = None,
    pubkey: Annotated[
        Path | None, typer.Option("--pubkey", help="PEM public key for signature verification.")
    ] = None,
    signature: Annotated[
        Path | None, typer.Option("--signature", help="Detached signature file.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Verify a feed file against pinned digests or a signature, without importing it."""
    settings = get_settings()
    resolved = path.expanduser()
    if not resolved.is_file():
        typer.echo(f"no such file: {resolved}", err=True)
        raise typer.Exit(code=2)
    payload = resolved.read_bytes()
    try:
        if digest:
            policy = VerificationPolicy(mode="checksum", digests={source: digest})
        else:
            pem = None
            if pubkey is not None:
                pem = pubkey.expanduser().read_text(encoding="utf-8")
            mode = "signature" if pem else "checksum"
            policy = VerificationPolicy(
                mode=mode,
                digests=resolve_expectations(
                    manifest=checksums or settings.intel.checksums_file,
                    inline={} if checksums else dict(settings.intel.checksums),
                ),
                public_key_pem=pem,
            )
        result = verify_payload(
            source=source,
            payload=payload,
            policy=policy,
            signature=signature.expanduser().read_bytes() if signature else None,
        )
    except (ArachneError, OSError) as exc:
        typer.echo(f"cannot verify {resolved}: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if json_output:
        typer.echo(json.dumps({"file": str(resolved), **result.to_dict()}, indent=2))
    else:
        typer.echo(f"{resolved}: {result.digest}")
        typer.echo(
            f"  mode {result.mode}: "
            + ("verified" if result.verified else f"REJECTED — {result.reason}")
        )
    if not result.verified:
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- helpers
def _render_outcome(item: SyncOutcome) -> str:
    label = f"{item.source:<5} {item.kind:<5} {item.status:<10}"
    if item.status == "imported":
        return (
            f"{label} {item.version or '-'} -> feed #{item.feed_id} "
            f"({item.record_count} row(s), {item.digest})"
        )
    if item.status in {"unchanged", "pinned"}:
        return f"{label} {item.version or '-'} {item.digest or ''}".rstrip()
    return f"{label} {item.reason or ''}".rstrip()


def _manifest_path(intel: IntelSettings, store: FeedStore, *, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.expanduser()
    if intel.checksums_file:
        return Path(intel.checksums_file).expanduser()
    return store.directory / "intel-checksums.json"


def _baseline_path(settings: Settings, store: FeedStore, *, explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.expanduser()
    if settings.net.cve_index_baseline:
        return Path(settings.net.cve_index_baseline).expanduser()
    return store.directory / "cve-index-baseline.yaml"


def _write_manifest(path: Path, pins: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(sorted(pins.items())), indent=2) + "\n", encoding="utf-8")


def _all_entries(store: FeedStore, feed_id: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        chunk = store.entries(feed_id, limit=_ENTRY_CHUNK, offset=offset)
        rows.extend(chunk)
        if len(chunk) < _ENTRY_CHUNK:
            return rows
        offset += _ENTRY_CHUNK


def _kev_cves(store: FeedStore) -> set[str]:
    """The CVE ids in the active KEV feed (empty when none is stored)."""
    record = store.active("kev")
    if record is None:
        return set()
    return {str(row.get("cve")) for row in _all_entries(store, record.id) if row.get("cve")}


def _scores(store: FeedStore, kind: str) -> dict[str, float]:
    """``{cve: epss}`` from the active feed of ``kind`` (empty when there is none)."""
    record = store.active(kind)
    if record is None:
        return {}
    scores: dict[str, float] = {}
    for row in _all_entries(store, record.id):
        value = row.get("epss")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            scores[str(row.get("cve"))] = float(value)
    return scores
