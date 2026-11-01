"""``arachne synthesize`` — feed-driven check proposals (S21, REQ-AGENT-004).

The operator's verb for the self-improvement loop. It reads threat-intel records and writes
*reviewable artefacts* to a directory (``--out``, default ``.arachne/proposals``). It has no
verb that deploys anything, because there is no code path from a proposal into the live
registry: a human reviews the artefacts, runs parity, and merges the catalogue row.

``list`` shows what has been proposed (from the manifest), ``parity`` runs the benchmark harness
for a proposal so its approval can record a result, and ``review`` marks a proposal approved
*only* with a passing parity result and a named reviewer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.data.services import build_services
from arachne.quality.synthesis import (
    CheckProposal,
    CheckSynthesizer,
    FeedHint,
    ParityEvidence,
    approve,
    write_artifacts,
)

__all__ = ["synthesize_app"]

synthesize_app = typer.Typer(
    name="synthesize",
    help="Turn threat-intel records into reviewable check proposals (S21, REQ-AGENT-004).",
    no_args_is_help=True,
)

#: Where proposals are written unless an operator says otherwise.
DEFAULT_PROPOSALS_DIR = ".arachne/proposals"


def _hints_from_feed(kind: str, limit: int) -> tuple[FeedHint, ...]:
    """Read the active feed of ``kind`` (KEV/CVE) and turn its rows into hints."""
    services = build_services(get_settings())
    try:
        record = services.feeds.active(kind)
        if record is None:
            raise ArachneError(f"no active {kind!r} feed; import or sync one first")
        out: list[FeedHint] = []
        for row in services.feeds.entries(record.id, limit=limit):
            cve = str(row.get("cve") or "")
            if not cve.upper().startswith("CVE-"):
                continue
            product = str(
                row.get("product")
                or row.get("vendorProject")
                or row.get("vendor")
                or row.get("package")
                or ""
            )
            summary = str(
                row.get("shortDescription")
                or row.get("summary")
                or row.get("description")
                or ""
            )
            known = bool(row.get("knownExploited") or kind == "kev")
            cvss = row.get("cvss") or row.get("baseScore")
            out.append(
                FeedHint(
                    cve=cve.upper(),
                    product=product,
                    summary=summary,
                    source=f"feed:{kind}",
                    known_exploited=known,
                    cvss=float(cvss) if isinstance(cvss, int | float) else None,
                )
            )
        return tuple(out)
    finally:
        services.close()


@synthesize_app.command("propose")
def synthesize_propose(
    feed: Annotated[
        str, typer.Option("--feed", help="Feed kind to derive from (kev, cve).")
    ] = "kev",
    limit: Annotated[int, typer.Option("--limit", help="How many feed rows to read.")] = 25,
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Directory to write the proposals to.")
    ] = Path(DEFAULT_PROPOSALS_DIR),
    catalogue: Annotated[
        str | None,
        typer.Option("--catalogue", help="Path of the live catalogue to version against."),
    ] = None,
) -> None:
    """Write reviewable check proposals from the active threat-intel feed."""
    from arachne.core.catalog import load_catalog

    hints = _hints_from_feed(feed, limit)
    if not hints:
        raise ArachneError(f"the active {feed!r} feed holds no CVE rows")
    live = load_catalog(catalogue)
    existing = {spec.id: spec.version for spec in live.checks}
    synthesizer = CheckSynthesizer(catalogue_version=live.catalog_version)
    proposals = synthesizer.propose(hints, existing_versions=existing)
    manifest = write_artifacts(proposals, out)
    typer.echo(
        f"wrote {len(proposals)} proposal(s) to {out} (catalogue v{live.catalog_version}); "
        f"manifest: {manifest}"
    )
    typer.echo(
        "these are proposals: review each REVIEW.md, run `arachne synthesize parity`, then "
        "merge the catalogue row and implement the check by hand"
    )


@synthesize_app.command("list")
def synthesize_list(
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Directory the proposals were written to.")
    ] = Path(DEFAULT_PROPOSALS_DIR),
    as_json: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List the proposals a directory holds (from its manifest)."""
    manifest_path = Path(out) / "manifest.json"
    if not manifest_path.exists():
        typer.echo(f"no manifest at {manifest_path}")
        return
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if as_json:
        typer.echo(json.dumps(manifest, indent=2))
        return
    typer.echo(
        f"{len(manifest.get('proposals') or [])} proposal(s) against catalogue "
        f"v{manifest.get('catalogue_version') or 'unknown'}; deployed: "
        f"{manifest.get('deployed', False)}"
    )
    for entry in manifest.get("proposals") or []:
        previous = entry.get("previous_version") or "new"
        typer.echo(
            f"  {entry.get('check_id')} {entry.get('proposed_version')} "
            f"(was {previous}) [{entry.get('status')}] {entry.get('cve')}"
        )


@synthesize_app.command("review")
def synthesize_review(
    check_id: Annotated[str, typer.Argument(help="Proposed check id to approve.")],
    reviewer: Annotated[str, typer.Option("--reviewer", help="Who is approving.")],
    out: Annotated[
        Path, typer.Option("--out", "-o", help="Directory the proposal was written to.")
    ] = Path(DEFAULT_PROPOSALS_DIR),
    parity_suite: Annotated[
        str, typer.Option("--parity-suite", help="Suite the parity run used.")
    ] = "arachne-lab",
    parity_ok: Annotated[
        bool, typer.Option("--parity-ok/--parity-failed", help="Result of the parity run.")
    ] = False,
) -> None:
    """Approve a proposal — only with a passing parity result and a named reviewer."""
    folder = Path(out) / check_id
    path = folder / "proposal.json"
    if not path.exists():
        raise ArachneError(f"no proposal at {path}")
    proposal = CheckProposal.from_document(json.loads(path.read_text(encoding="utf-8")))
    approved = approve(
        proposal,
        parity=ParityEvidence(
            ok=parity_ok,
            suite=parity_suite,
            detail="recorded by `arachne synthesize review`",
        ),
        reviewer=reviewer,
    )
    path.write_text(
        json.dumps(approved.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    typer.echo(
        f"{check_id} approved by {reviewer} (parity {parity_suite}); it is still a proposal — "
        "merge the catalogue row and implement the check by hand"
    )


def proposal_document(path: Path) -> dict[str, Any]:
    """Read a proposal document (used by tests and by an integration that wants the row)."""
    return dict(json.loads(Path(path).read_text(encoding="utf-8")))
