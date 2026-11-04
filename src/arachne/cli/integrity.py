"""``arachne verify-chain`` and ``arachne integrity`` — tamper-evidence (S25, REQ-TRUST-005).

``verify-chain`` is the requirement's named command: it walks the audit hash chain, checks
the signed anchors, re-verifies every finding's and evidence row's deployment-key signature
and recomputes every completed scan's seal, then exits non-zero if anything is not intact.
An operator runs it on a schedule (or before an audit) and reads one verdict.

``integrity anchor`` writes a signed checkpoint of the chain's head — the evidence that a
*truncated tail* was detected, which a hash chain alone cannot provide — and
``integrity seal`` seals a scan that was completed before this stage existed (or that was
re-sealed after a deliberate re-analysis).

The exit code is the contract: ``0`` intact, ``1`` not intact, ``2`` the command could not
run (no schema, no key when signatures are required). ``--require-signatures`` turns "no
key configured" from a note into a failure, which is what a deployment that *has* a key
should use.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import get_settings
from arachne.core.errors import ArachneError
from arachne.core.integrity import IntegrityReport
from arachne.core.signing import build_signer, build_verifier
from arachne.data.services import build_integrity_verifier, build_services

__all__ = ["integrity_app", "verify_chain_command"]

integrity_app = typer.Typer(
    name="integrity",
    help="Tamper-evidence: anchor the audit chain and seal completed scans (S25).",
    no_args_is_help=True,
)


def verify_chain_command(
    scan_id: Annotated[
        int | None, typer.Option("--scan", help="Verify only one scan's rows and seal.")
    ] = None,
    since_seq: Annotated[
        int, typer.Option("--since-seq", min=1, help="Start the chain walk at this position.")
    ] = 1,
    require_signatures: Annotated[
        bool,
        typer.Option(
            "--require-signatures",
            help="Fail when the chain or the rows are unsigned (ARACHNE_INTEGRITY_KEY unset).",
        ),
    ] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Emit the full report as JSON.")] = (
        False
    ),
) -> None:
    """Verify the audit chain, the signatures and the seals; exit 1 when not intact."""
    settings = get_settings()
    services = build_services(settings)
    try:
        verifier = build_integrity_verifier(services)
        if require_signatures:
            verifier.require_signatures = True
        # "Has keys" means the *verifier* holds one, not that this process can sign: an auditor
        # configures only the Ed25519 public key and must be able to run this command
        # (REQ-TRUST-008). `signer` answers the narrower question "can this host sign?".
        signer = build_signer(settings)
        verifies_with_keys = verifier.signer is not None
        if verifier.require_signatures and not verifies_with_keys:
            typer.echo(
                "error: --require-signatures was given but no integrity key is configured; set "
                "ARACHNE_INTEGRITY_KEY, or ARACHNE_INTEGRITY_ED25519_PUBLIC_KEY to verify with a "
                "public key alone",
                err=True,
            )
            raise typer.Exit(code=2)
        report = verifier.verify(scan_id=scan_id, since_seq=since_seq)
        services.auditor.record(
            AuditAction.INTEGRITY_VERIFIED if report.ok else AuditAction.INTEGRITY_TAMPER,
            outcome=AuditOutcome.ALLOWED if report.ok else AuditOutcome.BLOCKED,
            scan_id=scan_id,
            reason=None if report.ok else "; ".join(issue.detail for issue in report.issues[:3]),
            meta={
                "ok": report.ok,
                "issues": len(report.issues),
                "modified": len(report.modified),
                "deleted": len(report.deleted),
                "checked": report.checked,
                "signed": verifies_with_keys,
                "can_sign": signer is not None,
                "scheme": signer.scheme if signer is not None else None,
            },
        )
    finally:
        services.close()
    _emit_report(report, json_output=json_output, signed=verifies_with_keys)
    if not report.ok:
        raise typer.Exit(code=1)


@integrity_app.command("anchor")
def integrity_anchor(
    reason: Annotated[str, typer.Option("--reason", help="Why the anchor is written.")] = (
        "manual"
    ),
    export: Annotated[
        Path | None,
        typer.Option("--export", help="Also write the anchor JSON here (keep it off the host)."),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Write a signed checkpoint of the audit chain's head."""
    services = build_services(get_settings())
    try:
        if services.integrity is None:  # pragma: no cover - build_services always wires it
            typer.echo("error: this deployment has no integrity service", err=True)
            raise typer.Exit(code=2)
        record = services.integrity.anchor(reason=reason)
    finally:
        services.close()
    if record is None:
        typer.echo("nothing to anchor: the audit chain is empty")
        raise typer.Exit(code=0)
    payload = record.to_dict()
    if export is not None:
        export.parent.mkdir(parents=True, exist_ok=True)
        export.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        payload["exported_to"] = str(export)
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(f"anchored: seq {record.seq} hash {record.hash[:16]}… ({reason})")
    if export is not None:
        typer.echo(f"exported to {export} — keep a copy outside the database host")


@integrity_app.command("seal")
def integrity_seal(
    scan: Annotated[int, typer.Option("--scan", help="The scan to seal.")],
    reason: Annotated[str, typer.Option("--reason", help="Why the seal is (re)written.")] = (
        "manual"
    ),
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Sign and store the manifest of a scan's findings and evidence."""
    services = build_services(get_settings())
    try:
        if services.integrity is None:  # pragma: no cover - build_services always wires it
            typer.echo("error: this deployment has no integrity service", err=True)
            raise typer.Exit(code=2)
        try:
            record = services.integrity.seal_scan(scan, reason=reason)
        except ArachneError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(record.to_dict(), indent=2, default=str))
        return
    signed = "signed" if record.signature else "UNSIGNED (no ARACHNE_INTEGRITY_KEY)"
    typer.echo(
        f"sealed scan {record.scan_id}: {record.row_count} rows, "
        f"digest {record.digest[:16]}… ({signed})"
    )


@integrity_app.command("status")
def integrity_status(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show the key, the anchor table and the sealed scans."""
    settings = get_settings()
    services = build_services(settings)
    try:
        signer = build_signer(settings)
        # What this deployment can *verify* with, which is the wider question: an auditor
        # configures only a public key (REQ-TRUST-008) and is configured for all that.
        ring = build_verifier(settings)
        anchors = services.integrity.anchors(limit=10) if services.integrity else ()
        seals = services.integrity.seals(limit=10) if services.integrity else ()
        head = _chain_head(services)
        key_info: dict[str, Any] = (
            {
                "configured": True,
                "key_id": ring.key_id or ", ".join(ring.key_ids()),
                "schemes": list(ring.schemes()),
                "can_sign": signer is not None,
            }
            if ring.signers
            else {"configured": False}
        )
        payload: dict[str, Any] = {
            "integrity_key": key_info,
            "require_signatures": settings.integrity.require_signatures,
            "anchor_every": settings.integrity.anchor_every,
            "chain_head": head,
            "anchors": [record.to_dict() for record in anchors],
            "seals": [record.to_dict() for record in seals],
            "airgapped": settings.airgap.enabled,
            "region": settings.resilience.region,
            "seal_on_finish": settings.integrity.seal_on_finish,
        }
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    if key_info.get("configured"):
        typer.echo(f"integrity key:     configured ({key_info.get('key_id')})")
    else:
        typer.echo("integrity key:     NOT configured")
    typer.echo(f"chain head:        {payload['chain_head'] or '(empty)'}")
    typer.echo(f"anchors:           {len(payload['anchors'])}")
    typer.echo(f"seals:             {len(payload['seals'])}")
    typer.echo(f"air-gapped:        {payload['airgapped']}")
    typer.echo(f"region:            {payload['region'] or '(none declared)'}")


def _chain_head(services: Any) -> str | None:
    if services.integrity is None:  # pragma: no cover - build_services always wires it
        return None
    from arachne.data.integrity_store import SqlAuditChain

    chain = SqlAuditChain(services.session_factory, signer=None)
    tail = chain.tail()
    return f"seq {tail[0]} hash {tail[1][:16]}…" if tail else None


def _emit_report(report: IntegrityReport, *, json_output: bool, signed: bool) -> None:
    if json_output:
        payload = report.to_dict()
        payload["signed"] = signed
        typer.echo(json.dumps(payload, indent=2, default=str))
        return
    typer.echo(f"verify-chain: {report.summary()}")
    for issue in report.issues:
        # ``<check>.<kind>`` rather than just the kind: REQ-PROOF-018 names the verdict
        # ``evidence.mismatch``, and a body edit to a stored blob is a different answer from
        # an edited audit row. The bracketed pair keeps both readable in one line.
        typer.echo(f"  [{issue.check}.{issue.kind}] {issue.subject}: {issue.detail}", err=True)
    for note in report.notes:
        typer.echo(f"  note: {note}")
    if not signed and report.ok:
        typer.echo(
            "  note: no integrity key is configured, so signatures and seals are not checked; "
            "set ARACHNE_INTEGRITY_KEY (or pass --require-signatures to make this an error)"
        )
