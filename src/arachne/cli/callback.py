"""``arachne callback-server`` — the standalone out-of-band callback service (S15).

The L2 half of the proof ladder needs a listener on ARACHNE's own infrastructure that
blind sinks (SSRF, XXE, blind SQLi, template injection) can reach, and that issues the
single-use ``arachne-<scan-id>-<check-id>-<nonce>`` tokens checks inject
(REQ-PROOF-005). This command runs exactly that facade:

* ``ANY /arachne-…`` records a callback hit (redacted, rate-limited, audited);
* ``GET /hits?token=…`` is the single-use match a check polls once;
* ``GET /health`` is the liveness probe.

The service never dials out — it has no outbound client at all — and the audit trail it
keeps (``--audit-log``) is its own, so the hits an operator sees in a report are
reconstructible from the service's side alone. Point checks at it with
``ARACHNE_WEB_SSRF_CALLBACK=http://<host>:<port>`` (the host must be inside the scan's
declared scope, because the check's lookup goes through the scan's scoped client).
"""

from __future__ import annotations

from typing import Annotated

import typer

from arachne.proof.server import serve_forever

__all__ = ["callback_server_command"]


def callback_server_command(
    host: Annotated[
        str, typer.Option("--host", help="Bind address (loopback unless you mean to expose it).")
    ] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", help="Bind port (0 = ephemeral).")] = 0,
    audit_log: Annotated[
        str | None,
        typer.Option("--audit-log", help="Append the service's audit trail to this JSONL file."),
    ] = None,
    scan_gate: Annotated[
        bool,
        typer.Option(
            "--no-scan-gate",
            help=(
                "Do not read the scan row: run as a pure listener, without refusing callbacks "
                "for an inactive scan or an expired attestation (WP-14, REQ-PROOF-019)."
            ),
        ),
    ] = True,
) -> None:
    """Run the out-of-band callback service in the foreground."""
    raise typer.Exit(serve_forever(host=host, port=port, audit_log=audit_log, scan_gate=scan_gate))
