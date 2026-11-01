"""OT/ICS read-only protocol checks (research ch02#27, REQ-DEPTH-006).

An industrial protocol is the most sensitive thing on an estate and the least defensible: it
predates authentication, its devices run for decades, and a probe that reads or writes a coil
can move a physical process. So the design here is deliberately narrow, and the narrowness is
the feature:

* **Read-only, and only the status-carrying messages.** S7comm is reached with a COTP
  *connection request* (the handshake) and nothing else — no read-var job, no write-var job, no
  PLC memory access at all. DNP3 is reached with the link-layer ``REQUEST_LINK_STATUS``
  function; ``RESET_LINK_STATES`` — which would change the outstation's link state machine — is
  **not** sent, and neither :func:`~arachne.modules.m2.wire.dnp3_link_status_request` nor this
  module can express it. Modbus device identification lives in ``m2.ics-probe`` (S4) and is
  equally read-only.
* **Opt-in twice over.** The check is outside the default set *and* the deployment switch
  ``ARACHNE_NET_OT_PROBE`` must be on. OT protocols answer anybody who can reach them, so
  reaching one is itself the sensitive act (``REQ-DEPTH-006``: "opt-in checks").
* **Reachability is the finding.** What an operator needs to know is that a controller's
  engineering protocol answers from the segment being scanned. That is a *bad configuration*
  statement — the device is not segmented behind a unidirectional gateway or a firewall — and
  it needs no payload beyond the handshake.

Both facets declare **L1** (active read-only) and are held to it by the registry's
proof-consistency gate.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from arachne.core.net import ScopedNetClient
from arachne.core.results import CheckResult
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.netinfra import _candidate_ports, _hosts_for
from arachne.modules.m2.support import (
    NetworkCheck,
    catalog_ports_for_probe,
    inventory_or_skip,
    net_or_skip,
    skip_result,
    target_kinds_for_network_probes,
)

__all__ = ["OtProtocolProbe"]

#: The protocols one request reaches per candidate port, and the port each is declared on when
#: the operator's catalogue says nothing (the IANA/service assignments).
_FAMILIES: tuple[tuple[str, str, int], ...] = (
    ("s7", "s7", 102),
    ("dnp3", "dnp3", 20000),
)


class OtProtocolProbe(NetworkCheck, Module):
    """``m2.ot-protocol-probe`` — S7comm and DNP3 device discovery. Opt-in twice."""

    metadata = CheckMetadata(
        id="m2.ot-protocol-probe",
        module="M2",
        name="ot-protocol-probe",
        version="1.0",
        title="OT/ICS protocol discovery (S7comm, DNP3)",
        description=(
            "Reaches an S7comm endpoint with an ISO-TSAP connection request and a DNP3 "
            "outstation with a link-layer status request, reporting a controller whose "
            "engineering protocol answers from the scanned segment. Read-only: no S7 read or "
            "write job, no PLC memory access, and no DNP3 link reset. Opt-in."
        ),
        research_ref="ch02#27",
        cwe="CWE-306",
        target_kinds=target_kinds_for_network_probes(),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=4,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skipped = net_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert client is not None
        if not ctx.config.net_ot_probe:
            yield skip_result(
                ctx,
                "OT/ICS probing is off: set ARACHNE_NET_OT_PROBE=true to enable it (OT "
                "protocols predate authentication, so reaching one is the sensitive act)",
            )
            return
        inventory, skipped = inventory_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None
        hosts = _hosts_for(ctx)
        if not hosts:
            yield skip_result(ctx, f"no probed host for asset {ctx.asset.key}")
            return

        findings = 0
        probed = 0
        for host in hosts:
            for family, probe_name, default_port in _FAMILIES:
                declared = catalog_ports_for_probe(ctx, probe_name) or (default_port,)
                for port in _candidate_ports(ctx, host, declared):
                    probed += 1
                    finding = await self._probe_family(
                        ctx, client, host=host, port=port, family=family
                    )
                    if finding is not None:
                        findings += 1
                        yield finding
        if not findings:
            yield ctx.clean(
                "no OT/ICS protocol endpoint answered",
                detail=(
                    f"sent {probed} read-only probe(s) across S7comm and DNP3 candidate ports; "
                    "none returned a valid protocol answer"
                ),
                confidence=0.6,
            )

    async def _probe_family(
        self, ctx: CheckContext, client: ScopedNetClient, *, host: str, port: int, family: str
    ) -> CheckResult | None:
        """One read-only probe; a :class:`CheckResult` when the endpoint answers."""
        tcp = client.tcp
        if family == "s7":
            exchange = await tcp(host, port, payload=wire.s7_cotp_connection_request(), reads=1)
            connection = (
                wire.parse_s7_connection_confirm(exchange.banner) if exchange.is_open else None
            )
            if connection is None:
                return None
            return ctx.candidate(
                f"S7comm engineering protocol reachable on {host}:{port}",
                detail=(
                    "the endpoint answered an ISO-TSAP COTP connection request with a "
                    "connection confirm, so a PLC's engineering protocol is reachable from "
                    "this network segment. S7comm has no authentication in the base protocol, "
                    "and this probe stops at the handshake: it sent no read-var or write-var "
                    "job and read no PLC memory (research ch02#27). Segment OT networks behind "
                    "a unidirectional gateway and forbid port 102 from business networks."
                ),
                cwe="CWE-306",
                confidence=0.8,
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "host": host,
                            "port": port,
                            "protocol": "s7comm",
                            "handshake": "cotp-connection-confirm",
                            "source_tsap": connection.source_tsap.hex(),
                            "destination_tsap": connection.destination_tsap.hex(),
                            "jobs_sent": 0,
                        },
                        source=f"{host}:{port}/tcp",
                    )
                ],
            )
        exchange = await tcp(host, port, payload=wire.dnp3_link_status_request(), reads=1)
        link = wire.parse_dnp3_link(exchange.banner) if exchange.is_open else None
        if link is None or not link.is_link_status:
            return None
        return ctx.candidate(
            f"DNP3 outstation answers on {host}:{port}",
            detail=(
                "the endpoint returned a valid DNP3 link-layer status reply (CRC verified) to "
                "an unauthenticated unicast request, so an outstation is reachable and its "
                "link layer accepts unauthenticated frames. DNP3 Secure Authentication "
                "(IEEE 1815-2012) is what prevents this; a deployment that answers this probe "
                "without it is running the pre-2012 trust model (research ch02#27). This probe "
                "sends only the read-only status request — it never sends a link reset, which "
                "would change the outstation's link state machine."
            ),
            cwe="CWE-306",
            confidence=0.8,
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "host": host,
                        "port": port,
                        "protocol": "dnp3",
                        "destination": link.destination,
                        "source": link.source,
                        "link_function": link.function,
                        "crc_verified": True,
                        "link_reset_sent": False,
                    },
                    source=f"{host}:{port}/tcp",
                )
            ],
        )
