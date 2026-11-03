"""``m2.http3-probe`` — HTTP/3 parity for the security-header family (REQ-DET-006).

The question this check answers is not "does the target speak HTTP/3" but "does it answer the
*same* security questions over HTTP/3". A deployment whose QUIC path is served by a different
edge configuration — a CDN that terminates h2 with a hardened config and h3 with a default
one — is clean over the transport a scanner probably tests and weak over the one it does not.

Three outcomes, all recorded with the transport named in evidence:

* the extra is not installed → an observation naming the installation gap, and nothing else.
  The air-gapped install, the default install and the suite are unaffected (REQ-DET-006's
  "no new mandatory dependency").
* HTTP/3 is not reachable → an observation, **never a finding**: not speaking QUIC is not a
  weakness.
* HTTP/3 is reachable → the security header set is compared with the HTTP/1.1-2 response; a
  path that serves a weaker set is the finding.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import http3
from arachne.modules.m2.support import NetworkCheck

__all__ = ["Http3Probe"]


class Http3Probe(NetworkCheck, Module):
    """``m2.http3-probe`` — the same security-header question, asked over QUIC."""

    metadata = CheckMetadata(
        id="m2.http3-probe",
        module="M2",
        name="http3-probe",
        version="1.0",
        title="HTTP/3 transport parity",
        description=(
            "Reads the Alt-Svc advertisement and, when the optional QUIC client is installed, "
            "performs one HTTP/3 GET of the same path. The security-relevant response headers "
            "are compared with the HTTP/1.1-2 response, so a QUIC path that serves a weaker "
            "header set than the TCP path is reported. The transport used is recorded in "
            "evidence. Without the optional extra the check records that QUIC probing is "
            "unavailable and sends nothing over QUIC; the target not speaking HTTP/3 is an "
            "observation, never a finding."
        ),
        research_ref="ch02#12",
        framework=("WSTG-CONF-01", "WSTG-CONF-07", "CWE-693"),
        cwe="CWE-693",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        http = ctx.http
        if http is None:
            yield ctx.skipped(
                "no HTTP client in this run: the HTTP/3 probe needs a live scan "
                "(a dry run sends nothing)"
            )
            return
        url = str(ctx.asset.value)
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            yield ctx.skipped(
                f"HTTP/3 is only meaningful for an https endpoint; {url!r} is not one"
            )
            return
        host = parts.hostname
        port = parts.port or 443
        path = parts.path or "/"

        base = await http.get(url)
        headers = dict(base.response_headers)
        alt_svc = http3.alt_svc_http3(headers)
        tcp_missing = http3.missing_security_headers(headers)
        evidence_facts: dict[str, object] = {
            "url": url,
            "alt_svc": alt_svc,
            "http3_advertised": alt_svc is not None,
            "tcp_transport": "http/1.1-or-2",
            "tcp_missing_security_headers": list(tcp_missing),
            "h3_unavailable_reason": None,
        }

        if not http3.http3_available():
            evidence_facts["h3_unavailable_reason"] = (
                f"the optional extra arachne[{http3.HTTP3_EXTRA}] is not installed"
            )
            yield ctx.info(
                f"HTTP/3 probing is unavailable for {host}: no QUIC client installed",
                detail=(
                    "The Alt-Svc advertisement was read over the TCP path "
                    f"({'h3 advertised' if alt_svc else 'no h3 alternative advertised'}), but "
                    f"no QUIC handshake was attempted because the optional extra "
                    f"arachne[{http3.HTTP3_EXTRA}] is not installed. This is an installation "
                    "observation, not a finding: the default and air-gapped installs are "
                    "unaffected and the TCP families still run."
                ),
                evidence=[ctx.evidence("note", evidence_facts, source=url)],
                confidence=0.9,
            )
            return

        response = await http3.http3_get(host, port, path=path, server_name=host)
        evidence_facts["h3_attempted"] = True
        evidence_facts["h3_transport"] = response.transport
        evidence_facts["h3_error"] = response.error
        evidence_facts["h3_status"] = response.status_code
        if not response.ok:
            yield ctx.info(
                f"{host} does not answer HTTP/3",
                detail=(
                    "The QUIC handshake or the HTTP/3 exchange did not complete "
                    f"({response.error}). That is an observation: not offering HTTP/3 is not a "
                    "weakness, and the TCP families already covered the target."
                ),
                evidence=[ctx.evidence("note", evidence_facts, source=url)],
                confidence=0.8,
            )
            return

        h3_missing = http3.missing_security_headers(response.headers)
        evidence_facts["h3_missing_security_headers"] = list(h3_missing)
        evidence_facts["h3_security_headers"] = {
            name: response.headers[name]
            for name in http3.SECURITY_HEADERS
            if name in response.headers
        }
        evidence = [ctx.evidence("note", evidence_facts, source=url)]
        yield ctx.info(
            f"HTTP/3 is available on {host} (transport {response.transport})",
            detail=(
                f"HTTP/3 GET {path} answered {response.status_code} over "
                f"{response.transport}; {len(h3_missing)} of "
                f"{len(http3.SECURITY_HEADERS)} security headers are absent."
            ),
            evidence=evidence,
            confidence=0.9,
        )
        weaker = [name for name in h3_missing if name not in tcp_missing]
        evidence_facts["headers_lost_over_h3"] = weaker
        if weaker:
            yield ctx.candidate(
                f"{host} serves a weaker security-header set over HTTP/3 than over HTTP/2",
                detail=(
                    "The HTTP/3 response omits "
                    + ", ".join(f"'{name}'" for name in weaker)
                    + " that the HTTP/1.1-2 response carried. A deployment whose QUIC path is "
                    "terminated by a different configuration than its TCP path has a security "
                    "boundary that depends on the protocol the client chose (CWE-693). Agent "
                    "and browser clients increasingly prefer HTTP/3, so this is the path that "
                    "most clients take."
                ),
                confidence=0.7,
                evidence=evidence,
            )
            return
        yield ctx.clean(
            f"{host} answers HTTP/3 with the same security-header posture as HTTP/2",
            detail=(
                f"Both transports are missing the same {len(tcp_missing)} header(s), so the "
                "QUIC path does not weaken the TCP path."
            ),
            evidence=evidence,
            confidence=0.85,
        )
