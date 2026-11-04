"""M1 threat-intel checks: what third-party indexes know that the scan cannot see (ch01).

Three checks, one per REQ-INTEL-004 example, and each one is **opt-in** twice over: the
provider must be named in ``ARACHNE_OSINT_PROVIDERS`` (none of the S18 providers is on by
default) *and* the check must be selected, because every one of them asks somebody else's
service about the target.

``m1.service-exposure-drift`` (ch01#3-4)
    Shodan (and Censys, when both are enabled) report what the internet observed listening on
    an address. Comparing that with what this scan found is the drift signal: a port the
    provider sees and the scan does not is usually a filtered or recently-closed service; a
    port the scan sees and the provider does not is a service that is new or internally
    reachable. The check reports the *difference*, not a verdict.
``m1.ct-surprise`` (ch01#8-9)
    Certificate Transparency is the one place third parties publish names before the operator
    announces them. Recently issued certificates for the domain, and — the part an operator
    acts on — CT names that this scan's scope does not cover, are the surprises worth a
    finding. RDAP registration facts ride along as context (a domain registered days ago with
    mail on it is a different story from a decade-old one).
``m1.breach-exposure`` (ch01#18)
    Which breaches exposed accounts at the target's domain. Not a vulnerability in the target,
    but an exposure an operator must triage: reused credentials and published addresses are
    the raw material of credential stuffing.

Every one degrades to a skipped result with the reason when its provider is absent
(REQ-INTEL-005) — never to an error and never to a silent "clean".
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from arachne.core.config import DEFAULT_WHOIS_RDAP_URL
from arachne.core.errors import OsintError
from arachne.core.results import CheckResult
from arachne.core.safety import normalize_host
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext, require_osint
from arachne.modules.providers.sources import (
    CtIssuance,
    censys_host_url,
    certspotter_url,
    hibp_breaches_url,
    parse_censys_host,
    parse_certspotter,
    parse_hibp_breaches,
    parse_rdap,
    parse_shodan_host,
    rdap_url_for,
    shodan_display_url,
    shodan_host_url,
)

__all__ = [
    "BreachExposure",
    "CertificateSurprise",
    "ServiceExposureDrift",
]

_DOMAIN_KINDS = (TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN)
_ADDRESS_KINDS = (TargetKind.IP, TargetKind.CIDR)

#: Default for "certificates issued within this many days count as a surprise" (the
#: deployment can change it: ``ARACHNE_OSINT_CT_WINDOW_DAYS`` → ``ModuleConfig``).
CT_SURPRISE_WINDOW_DAYS = 14
#: Addresses a drift check walks in one CIDR target (the provider charges per lookup).
DRIFT_MAX_ADDRESSES = 16
#: Addresses a drift check will compare against the scan's inventory.
MAX_REPORTED_PORTS = 32


# --------------------------------------------------------------------------- drift
class ServiceExposureDrift(Module):
    """``m1.service-exposure-drift`` — provider vs. scan view of an address (ch01#3-4)."""

    metadata = CheckMetadata(
        id="m1.service-exposure-drift",
        module="M1",
        name="service-exposure-drift",
        version="1.0",
        title="Exposed-service drift against Shodan/Censys",
        description=(
            "Compares the open services a third-party scanner observed on an address with the "
            "services this scan found, and reports the difference. When the scan's own "
            "inventory is not available (M1 runs before discovery), it reports the one-way "
            "signal that is still true: services the provider sees that this scan's port "
            "catalogue will never look at. Opt-in: it spends the deployment's Shodan and/or "
            "Censys key."
        ),
        research_ref="ch01#3-4",
        framework=("WSTG-CONF-01", "CWE-668"),
        compliance=(
            "ISO-A.5.22",
            "ISO-A.8.16",
            "ISO-A.8.32",
            "CSF-DE.CM-01",
            "CSF-DE.CM-06",
            "CSF-DE.CM-09",
            "CSF-ID.AM-04",
            "CSF-ID.RA-07",
        ),
        target_kinds=_ADDRESS_KINDS,
        cwe="CWE-668",
        severity_hint="low",
        type="passive",
        verifiable=True,
        enabled_by_default=False,
        requires_credentials=("shodan_api_key",),
        estimated_requests=DRIFT_MAX_ADDRESSES,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        providers = [
            name
            for name in ("shodan", "censys")
            if ctx.osint is not None and ctx.osint.available(name)
        ]
        if not providers:
            first = await self._skip_reason(ctx)
            yield ctx.skipped(first)
            return
        assert ctx.osint is not None
        addresses = list(_addresses_of(ctx.asset.value, DRIFT_MAX_ADDRESSES))
        if not addresses:
            yield ctx.skipped(f"asset {ctx.asset.key} names no single address to look up")
            return
        observed, view = _observed_ports(ctx)
        looked_up: list[dict[str, Any]] = []
        failures: list[str] = []
        for address in addresses:
            if not ctx.osint.can_spend():
                failures.append(f"budget exhausted after {len(looked_up)} lookup(s)")
                break
            for provider in providers:
                if not ctx.osint.can_spend():
                    failures.append(f"budget exhausted before {provider} {address}")
                    break
                try:
                    record = await _lookup(ctx, provider, address)
                except OsintError as exc:
                    # A 404-shaped answer is data, but a transport error is not worth
                    # spending the remaining budget on: record it and move on.
                    failures.append(f"{provider} {address}: {exc}")
                    continue
                if record is None:
                    continue
                looked_up.append(record)
                await ctx.record_asset(
                    "host",
                    address,
                    meta={"provider": provider, "ports": record.get("ports")},
                    source=self.metadata.id,
                )
        if not looked_up:
            yield ctx.error(
                OsintError("; ".join(failures) or "no provider returned a usable answer")
            )
            return
        coverage = _catalogue_ports(ctx)
        scan_view = (
            {host: sorted(ports) for host, ports in observed.items()}
            if observed
            else {"catalogue_tcp": sorted(coverage)}
        )
        evidence = ctx.evidence(
            "artifact",
            {
                "providers": providers,
                "addresses": addresses,
                "scan_view_source": view,
                "provider_view": looked_up,
                "scan_view": scan_view,
                "failures": failures[:16],
            },
            source=ctx.asset.key,
        )
        drift = [
            item
            for item in (
                _drift_entry(entry, observed, coverage=coverage, two_sided=bool(observed))
                for entry in looked_up
            )
            if item["provider_only"] or item["scan_only"]
        ]
        if not drift:
            yield ctx.info(
                f"the provider's view of {', '.join(addresses)} adds nothing to this scan's",
                detail=(
                    f"{len(looked_up)} address(es) compared across {', '.join(providers)} "
                    f"(scan view: {view}); no port the scan does not already cover."
                ),
                evidence=[evidence],
                confidence=0.7,
            )
            return
        for entry in drift:
            provider_only = entry["provider_only"]
            scan_only = entry["scan_only"]
            parts: list[str] = []
            if provider_only:
                parts.append(
                    f"{', '.join(str(port) for port in provider_only)} observed by the provider "
                    "but not by this scan"
                )
            if scan_only:
                parts.append(
                    f"{', '.join(str(port) for port in scan_only)} found by this scan but not "
                    "indexed by the provider"
                )
            title = (
                f"Exposed services on {entry['address']} differ from the provider's index"
                if entry["two_sided"]
                else f"{entry['address']} exposes services outside this scan's port coverage"
            )
            yield ctx.candidate(
                title,
                detail=(
                    f"{entry['provider']} reports "
                    f"{', '.join(str(p) for p in entry['provider_ports']) or 'no'} open port(s); "
                    + (
                        f"this scan observed "
                        f"{', '.join(str(p) for p in entry['scan_ports']) or 'none'}. "
                        if entry["two_sided"]
                        else "this scan's port catalogue does not include "
                        f"{', '.join(str(p) for p in entry['provider_only'] or [])}. "
                    )
                    + "; ".join(parts)
                    + ". Confirm which view is current before acting: a difference can be a "
                    "recent change, a filter between the two vantage points, or a provider "
                    "refreshing behind."
                ),
                cwe="CWE-668",
                confidence=0.4,
                evidence=[
                    evidence,
                    ctx.evidence("artifact", entry, source=entry["address"]),
                ],
            )

    async def _skip_reason(self, ctx: CheckContext) -> str:
        if ctx.osint is None:
            return (
                "OSINT access is disabled for this scan "
                "(set ARACHNE_OSINT_ENABLED=true and name shodan/censys in ARACHNE_OSINT_PROVIDERS)"
            )
        reasons: list[str] = []
        for name in ("shodan", "censys"):
            reason = ctx.osint.unavailable_reason(name)
            # "We asked for a provider and were refused" is a recorded event, not a silent
            # skip (REQ-INTEL-005).
            ctx.osint.note_blocked(name, reason)
            reasons.append(reason)
        return "no address provider is usable: " + "; ".join(reasons)


async def _lookup(ctx: CheckContext, provider: str, address: str) -> dict[str, Any] | None:
    """One provider lookup, normalised to ``{address, provider, ports, ...}``."""
    assert ctx.osint is not None
    if provider == "shodan":
        key = ctx.config.shodan_api_key.get_secret_value() if ctx.config.shodan_api_key else None
        response = await ctx.osint.fetch("shodan", shodan_host_url(address, api_key=key))
        if response.status == 404:
            return None
        record = parse_shodan_host(response.json(), address=address)
        if not record.found:
            return None
        return {
            "address": record.address,
            "provider": "shodan",
            "url": shodan_display_url(address),
            "ports": list(record.ports),
            "hostnames": list(record.hostnames),
            "org": record.org,
            "vulns": list(record.vulns),
        }
    if ctx.config.censys_api_id is None or ctx.config.censys_api_secret is None:
        return None
    token = f"{ctx.config.censys_api_id}:{ctx.config.censys_api_secret.get_secret_value()}"
    response = await ctx.osint.fetch("censys", censys_host_url(address), headers=_basic_auth(token))
    if response.status in (404, 403):
        return None
    censys_record = parse_censys_host(response.json(), address=address)
    if not censys_record.found:
        return None
    return {
        "address": censys_record.address,
        "provider": "censys",
        "url": censys_host_url(address),
        "ports": list(censys_record.ports),
        "services": [service.to_dict() for service in censys_record.services[:MAX_REPORTED_PORTS]],
    }


def _basic_auth(token: str) -> dict[str, str]:
    import base64

    encoded = base64.b64encode(token.encode("utf-8")).decode("ascii")
    return {"authorization": f"Basic {encoded}"}


def _catalogue_ports(ctx: CheckContext) -> set[int]:
    """The TCP ports this deployment's port catalogue probes (the scan's intended coverage)."""
    from arachne.modules.m2.catalog import load_port_catalog

    try:
        catalog = load_port_catalog(ctx.config.port_catalog)
    except Exception:  # a broken catalogue must not turn a provider answer into an error
        return set()
    return {entry.port for entry in catalog.tcp}


def _drift_entry(
    entry: dict[str, Any],
    observed: dict[str, set[int]],
    *,
    coverage: set[int],
    two_sided: bool,
) -> dict[str, Any]:
    address = str(entry.get("address") or "")
    provider_ports = {int(port) for port in entry.get("ports") or ()}
    if two_sided:
        scan_ports = observed.get(address, set())
        scan_only = sorted(scan_ports - provider_ports)
    else:
        scan_ports = set(coverage)
        scan_only = []
    return {
        "address": address,
        "provider": entry.get("provider"),
        "two_sided": two_sided,
        "provider_ports": sorted(provider_ports)[:MAX_REPORTED_PORTS],
        "scan_ports": sorted(scan_ports)[:MAX_REPORTED_PORTS],
        "provider_only": sorted(provider_ports - scan_ports)[:MAX_REPORTED_PORTS],
        "scan_only": scan_only[:MAX_REPORTED_PORTS],
    }


# --------------------------------------------------------------------------- CT surprises
class CertificateSurprise(Module):
    """``m1.ct-surprise`` — new certificates and out-of-scope names (ch01#8-9)."""

    metadata = CheckMetadata(
        id="m1.ct-surprise",
        module="M1",
        name="ct-surprise",
        version="1.0",
        title="Certificate-transparency and registration surprises",
        description=(
            "Reads a second certificate-transparency view (Cert Spotter, falling back to "
            "crt.sh), flags certificates issued inside a two-week surprise window, and reports "
            "names the scan's scope does not cover. RDAP registration facts (registrar, "
            "created, expiry, nameservers) are attached as context. Opt-in: it asks "
            "third-party registries about the domain."
        ),
        research_ref="ch01#8-9",
        framework=("WSTG-INFO-04", "CWE-200"),
        target_kinds=_DOMAIN_KINDS,
        cwe="CWE-200",
        severity_hint="medium",
        type="passive",
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=3,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        domain = normalize_host(name)
        if ctx.osint is None:
            yield ctx.skipped(
                "OSINT access is disabled for this scan "
                "(set ARACHNE_OSINT_ENABLED=true and name certspotter/whois in "
                "ARACHNE_OSINT_PROVIDERS)"
            )
            return
        issuances, ct_source, notes = await self._issuances(ctx, domain)
        registration = await self._registration(ctx, domain)
        if not issuances and registration is None:
            yield ctx.skipped(
                "no certificate-transparency or RDAP source is usable: " + "; ".join(notes)
            )
            return

        window_days = max(0, ctx.config.osint_ct_window_days)
        window_start = ctx.now() - timedelta(days=window_days)
        recent = [item for item in issuances if _issued_after(item, window_start)]
        out_of_scope: dict[str, None] = {}
        for item in issuances:
            for host in item.dns_names:
                if host and host != domain and not ctx.scope.check(host).allowed:
                    out_of_scope.setdefault(host, None)

        evidence = ctx.evidence(
            "artifact",
            {
                "domain": domain,
                "ct_source": ct_source,
                "window_days": window_days,
                "recent_issuances": [item.to_dict() for item in recent[:50]],
                "distinct_names": len({host for item in issuances for host in item.dns_names}),
                "out_of_scope_names": list(out_of_scope)[:100],
                "registration": registration.to_dict() if registration is not None else None,
                "notes": notes[:8],
            },
            source=domain,
        )
        if not recent and not out_of_scope:
            yield ctx.info(
                f"no certificate or registration surprise for {domain}",
                detail=(
                    f"{len(issuances)} issuance(s) from {ct_source or 'no CT source'}, none "
                    f"within {window_days} days, and every name it lists is inside this "
                    "scan's scope." + _registration_note(registration)
                ),
                evidence=[evidence],
                confidence=0.7,
            )
            return
        if recent:
            yield ctx.candidate(
                f"{len(recent)} certificate(s) issued for {domain} in the last {window_days} days",
                detail=(
                    "Certificate Transparency records what is issued, not who asked: a recent "
                    "certificate for the domain can be a planned deployment, a hosting change, "
                    "or an attempt at impersonation. Names on the new certificates: "
                    + _names_of(recent)
                    + "."
                    + _registration_note(registration)
                ),
                cwe="CWE-200",
                confidence=0.35,
                evidence=[evidence],
            )
        if out_of_scope:
            yield ctx.candidate(
                f"Certificate transparency lists {len(out_of_scope)} name(s) outside this "
                "scan's scope",
                detail=(
                    "The certificates name hosts that this scan is not allowed to touch, so "
                    "nothing in it covers them: "
                    + ", ".join(sorted(out_of_scope)[:16])
                    + (", …" if len(out_of_scope) > 16 else "")
                    + ". Either the scope is narrower than the estate, or the names should not "
                    "carry a certificate for this domain at all."
                ),
                cwe="CWE-200",
                confidence=0.4,
                evidence=[evidence],
            )

    async def _issuances(
        self, ctx: CheckContext, domain: str
    ) -> tuple[tuple[CtIssuance, ...], str | None, list[str]]:
        assert ctx.osint is not None
        notes: list[str] = []
        if ctx.osint.available("certspotter"):
            try:
                response = await ctx.osint.fetch("certspotter", certspotter_url(domain))
                if response.ok:
                    return parse_certspotter(response.json(), domain=domain), "certspotter", notes
                notes.append(f"certspotter returned HTTP {response.status}")
            except OsintError as exc:
                notes.append(f"certspotter: {exc}")
        if ctx.osint.available("crtsh"):
            from arachne.modules.providers.sources import crtsh_url, parse_crtsh

            try:
                response = await ctx.osint.fetch("crtsh", crtsh_url(domain))
                if response.ok:
                    parsed = parse_crtsh(response.json(), domain=domain)
                    return (
                        tuple(
                            CtIssuance(
                                id=item.name_value[:64],
                                dns_names=tuple(
                                    sorted(
                                        {
                                            normalize_host(entry.strip().lstrip("*."))
                                            for entry in item.name_value.splitlines()
                                            if entry.strip()
                                        }
                                    )
                                ),
                                issuer=item.issuer,
                                not_before=item.not_before,
                                not_after=item.not_after,
                            )
                            for item in parsed.certificates
                        ),
                        "crtsh",
                        notes,
                    )
                notes.append(f"crtsh returned HTTP {response.status}")
            except OsintError as exc:
                notes.append(f"crtsh: {exc}")
        if not notes:
            notes.append("neither certspotter nor crtsh is enabled")
        return (), None, notes

    async def _registration(self, ctx: CheckContext, domain: str) -> Any:
        assert ctx.osint is not None
        if not ctx.osint.available("whois"):
            return None
        try:
            base = ctx.config.whois_url or DEFAULT_WHOIS_RDAP_URL
            response = await ctx.osint.fetch("whois", rdap_url_for(base, domain))
        except OsintError:
            return None
        if not response.ok:
            return None
        return parse_rdap(response.json())


# --------------------------------------------------------------------------- breaches
class BreachExposure(Module):
    """``m1.breach-exposure`` — which breaches exposed accounts at this domain (ch01#18)."""

    metadata = CheckMetadata(
        id="m1.breach-exposure",
        module="M1",
        name="breach-exposure",
        version="1.0",
        title="Breach exposure summary (HIBP)",
        description=(
            "Asks Have I Been Pwned which breaches exposed accounts registered at the target's "
            "domain, and summarises the dates, volumes and data classes. Exposure of the "
            "domain's users, not a vulnerability in the target. Opt-in: needs an HIBP API key "
            "and the provider named in ARACHNE_OSINT_PROVIDERS."
        ),
        research_ref="ch01#18",
        framework=("WSTG-INFO-01", "CWE-522"),
        compliance=("ISO-A.5.34",),
        target_kinds=_DOMAIN_KINDS,
        cwe="CWE-522",
        severity_hint="medium",
        type="passive",
        verifiable=True,
        enabled_by_default=False,
        requires_credentials=("hibp_api_key",),
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        osint, skip = require_osint(ctx, "hibp")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        if ctx.config.hibp_api_key is None:
            yield ctx.skipped("the HIBP provider needs ARACHNE_HIBP_API_KEY in the environment")
            return
        domain = normalize_host(name)
        headers = {
            "hibp-api-key": ctx.config.hibp_api_key.get_secret_value(),
            "user-agent": "ARACHNE-scanner",
        }
        try:
            response = await osint.fetch("hibp", hibp_breaches_url(domain), headers=headers)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        if response.status == 404:
            yield ctx.info(
                f"no published breach lists accounts at {domain}",
                detail="HIBP has no breach attributed to this domain.",
                evidence=[ctx.evidence("note", {"domain": domain, "breaches": 0}, source=domain)],
                confidence=0.6,
            )
            return
        if not response.ok:
            yield ctx.error(OsintError(f"HIBP returned HTTP {response.status} for {domain}"))
            return
        breaches = parse_hibp_breaches(response.json())
        evidence = ctx.evidence(
            "artifact",
            {
                "domain": domain,
                "breach_count": len(breaches),
                "accounts_exposed": sum(item.pwn_count for item in breaches),
                "breaches": [item.to_dict() for item in breaches[:25]],
                "data_classes": sorted({name for item in breaches for name in item.data_classes}),
            },
            source=domain,
        )
        if not breaches:
            yield ctx.info(
                f"no published breach lists accounts at {domain}",
                detail="HIBP returned an empty list.",
                evidence=[evidence],
                confidence=0.6,
            )
            return
        accounts = sum(item.pwn_count for item in breaches)
        data_classes = sorted({name for item in breaches for name in item.data_classes})
        passwords = any("password" in name.lower() for name in data_classes)
        yield ctx.candidate(
            f"{len(breaches)} breach(es) exposed accounts at {domain}",
            detail=(
                f"HIBP attributes {len(breaches)} breach(es) to this domain, "
                f"{accounts} account record(s) in total; exposed data classes: "
                f"{', '.join(data_classes) or 'unreported'}. "
                + (
                    "Passwords were among the exposed fields, so credential reuse makes these "
                    "accounts a direct path into the estate. "
                    if passwords
                    else ""
                )
                + "This is exposure of the domain's user accounts, not a vulnerability in the "
                "target: treat it as a credential-hygiene item, verify with the identity team, "
                "and check for reuse against any authentication surface this scan found."
            ),
            cwe="CWE-522",
            confidence=0.5,
            evidence=[evidence],
        )


# --------------------------------------------------------------------------- helpers
def _addresses_of(value: str, limit: int) -> tuple[str, ...]:
    """Single addresses named by ``value`` (an IP or a bounded CIDR walk)."""
    text = value.strip()
    try:
        if "/" in text:
            network = ipaddress.ip_network(text, strict=False)
            return tuple(str(address) for address in tuple(network.hosts())[:limit])
        return (str(ipaddress.ip_address(text)),)
    except ValueError:
        return ()


def _observed_ports(ctx: CheckContext) -> tuple[dict[str, set[int]], str]:
    """The scan's own view of open ports, and where that view came from.

    Two cases, both honest:

    * the step has an inventory (a check run beside discovery, or on a discovered asset) →
      ``{address: {open port, ...}}`` from it, which supports the full two-sided drift;
    * it does not (the normal case: M1 runs in the recon step, before M2 probes anything) →
      the scan's view is the port *coverage* its catalogue declares, and the check reports the
      one-way signal that is still true: services the provider sees that this scan will never
      look at.
    """
    observed: dict[str, set[int]] = {}
    inventory = ctx.inventory
    hosts = getattr(inventory, "hosts", None)
    if isinstance(hosts, dict):
        for address, record in hosts.items():
            open_ports = getattr(record, "open_ports", None)
            ports = set(open_ports()) if callable(open_ports) else set()
            if ports:
                observed[str(address)] = ports
        if observed:
            return observed, "scan inventory"
    return {}, "catalogue coverage"


def _issued_after(issuance: CtIssuance, moment: datetime) -> bool:
    raw = issuance.not_before
    if not raw:
        return False
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed >= moment


def _names_of(issuances: Sequence[CtIssuance]) -> str:
    names = sorted({host for item in issuances for host in item.dns_names})
    if not names:
        return "(none listed)"
    shown = ", ".join(names[:16])
    return shown + (", …" if len(names) > 16 else "")


def _registration_note(registration: Any) -> str:
    if registration is None:
        return ""
    parts: list[str] = []
    if registration.registrar:
        parts.append(f"registrar {registration.registrar}")
    if registration.created:
        parts.append(f"registered {registration.created}")
    if registration.expires:
        parts.append(f"expires {registration.expires}")
    if registration.nameservers:
        parts.append(f"nameservers {', '.join(registration.nameservers[:4])}")
    return f" RDAP: {'; '.join(parts)}." if parts else ""
