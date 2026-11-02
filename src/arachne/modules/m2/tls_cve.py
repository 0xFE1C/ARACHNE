"""``m2.tls-deep-scan`` and ``m2.cve-correlate``: the two M2 checks that turn observations
into findings (research ch02#14 and ch02#29).

``m2.tls-deep-scan`` profiles each TLS endpoint (protocols, cipher suites, certificate,
trust) with the stdlib and reports every weakness it can substantiate — a protocol the
endpoint still negotiates, a suite it still accepts, a certificate that is expired,
self-signed or does not name the host. It is the check that makes the DONE criterion "TLS
issues" real, and every finding carries the certificate or the handshake that proves it.

``m2.cve-correlate`` is the module's payoff: it matches the ``(product, version)`` pairs M2
fingerprinted against the offline CVE/EPSS index (F-09-03), and — when the deployment has
configured the ``vulners`` provider and an API key — enriches those matches with the online
feed through the audited OSINT client. It is the one **hybrid** M2 check: it sends no packet
to the target, so it runs by default (no active-checks opt-in) and reports what the rest of
M2 established.

The severity of a CVE match is intentionally *not* decided here (ADR-02): the candidate
carries CVSS and EPSS in its evidence, and the analyzer owns the score.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from arachne.core.errors import OsintError
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2.catalog import CveEntry, MatchResult, version_matches
from arachne.modules.m2.inventory import ServiceRecord
from arachne.modules.m2.support import (
    NetworkCheck,
    cve_index_for,
    inventory_or_skip,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
    tls_capable_services,
)
from arachne.modules.m2.tls import TlsAssessment, profile_tls

__all__ = ["CveCorrelate", "TlsDeepScan", "vulners_url"]

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)

#: How many versioned services the online enrichment will query (bounded by the OSINT budget
#: too, which the provider layer enforces).
MAX_VULNERS_LOOKUPS = 8


class TlsDeepScan(NetworkCheck, Module):
    """``m2.tls-deep-scan`` — protocols, ciphers, certificate and trust (ch02#14)."""

    metadata = CheckMetadata(
        id="m2.tls-deep-scan",
        module="M2",
        name="tls-deep-scan",
        version="1.0",
        title="TLS configuration scan",
        description=(
            "Profiles every TLS endpoint M2 found: which protocol versions it negotiates, "
            "which cipher suites it accepts (probed one suite at a time), and whether its "
            "certificate is valid, trusted, correctly named and strongly keyed. Weak protocols "
            "and suites are reported with the handshake that accepted them."
        ),
        research_ref="ch02#14",
        framework=("WSTG-CRYP-01", "CWE-327"),
        cwe="CWE-327",
        target_kinds=_NETWORK_KINDS,
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        services = [
            service
            for service in tls_capable_services(services_of(inventory, ctx.asset), catalog)
            if service.protocol == "tcp"
        ]
        if not services:
            yield ctx.skipped(
                f"no TLS-capable service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        server_name = None if _is_address(ctx.asset.value) else ctx.asset.value
        assessments: list[dict[str, Any]] = []
        by_key: dict[str, TlsAssessment] = {}
        all_issues: list[tuple[ServiceRecord, Any]] = []
        for service in services:
            assessment = await profile_tls(
                client,
                host=service.host,
                port=service.port,
                server_name=server_name,
                cipher_candidates=client.net_settings.tls_cipher_probes,
            )
            service.probes += len(assessment.probes)
            service.tls = assessment.profile
            if assessment.profile.error:
                yield ctx.clean(
                    f"TLS handshake to {service.key} failed",
                    detail=(
                        f"{assessment.profile.error} — the port is open but did not complete a "
                        "TLS handshake, so it is not a TLS endpoint (or it requires a protocol "
                        "this build cannot negotiate)."
                    ),
                    evidence=[
                        ctx.evidence(
                            "note",
                            {
                                "host": service.host,
                                "port": service.port,
                                "error": assessment.profile.error,
                            },
                            source=service.key,
                        )
                    ],
                    confidence=0.5,
                )
                continue
            if service.identity is None or service.effective_service == "unknown":
                service.notes["tls_detected"] = True
            assessments.append(
                {
                    "host": service.host,
                    "port": service.port,
                    **assessment.to_dict(),
                }
            )
            by_key[service.key] = assessment
            all_issues.extend((service, issue) for issue in assessment.issues)

            yield ctx.info(
                f"TLS on {service.key}: "
                f"{', '.join(assessment.supported_versions) or 'no version negotiated'}",
                detail=(
                    f"{len(assessment.profile.ciphers)} cipher suite(s) accepted from the "
                    "probe list; "
                    "certificate "
                    f"{_cert_name(assessment)}; "
                    f"{len(assessment.issues)} issue(s)"
                ),
                evidence=[_tls_evidence(ctx, service, assessment)],
                confidence=0.9,
            )

        if not assessments:
            return
        if all_issues:
            yield ctx.candidate(
                f"{len(all_issues)} TLS weakness(es) across "
                f"{len({id(item[0]) for item in all_issues})} endpoint(s)",
                detail="; ".join(
                    f"{service.key}: {issue.summary}" for service, issue in all_issues[:12]
                ),
                cwe=all_issues[0][1].cwe,
                confidence=0.9,
                evidence=[
                    _tls_evidence(ctx, service, by_key[service.key])
                    for service, _ in all_issues[:8]
                ],
            )
        else:
            yield ctx.clean(
                f"no TLS weakness found on {len(assessments)} endpoint(s)",
                detail=(
                    "No deprecated protocol was negotiated, no weak suite in the probe list was "
                    "accepted, and the certificates were valid, trusted and correctly named "
                    "(for the certificate's own host)."
                ),
                evidence=[
                    ctx.evidence("artifact", {"endpoints": assessments}, source=ctx.asset.key)
                ],
                confidence=0.7,
            )


class CveCorrelate(NetworkCheck, Module):
    """``m2.cve-correlate`` — version → CVE/EPSS correlation (research ch02#29)."""

    metadata = CheckMetadata(
        id="m2.cve-correlate",
        module="M2",
        name="cve-correlate",
        version="1.0",
        title="CVE/EPSS correlation",
        description=(
            "Matches the product and version M2 fingerprinted against the offline CVE/EPSS "
            "index, and reports every known CVE whose version range the observed version falls "
            "in. Optional online enrichment through the vulners provider when the deployment "
            "has configured a key. Sends nothing to the target."
        ),
        research_ref="ch02#29",
        framework=("WSTG-CONF-01", "CWE-1035"),
        cwe="CWE-1035",
        target_kinds=_NETWORK_KINDS,
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=0,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        index = cve_index_for(ctx)
        by_product = index.by_product()
        services = services_of(inventory, ctx.asset)
        versioned = [
            service for service in services if service.identity and service.identity.versioned
        ]

        matches: list[tuple[ServiceRecord, MatchResult]] = []
        for service in versioned:
            product = service.identity.product if service.identity else None
            version = service.identity.version if service.identity else None
            if not product or not version:
                continue
            entries: tuple[CveEntry, ...] = ()
            for name in _product_keys(product):
                entries = by_product.get(name, ())
                if entries:
                    break
            for entry in entries:
                if entry.match is not None:
                    continue  # a signal entry, handled below
                if version_matches(version, entry.constraints):
                    matches.append(
                        (
                            service,
                            MatchResult(
                                entry=entry, version=version, constraints=entry.constraints
                            ),
                        )
                    )

        # A configuration signal (SMBv1 enabled, a 3DES-only cipher list) is a match even
        # when nothing has a version, so it is computed before the "nothing to do" exit.
        signal_matches = _signal_matches(index, services)

        online: dict[str, list[dict[str, Any]]] = {}
        if versioned and (not matches or ctx.config.vulners_api_key is not None):
            online = await _vulners_enrich(ctx, versioned)

        evidence: list[Evidence] = [
            ctx.evidence(
                "artifact",
                {
                    "index_version": index.index_version,
                    "versioned_services": [
                        {
                            "service": service.key,
                            "product": service.identity.product if service.identity else None,
                            "version": service.identity.version if service.identity else None,
                        }
                        for service in versioned[:64]
                    ],
                    "matches": [
                        {"service": service.key, **match.to_dict()}
                        for service, match in matches[:64]
                    ],
                    "signal_matches": [
                        {"service": service.key, **match.to_dict()}
                        for service, match in signal_matches
                    ],
                    "online": online,
                },
                source=ctx.asset.key,
            )
        ]

        if not versioned and not signal_matches:
            yield ctx.info(
                f"no fingerprinted product/version to correlate for {ctx.asset.key}",
                detail=(
                    "CVE correlation needs a product and a version; M2 reports one only when a "
                    "banner or handshake actually named it (m2.service-fingerprint). Nothing is "
                    "guessed, so an unidentified service correlates with nothing."
                ),
                evidence=evidence,
                confidence=0.5,
            )
            return

        yield ctx.info(
            f"correlated {len(versioned)} versioned service(s): "
            f"{len(matches) + len(signal_matches)} CVE match(es)",
            detail=(
                f"offline index {index.index_version}"
                + (f"; online enrichment for {len(online)} product(s)" if online else "")
            ),
            evidence=evidence,
            confidence=0.9,
        )

        for service, match in matches:
            yield ctx.candidate(
                f"{match.entry.cve}: {match.entry.title} ({service.product} {match.version})",
                detail=(
                    f"{service.host}:{service.port} runs {service.product} {match.version}, which "
                    f"falls in the affected range of {match.entry.cve} "
                    f"(CVSS {match.entry.cvss if match.entry.cvss is not None else 'n/a'}, "
                    f"EPSS {match.entry.epss if match.entry.epss is not None else 'n/a'})."
                    f"{_kev_note(match.entry)} "
                    f"{match.entry.impact} Remediation: {match.entry.remediation}"
                ),
                cwe=match.entry.cwe,
                confidence=0.8,
                evidence=[*evidence, _match_evidence(ctx, service, match)],
            )

        for service, match in signal_matches:
            yield ctx.candidate(
                f"{match.entry.cve}: {match.entry.title} "
                f"({service.effective_service} on {service.key})",
                detail=(
                    f"The {service.effective_service} configuration observed on {service.key} "
                    f"matches the {match.entry.cve} condition (CVSS "
                    f"{match.entry.cvss if match.entry.cvss is not None else 'n/a'}). "
                    f"{match.entry.impact} Remediation: {match.entry.remediation}"
                ),
                cwe=match.entry.cwe,
                confidence=0.7,
                evidence=[*evidence, _match_evidence(ctx, service, match)],
            )


# --------------------------------------------------------------------------- helpers
def _product_keys(product: str) -> tuple[str, ...]:
    """Candidate index keys for a fingerprinted product name."""
    from arachne.modules.m2.catalog import normalize_product

    normalized = normalize_product(product)
    keys = [normalized]
    if " " in normalized:
        keys.append(normalized.split(" ", 1)[0])
    if "/" in normalized:
        keys.append(normalized.replace(" ", ""))
    return tuple(dict.fromkeys(keys))


def _signal_matches(
    index: Any, services: tuple[ServiceRecord, ...]
) -> list[tuple[ServiceRecord, MatchResult]]:
    """CVE entries triggered by an observed configuration, not by a version number."""
    matches: list[tuple[ServiceRecord, MatchResult]] = []
    for service in services:
        signals: list[str] = []
        if service.effective_service == "smb":
            notes = service.notes.get("smb") or {}
            if notes.get("smb1_supported") or notes.get("dialect_revision") == 1:
                signals.append("smb1-supported")
        if service.tls is not None:
            if any(item.supported and item.version == "SSLv3" for item in service.tls.versions):
                signals.append("sslv3-supported")
            if any(
                "3DES" in cipher.upper() or "DES-CBC3" in cipher.upper()
                for cipher in service.tls.ciphers
            ):
                signals.append("3des-cipher")
        for signal in signals:
            for entry in index.for_signal(signal):
                matches.append(
                    (
                        service,
                        MatchResult(entry=entry, version=signal, constraints=entry.constraints),
                    )
                )
    return matches


def _kev_note(entry: Any) -> str:
    """One sentence for a CISA-KEV row, empty otherwise (the signal an operator acts on first)."""
    return " This CVE is in CISA's Known Exploited Vulnerabilities catalogue." if entry.kev else ""


def _match_evidence(ctx: CheckContext, service: ServiceRecord, match: MatchResult) -> Evidence:
    entry = match.entry
    return ctx.evidence(
        "artifact",
        {
            "cve": entry.cve,
            "title": entry.title,
            "product": entry.product,
            "vendor": entry.vendor,
            "observed_version": match.version,
            "constraints": [item.to_dict() for item in match.constraints],
            "cvss": entry.cvss,
            "epss": entry.epss,
            "kev": entry.kev,
            "cwe": entry.cwe,
            "references": list(entry.references),
            "service": service.evidence_payload(),
        },
        source=service.key,
    )


def _cert_name(assessment: TlsAssessment) -> str:
    """The certificate's common name, or a readable placeholder when none was presented."""
    if assessment.certificate is None or not assessment.certificate.common_name:
        return "not presented"
    return assessment.certificate.common_name


def _tls_evidence(ctx: CheckContext, service: ServiceRecord, assessment: TlsAssessment) -> Evidence:
    return ctx.evidence("tls_certificate", assessment.to_dict(), source=service.key)


def _is_address(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


# --------------------------------------------------------------------------- vulners
def vulners_url(product: str, version: str) -> str:
    """The vulners search endpoint for one product/version (F-09-03 online enrichment)."""
    from urllib.parse import quote

    query = f"{product} {version}"
    return (
        f"https://vulners.com/api/v3/search/lucene/?query={quote(f'type:cve AND {query}')}&size=10"
    )


async def _vulners_enrich(
    ctx: CheckContext, versioned: list[ServiceRecord]
) -> dict[str, list[dict[str, Any]]]:
    """Query the vulners index for the fingerprinted versions (opt-in, budgeted, audited).

    Returns ``{}`` unless the deployment enabled the provider *and* supplied a key. Every
    failure degrades to "no online enrichment", because a third-party feed being unavailable
    must not turn into a failed check .
    """
    if ctx.osint is None or not ctx.osint.available("vulners"):
        return {}
    if ctx.config.vulners_api_key is None:
        return {}
    headers = {"X-Api-Key": ctx.config.vulners_api_key.get_secret_value()}
    results: dict[str, list[dict[str, Any]]] = {}
    for service in versioned[:MAX_VULNERS_LOOKUPS]:
        if not ctx.osint.can_spend():
            break
        if not service.identity or not service.identity.product or not service.identity.version:
            continue
        key = f"{service.identity.product} {service.identity.version}"
        try:
            response = await ctx.osint.fetch(
                "vulners",
                vulners_url(service.identity.product, service.identity.version),
                headers=headers,
            )
        except OsintError:
            continue
        if not response.ok:
            continue
        results[key] = _parse_vulners(response.json())
    return results


def _parse_vulners(document: Any) -> list[dict[str, Any]]:
    """Bounded extraction of the CVE entries a vulners lucene search returns."""
    if not isinstance(document, dict):
        return []
    data = document.get("data")
    rows = data.get("search") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return []
    entries: list[dict[str, Any]] = []
    for row in rows[:10]:
        if not isinstance(row, dict):
            continue
        identifier = str(row.get("id", ""))
        raw_source = row.get("_source")
        source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
        if not identifier.startswith("CVE-"):
            continue
        cvss = row.get("cvss")
        entries.append(
            {
                "cve": identifier,
                "title": str(source.get("title") or row.get("title") or ""),
                "cvss": cvss.get("score") if isinstance(cvss, dict) else cvss,
                "href": row.get("href"),
            }
        )
    return entries
