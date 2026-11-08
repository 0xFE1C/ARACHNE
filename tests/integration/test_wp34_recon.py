"""WP-34 acceptance: the reconnaissance-breadth family reports its positive and stays clean.

REQ-DET-027's recon half is DNS and ASN enumeration, virtual-host discovery, certificate
fingerprinting and technology-fingerprint breadth. Each check is driven here through the real
``CheckContext`` — a recorded provider answer for the four that read a third party, a hand-built
crawl inventory for the two that read the crawl, and a live Host-branching origin for the one
that probes a virtual host — with a positive fixture and a decoy beside it:

* an inventory (a delegation set, a mail-exchanger list, a certificate set, an attributed
  network, a co-tenant list, a technology list) **is** the finding, so "firing" means the
  inventory result carries the check's ``signal`` and the decoy must not;
* the two checks that raise a candidate (an expired certificate, a corroborated virtual host)
  must produce a *finding* on the positive and a ``not_vulnerable`` result on the decoy.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.helpers.checks import asset_for, make_osint, run_check
from tests.lab.recon_lab import (
    ORIGIN_BODY,
    PLAIN_BODY,
    VHOST_NAME,
    build_inventory,
    start_vhost_lab,
)

from arachne.modules.m1.recon_breadth import RECON_BREADTH_CHECKS
from arachne.modules.registry import ModuleRegistry

pytestmark = pytest.mark.timeout(300)

#: The providers this family reads. ``whois`` (RDAP) is strictly opt-in, so a test that wants
#: the address-attribution check to run must name it — which is the requirement's own opt-in.
PROVIDERS = ("dns", "crtsh", "internetdb", "whois")
WHOIS_URL = "https://rdap.org/domain/{query}"

DOMAIN = asset_for("domain", "recon.example.com")
CLEAN_DOMAIN = asset_for("domain", "clean.recon.example.com")
FRESH_DOMAIN = asset_for("domain", "fresh.recon.example.com")
ADDRESS = asset_for("host", "198.51.100.10")
CLEAN_ADDRESS = asset_for("host", "198.51.100.11")


def _osint() -> Any:
    return make_osint(providers=PROVIDERS, whois_url=WHOIS_URL)


def _signals(results: list[Any], signal: str) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    for result in results:
        for item in getattr(result, "evidence", ()):
            payload = dict(item.payload)
            if payload.get("signal") == signal:
                found.append(payload)
    return found


def _candidates(results: list[Any]) -> list[Any]:
    return [result for result in results if getattr(result, "status", None) == "vulnerable"]


# --------------------------------------------------------------------------- registry shape
def test_the_family_is_registered_in_m1() -> None:
    from arachne.modules.m1 import M1_CHECKS

    registered = {check.metadata.id for check in M1_CHECKS}
    assert {check.metadata.id for check in RECON_BREADTH_CHECKS} <= registered
    registry = ModuleRegistry.discover()
    assert len(registry.checks()) == 448
    assert len(registry.group("M1").checks) == 25


def test_every_check_is_l1_or_lower_mapped_and_bounded() -> None:
    for check in RECON_BREADTH_CHECKS:
        metadata = check.metadata
        assert metadata.proof.value in {"L0", "L1"}, metadata.id
        assert metadata.safe, metadata.id
        assert not metadata.requires_state_attestation, metadata.id
        assert metadata.framework, metadata.id
        assert metadata.estimated_requests >= 0, metadata.id
        assert metadata.estimated_requests <= 8, metadata.id
        assert metadata.target_kinds, metadata.id


# --------------------------------------------------------------------------- DNS enumeration
async def test_nameserver_inventory_reports_the_delegation_and_is_clean_on_the_decoy() -> None:
    results, _ = await run_check(RECON_BREADTH_CHECKS[0], DOMAIN, osint=_osint())
    payloads = _signals(results, "nameserver-inventory")
    assert payloads and payloads[0]["nameservers"] == ["ns1.example.net", "ns2.example.net"]

    clean, _ = await run_check(RECON_BREADTH_CHECKS[0], CLEAN_DOMAIN, osint=_osint())
    assert _signals(clean, "nameserver-inventory") == []
    assert [result.status for result in clean] == ["not_vulnerable"]


async def test_mail_infrastructure_inventory_reports_the_exchangers_and_is_clean() -> None:
    results, _ = await run_check(RECON_BREADTH_CHECKS[1], DOMAIN, osint=_osint())
    payloads = _signals(results, "mail-infrastructure-inventory")
    assert payloads and payloads[0]["mail_exchangers"] == [
        "10 mail.recon.example.com",
        "20 mail2.recon.example.com",
    ]

    clean, _ = await run_check(RECON_BREADTH_CHECKS[1], CLEAN_DOMAIN, osint=_osint())
    assert _signals(clean, "mail-infrastructure-inventory") == []


# --------------------------------------------------------------------------- certificates
async def test_certificate_inventory_reports_issuers_and_is_clean_without_certificates() -> None:
    results, _ = await run_check(RECON_BREADTH_CHECKS[2], DOMAIN, osint=_osint())
    payloads = _signals(results, "certificate-inventory")
    assert payloads and payloads[0]["certificate_count"] == 2
    assert payloads[0]["issuers"] == ["C=US, O=Example CA"]

    clean, _ = await run_check(RECON_BREADTH_CHECKS[2], CLEAN_DOMAIN, osint=_osint())
    assert _signals(clean, "certificate-inventory") == []
    assert [result.status for result in clean] == ["not_vulnerable"]


async def test_certificate_expiry_fires_on_an_expired_certificate_and_not_on_a_fresh_one() -> None:
    results, _ = await run_check(RECON_BREADTH_CHECKS[3], DOMAIN, osint=_osint())
    candidates = _candidates(results)
    assert candidates and "expired certificate" in candidates[0].title
    assert _signals(results, "certificate-expiry")[0]["state"] == "expired"

    clean, _ = await run_check(RECON_BREADTH_CHECKS[3], FRESH_DOMAIN, osint=_osint())
    assert _candidates(clean) == []
    assert [result.status for result in clean] == ["not_vulnerable"]


# --------------------------------------------------------------------------- addresses
async def test_asn_attribution_reports_the_network_and_is_clean_on_an_unattributed_address() -> (
    None
):
    results, _ = await run_check(RECON_BREADTH_CHECKS[4], ADDRESS, osint=_osint())
    payloads = _signals(results, "asn-network-attribution")
    assert payloads and payloads[0]["name"] == "EXAMPLE-NET"
    assert payloads[0]["start_address"] == "198.51.100.0"

    clean, _ = await run_check(RECON_BREADTH_CHECKS[4], CLEAN_ADDRESS, osint=_osint())
    assert _signals(clean, "asn-network-attribution") == []


async def test_asn_attribution_skips_without_the_opt_in_provider() -> None:
    results, _ = await run_check(
        RECON_BREADTH_CHECKS[4], ADDRESS, osint=make_osint(providers=("dns",))
    )
    assert results[0].status == "info"
    assert any(item.payload.get("skipped") for item in results[0].evidence)


async def test_reverse_ip_cluster_reports_co_tenants_and_is_clean_when_alone() -> None:
    results, _ = await run_check(RECON_BREADTH_CHECKS[5], ADDRESS, osint=_osint())
    payloads = _signals(results, "reverse-ip-cluster")
    assert payloads and payloads[0]["hostnames"] == [
        "recon.example.com",
        "shop.recon.example.com",
        "cdn.example.net",
    ]

    clean, _ = await run_check(RECON_BREADTH_CHECKS[5], CLEAN_ADDRESS, osint=_osint())
    assert _signals(clean, "reverse-ip-cluster") == []
    assert [result.status for result in clean] == ["not_vulnerable"]


# --------------------------------------------------------------------------- crawl readers
async def test_technology_inventory_reports_published_versions() -> None:
    origin = "http://127.0.0.1:8099/"
    inventory = build_inventory(
        origin,
        pages=[
            {
                "url": origin,
                "headers": {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/8.1.2"},
                "body": (
                    "<html><head><meta name='generator' content='WordPress 6.4'></head>"
                    "<body><link href='/wp-content/themes/x.css'></body></html>"
                ),
            }
        ],
    )
    results, _ = await run_check(RECON_BREADTH_CHECKS[6], asset_for("url", origin), web=inventory)
    payloads = _signals(results, "technology-inventory")
    assert payloads, [r.title for r in results]
    technologies = payloads[0]["technologies"]
    assert technologies["nginx"] == "1.18.0"
    assert technologies["php"] == "8.1.2"
    assert technologies["wordpress"] == "6.4"
    assert payloads[0]["requests_issued"] == 0


async def test_technology_inventory_is_clean_on_a_plain_page() -> None:
    origin = "http://127.0.0.1:8099/"
    inventory = build_inventory(origin, pages=[{"url": origin, "body": PLAIN_BODY}])
    results, _ = await run_check(RECON_BREADTH_CHECKS[6], asset_for("url", origin), web=inventory)
    assert _signals(results, "technology-inventory") == []
    assert [result.status for result in results] == ["not_vulnerable"]


async def test_vhost_discovery_finds_the_alternate_name_and_is_clean_on_a_single_site() -> None:
    with start_vhost_lab() as lab:
        origin = f"{lab.base_url}/"
        inventory = build_inventory(origin, pages=[{"url": origin, "body": ORIGIN_BODY}])
        harness = _harness(lab.base_url)
        try:
            results, _ = await run_check(
                RECON_BREADTH_CHECKS[7],
                asset_for("url", origin),
                web=inventory,
                http=harness.client,
                memory=harness.memory,
            )
        finally:
            await harness.aclose()
        assert _candidates(results), [r.title for r in results]
        assert _signals(results, "vhost-discovery")[0]["virtual_host"] == VHOST_NAME
        # The probe asked the origin for the alternate name; it sent nothing else.
        assert any(f"Host={VHOST_NAME}" in entry for entry in lab.requests)

    # A host that answers every name with the same application has no virtual host.
    with start_vhost_lab(vhost="") as lab:
        origin = f"{lab.base_url}/"
        inventory = build_inventory(origin, pages=[{"url": origin, "body": ORIGIN_BODY}])
        harness = _harness(lab.base_url)
        try:
            clean, _ = await run_check(
                RECON_BREADTH_CHECKS[7],
                asset_for("url", origin),
                web=inventory,
                http=harness.client,
                memory=harness.memory,
            )
        finally:
            await harness.aclose()
        assert _candidates(clean) == []


def _harness(base_url: str) -> Any:
    from tests.helpers.m6 import make_m6_harness

    return make_m6_harness(asset=asset_for("url", base_url))


# --------------------------------------------------------------------------- shape
def test_the_family_is_eight_checks() -> None:
    assert len(RECON_BREADTH_CHECKS) == 8
