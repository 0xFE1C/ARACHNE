"""M2's managed data, its matching engines, the certificate reader and the scan backends.

Three things are being protected here:

* **The offline index and the port catalogue are data, and data goes wrong quietly.** A CVE
  entry with a typo in its range would silently report nothing, and a port catalogue with a
  truncated TCP list would silently scan less. Both are validated on load and asserted here.
* **Version matching must fail towards "no match".** A version the matcher cannot parse has to
  come back *unmatched*: a false CVE is worse than a missed one.
* **The certificate reader is the thing that decides whether "expired" is reported.** It is
  checked against real OpenSSL-generated certificates (the committed fixtures) rather than
  hand-built DER, because the point is to read what a real peer presents.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.fixtures_lab import CERT_DIR, expired_certificate_der, valid_certificate_der

from arachne.core.errors import ConfigurationError
from arachne.modules.m2.catalog import (
    CveEntry,
    PortEntry,
    VersionConstraint,
    load_cve_index,
    load_port_catalog,
    normalize_product,
    parse_version,
    version_matches,
)
from arachne.modules.m2.scanners import ConnectBackend, NmapBackend, PortFinding, pick_backend
from arachne.modules.m2.x509 import parse_certificate, parse_der_time


# ------------------------------------------------------------------ port catalogue
def test_the_shipped_port_catalogue_is_ordered_and_labelled() -> None:
    catalog = load_port_catalog()
    assert catalog.catalog_version
    ports = [entry.port for entry in catalog.tcp]
    assert len(ports) == len(set(ports)), "a port must appear once in the catalogue"
    assert ports[:5] == [80, 23, 443, 21, 22], "the list order *is* the frequency rank"
    assert all(entry.service for entry in catalog.tcp)
    assert catalog.top_tcp(10) == tuple(ports[:10])
    assert catalog.top_tcp(0) == ()


def test_the_catalogue_maps_probes_to_ports() -> None:
    catalog = load_port_catalog()
    assert 22 in catalog.ports_for_probe("ssh")
    assert 445 in catalog.ports_for_probe("smb")
    assert 161 in catalog.ports_for_probe("snmp", protocol="udp")
    assert catalog.hint_service(6379) == "redis"
    assert catalog.hint_service(65000) is None
    assert catalog.hint(443) == PortEntry(port=443, service="https", probe="tls")


def test_a_malformed_port_catalogue_is_refused(tmp_path: Path) -> None:
    broken = tmp_path / "ports.yaml"
    broken.write_text("catalog_version: '1'\ntcp: []\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="no TCP ports"):
        load_port_catalog(broken)
    broken.write_text("catalog_version: '1'\ntcp:\n  - {port: 99999}\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="invalid data"):
        load_port_catalog(broken)
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_port_catalog(tmp_path / "absent.yaml")


def test_a_custom_catalogue_replaces_the_shipped_one(tmp_path: Path) -> None:
    """F-09-04: the port policy is managed data, so an operator can point at their own."""
    custom = tmp_path / "ports.yaml"
    custom.write_text(
        "catalog_version: 'lab'\ntcp:\n  - {port: 2222, service: ssh-alt, probe: ssh}\n",
        encoding="utf-8",
    )
    catalog = load_port_catalog(custom)
    assert catalog.top_tcp(10) == (2222,)
    assert catalog.ports_for_probe("ssh") == (2222,)


# ------------------------------------------------------------------ CVE index + matching
def test_the_shipped_index_matches_the_planted_versions() -> None:
    index = load_cve_index()
    by_product = index.by_product()
    openssh = by_product["openssh"]
    regresshion = next(entry for entry in openssh if entry.cve == "CVE-2024-6387")
    assert version_matches("8.5p1", regresshion.constraints)
    assert version_matches("9.7p1", regresshion.constraints)
    assert not version_matches("9.8", regresshion.constraints)
    nginx = by_product["nginx"]
    resolver = next(entry for entry in nginx if entry.cve == "CVE-2021-23017")
    assert version_matches("1.18.0", resolver.constraints)
    assert not version_matches("1.20.1", resolver.constraints)


def test_the_index_exposes_configuration_signals() -> None:
    index = load_cve_index()
    assert [entry.cve for entry in index.for_signal("smb1-supported")] == ["CVE-2017-0144"]
    assert [entry.cve for entry in index.for_signal("sslv3-supported")] == ["CVE-2014-3566"]
    assert index.for_signal("nothing-uses-this") == ()


def test_version_parsing_is_lenient_about_banner_noise_and_strict_about_nonsense() -> None:
    assert parse_version("9.8p1") == (9, 8, 1)
    assert parse_version("1.18.0") == (1, 18, 0)
    assert parse_version("5.5.62-log") == (5, 5, 62)
    assert parse_version("OpenSSH_8.5p1") == (8, 5, 1)
    assert parse_version("no digits here") is None
    assert parse_version("") is None


def test_an_unparseable_version_never_matches() -> None:
    entry = CveEntry(
        product="thing",
        affected=({"op": "<", "version": "9"},),
        cve="CVE-2020-0001",
        title="t",
    )
    assert not version_matches("unknown", entry.constraints)
    assert not version_matches("", entry.constraints)


def test_an_unparseable_constraint_makes_the_entry_unmatched() -> None:
    """Fail closed: a typo in the index must not become a finding."""
    assert not version_matches("1.2.3", (VersionConstraint(op="<", version="abc"),))
    assert version_matches("1.2.3", (VersionConstraint(op="<", version="2.0"),))
    assert not version_matches("2.0", (VersionConstraint(op="<", version="2.0"),))
    assert version_matches("1.2.3", (VersionConstraint(op="<=", version="1.2.3"),))
    assert version_matches("1.2.3", (VersionConstraint(op="all"),))


def test_zero_padding_makes_1_18_and_1_18_0_equivalent() -> None:
    assert version_matches("1.18", (VersionConstraint(op="==", version="1.18.0"),))
    assert version_matches("1.18.0", (VersionConstraint(op="==", version="1.18"),))
    assert not version_matches("1.18.1", (VersionConstraint(op="==", version="1.18"),))


def test_product_names_are_normalized_for_matching() -> None:
    assert normalize_product("Apache httpd") == "apache httpd"
    assert normalize_product("OpenSSH_9.8") == "openssh 9.8"
    assert normalize_product("  Redis  ") == "redis"
    index = load_cve_index()
    aliases = index.by_product()
    assert "apache httpd" in aliases and "apache" in aliases  # both names resolve


def test_a_malformed_index_is_refused(tmp_path: Path) -> None:
    broken = tmp_path / "cve.yaml"
    broken.write_text(
        "index_version: '1'\nentries:\n  - product: x\n    cve: not-a-cve\n", encoding="utf-8"
    )
    with pytest.raises(ConfigurationError, match="invalid data"):
        load_cve_index(broken)


def test_a_cve_entry_can_be_built_in_a_test() -> None:
    entry = CveEntry(
        product="redis",
        aliases=("redis-server",),
        affected=("all",),
        cve="CVE-2022-0543",
        cvss=10.0,
        epss=0.72,
        cwe="CWE-862",
        title="Redis Lua sandbox escape",
        references=("https://example.test/advisory",),
    )
    assert entry.all_versions_affected()
    assert entry.product_names() == ("redis", "redis-server")
    assert entry.constraints == (VersionConstraint(op="all"),)


# ------------------------------------------------------------------ certificates
def test_the_expired_fixture_is_read_as_expired_and_self_signed() -> None:
    info = parse_certificate(expired_certificate_der())
    assert info is not None
    assert info.common_name == "weak-lab.local"
    assert info.is_self_signed
    assert info.expired()
    assert info.not_after is not None and info.not_after.year == 2021
    assert info.subject_alt_names == ("weak-lab.local", "localhost")
    assert info.public_key_bits == 2048
    assert info.public_key_algorithm == "rsaEncryption"
    assert info.signature_algorithm == "sha256WithRSAEncryption"
    assert info.is_ca is False
    assert info.der_length == len(expired_certificate_der())
    assert len(info.sha256) == 64


def test_the_valid_fixture_is_read_as_current() -> None:
    info = parse_certificate(valid_certificate_der())
    assert info is not None
    assert not info.expired()
    assert not info.not_yet_valid()
    assert info.days_until_expiry() is not None and info.days_until_expiry() > 0


def test_hostname_matching_understands_wildcards_and_ip_sans() -> None:
    info = parse_certificate(valid_certificate_der())
    assert info is not None
    assert not info.hostname_mismatch("strong-lab.local")
    assert not info.hostname_mismatch("localhost")
    assert not info.hostname_mismatch("127.0.0.1")
    assert info.hostname_mismatch("elsewhere.example")

    wildcard = parse_certificate(expired_certificate_der())
    assert wildcard is not None
    assert wildcard.hostname_mismatch("127.0.0.1")  # the fixture has no IP SAN
    assert not wildcard.hostname_mismatch("weak-lab.local")


def test_the_certificate_reader_refuses_rubbish() -> None:
    assert parse_certificate(b"") is None
    assert parse_certificate(b"\x30\x03\x02\x01\x01") is None
    assert parse_certificate(b"\xff" * 200) is None


def test_der_time_parsing_handles_both_time_types() -> None:
    utc = parse_der_time(b"200101000000Z")
    assert utc is not None and utc.year == 2020 and utc.month == 1
    general = parse_der_time(b"20360101000000Z")
    assert general is not None and general.year == 2036
    assert parse_der_time(b"nonsense") is None
    # An explicit offset is converted to UTC (the fixtures use the Z form, but a peer may not).
    offset = parse_der_time(b"200101000000+0200")
    assert offset is not None and offset.hour == 22 and offset.day == 31
    assert parse_der_time(b"20010100Z") is None


def test_the_committed_fixtures_exist() -> None:
    for name in ("expired.crt", "expired.key", "valid.crt", "valid.key"):
        assert (CERT_DIR / name).is_file(), f"{name} is a test fixture the TLS tests need"


# ------------------------------------------------------------------ inventory
def test_inventory_tracks_hosts_and_services() -> None:
    from arachne.modules.m2.inventory import NetworkInventory, ServiceIdentity

    inventory = NetworkInventory(max_hosts=4, max_ports=8)
    inventory.mark_alive("10.0.0.1", method="tcp:80")
    service = inventory.add_service("10.0.0.1", 80, service="http")
    assert inventory.live_hosts()[0].address == "10.0.0.1"
    assert inventory.host("10.0.0.1").open_ports() == (80,)
    assert service.effective_service == "http"
    service.identity = ServiceIdentity(protocol="http", product="nginx", version="1.18.0")
    assert service.product == "nginx"
    assert inventory.versioned_services() == (service,)
    assert inventory.services_on_ports([80]) == (service,)
    assert inventory.services_with_protocol("http") == (service,)
    assert inventory.summary()["versioned_services"] == 1
    assert inventory.evidence_payload()["service_count"] == 1


def test_the_inventory_caps_how_many_hosts_it_accepts() -> None:
    from arachne.modules.m2.inventory import NetworkInventory

    inventory = NetworkInventory(max_hosts=2)
    assert inventory.can_add_host()
    inventory.host("10.0.0.1")
    inventory.host("10.0.0.2")
    assert not inventory.can_add_host()


def test_adding_a_service_also_marks_the_host_alive() -> None:
    from arachne.modules.m2.inventory import NetworkInventory

    inventory = NetworkInventory()
    inventory.add_service("10.0.0.9", 443, service="https")
    record = inventory.get("10.0.0.9")
    assert record is not None and record.alive and record.discovery == ["tcp:443"]


def test_addresses_for_an_asset_are_bounded_and_typed() -> None:
    from tests.helpers.checks import asset_for

    from arachne.modules.m2.support import addresses_for_asset

    assert addresses_for_asset(asset_for("host", "10.0.0.5")) == ("10.0.0.5",)
    assert addresses_for_asset(asset_for("domain", "example.test")) == ("example.test",)
    assert addresses_for_asset(asset_for("url", "https://example.test/x")) == ("example.test",)
    network = addresses_for_asset(asset_for("network", "10.0.0.0/29"), max_hosts=3)
    assert network == ("10.0.0.1", "10.0.0.2", "10.0.0.3")
    assert addresses_for_asset(asset_for("git", "https://github.com/a/b")) == ()


# ------------------------------------------------------------------ scan backends
async def test_the_connect_backend_maps_outcomes_to_findings() -> None:
    from tests.helpers.checks import make_m2_harness

    from arachne.core.net import ScriptedNetTransport

    harness = make_m2_harness(routes={("tcp", "93.184.216.34", 22): b"SSH-2.0-x\r\n"})
    backend = ConnectBackend(
        client=harness.client, settings=harness.client.net_settings, hints={22: "ssh"}
    )
    assert backend.name == "connect"
    findings = await backend.probe_ports("93.184.216.34", [22, 23])
    assert [finding.state for finding in findings] == ["open", "closed"]
    assert findings[0].service_hint == "ssh"
    assert findings[0].banner.startswith("SSH-2.0")
    assert isinstance(harness.transport, ScriptedNetTransport)
    with pytest.raises(ValueError, match="TCP only"):
        await backend.probe_ports("93.184.216.34", [161], protocol="udp")


def test_nmap_backend_availability_needs_both_the_module_and_the_binary() -> None:
    from arachne.core.config import NetSettings

    assert (
        NmapBackend.available(NetSettings(nmap_enabled=False), which=lambda name: "/usr/bin/nmap")
        is False
    )
    # The python-nmap module is not installed in this environment, so even with the binary
    # present the backend reports itself unavailable (and the connect scan is used instead).
    assert NmapBackend.available(NetSettings(), which=lambda name: "/usr/bin/nmap") is False
    assert NmapBackend.available(NetSettings(), which=lambda name: None) is False


async def test_the_nmap_backend_maps_a_scan_result_and_bounds_its_run() -> None:
    """The adapter is thin on purpose: this asserts the mapping, with a fake PortScanner."""
    from arachne.core.config import NetSettings

    class FakeScanner:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        def scan(self, **kwargs: object) -> None:
            self.calls.append(kwargs)

        def __getitem__(self, host: str) -> dict[str, object]:
            return {
                "tcp": {
                    22: {
                        "state": "open",
                        "name": "ssh",
                        "product": "OpenSSH",
                        "version": "9.6",
                        "extrainfo": "Ubuntu",
                    },
                    80: {"state": "closed", "name": "http"},
                },
                "udp": {161: {"state": "open|filtered", "name": "snmp"}},
            }

    scanner = FakeScanner()
    backend = NmapBackend(scanner, settings=NetSettings(), hints={22: "ssh-alt"})
    findings = await backend.probe_ports("10.0.0.5", [22, 80])
    assert scanner.calls[0]["hosts"] == "10.0.0.5"
    assert scanner.calls[0]["ports"] == "22,80"
    assert "-sT" in str(scanner.calls[0]["arguments"])
    by_port = {(finding.port, finding.protocol): finding for finding in findings}
    assert by_port[(22, "tcp")].product == "OpenSSH"
    assert by_port[(22, "tcp")].version == "9.6"
    assert by_port[(22, "tcp")].service_hint == "ssh-alt"
    assert by_port[(22, "tcp")].banner == "OpenSSH 9.6 Ubuntu"
    assert by_port[(80, "tcp")].state == "closed"
    assert by_port[(161, "udp")].state == "open|filtered"
    assert all(finding.source == "nmap" for finding in findings)


async def test_the_nmap_backend_degrades_when_the_scan_raises() -> None:
    from arachne.core.config import NetSettings

    class BrokenScanner:
        def scan(self, **kwargs: object) -> None:
            raise RuntimeError("nmap binary missing")

        def __getitem__(self, host: str) -> dict[str, object]:
            raise KeyError(host)

    backend = NmapBackend(BrokenScanner(), settings=NetSettings())
    assert await backend.probe_ports("10.0.0.5", [22]) == ()
    assert backend.last_error is not None and "nmap binary missing" in backend.last_error


def test_pick_backend_falls_back_to_the_connect_scanner() -> None:
    from tests.helpers.checks import make_m2_harness

    harness = make_m2_harness()
    backend = pick_backend(harness.client, settings=harness.client.settings)
    assert backend.name == "connect"
    assert isinstance(backend, ConnectBackend)


def test_port_findings_render_evidence() -> None:
    finding = PortFinding(
        host="10.0.0.1",
        port=443,
        state="open",
        service_hint="https",
        product="nginx",
        version="1.18.0",
        banner="nginx 1.18.0",
        elapsed_ms=1.5,
    )
    payload = finding.to_dict()
    assert payload["state"] == "open"
    assert payload["product"] == "nginx"
    assert payload["banner"] == "nginx 1.18.0"
    closed = PortFinding(host="10.0.0.1", port=80, state="closed")
    assert closed.to_dict() == {
        "host": "10.0.0.1",
        "port": 80,
        "protocol": "tcp",
        "state": "closed",
        "source": "connect",
    }
