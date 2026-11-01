"""Threat-intel feeds: sources, verification, sync, freshness and the generated baseline.

The five properties these tests pin, in the order the requirements list them:

* **REQ-INTEL-001** — NVD/KEV/EPSS parse into one normalised, versioned document; a sync
  resumes from its cursor; a stored feed carries its freshness; the CVE index is a generated
  baseline plus the curated overlay.
* **REQ-INTEL-002** — a payload is verified *before* it is imported, and the tampered-fixture
  test is the accept criterion: one changed byte, no import, one blocked audit line.
* **REQ-INTEL-005** — a deployment with intel switched off builds no sync service at all, and
  a source without a pin is refused rather than waved through.

Everything runs against recorded fixtures, so the whole path — parse, verify, import, audit,
freshness, baseline generation — is exercised with no packet leaving the process.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import (
    DEFAULT_FRESHNESS_TTL_HOURS,
    INTEL_FEED_HOSTS,
    IntelSettings,
    Settings,
    reset_settings_cache,
)
from arachne.core.errors import ConfigurationError, FeedIntegrityError
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.feed_store import FeedStore
from arachne.intel.freshness import intel_snapshot, observations_from_store
from arachne.intel.index_builder import (
    build_baseline,
    load_product_map,
    parse_product_map,
    range_to_affected,
)
from arachne.intel.sources import (
    SOURCES,
    epss_url,
    nvd_url,
    nvd_window,
    parse_source,
    source_for,
)
from arachne.intel.sync import (
    FixtureFeedTransport,
    build_sync_service,
    canonical_payload,
)
from arachne.intel.verify import (
    VerificationPolicy,
    normalise_digest,
    parse_checksum_manifest,
    resolve_expectations,
    verify_payload,
    verify_rsa_pkcs1_sha256,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "intel"
PINS: dict[str, str] = json.loads((FIXTURES / "checksums.json").read_text(encoding="utf-8"))


def _fixture_body(source: str) -> str:
    return str(json.loads((FIXTURES / f"{source}.json").read_text(encoding="utf-8"))["body"])


@pytest.fixture
def store(tmp_path: Path) -> Iterator[FeedStore]:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'intel.db'}")
    create_all(engine)
    factory = create_session_factory(engine)
    try:
        yield FeedStore(factory, directory=tmp_path / "feeds")
    finally:
        engine.dispose()


@pytest.fixture
def auditor() -> Auditor:
    return Auditor(MemoryAuditSink(), actor="pytest")


def _settings(**overrides: Any) -> IntelSettings:
    base = IntelSettings(
        enabled=True,
        fixtures_dir=str(FIXTURES),
        checksums=tuple(PINS.items()),
        request_delay_s=0.0,
        max_pages=2,
    )
    return replace(base, **overrides)


# ------------------------------------------------------------------ allowlist
def test_the_feed_sources_and_the_deployment_allowlist_agree() -> None:
    """One table decides which hosts a sync may contact; a source cannot widen it."""
    assert set(SOURCES) == set(INTEL_FEED_HOSTS)
    assert source_for("NVD").name == "nvd"
    with pytest.raises(ConfigurationError, match="unknown intel feed source"):
        source_for("osv")


def test_the_sync_client_scope_is_exactly_the_source_hosts() -> None:
    settings = _settings()
    assert set(settings.source_hosts()) == set(INTEL_FEED_HOSTS.values())


# ------------------------------------------------------------------ parsing
def test_an_nvd_page_is_normalised_with_ranges_cvss_and_references() -> None:
    document = parse_source("nvd", _fixture_body("nvd"))
    assert document.kind == "nvd"
    assert document.version == "2026-10-29T00:00:00.000"
    assert document.record_count == 5
    record = document.entries["CVE-2024-6387"]
    assert record["cvss"] == 8.1
    assert record["cvss_severity"] == "HIGH"
    assert record["cwe"] == "CWE-364"
    assert record["cpe_ranges"][0]["vendor"] == "openbsd"
    assert record["cpe_ranges"][0]["version_end_excluding"] == "9.8"
    assert any("openwall.com" in url for url in record["references"])
    # The English description is kept and the Spanish one is not.
    assert "signal handler race" in record["title"].lower()
    assert "ignorado" not in record["title"]


def test_a_kev_catalogue_is_versioned_and_flags_every_row() -> None:
    document = parse_source("kev", _fixture_body("kev"))
    assert document.version == "2026.10.29"
    assert document.published_at == "2026-10-29T14:00:00.000Z"
    assert all(entry["kev"] is True for entry in document.entries.values())
    assert "CVE-2024-6387" in document.entries


def test_an_epss_page_is_versioned_by_score_date() -> None:
    document = parse_source("epss", _fixture_body("epss"))
    assert document.version == "2026-10-29"
    assert document.cursor == {"since": "2026-10-29"}
    assert document.entries["CVE-2021-44228"]["epss"] == pytest.approx(0.97507)


def test_a_malformed_document_is_refused_with_the_reason() -> None:
    with pytest.raises(ConfigurationError, match="not valid JSON"):
        parse_source("kev", "{not json")
    with pytest.raises(ConfigurationError, match="needs a 'vulnerabilities' list"):
        parse_source("kev", json.dumps({"catalogVersion": "1"}))
    with pytest.raises(ConfigurationError, match="needs a 'data' list"):
        parse_source("epss", json.dumps({"status": "OK"}))


def test_the_nvd_url_carries_the_modification_window_and_refuses_a_long_one() -> None:
    start = datetime(2026, 10, 1, tzinfo=UTC)
    end = datetime(2026, 10, 2, tzinfo=UTC)
    url = nvd_url(last_mod_start=start, last_mod_end=end, start_index=2000)
    assert "lastModStartDate=2026-10-01T00%3A00%3A00.000Z" in url
    assert "startIndex=2000" in url
    assert "resultsPerPage=2000" in url
    with pytest.raises(ConfigurationError, match="at most 120 days"):
        nvd_url(last_mod_start=datetime(2026, 1, 1, tzinfo=UTC), last_mod_end=end)


def test_the_epss_url_takes_since_or_date_but_not_both() -> None:
    assert "since=2026-10-29" in epss_url(since="2026-10-29")
    assert "date=2026-10-29" in epss_url(date="2026-10-29")
    with pytest.raises(ConfigurationError, match="not both"):
        epss_url(since="2026-10-29", date="2026-10-29")


def test_the_nvd_window_resumes_from_the_cursor_with_a_one_day_overlap() -> None:
    cursor = {"last_mod_end": "2026-10-20T00:00:00.000"}
    start, end = nvd_window(cursor=cursor, now=datetime(2026, 10, 30, tzinfo=UTC))
    assert end == datetime(2026, 10, 30, tzinfo=UTC)
    assert start == datetime(2026, 10, 19, tzinfo=UTC)


def test_the_nvd_window_without_a_cursor_is_the_api_maximum() -> None:
    start, end = nvd_window(cursor=None, now=datetime(2026, 10, 30, tzinfo=UTC))
    assert (end - start).days == 120


# ------------------------------------------------------------------ verification
def test_a_matching_digest_verifies() -> None:
    body = _fixture_body("kev").encode("utf-8")
    result = verify_payload(
        source="kev",
        payload=body,
        policy=VerificationPolicy(mode="checksum", digests={"kev": PINS["kev"]}),
    )
    assert result.verified
    assert result.digest == PINS["kev"]
    assert result.reason is None


def test_a_single_changed_byte_is_refused() -> None:
    """REQ-INTEL-002's accept criterion: a tampered payload cannot pass verification."""
    body = _fixture_body("kev").encode("utf-8")
    tampered = body.replace(b"Log4Shell", b"Log4Shel1")
    assert tampered != body
    result = verify_payload(
        source="kev",
        payload=tampered,
        policy=VerificationPolicy(mode="checksum", digests={"kev": PINS["kev"]}),
    )
    assert not result.verified
    assert "sha256 mismatch" in (result.reason or "")


def test_a_source_with_no_pin_is_refused_not_waved_through() -> None:
    result = verify_payload(
        source="nvd",
        payload=b"{}",
        policy=VerificationPolicy(mode="checksum", digests={"kev": PINS["kev"]}),
    )
    assert not result.verified
    assert "no pinned sha256" in (result.reason or "")


def test_a_detached_signature_verifies_against_the_pinned_key() -> None:
    body = _fixture_body("kev").encode("utf-8")
    key = (FIXTURES / "signing-key.pub.pem").read_text(encoding="utf-8")
    signature = (FIXTURES / "kev.sig").read_bytes()
    verify_rsa_pkcs1_sha256(key, body, signature)
    result = verify_payload(
        source="kev",
        payload=body,
        policy=VerificationPolicy(mode="signature", public_key_pem=key),
        signature=signature,
    )
    assert result.verified
    assert result.key_id


def test_a_tampered_payload_cannot_reuse_the_signature() -> None:
    key = (FIXTURES / "signing-key.pub.pem").read_text(encoding="utf-8")
    signature = (FIXTURES / "kev.sig").read_bytes()
    body = _fixture_body("kev").encode("utf-8") + b" "
    result = verify_payload(
        source="kev",
        payload=body,
        policy=VerificationPolicy(mode="signature", public_key_pem=key),
        signature=signature,
    )
    assert not result.verified
    assert "does not match" in (result.reason or "")
    with pytest.raises(FeedIntegrityError):
        verify_rsa_pkcs1_sha256(key, body, signature)


def test_signature_mode_without_a_signature_is_refused() -> None:
    key = (FIXTURES / "signing-key.pub.pem").read_text(encoding="utf-8")
    result = verify_payload(
        source="kev",
        payload=b"payload",
        policy=VerificationPolicy(mode="signature", public_key_pem=key),
    )
    assert not result.verified
    assert "no detached signature" in (result.reason or "")


def test_a_manifest_file_and_inline_pins_resolve_together() -> None:
    pins = resolve_expectations(
        inline={"epss": PINS["epss"]}, manifest=str(FIXTURES / "checksums.json")
    )
    assert pins["kev"] == normalise_digest(PINS["kev"])
    assert pins["epss"] == normalise_digest(PINS["epss"])
    parsed = parse_checksum_manifest("nvd=sha256:" + "a" * 64)
    assert parsed["nvd"] == "sha256:" + "a" * 64
    with pytest.raises(ConfigurationError, match="not a SHA-256"):
        normalise_digest("sha256:xyz")


def test_the_canonical_payload_of_one_page_is_the_file_itself() -> None:
    """A single-request source is verified over its raw body, so an operator's pin is
    exactly what ``sha256sum`` prints for the file they fetched."""
    from arachne.intel.sync import FeedPayload

    one = FeedPayload(source="kev", url="u", body=b"abc")
    assert canonical_payload([one]) == b"abc"
    two = [one, FeedPayload(source="kev", url="u", body=b"de")]
    expected = (3).to_bytes(8, "big") + b"abc" + (2).to_bytes(8, "big") + b"de"
    assert canonical_payload(two) == expected


# ------------------------------------------------------------------ sync from fixtures
def _service(store: FeedStore, auditor: Auditor, **overrides: Any) -> Any:
    return build_sync_service(
        store, _settings(**overrides), auditor=auditor, imported_by="pytest", transport=None
    )


def test_a_sync_from_recorded_fixtures_imports_every_verified_feed(
    store: FeedStore, auditor: Auditor
) -> None:
    outcome = asyncio.run(_service(store, auditor).sync())
    statuses = {item.source: item.status for item in outcome}
    assert statuses == {"nvd": "imported", "kev": "imported", "epss": "imported"}
    feeds = {record.kind: record for record in store.list_feeds()}
    assert set(feeds) == {"nvd", "kev", "epss"}
    assert feeds["kev"].version == "kev@2026.10.29"
    assert feeds["kev"].record_count == 2
    # Every import records its own verification, so the report can state it later.
    assert feeds["kev"].meta["verified"] is True
    assert feeds["kev"].meta["verification"]["mode"] == "checksum"
    assert feeds["kev"].meta["sha256"] == PINS["kev"]
    assert feeds["nvd"].meta["cursor"]["last_mod_end"] == "2026-10-29T00:00:00.000"


def test_the_sync_is_audited_end_to_end(store: FeedStore, auditor: Auditor) -> None:
    sink = auditor._sink  # type: ignore[attr-defined]
    assert isinstance(sink, MemoryAuditSink)
    asyncio.run(_service(store, auditor).sync(["kev"]))
    # Fixture replay records no ``intel.feed_fetched`` (nothing was fetched); the integrity
    # decision and the import are always recorded.
    assert sink.of_action(AuditAction.INTEL_FEED_VERIFIED)
    synced = sink.of_action(AuditAction.INTEL_FEED_SYNCED)
    assert len(synced) == 1
    assert synced[0].meta["version"] == "kev@2026.10.29"
    assert synced[0].meta["digest"] == PINS["kev"]


def test_a_second_sync_of_the_same_version_imports_nothing(
    store: FeedStore, auditor: Auditor
) -> None:
    asyncio.run(_service(store, auditor).sync(["kev"]))
    again = asyncio.run(_service(store, auditor).sync(["kev"]))
    assert again[0].status == "unchanged"
    assert len(store.list_feeds(kind="kev")) == 1


def test_a_tampered_fixture_is_refused_and_nothing_is_imported(
    store: FeedStore, auditor: Auditor, tmp_path: Path
) -> None:
    """The REQ-INTEL-002 accept criterion, end to end: refuse, audit, import nothing."""
    import asyncio

    tampered_dir = tmp_path / "tampered"
    tampered_dir.mkdir()
    for name in ("nvd.json", "kev.json", "epss.json"):
        payload = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
        if name == "kev.json":
            payload["body"] = payload["body"].replace("Log4Shell", "Log4Shel1")
        (tampered_dir / name).write_text(json.dumps(payload), encoding="utf-8")

    service = build_sync_service(
        store, _settings(fixtures_dir=str(tampered_dir)), auditor=auditor, transport=None
    )
    outcome = asyncio.run(service.sync())
    assert {item.source: item.status for item in outcome} == {
        "nvd": "imported",
        "kev": "rejected",
        "epss": "imported",
    }
    assert "sha256 mismatch" in (outcome[1].reason or "")
    assert store.list_feeds(kind="kev") == ()
    rejected = auditor._sink.of_action(AuditAction.INTEL_FEED_REJECTED)  # type: ignore[attr-defined]
    assert len(rejected) == 1
    assert rejected[0].meta["source"] == "kev"


def test_an_unpinned_source_is_refused(store: FeedStore, auditor: Auditor) -> None:
    import asyncio

    service = build_sync_service(
        store,
        _settings(checksums=(("nvd", PINS["nvd"]),)),
        auditor=auditor,
        transport=None,
    )
    outcome = asyncio.run(service.sync(["kev"]))
    assert outcome[0].status == "rejected"
    assert "no pinned sha256" in (outcome[0].reason or "")
    assert store.list_feeds(kind="kev") == ()


def test_pinning_records_the_digests_and_then_verifies_against_them(
    store: FeedStore, auditor: Auditor
) -> None:
    import asyncio

    service = _service(store, auditor, checksums=())
    pins, outcome = asyncio.run(service.fetch_and_pin(["kev"]))
    assert pins == {"kev": PINS["kev"]}
    assert outcome[0].status == "pinned"
    # Nothing was imported by the pinning pass itself.
    assert store.list_feeds(kind="kev") == ()
    assert auditor._sink.of_action(AuditAction.INTEL_CHECKSUMS_PINNED)  # type: ignore[attr-defined]


def test_the_sync_requires_the_master_switch(store: FeedStore, auditor: Auditor) -> None:
    with pytest.raises(ConfigurationError, match="ARACHNE_INTEL_ENABLED"):
        build_sync_service(store, IntelSettings(enabled=False), auditor=auditor)


def test_signature_mode_syncs_a_signed_fixture(store: FeedStore, auditor: Auditor) -> None:
    import asyncio

    service = build_sync_service(
        store,
        _settings(
            verify="signature",
            checksums=(),
            public_key=str(FIXTURES / "signing-key.pub.pem"),
        ),
        auditor=auditor,
        transport=None,
    )
    outcome = asyncio.run(service.sync(["kev"]))
    assert outcome[0].status == "imported"
    assert store.active("kev").meta["verification"]["key_id"]  # type: ignore[union-attr]


def test_the_fixture_transport_never_dials(store: FeedStore) -> None:
    transport = FixtureFeedTransport(FIXTURES)
    assert set(transport.sources()) == {"nvd", "kev", "epss"}


# ------------------------------------------------------------------ freshness
def test_freshness_reports_age_ttl_state_and_missing_feeds(store: FeedStore) -> None:
    import asyncio

    asyncio.run(
        build_sync_service(
            store, _settings(), auditor=Auditor(MemoryAuditSink(), actor="pytest"), transport=None
        ).sync()
    )
    now = datetime.now(UTC)
    observations = observations_from_store(
        store, ttl_hours=dict(DEFAULT_FRESHNESS_TTL_HOURS), now=now
    )
    by_kind = {item.kind: item for item in observations}
    assert by_kind["kev"].verified is True
    assert by_kind["kev"].stale is False
    assert by_kind["kev"].age_hours is not None
    # The curated `cve` snapshot was never ingested, and says so instead of pretending.
    assert by_kind["cve"].imported_at is None


def test_a_feed_past_its_ttl_is_stale(store: FeedStore) -> None:
    import asyncio

    asyncio.run(
        build_sync_service(
            store, _settings(), auditor=Auditor(MemoryAuditSink(), actor="pytest"), transport=None
        ).sync(["kev"])
    )
    later = datetime.now(UTC) + timedelta(days=30)
    observations = observations_from_store(store, ttl_hours={"kev": 24.0}, now=later)
    kev = next(item for item in observations if item.kind == "kev")
    assert kev.stale is True
    assert kev.age_hours is not None and kev.age_hours > 24


def test_the_intel_snapshot_separates_stale_from_missing(store: FeedStore) -> None:
    import asyncio

    asyncio.run(
        build_sync_service(
            store, _settings(), auditor=Auditor(MemoryAuditSink(), actor="pytest"), transport=None
        ).sync(["kev"])
    )
    settings = Settings(database_url="sqlite:///:memory:")
    snapshot = intel_snapshot(store, settings=settings)
    assert snapshot["stale"] is False
    assert set(snapshot["missing"]) == {"nvd", "epss", "cve"}
    assert [feed["kind"] for feed in snapshot["feeds"]].count("kev") == 1
    # Freshness never carries a provider key — only provider names, and only when enabled.
    assert snapshot["providers"] == {"enabled": [], "opted_in": []}


def test_a_snapshot_without_a_store_still_describes_every_kind() -> None:
    snapshot = intel_snapshot(None, settings=Settings(database_url="sqlite:///:memory:"))
    assert {feed["kind"] for feed in snapshot["feeds"]} == {"epss", "kev", "cve", "nvd"}
    assert all(feed["imported_at"] is None for feed in snapshot["feeds"])


# ------------------------------------------------------------------ generated baseline
def test_the_baseline_covers_only_mapped_products() -> None:
    document = parse_source("nvd", _fixture_body("nvd"))
    records = [{"cve": cve, **entry} for cve, entry in document.entries.items()]
    index = build_baseline(
        records,
        products=load_product_map(),
        epss={"CVE-2024-6387": 0.42},
        kev={"CVE-2024-6387"},
        source="nvd@test",
        now=datetime(2026, 10, 29, tzinfo=UTC),
    )
    cves = {entry["cve"] for entry in index.entries}
    assert cves == {
        "CVE-2024-6387",
        "CVE-2023-25690",
        "CVE-2024-24989",
        "CVE-2023-45145",
    }
    # The unmapped product (widgetizer) is filtered out — it is not something M2 fingerprints.
    assert "CVE-2023-9999" not in cves
    ssh = next(entry for entry in index.entries if entry["cve"] == "CVE-2024-6387")
    assert ssh["product"] == "openssh"
    assert ssh["kev"] is True
    assert ssh["epss"] == 0.42
    assert ssh["affected"] == [{"op": "<", "version": "9.8"}]


def test_the_generated_baseline_round_trips_through_the_m2_loader(tmp_path: Path) -> None:
    from arachne.intel.index_builder import write_baseline
    from arachne.modules.m2.catalog import load_cve_index

    document = parse_source("nvd", _fixture_body("nvd"))
    records = [{"cve": cve, **entry} for cve, entry in document.entries.items()]
    index = build_baseline(records, products=load_product_map(), source="nvd@test")
    path = write_baseline(index, tmp_path / "baseline.yaml")
    loaded = load_cve_index(baseline=path)
    assert loaded.index_version.startswith("nvd-")
    # The generated rows arrive, and the bundled overlay is merged on top of them.
    generated = {entry["cve"] for entry in index.entries}
    assert generated <= {entry.cve for entry in loaded.entries}
    assert len(loaded.entries) >= index.count
    # And the index a scan reads by default still validates with both layers.
    assert load_cve_index().entries


def test_the_shipped_baseline_is_the_one_the_generator_produces() -> None:
    """The committed baseline is generated data: regenerating it must not change it."""
    from importlib.resources import files

    generated = build_baseline(
        [
            {"cve": cve, **entry}
            for cve, entry in parse_source("nvd", _fixture_body("nvd")).entries.items()
        ],
        products=load_product_map(),
        epss={"CVE-2024-6387": 0.4211, "CVE-2023-25690": 0.15},
        kev={"CVE-2024-6387", "CVE-2021-44228"},
        source="nvd@2026-10-29T00:00:00.000",
        now=datetime(2026, 10, 29, tzinfo=UTC),
    )
    shipped = files("arachne.templates").joinpath("m2/cve-index-baseline.yaml").read_text("utf-8")
    assert generated.to_yaml() == shipped


def test_the_curated_overlay_wins_on_a_repeated_product_and_cve() -> None:
    from arachne.modules.m2.catalog import CveEntry, CveIndex, merge_cve_indexes

    generated = CveIndex(
        index_version="gen",
        source="nvd@test",
        entries=(
            CveEntry(
                product="openssh",
                cve="CVE-2024-6387",
                title="generated title",
                cvss=8.1,
                kev=True,
                affected=({"op": "<", "version": "9.8"},),
            ),
            CveEntry(product="redis", cve="CVE-2023-45145", title="generated redis"),
        ),
    )
    overlay = CveIndex(
        index_version="curated",
        entries=(
            CveEntry(
                product="OpenSSH",
                cve="CVE-2024-6387",
                title="curated title",
                remediation="upgrade",
            ),
        ),
    )
    merged = merge_cve_indexes(baseline=generated, overlay=overlay)
    assert merged.index_version == "gen+curated"
    openssh = [entry for entry in merged.entries if entry.cve == "CVE-2024-6387"]
    assert len(openssh) == 1
    assert openssh[0].title == "curated title"
    # A generated row the overlay does not mention survives.
    assert [entry.cve for entry in merged.entries if entry.product == "redis"] == ["CVE-2023-45145"]


def test_the_product_map_and_the_curated_index_agree() -> None:
    """Every product the generator can emit must be a name the curated index also uses."""
    from arachne.modules.m2.catalog import load_cve_index, normalize_product

    products = load_product_map()
    known = {normalize_product(entry.product) for entry in load_cve_index(baseline="off").entries}
    for entry in products.entries:
        assert normalize_product(entry.product) in known, entry.product


def test_a_range_becomes_an_affected_clause() -> None:
    assert range_to_affected({}) == ({"op": "all", "version": ""},)
    assert range_to_affected(
        {"version_start_including": "2.4.0", "version_end_including": "2.4.55"}
    ) == (
        {"op": ">=", "version": "2.4.0"},
        {"op": "<=", "version": "2.4.55"},
    )


def test_a_product_map_without_entries_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="non-empty list"):
        parse_product_map("entries: []")


# ------------------------------------------------------------------ CLI
@pytest.fixture
def intel_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'intel-cli.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.setenv("ARACHNE_INTEL_ENABLED", "true")
    monkeypatch.setenv("ARACHNE_INTEL_FIXTURES", str(FIXTURES))
    monkeypatch.setenv("ARACHNE_INTEL_FEED_CHECKSUMS_FILE", str(FIXTURES / "checksums.json"))
    monkeypatch.setenv("ARACHNE_FEEDS_DIR", str(tmp_path / "feeds"))
    reset_settings_cache()
    try:
        result = CliRunner().invoke(app, ["db", "upgrade"])
        assert result.exit_code == 0, result.output
        yield tmp_path
    finally:
        reset_settings_cache()


def test_the_cli_syncs_verifies_and_reports(intel_cli: Path) -> None:
    runner = CliRunner()
    synced = runner.invoke(app, ["intel", "sync"])
    assert synced.exit_code == 0, synced.output
    assert "imported" in synced.output
    status = runner.invoke(app, ["intel", "status", "--json"])
    assert status.exit_code == 0, status.output
    snapshot = json.loads(status.output)
    assert snapshot["stale"] is False
    kev = next(feed for feed in snapshot["feeds"] if feed["kind"] == "kev")
    assert kev["verified"] is True
    assert kev["version"] == "kev@2026.10.29"


def test_the_cli_refuses_an_unpinned_sync(intel_cli: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARACHNE_INTEL_FEED_CHECKSUMS_FILE")
    reset_settings_cache()
    result = CliRunner().invoke(app, ["intel", "sync", "--source", "kev"])
    assert result.exit_code == 1
    assert "rejected" in result.output
    assert "no pinned sha256" in result.output


def test_the_cli_pins_then_imports(
    intel_cli: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ARACHNE_INTEL_FEED_CHECKSUMS_FILE")
    reset_settings_cache()
    manifest = tmp_path / "pins.json"
    result = CliRunner().invoke(
        app, ["intel", "sync", "--source", "kev", "--pin", "--checksums", str(manifest)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(manifest.read_text()) == {"kev": PINS["kev"]}
    assert "imported" in result.output


def test_the_cli_builds_the_baseline_from_the_synced_corpus(intel_cli: Path) -> None:
    runner = CliRunner()
    assert runner.invoke(app, ["intel", "sync", "--source", "nvd"]).exit_code == 0
    output = intel_cli / "baseline.yaml"
    built = runner.invoke(app, ["intel", "build-index", "--output", str(output)])
    assert built.exit_code == 0, built.output
    assert output.is_file()
    assert "baseline entr" in built.output
    text = output.read_text(encoding="utf-8")
    assert "GENERATED FILE" in text
    assert "CVE-2024-6387" in text


def test_the_cli_verifies_a_file_offline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    reset_settings_cache()
    target = tmp_path / "kev.json"
    target.write_text(_fixture_body("kev"), encoding="utf-8")
    ok = CliRunner().invoke(
        app, ["intel", "verify", str(target), "--source", "kev", "--sha256", PINS["kev"]]
    )
    assert ok.exit_code == 0, ok.output
    assert "verified" in ok.output
    bad = CliRunner().invoke(
        app, ["intel", "verify", str(target), "--source", "kev", "--sha256", "sha256:" + "0" * 64]
    )
    assert bad.exit_code == 1
    assert "REJECTED" in bad.output
    reset_settings_cache()


def test_build_index_without_a_corpus_explains_itself(intel_cli: Path) -> None:
    result = CliRunner().invoke(app, ["intel", "build-index"])
    assert result.exit_code == 2
    assert "intel sync --source nvd" in result.output
