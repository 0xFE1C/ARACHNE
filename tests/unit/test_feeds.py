"""CVE/EPSS feed ingestion: validation, normalisation, lookup and M6 wiring (F-09-03, S14)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.feed_store import FeedStore, detect_kind, parse_feed
from arachne.modules.context import ModuleConfig
from arachne.modules.m6.feeds import load_epss

EPSS_CSV = """cve,epss,percentile
CVE-2021-44228,0.97,0.999
CVE-2024-6387,0.42,0.95
"""
KEV_JSON = json.dumps(
    {
        "catalogVersion": "2026.10.29",
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell"},
            {"cveID": "CVE-2017-0144"},
        ],
    }
)
CVE_JSON = json.dumps(
    {
        "version": "internal-1",
        "entries": [
            {"cve": "CVE-2023-0001", "epss": 0.12, "cvss": 9.8, "kev": True},
            "CVE-2023-0002",
        ],
    }
)


@pytest.fixture
def engine(tmp_path: Path) -> Iterator[Engine]:
    created = create_sqlite_engine(f"sqlite:///{tmp_path / 'feeds.db'}")
    create_all(created)
    try:
        yield created
    finally:
        created.dispose()


@pytest.fixture
def factory(engine: Engine) -> sessionmaker[Session]:
    return create_session_factory(engine)


@pytest.fixture
def store(factory: sessionmaker[Session], tmp_path: Path) -> FeedStore:
    return FeedStore(factory, directory=tmp_path / "feeds")


# --------------------------------------------------------------------------- parsing
def test_epss_csv_is_normalised() -> None:
    parsed = parse_feed(EPSS_CSV, kind="epss")
    assert parsed["CVE-2021-44228"]["epss"] == pytest.approx(0.97)
    assert parsed["CVE-2021-44228"]["percentile"] == pytest.approx(0.999)
    assert parsed["CVE-2021-44228"]["kev"] is False


def test_a_kev_document_marks_every_row_as_exploited() -> None:
    parsed = parse_feed(KEV_JSON, kind="kev")
    assert set(parsed) == {"CVE-2021-44228", "CVE-2017-0144"}
    assert all(row["kev"] for row in parsed.values())


def test_a_cve_snapshot_accepts_objects_and_bare_ids() -> None:
    parsed = parse_feed(CVE_JSON, kind="cve")
    assert parsed["CVE-2023-0001"] == {
        "epss": pytest.approx(0.12),
        "percentile": None,
        "kev": True,
        "cvss": pytest.approx(9.8),
    }
    assert parsed["CVE-2023-0002"]["kev"] is False


def test_a_malformed_cve_id_is_a_clear_error() -> None:
    with pytest.raises(ConfigurationError, match="not a CVE id"):
        parse_feed("cve,epss\nnot-a-cve,0.5\n", kind="epss")


def test_a_missing_epss_column_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="needs 'cve' and 'epss'"):
        parse_feed("identifier,score\nCVE-2021-44228,0.5\n", kind="epss")


def test_an_unknown_kind_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="unknown feed kind"):
        parse_feed(EPSS_CSV, kind="osv")


def test_an_nvd_snapshot_is_imported_as_its_own_kind(store: FeedStore, tmp_path: Path) -> None:
    """S18's richer feed kind: the normalised NVD artefact, one row per CVE with ranges."""
    path = tmp_path / "nvd.yaml"
    path.write_text(
        "version: nvd@test\nentries:\n"
        "  - cve: CVE-2024-6387\n"
        "    title: OpenSSH signal-handler race\n"
        "    cvss: 8.1\n"
        "    cwe: CWE-364\n"
        "    cpe_ranges:\n"
        "      - vendor: openbsd\n"
        "        product: openssh\n"
        "        version_end_excluding: '9.8'\n",
        encoding="utf-8",
    )
    record = store.import_file(path, kind="nvd")
    assert record.kind == "nvd"
    assert record.record_count == 1
    assert record.path.endswith(".yaml")
    assert "nvd-" in Path(record.path).name
    rows = store.entries(record.id)
    assert rows[0]["cve"] == "CVE-2024-6387"
    assert rows[0]["cpe_ranges"][0]["product"] == "openssh"
    assert store.entries(record.id)[0]["cvss"] == pytest.approx(8.1)


def test_the_kind_is_detected_from_the_document_shape(tmp_path: Path) -> None:
    csv_path = tmp_path / "x.csv"
    csv_path.write_text(EPSS_CSV)
    assert detect_kind(csv_path, EPSS_CSV) == "epss"
    json_path = tmp_path / "x.json"
    json_path.write_text(KEV_JSON)
    assert detect_kind(json_path, KEV_JSON) == "kev"
    cve_path = tmp_path / "y.json"
    cve_path.write_text(CVE_JSON)
    assert detect_kind(cve_path, CVE_JSON) == "cve"


# --------------------------------------------------------------------------- store
def test_import_writes_a_normalised_artefact_and_rows(store: FeedStore, tmp_path: Path) -> None:
    source = tmp_path / "epss.csv"
    source.write_text(EPSS_CSV)
    record = store.import_file(source, imported_by="pytest")
    assert record.kind == "epss"
    assert record.record_count == 2
    assert Path(record.path).is_file()
    assert Path(record.path).suffix == ".csv"
    assert store.effective_path("epss") == record.path
    assert [row["cve"] for row in store.entries(record.id)] == [
        "CVE-2021-44228",
        "CVE-2024-6387",
    ]


def test_the_epss_artefact_is_exactly_what_m6_reads(store: FeedStore, tmp_path: Path) -> None:
    source = tmp_path / "epss.csv"
    source.write_text(EPSS_CSV)
    record = store.import_file(source)
    snapshot = load_epss(record.path)
    assert snapshot.rank("CVE-2021-44228") == pytest.approx(0.97)


def test_a_kev_import_marks_the_snapshot_entry(store: FeedStore, tmp_path: Path) -> None:
    source = tmp_path / "kev.json"
    source.write_text(KEV_JSON)
    record = store.import_file(source)
    assert store.active("kev").id == record.id  # type: ignore[union-attr]
    snapshot = load_epss(kev_path=record.path)
    assert snapshot.get("CVE-2021-44228").kev is True  # type: ignore[union-attr]


def test_lookup_merges_epss_and_kev_across_active_feeds(store: FeedStore, tmp_path: Path) -> None:
    epss = tmp_path / "epss.csv"
    epss.write_text(EPSS_CSV)
    kev = tmp_path / "kev.json"
    kev.write_text(KEV_JSON)
    store.import_file(epss)
    store.import_file(kev)
    merged = store.lookup("cve-2021-44228")
    assert merged is not None
    assert merged["epss"] == pytest.approx(0.97)
    assert merged["kev"] is True
    assert {item["kind"] for item in merged["sources"]} == {"epss", "kev"}
    assert store.lookup("CVE-0000-0000") is None


def test_the_newest_feed_of_a_kind_is_active(store: FeedStore, tmp_path: Path) -> None:
    first = tmp_path / "epss-1.csv"
    first.write_text(EPSS_CSV)
    second = tmp_path / "epss-2.csv"
    second.write_text("cve,epss,percentile\nCVE-2020-0001,0.5,0.5\n")
    first_record = store.import_file(first, name="first")
    second_record = store.import_file(second, name="second")
    assert store.active("epss").id == second_record.id  # type: ignore[union-attr]
    assert store.get(first_record.id) is not None


def test_import_text_is_the_upload_path(store: FeedStore) -> None:
    record = store.import_text(EPSS_CSV, kind="epss", name="uploaded", imported_by="api")
    assert record.source == "upload"
    assert store.get(record.id) is not None


def test_delete_removes_rows_record_and_artefact(store: FeedStore, tmp_path: Path) -> None:
    source = tmp_path / "epss.csv"
    source.write_text(EPSS_CSV)
    record = store.import_file(source)
    artefact = Path(record.path)
    assert store.delete(record.id) is True
    assert store.get(record.id) is None
    assert not artefact.exists()
    assert store.effective_path("epss") is None


def test_stats_group_by_kind(store: FeedStore, tmp_path: Path) -> None:
    for name, text, kind in (
        ("a.csv", EPSS_CSV, "epss"),
        ("b.json", KEV_JSON, "kev"),
    ):
        path = tmp_path / name
        path.write_text(text)
        store.import_file(path, kind=kind)
    stats = store.stats()
    assert stats["by_kind"]["epss"] == {"feeds": 1, "entries": 2}
    assert stats["by_kind"]["kev"] == {"feeds": 1, "entries": 2}
    assert stats["by_kind"]["cve"] == {"feeds": 0, "entries": 0}


# --------------------------------------------------------------------------- M6 wiring
def test_the_composition_root_points_m6_at_the_ingested_feed(tmp_path: Path) -> None:
    """`build_handlers` resolves the active feed into ModuleConfig (the scan uses it)."""
    from arachne.modules.handlers import _module_config

    class StubFeeds:
        def effective_path(self, kind: str) -> str | None:
            return {"epss": "/feeds/epss.csv", "kev": "/feeds/kev.json"}.get(kind)

    config = _module_config(Settings(), StubFeeds())
    assert config.m6.epss_feed == "/feeds/epss.csv"
    assert config.m6.kev_feed == "/feeds/kev.json"


def test_a_feed_store_error_falls_back_to_the_configured_path() -> None:
    from arachne.modules.handlers import _module_config

    class Broken:
        def effective_path(self, kind: str) -> str | None:
            raise RuntimeError("database is gone")

    config = _module_config(Settings(), Broken())
    assert config.m6.epss_feed is None  # the shipped snapshot, not a crash


def test_module_config_overrides_only_the_named_feed() -> None:
    settings = Settings()
    config = ModuleConfig.from_settings(settings, epss_feed="/x.csv")
    assert config.m6.epss_feed == "/x.csv"
    assert config.m6.kev_feed == settings.m6.kev_feed
