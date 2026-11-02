"""The posture store: drift baselines, fix-verification records, criticality (S23).

Both implementations (memory and SQL) must behave identically — the unit and integration
tests drive the memory store, the deployment drives SQL, and a behaviour that only exists
in one of them is a behaviour nobody can trust.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from arachne.data.models import Base
from arachne.data.posture_store import (
    FINDING_CLOSED,
    CriticalityEntry,
    MemoryPostureStore,
    SqlPostureStore,
)
from arachne.posture.state import parse_snapshot_document

MOMENT = datetime(2026, 10, 31, 12, 0, 0, tzinfo=UTC)


def _snapshot(resources: list[dict[str, object]]) -> Any:
    return parse_snapshot_document(
        {"provider": "aws", "account": "0", "resources": resources}, source="test"
    )


def _resource(rid: str, public: bool) -> dict[str, object]:
    return {
        "id": rid,
        "service": "storage",
        "type": "storage",
        "config": {"public": public, "encrypted": True},
    }


def _stores(tmp_path) -> list[Any]:  # type: ignore[type-arg]
    engine = create_engine(f"sqlite:///{tmp_path / 'posture.db'}")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    return [
        MemoryPostureStore(auditor=None),
        SqlPostureStore(factory, auditor=None),
        MemoryPostureStore(auditor=None),
        _Seeded(factory),
    ]


class _Seeded:
    """The SQL store plus the scan/target/check/asset rows finding transitions need."""

    def __init__(self, factory: sessionmaker) -> None:  # type: ignore[type-arg]
        self.store = SqlPostureStore(factory)
        self.factory = factory
        from arachne.data.models import Asset, Check, Scan, Target

        with factory() as session:
            target = Target(name="posture-target", scope_json={})
            session.add(target)
            session.flush()
            scan = Scan(target_id=target.id, plan_json={"target_name": "posture-target"})
            session.add(scan)
            session.flush()
            check = Check(module="M5", name="bucket-enumerator", version="1.0")
            session.add(check)
            session.flush()
            asset = Asset(scan_id=scan.id, kind="bucket", value="s3:app-assets")
            session.add(asset)
            session.flush()
            self.target_id = target.id
            self.scan_id = scan.id
            self.check_id = check.id
            self.asset_id = asset.id
            session.commit()

    def __getattr__(self, name: str) -> Any:
        # Everything the store protocol defines delegates to the SQL store; the seed rows
        # are this wrapper's only additions.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.store, name)

    def seed_finding(self, record: dict[str, Any]) -> dict[str, Any]:
        from arachne.data.models import Finding

        with self.factory() as session:
            row = Finding(
                scan_id=self.scan_id,
                check_id=self.check_id,
                asset_id=self.asset_id,
                title=str(record.get("title", "seeded")),
                status="open",
                evidence_refs_json=[],
            )
            session.add(row)
            session.commit()
            seeded = dict(record)
            seeded["id"] = int(row.id)
            seeded["scan_id"] = self.scan_id
            return seeded


# ------------------------------------------------------------------ baselines
@pytest.mark.parametrize("store", [0, 1], ids=["memory", "sql"])
def test_baselines_round_trip_and_replace(store: int, tmp_path) -> None:
    under_test = _stores(tmp_path)[store]
    scope = "endpoint:http://lab/posture"
    assert under_test.baselines(scope) == ()
    under_test.save_baselines(scope, _snapshot([_resource("a", False), _resource("b", False)]))
    records = {record.resource_key: record for record in under_test.baselines(scope)}
    assert set(records) == {"aws:storage/a", "aws:storage/b"}
    assert records["aws:storage/a"].config == {"encrypted": True, "public": False}
    first_seen = records["aws:storage/a"].first_seen_at
    # A second run that shrinks the estate: the missing row is gone, the survivor keeps
    # its first-seen (the baseline is "the last observed state", with lineage).
    later = MOMENT + timedelta(hours=1)
    under_test.save_baselines(scope, _snapshot([_resource("a", True)]), now=later)
    records = {record.resource_key: record for record in under_test.baselines(scope)}
    assert set(records) == {"aws:storage/a"}
    assert records["aws:storage/a"].first_seen_at == first_seen
    assert records["aws:storage/a"].last_seen_at == later
    assert records["aws:storage/a"].config == {"encrypted": True, "public": True}


@pytest.mark.parametrize("store", [0, 1], ids=["memory", "sql"])
def test_forget_scope_removes_only_that_scope(store: int, tmp_path) -> None:
    under_test = _stores(tmp_path)[store]
    under_test.save_baselines("scope-1", _snapshot([_resource("a", False)]))
    under_test.save_baselines("scope-2", _snapshot([_resource("b", False)]))
    assert under_test.forget_scope("scope-1") == 1
    assert under_test.baselines("scope-1") == ()
    assert len(under_test.baselines("scope-2")) == 1


# ------------------------------------------------------------------ verifications
@pytest.mark.parametrize("store", [0, 2, 3], ids=["memory-seedless", "memory-seeded", "sql"])
def test_finding_status_transitions_link_evidence(store: int, tmp_path) -> None:
    under_test = _stores(tmp_path)[store]
    finding_id: int
    if isinstance(under_test, _Seeded):
        finding = under_test.seed_finding({"id": 0, "title": "public bucket", "status": "open"})
        finding_id = int(finding["id"])
    else:
        finding = under_test.seed_finding(
            {
                "id": 7,
                "title": "public bucket",
                "status": "open",
                "scan_id": 1,
                "check_key": "M5/bucket-enumerator@1.0",
                "asset_value": "s3:app-assets",
                "evidence_refs": [],
            }
        )
        finding_id = int(finding["id"])
    evidence = {"kind": "note", "payload": {"signal": "fix-verification", "outcome": "verified"}}
    evidence_id = under_test.set_finding_status(finding_id, FINDING_CLOSED, evidence=evidence)
    assert evidence_id is not None
    row = under_test.finding(finding_id)
    assert row is not None and row["status"] == FINDING_CLOSED
    assert evidence_id in row["evidence_refs"]

    record = under_test.record_verification(
        finding_id=finding_id,
        scan_id=99,
        outcome="verified",
        detail="closed by scan 99",
        evidence_id=evidence_id,
    )
    assert record.id is not None
    assert [item.outcome for item in under_test.verifications_for(finding_id)] == ["verified"]
    # Reopen on regression.
    under_test.set_finding_status(
        finding_id,
        "open",
        evidence={**evidence, "payload": {"outcome": "reopened"}},
    )
    under_test.record_verification(
        finding_id=finding_id, scan_id=100, outcome="reopened", detail="regressed in scan 100"
    )
    assert [item.outcome for item in under_test.verifications_for(finding_id)] == [
        "verified",
        "reopened",
    ]
    assert under_test.finding(finding_id)["status"] == "open"


@pytest.mark.parametrize("store", [0, 3], ids=["memory", "sql"])
def test_an_unknown_outcome_is_refused(store: int, tmp_path) -> None:
    under_test = _stores(tmp_path)[store]
    if isinstance(under_test, _Seeded):
        under_test = under_test.store
    with pytest.raises(ValueError):
        under_test.record_verification(finding_id=1, scan_id=1, outcome="meh")


@pytest.mark.parametrize("store", [0, 3], ids=["memory", "sql"])
def test_closed_findings_query_by_identity(store: int, tmp_path) -> None:
    under_test = _stores(tmp_path)[3]
    if isinstance(under_test, _Seeded):
        finding = under_test.seed_finding({"id": 0, "status": "open"})
        finding_id = int(finding["id"])
        sql_store = under_test.store
    else:
        finding = under_test.seed_finding(
            {
                "id": 5,
                "status": "open",
                "scan_id": 1,
                "check_key": "M5/bucket-enumerator@1.0",
                "asset_value": "s3:app-assets",
                "evidence_refs": [],
            }
        )
        finding_id = int(finding["id"])
        sql_store = under_test
    sql_store.set_finding_status(finding_id, FINDING_CLOSED)
    closed = sql_store.closed_findings(
        check_key="M5/bucket-enumerator@1.0", asset_value="s3:app-assets"
    )
    assert [int(item["id"]) for item in closed] == [finding_id]
    assert sql_store.closed_findings(check_key="M1/other@1.0") == ()


# ------------------------------------------------------------------ criticality
@pytest.mark.parametrize("store", [0, 1], ids=["memory", "sql"])
def test_criticality_import_upserts_and_indexes(store: int, tmp_path) -> None:
    under_test = _stores(tmp_path)[store]
    assert (
        under_test.import_criticality(
            [CriticalityEntry(host="Payments.Example.com", tier=1, name="Payments")]
        )
        == 1
    )
    under_test.import_criticality(
        [
            CriticalityEntry(
                host="payments.example.com", tier=2, name="Payments", source="cmdb-nightly"
            )
        ]
    )
    assert under_test.criticality_index() == {"payments.example.com": 2}
    with pytest.raises(ValueError):
        under_test.import_criticality([CriticalityEntry(host="x", tier=9)])


@pytest.mark.parametrize("store", [0, 1], ids=["memory", "sql"])
def test_reporting_reads_summarize_the_loop_and_the_estate(store: int, tmp_path) -> None:
    under_test = _stores(tmp_path)[store]
    under_test.save_baselines("scope-1", _snapshot([_resource("a", False)]))
    under_test.record_verification(finding_id=1, scan_id=9, outcome="verified")
    under_test.record_verification(finding_id=1, scan_id=10, outcome="reopened")
    under_test.record_verification(finding_id=2, scan_id=11, outcome="still-open")
    counts = under_test.verification_counts()
    assert counts == {"verified": 1, "reopened": 1, "still-open": 1}
    inventory = under_test.baseline_inventory()
    assert inventory["scopes"] == [("scope-1", 1)]
    assert inventory["by_service"] == {"storage": 1}
