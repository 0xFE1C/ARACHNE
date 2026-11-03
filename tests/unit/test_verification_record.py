"""The verification record on every finding (WP-13, REQ-PROOF-015/016).

Three things are asserted here, all at the layer that owns them:

* **derivation** — a candidate's record is built from the check's own result: its declared
  rung (the proof artifact's, else ``L1``), the observations the check captured, a
  reproducibility token, and the check's version;
* **persistence** — the SQL store writes exactly one record per finding, exposes it on the
  candidate, keeps the history when a re-verification appends one, and refuses to store an
  escalation (PD-7);
* **the AI guard** — no AI contribution can create or alter a record (PD-8), asserted both
  structurally (the only verified constructor takes a ``CheckResult``) and behaviourally (an
  analysis carrying a ``verification`` key changes nothing in the report).
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from pathlib import Path

import pytest

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult, Evidence
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.finding_store import MemoryFindingStore, SqlFindingStore
from arachne.data.models import Check, Scan, Target
from arachne.data.verification import (
    MAX_OBSERVATIONS,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_STILL_VERIFIED,
    SqlVerificationStore,
    VerificationRecord,
    level_rank,
    record_for_result,
    reverification_record,
)

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


def _exchange_evidence(url: str = "https://t.example/search?id=1") -> tuple[Evidence, Evidence]:
    request = Evidence.of("http_request", {"method": "GET", "url": url, "headers": {}, "body": ""})
    response = Evidence.of(
        "http_response", {"status_code": 200, "headers": {}, "body": "<html>ok</html>"}
    )
    return request, response


def _result(*, proof: dict | None = None, check: str = "m3.sqli-oracle") -> CheckResult:
    evidence = list(_exchange_evidence())
    if proof is not None:
        evidence.append(Evidence.of("proof", proof))
    return CheckResult(
        status="vulnerable", title="t", check=check, module="M3", evidence=tuple(evidence)
    )


# --------------------------------------------------------------------------- derivation
def test_a_record_is_derived_from_the_check_result() -> None:
    result = _result()
    record = record_for_result(result, check_version="1.0", verified_at=NOW)
    assert record.status == "verified"
    assert record.level == "L1", "a check with no proof artifact was proven at L1"
    assert record.method
    assert record.check_version == "1.0"
    assert record.reproducibility_token and record.reproducibility_token.startswith("sha256:")
    # The observations are the spec's {request, status, length} rows.
    exchange = next(item for item in record.observations if item.get("what") == "exchange")
    assert exchange["request"] == "GET https://t.example/search?id=1"
    assert exchange["status"] == 200
    assert exchange["length"] == len("<html>ok</html>")


def test_the_proof_artifact_sets_the_level_method_and_token() -> None:
    result = _result(
        proof={
            "level": "L2",
            "method": "out-of-band callback (time-free blind SQLi)",
            "nonce": "arachne-1-m3.sqli-oob-abcdef012345",
            "hit": {"token": "arachne-1-m3.sqli-oob-abcdef012345", "source": "10.0.0.9"},
            "cleanup": "none required (no state was changed)",
        }
    )
    record = record_for_result(result, check_version="1.0", verified_at=NOW)
    assert record.level == "L2"
    assert record.method.startswith("out-of-band")
    assert record.reproducibility_token == "arachne-1-m3.sqli-oob-abcdef012345"
    what = {str(item.get("what")) for item in record.observations}
    assert "out-of-band-callback" in what


def test_a_redacted_token_falls_back_to_the_content_digest() -> None:
    """``Evidence.of`` masks a ``callback_token``, so the record must not carry the mask."""
    result = _result(
        proof={"level": "L2", "method": "out-of-band", "callback_token": "secret-value"}
    )
    record = record_for_result(result, check_version="1.0", verified_at=NOW)
    assert record.reproducibility_token is not None
    assert record.reproducibility_token.startswith("sha256:")


def test_an_unknown_level_falls_back_rather_than_trusting_the_payload() -> None:
    result = _result(proof={"level": "L9", "method": "bogus"})
    record = record_for_result(result, check_version="1.0", verified_at=NOW)
    assert record.level == "L1"


def test_observations_are_bounded() -> None:
    evidence = tuple(item for _ in range(50) for item in _exchange_evidence())
    result = CheckResult(status="vulnerable", title="t", check="m3.x", evidence=evidence)
    record = record_for_result(result, check_version=None, verified_at=NOW)
    assert len(record.observations) <= MAX_OBSERVATIONS


# --------------------------------------------------------------------------- level guard
def test_a_reverification_refuses_to_escalate_the_level() -> None:
    """PD-7 / REQ-PROOF-016: a re-run may hold or weaken a claim, never strengthen it."""
    parent = VerificationRecord(
        id=7,
        finding_id=1,
        level="L1",
        method="original",
        reproducibility_token="t",
        verified_at=NOW,
    )
    with pytest.raises(ValueError, match="refuses to raise the proof level"):
        reverification_record(
            parent,
            level="L3",
            method="escalated",
            observations=(),
            reproducibility_token="t",
            verified_at=NOW,
            check_version="1.0",
            outcome=OUTCOME_STILL_VERIFIED,
        )


def test_a_reverification_at_or_below_the_parent_is_accepted() -> None:
    parent = VerificationRecord(id=7, finding_id=1, level="L2", method="original", verified_at=NOW)
    same = reverification_record(
        parent,
        level="L2",
        method="re-run",
        observations=({"what": "re-verification"},),
        reproducibility_token="t",
        verified_at=NOW,
        check_version="1.0",
        outcome=OUTCOME_STILL_VERIFIED,
        scan_id=42,
    )
    assert same.parent_id == 7
    assert same.scan_id == 42, "the record names the scan that produced it"
    assert same.status == "verified"
    lower = reverification_record(
        parent,
        level="L1",
        method="re-run",
        observations=(),
        reproducibility_token=None,
        verified_at=NOW,
        check_version=None,
        outcome=OUTCOME_INCONCLUSIVE,
    )
    assert lower.status == "unverified", "an inconclusive re-run establishes nothing"


def test_the_store_refuses_a_hand_built_escalation(tmp_path: Path) -> None:
    """The guard is at the persistence boundary too, not only in the constructor."""
    store, session_factory = _sql_stores(tmp_path)
    finding_id = _seed_finding(session_factory)
    parent = store.append(
        VerificationRecord(finding_id=finding_id, level="L1", method="original", verified_at=NOW)
    )
    with pytest.raises(ValueError, match="above its parent"):
        store.append(
            VerificationRecord(
                finding_id=finding_id,
                level="L4",
                method="escalated",
                parent_id=parent.id,
                verified_at=NOW,
            )
        )


# --------------------------------------------------------------------------- persistence
def _sql_stores(tmp_path: Path) -> tuple[SqlVerificationStore, object]:
    from arachne.data.models import Base

    engine = create_db_engine(url=f"sqlite:///{tmp_path / 'verify.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    return SqlVerificationStore(factory), factory


def _seed_finding(factory: object, *, title: str = "f") -> int:
    with factory() as session:  # type: ignore[operator]
        target = Target(name="t", scope_json={"targets": []})
        session.add(target)
        session.commit()
        scan = Scan(target_id=int(target.id), status="completed")
        session.add(scan)
        session.commit()
        from arachne.data.models import Finding

        finding = Finding(scan_id=int(scan.id), title=title, status="open")
        session.add(finding)
        session.commit()
        return int(finding.id)


def test_the_store_records_one_row_per_finding_and_exposes_it(tmp_path: Path) -> None:
    store, factory = _sql_stores(tmp_path)
    finding_id = _seed_finding(factory)
    record = store.append(
        record_for_result(_result(), check_version="1.0", verified_at=NOW, finding_id=finding_id)
    )
    assert record.id is not None
    current = store.current(finding_id)
    assert current is not None and current.id == record.id
    assert current.level == "L1"
    assert current.observations, "the record's observations survived the round trip"
    assert store.history(finding_id) == (current,)


def test_a_reverification_appends_and_repoints_the_finding(tmp_path: Path) -> None:
    store, factory = _sql_stores(tmp_path)
    finding_id = _seed_finding(factory)
    original = store.append(
        VerificationRecord(finding_id=finding_id, level="L1", method="original", verified_at=NOW)
    )
    reverified = store.append(
        reverification_record(
            original,
            level="L1",
            method="re-run",
            observations=({"what": "re-verification"},),
            reproducibility_token="t",
            verified_at=NOW,
            check_version="1.0",
            outcome=OUTCOME_STILL_VERIFIED,
        )
    )
    history = store.history(finding_id)
    assert [item.id for item in history] == [original.id, reverified.id]
    assert store.current(finding_id) is not None
    assert store.current(finding_id).id == reverified.id  # type: ignore[union-attr]


def test_the_sql_finding_store_persists_a_record_for_every_candidate(tmp_path: Path) -> None:
    """REQ-PROOF-015: the write path creates the record in the same transaction."""
    from arachne.data.models import Base

    engine = create_db_engine(url=f"sqlite:///{tmp_path / 'findings.db'}")
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        target = Target(name="t", scope_json={"targets": []})
        session.add(target)
        session.commit()
        scan = Scan(target_id=int(target.id), status="completed")
        session.add(scan)
        session.commit()
        scan_id = int(scan.id)
        check = Check(module="M3", name="sqli-oracle", version="1.0")
        session.add(check)
        session.commit()
        check_id = int(check.id)

    findings = SqlFindingStore(factory)
    record = findings.record_candidate(
        scan_id, result=_result(), check_id=check_id, asset_id=None, asset=("url", "https://t/x")
    )
    assert record.verification is not None
    assert record.verification.status == "verified"
    assert record.verification.check_version == "1.0"

    loaded = findings.list_candidates(scan_id)
    assert len(loaded) == 1
    assert loaded[0].verification is not None
    assert loaded[0].verification.id == record.verification.id
    assert loaded[0].verifications == (loaded[0].verification,)


def test_the_memory_store_records_the_check_version_too() -> None:
    store = MemoryFindingStore()
    store.record_checks([_FakeMeta(key="M3/sqli-oracle@1.0", version="1.0")])
    record = store.record_candidate(
        1,
        result=_result(),
        check_id=store._checks["M3/sqli-oracle@1.0"],
        asset_id=None,
        asset=("url", "https://t/x"),
    )
    assert record.verification is not None
    assert record.verification.check_version == "1.0"


class _FakeMeta:
    def __init__(self, *, key: str, version: str) -> None:
        self.key = key
        self.version = version
        self.module = "M3"
        self.name = "sqli-oracle"
        self.description = ""
        self.cwe = None
        self.research_ref = None


# --------------------------------------------------------------------------- the AI guard
def test_the_only_verified_constructor_accepts_a_check_result() -> None:
    """PD-8, structurally: an analysis cannot be handed to the record builder."""
    signature = inspect.signature(record_for_result)
    annotation = signature.parameters["result"].annotation
    assert annotation in (CheckResult, "CheckResult"), annotation


def test_the_ai_stage_cannot_populate_a_verification_record() -> None:
    """An AI-authored ``verification`` key in an analysis changes nothing in the report.

    The analyzer's payload is where a model's output lands, so that is where a hostile or
    confused completion would try to claim a finding was proven. The builder reads the
    record from the *store* only, so the claim is ignored and the persisted record stands.
    """
    from tests.helpers.report import make_analysis, make_candidate, make_inputs

    from arachne.report.builder import build_report_data

    candidate = make_candidate(number=3, title="t", asset_value="https://t/x")
    analysis = make_analysis(candidate)
    forged = dict(analysis.payload)
    forged["verification"] = {
        "status": "verified",
        "level": "L4",
        "method": "an AI said so",
        "reproducibility_token": "forged",
    }
    from dataclasses import replace

    analysis = replace(analysis, payload=forged)

    report = build_report_data(make_inputs(candidates=[candidate], analyses=[analysis]))
    finding = report.findings[0]
    assert finding.verification.method != "an AI said so"
    assert finding.verification.level == "L1", "the store's record wins, not the analysis"
    assert finding.verification.reproducibility != "forged"


def test_level_rank_is_fail_closed_on_an_unknown_level() -> None:
    assert level_rank("L1") == ProofLevel.L1.rank
    assert level_rank("bogus") == -1, "an unknown level ranks lowest, so it can never escalate"
