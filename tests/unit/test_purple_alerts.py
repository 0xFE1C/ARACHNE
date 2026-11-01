"""Defender-alert ingest: the SIEM side of the conversation (S24, REQ-VALID-002).

Three properties are load-bearing and each is pinned here:

1. **Tolerance without guessing** — a SIEM's vocabulary is not ARACHNE's, so the field
   mapping accepts the shapes a forwarder actually sends, and an alert ARACHNE cannot
   attribute is *kept* (counted as unmatched) rather than dropped.
2. **Refusal where guessing would be dangerous** — an alert with no timestamp cannot be
   placed in a window, so it is refused loudly with its index.
3. **Deduplication** — a re-delivered webhook must not inflate coverage; the store keys on
   ``(source, alert_id)``, in both implementations.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from arachne.core.errors import ConfigurationError
from arachne.data.models import Base
from arachne.data.purple_store import MemoryPurpleStore, SqlPurpleStore
from arachne.purple.alerts import (
    DefenderAlert,
    parse_alert_document,
    parse_alert_text,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "purple" / "siem-alerts.json"
NONCE = "abcdef0123456789abcdef01"


def _fixture_alerts(nonce: str = NONCE) -> tuple[DefenderAlert, ...]:
    text = FIXTURE.read_text(encoding="utf-8").replace("{{NONCE}}", nonce)
    return parse_alert_text(text, source="lab-siem")


def test_the_planted_fixture_parses_into_the_shapes_the_scorer_needs() -> None:
    alerts = _fixture_alerts()
    assert [item.alert_id for item in alerts] == [
        "SIEM-9001",
        "SIEM-9002",
        "SIEM-9003",
        "SIEM-9004",
        "SIEM-9005",
    ]
    by_id = {item.alert_id: item for item in alerts}
    assert by_id["SIEM-9001"].technique == "T1190"
    assert by_id["SIEM-9001"].tactic == "initial-access"
    assert by_id["SIEM-9001"].nonce == NONCE
    assert by_id["SIEM-9002"].nonce == NONCE, "the free-text message carries the nonce"
    assert by_id["SIEM-9004"].nonce is None
    assert by_id["SIEM-9005"].technique is None
    assert by_id["SIEM-9003"].observed_at == datetime(2026, 10, 31, 11, 58, tzinfo=UTC)


def test_the_ingest_accepts_the_three_payload_shapes_a_forwarder_sends() -> None:
    one = parse_alert_document(
        {"alert_id": "A1", "timestamp": "2026-10-31T12:00:00Z", "technique": "T1059"},
        source="hook",
    )
    assert len(one) == 1 and one[0].technique == "T1059"

    nested = parse_alert_document(
        {"alerts": [{"id": "A2", "time": "2026-10-31T12:00:00+00:00"}]}, source="hook"
    )
    assert [item.alert_id for item in nested] == ["A2"]
    assert nested[0].observed_at.tzinfo is not None

    ndjson = parse_alert_text(
        '{"id": "A3", "timestamp": "2026-10-31T12:00:00Z", "technique": "attack.t1190"}\n'
        '{"id": "A4", "timestamp": "2026-10-31T12:01:00Z"}\n',
        source="export",
    )
    assert [item.alert_id for item in ndjson] == ["A3", "A4"]
    assert ndjson[0].technique == "T1190"


def test_an_unusable_alert_is_refused_with_its_index() -> None:
    with pytest.raises(ConfigurationError, match=r"alert\[1\].*timestamp"):
        parse_alert_document(
            {"alerts": [{"id": "A1", "timestamp": "2026-10-31T12:00:00Z"}, {"id": "A2"}]},
            source="hook",
        )
    with pytest.raises(ConfigurationError, match=r"must include a timezone"):
        parse_alert_document({"id": "A1", "timestamp": "2026-10-31T12:00:00"}, source="hook")
    with pytest.raises(ConfigurationError, match=r"is empty"):
        parse_alert_text("   ", source="export")
    with pytest.raises(ConfigurationError, match=r"must be an object or a list"):
        parse_alert_document("not-an-object", source="hook")


def test_an_alert_without_an_id_or_a_nonce_is_still_kept() -> None:
    """Dropping an unattributable alert would hide that the SIEM fired at all."""
    alerts = parse_alert_document(
        {"timestamp": "2026-10-31T12:00:00Z", "message": "something happened"}, source="hook"
    )
    assert len(alerts) == 1
    assert alerts[0].alert_id.startswith("hook-0-")
    assert alerts[0].technique is None and alerts[0].nonce is None


def test_a_callback_token_in_free_text_yields_its_nonce() -> None:
    """The defender usually quotes the payload; the token's own nonce is what links it."""
    nonce = "0123456789abcdef01234567"
    alerts = parse_alert_document(
        {
            "id": "A1",
            "timestamp": "2026-10-31T12:00:00Z",
            "technique": "T1190",
            "message": f"outbound request to http://127.0.0.1/arachne-4-m3.sqli-oob-{nonce}",
        },
        source="hook",
    )
    assert alerts[0].nonce == nonce


@pytest.mark.parametrize("kind", ["memory", "sql"])
def test_the_store_deduplicates_a_re_delivered_alert(kind: str, tmp_path: Path) -> None:
    if kind == "memory":
        store = MemoryPurpleStore()
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'purple.db'}")
        Base.metadata.create_all(engine)
        store = SqlPurpleStore(sessionmaker(bind=engine))

    alerts = _fixture_alerts()
    assert store.ingest_alerts(alerts) == len(alerts)
    assert store.ingest_alerts(alerts) == 0, "the same (source, alert_id) is not counted twice"

    stored = store.alerts()
    assert len(stored) == len(alerts)
    assert stored[0].observed_at <= stored[-1].observed_at, "oldest first"
    midnight = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
    window = [item for item in stored if item.observed_at < midnight]
    assert [item.alert_id for item in window] == ["SIEM-9003"]
    later = datetime(2026, 10, 31, 12, 5, tzinfo=UTC)
    assert store.alerts(since=later)[0].alert_id == "SIEM-9001"
    assert store.clear_alerts() == len(alerts)
    assert store.alerts() == ()


@pytest.mark.parametrize("kind", ["memory", "sql"])
def test_campaigns_and_runs_round_trip_in_both_stores(kind: str, tmp_path: Path) -> None:
    if kind == "memory":
        store = MemoryPurpleStore()
    else:
        engine = create_engine(f"sqlite:///{tmp_path / 'purple2.db'}")
        Base.metadata.create_all(engine)
        store = SqlPurpleStore(sessionmaker(bind=engine))

    start = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
    store.upsert_campaign("nightly", {"target": "lab", "actions": ["m3.cmdi-oob"]}, now=start)
    assert store.campaign("nightly") is not None
    assert store.upsert_campaign(
        "nightly", {"target": "lab", "actions": ["m3.cmdi-oob", "m3.sqli-oob"]}, now=start
    ).spec["actions"] == ["m3.cmdi-oob", "m3.sqli-oob"]

    first = store.record_run(
        campaign="nightly",
        nonce=NONCE,
        window={"coordinator": "soc"},
        scan_id=1,
        emissions=[{"check_id": "m3.cmdi-oob", "technique": "T1059"}],
        now=start,
    )
    assert first is not None and first.id == 1
    second = store.record_run(
        campaign="nightly",
        nonce="ffffffffffffffffffffffff",
        window=None,
        scan_id=2,
        now=start + timedelta(hours=1),
    )
    assert second is not None

    updated = store.update_run(
        first.id, coverage={"coverage_pct": 50.0}, gaps=["T1190"], now=start + timedelta(hours=2)
    )
    assert updated is not None and updated.coverage_pct == 50.0
    assert updated.gaps == ("T1190",)
    assert updated.emissions[0]["technique"] == "T1059"
    assert [run.id for run in store.runs("nightly")] == [1, 2]
    assert store.previous_run("nightly", 2).id == 1
    assert store.runs("other") == ()

    assert store.set_campaign_enabled("nightly", False) is not None
    assert store.campaign("nightly").enabled is False
    assert store.delete_campaign("nightly") is True
    assert store.runs("nightly") == ()


def test_the_committed_fixture_carries_no_credential_literal() -> None:
    """A committed fixture is source code: it must not embed a usable-looking secret."""
    text = json.loads(FIXTURE.read_text(encoding="utf-8"))
    blob = json.dumps(text).lower()
    for marker in ("password", "passwd", "secret_key", "apikey", "api_key", "token=", "bearer "):
        assert marker not in blob, f"{marker} appears in the SIEM fixture"
