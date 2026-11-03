"""Out-of-band callback hardening (WP-14, REQ-PROOF-019).

L2 is the only rung that leaves the process on the target's behalf, so the receiver has to
be able to tell *this scan's* callback from one assembled by whoever learned a nonce. Four
controls, each refused **and audited**:

1. **A per-scan secret.** The secret is derived from the deployment key, so the scanner that
   mints a token and the callback service that receives it — different processes — agree
   without the secret ever travelling. A token with no authenticator, or the wrong one, is
   refused; a token minted by the same deployment is accepted.
2. **Single use, bounded replay window.** A callback that arrives after the token was spent
   is refused and counted; inside the window the first verdict stands (no second record),
   outside it the token is expired. Either way the hit is not stored twice.
3. **Only active scans.** A scan the deployment does not know, is not running, or whose
   attestation has expired is refused before anything is stored.
4. **A keyless deployment keeps working.** With no deployment key there is no secret to
   derive, the nonce is the authenticator exactly as before, and the receiver says which of
   the two it is rather than pretending.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import Settings
from arachne.core.proof import CallbackToken, per_scan_secret, token_mac
from arachne.core.signing import DeploymentSigner
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.models import Scan, Target
from arachne.data.scan_store import SqlScanStateStore
from arachne.proof.oob import CallbackService
from arachne.proof.server import scan_gate_for_services

KEY = "wp14-unit-test-callback-key-0001"


def _service(
    sink: MemoryAuditSink,
    *,
    key: str | None = KEY,
    gate: Any = None,
    replay_window_s: float = 300.0,
) -> CallbackService:
    return CallbackService(
        auditor=Auditor(sink, actor="callback-server"),
        signer=DeploymentSigner(key) if key else None,
        scan_gate=gate,
        replay_window_s=replay_window_s,
    )


# ------------------------------------------------------------------ 1. the per-scan secret
def test_a_token_minted_by_the_deployment_is_accepted_by_a_separate_receiver() -> None:
    """The cross-process case: the receiver never saw the issuance."""
    scanner = _service(MemoryAuditSink())
    token = scanner.issue(11, "m3.sqli-oob")
    assert token.mac is not None and token.value.endswith(token.mac)

    receiver = _service(MemoryAuditSink())
    assert receiver.secret_for("11") == per_scan_secret(DeploymentSigner(KEY), "11")
    assert receiver.record_hit(token.value, body="ARACHNE_POC hit") is not None
    assert receiver.consume(token.value) is not None


def test_a_token_with_the_wrong_scan_secret_is_refused_and_audited() -> None:
    sink = MemoryAuditSink()
    receiver = _service(sink)
    token = _service(MemoryAuditSink()).issue(11, "m3.sqli-oob")
    forged = f"{token.base}~{'0' * 16}"
    assert receiver.record_hit(forged, body="forged") is None
    refusals = sink.of_action(AuditAction.PROOF_OOB_REFUSED)
    assert len(refusals) == 1
    assert "wrong scan secret" in refusals[0].reason
    # Nothing was stored for the forged value.
    assert receiver.probe(forged) is None


def test_a_token_with_no_authenticator_is_refused_when_one_can_be_derived() -> None:
    sink = MemoryAuditSink()
    receiver = _service(sink)
    plain = CallbackToken(11, "m3.sqli-oob", "ab12cd34ef56ab12cd34ef56")
    assert plain.mac is None
    assert receiver.record_hit(plain.value) is None
    refusals = sink.of_action(AuditAction.PROOF_OOB_REFUSED)
    assert len(refusals) == 1 and "no per-scan secret" in refusals[0].reason


def test_a_token_from_a_key_this_deployment_does_not_hold_is_refused() -> None:
    """Fail closed: a MAC this receiver cannot verify is not a MAC it may accept."""
    sink = MemoryAuditSink()
    receiver = _service(sink, key="another-deployment-key-0002")
    token = _service(MemoryAuditSink()).issue(11, "m3.sqli-oob")
    assert receiver.record_hit(token.value) is None
    assert "wrong scan secret" in sink.of_action(AuditAction.PROOF_OOB_REFUSED)[0].reason


def test_a_registered_secret_authenticates_without_a_deployment_key() -> None:
    """A receiver handed a scan's secret out of band can authenticate it."""
    receiver = _service(MemoryAuditSink(), key=None)
    secret = "in-process-secret-0001"
    receiver.register_scan_secret(11, secret)
    base = CallbackToken(11, "m3.sqli-oob", "ab12cd34ef56ab12cd34ef56").base
    assert receiver.record_hit(f"{base}~{token_mac(secret, base)}") is not None
    # ...and a token for the same scan with no authenticator is not, because one is known.
    other = CallbackToken(11, "m3.sqli-oob", "ab12cd34ef56ab12cd34ef57")
    assert receiver.record_hit(other.value) is None


def test_a_keyless_deployment_still_accepts_its_own_nonce_only_tokens() -> None:
    """No deployment key: the 96-bit nonce is the authenticator, as it was before WP-14.

    A keyless process authenticates the tokens it issued itself (it mints a per-scan secret
    locally); a scan it never issued a token for has no secret to check against, and is
    accepted on the nonce alone. That second case is what keeps the pre-WP-14 flow working
    for a deployment that configured no key — and it is the *only* kind of token another
    keyless process can produce, since a token it minted would carry a secret this receiver
    cannot verify (and is refused, fail-closed).
    """
    sink = MemoryAuditSink()
    service = _service(sink, key=None)
    token = service.issue(11, "m3.sqli-oob")
    assert token.mac is not None and service.record_hit(token.value) is not None
    # Scan 12 has no registered secret here: a bare nonce-only token is accepted.
    unsigned = CallbackToken(12, "m3.sqli-oob", "ab12cd34ef56ab12cd34ef58")
    assert service.record_hit(unsigned.value) is not None
    assert sink.of_action(AuditAction.PROOF_OOB_REFUSED) == []


def test_a_keyless_receiver_refuses_a_mac_it_cannot_verify() -> None:
    """Fail closed: an authenticator this receiver cannot check is not one it may accept."""
    sink = MemoryAuditSink()
    issuer = _service(MemoryAuditSink(), key=None)
    receiver = _service(sink, key=None)
    token = issuer.issue(11, "m3.sqli-oob")
    assert token.mac is not None
    assert receiver.record_hit(token.value) is None
    assert "cannot verify" in sink.of_action(AuditAction.PROOF_OOB_REFUSED)[0].reason


# ------------------------------------------------------------------ 2. single use + replay
def test_a_replayed_callback_is_refused_counted_and_keeps_the_first_verdict() -> None:
    sink = MemoryAuditSink()
    service = _service(sink)
    token = service.issue(11, "m3.sqli-oob")
    first = service.record_hit(token.value, body="first")
    assert first is not None
    consumed = service.consume(token.value)
    assert consumed is not None and consumed.body == "first"

    # The replay: refused as a new callback, counted, and the verdict it would have produced
    # is the one already recorded — no second hit, no second record.
    assert service.record_hit(token.value, body="replay") is None
    probe = service.probe(token.value)
    assert probe is not None
    assert probe.replays == 1
    assert probe.hit is not None and probe.hit.body == "first"
    assert probe.consumed is True
    assert len(service.probes_for(11)) == 1
    # A second consume is still refused, and does not hand back the replayed body.
    assert service.consume(token.value) is None
    replays = sink.of_action(AuditAction.PROOF_OOB_REPLAY)
    assert len(replays) >= 1
    assert "replay counted" in replays[0].reason
    assert replays[0].outcome.value == "blocked"


def test_a_callback_past_the_replay_window_is_refused_as_expired() -> None:
    sink = MemoryAuditSink()
    # A zero-second window makes "the window has closed" the immediate next state, without a
    # wall-clock sleeping test.
    service = _service(sink, replay_window_s=0.0)
    token = service.issue(11, "m3.sqli-oob")
    assert service.record_hit(token.value, body="first") is not None
    assert service.consume(token.value) is not None
    assert service.record_hit(token.value, body="late") is None
    refusals = sink.of_action(AuditAction.PROOF_OOB_REFUSED)
    assert len(refusals) == 1
    assert "replay window closed" in refusals[0].reason
    probe = service.probe(token.value)
    assert probe is not None and probe.replays == 1


def test_a_second_callback_before_consumption_is_not_a_replay() -> None:
    """Single use is about *consumption*: two arrivals before a match are one proof."""
    sink = MemoryAuditSink()
    service = _service(sink)
    token = service.issue(11, "m3.sqli-oob")
    assert service.record_hit(token.value, body="one") is not None
    assert service.record_hit(token.value, body="two") is not None
    probe = service.probe(token.value)
    assert probe is not None and probe.replays == 0
    assert sink.of_action(AuditAction.PROOF_OOB_REPLAY) == []
    hit = service.consume(token.value)
    assert hit is not None and hit.body == "two"


# ------------------------------------------------------------------ 3. only active scans
def test_a_refused_scan_gate_refuses_and_audits_before_anything_is_stored() -> None:
    sink = MemoryAuditSink()
    reasons = {"11": "scan 11 attestation expired at 2026-01-01T00:00:00+00:00"}
    service = _service(sink, gate=lambda scan_id: reasons.get(scan_id))
    token = service.issue(11, "m3.sqli-oob")
    assert service.record_hit(token.value, body="late") is None
    refusals = sink.of_action(AuditAction.PROOF_OOB_REFUSED)
    assert len(refusals) == 1
    assert "attestation expired" in refusals[0].reason
    assert refusals[0].scan_id == "11"
    probe = service.probe(token.value)
    assert probe is not None and probe.hit is None
    # A scan the gate allows is unaffected.
    assert service.record_hit(service.issue(12, "m3.sqli-oob").value) is not None


def test_a_scan_gate_that_cannot_answer_refuses_rather_than_allowing() -> None:
    def broken(scan_id: str) -> str | None:
        raise RuntimeError("store is down")

    sink = MemoryAuditSink()
    service = _service(sink, gate=broken)
    token = service.issue(11, "m3.sqli-oob")
    assert service.record_hit(token.value) is None
    assert "could not decide" in sink.of_action(AuditAction.PROOF_OOB_REFUSED)[0].reason


def _scan_services(tmp_path: Any, *, status: str, expires: str | None) -> Any:
    """A real store with one scan, for the deployment's own gate."""
    from types import SimpleNamespace

    settings = Settings(database_url=f"sqlite:///{tmp_path / 'gate.db'}")
    engine = create_sqlite_engine(settings.database_url)
    create_all(engine)
    factory = create_session_factory(engine)
    plan: dict[str, Any] = {}
    if expires is not None:
        plan["attestation"] = {"attested_by": "test", "expires_at": expires}
    with factory() as session:
        target = Target(name="fixture", scope_json={}, auth_attestation=None)
        session.add(target)
        session.flush()
        scan = Scan(
            target_id=target.id,
            status=status,
            plan_json=plan,
            engine="heuristic",
            stats_json={},
        )
        session.add(scan)
        session.commit()
        scan_id = int(scan.id)
    return SimpleNamespace(
        store=SqlScanStateStore(factory), engine=engine, factory=factory, scan_id=scan_id
    )


def test_the_deployment_gate_refuses_unknown_inactive_and_expired_scans(tmp_path: Any) -> None:
    now = datetime.now(UTC)
    soon = (now + timedelta(hours=1)).isoformat()
    good = _scan_services(tmp_path, status="running", expires=soon)
    gate = scan_gate_for_services(good)
    assert gate(str(good.scan_id)) is None
    assert "not known to this deployment" in str(gate("999999"))

    expired = _scan_services(
        tmp_path, status="running", expires=(now - timedelta(minutes=1)).isoformat()
    )
    gate = scan_gate_for_services(expired)
    assert "attestation expired" in str(gate(str(expired.scan_id)))

    done = _scan_services(tmp_path, status="completed", expires=None)
    gate = scan_gate_for_services(done)
    assert "not active" in str(gate(str(done.scan_id)))

    # A scan with no expiry recorded, still running, passes: the plan predates attestations.
    unexpiring = _scan_services(tmp_path, status="running", expires=None)
    assert scan_gate_for_services(unexpiring)(str(unexpiring.scan_id)) is None
    # A non-numeric token scan id is refused rather than raising.
    assert "not a scan id" in str(scan_gate_for_services(good)("not-a-number"))

    for services in (good, expired, done, unexpiring):
        services.engine.dispose()


# ------------------------------------------------------------------ 4. issuance paths
def test_standalone_issuance_carries_the_secret_and_a_receiver_verifies_it() -> None:
    """``ProofAccess`` mints the token itself in standalone mode (no in-process service)."""
    from arachne.core.lifecycle import MemoryScanStateStore
    from arachne.core.proof import ProofLevel
    from arachne.proof.access import ProofAccess
    from arachne.proof.ledger import ProofLedger

    ledger = ProofLedger(MemoryScanStateStore(), 11)
    access = ProofAccess(
        level=ProofLevel.L2,
        check_id="m3.sqli-oob",
        scan_id=11,
        ledger=ledger,
        callback_base="http://127.0.0.1:8081",
        oob_secret=per_scan_secret(DeploymentSigner(KEY), 11),
    )
    token = access.oob_token().token
    assert token.mac is not None

    sink = MemoryAuditSink()
    receiver = _service(sink)  # a *different* process, same deployment key
    assert receiver.record_hit(str(token), body="ARACHNE_POC hit") is not None
    assert sink.of_action(AuditAction.PROOF_OOB_REFUSED) == []


def test_standalone_issuance_without_a_key_stays_nonce_only() -> None:
    from arachne.core.lifecycle import MemoryScanStateStore
    from arachne.core.proof import ProofLevel
    from arachne.proof.access import ProofAccess
    from arachne.proof.ledger import ProofLedger

    ledger = ProofLedger(MemoryScanStateStore(), 11)
    access = ProofAccess(
        level=ProofLevel.L2,
        check_id="m3.sqli-oob",
        scan_id=11,
        ledger=ledger,
        callback_base="http://127.0.0.1:8081",
        oob_secret=None,
    )
    assert access.oob_token().token.mac is None


def test_the_nonce_a_run_supplies_is_still_carried_verbatim_with_a_mac() -> None:
    """A purple run's visible nonce survives the authenticator (REQ-VALID-003)."""
    service = _service(MemoryAuditSink())
    token = service.issue(11, "m3.sqli-oob", nonce="abcdef0123456789abcdef01")
    assert token.nonce == "abcdef0123456789abcdef01"
    assert "abcdef0123456789abcdef01" in token.value
    assert token.mac is not None
    assert service.record_hit(token.value) is not None


def test_a_tampered_token_value_is_refused() -> None:
    """A nonce edited after issuance no longer matches the authenticator over the token."""
    sink = MemoryAuditSink()
    service = _service(sink)
    token = service.issue(11, "m3.sqli-oob")
    assert token.mac is not None
    flipped = "a" if token.base[-1] != "a" else "b"
    tampered = f"{token.base[:-1]}{flipped}~{token.mac}"
    assert tampered != token.value
    assert service.record_hit(tampered) is None
    assert sink.of_action(AuditAction.PROOF_OOB_REFUSED)


@pytest.mark.parametrize("shape", ["not-a-token", "arachne-11", "arachne-11-m3.sqli-oob-"])
def test_a_malformed_token_is_refused_without_touching_anything(shape: str) -> None:
    sink = MemoryAuditSink()
    service = _service(sink)
    assert service.record_hit(shape) is None
    assert sink.of_action(AuditAction.PROOF_OOB_HIT)[0].outcome.value == "blocked"
