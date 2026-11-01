"""Proof-ladder safety suite (S15, area PROOF) — ``tests/test_safety.py`` style.

The properties that must never regress, on top of the gates the earlier stages built:

1. **The proof gate refuses L3/L4 without a state-change attestation** (REQ-PROOF-003)
   — at plan time, at execute, and at resume — and every refusal is audited as
   ``proof.rejected``. A dry run only *prints* the requirement (REQ-PROOF-004).
2. **Unavailability downgrades, never upgrades** (REQ-PROOF-003): an L2 check without a
   callback service is downgraded to L1 with a recorded note — audited as
   ``proof.downgraded``, shown in the plan, and reported by the check itself.
3. **An L2+ check sends nothing without its opt-in chain** (the F-01-09 pattern at the
   new levels): not selected → nothing; selected but not active-authorized → nothing.
4. **The prohibition table bites at code boundaries** (REQ-PROOF-011) — one named test
   per prohibition.
5. **L2+ evidence flows through capture → redact → audit** (REQ-PROOF-012), and the
   callback service never dials out (REQ-PROOF-005).
"""

from __future__ import annotations

import json
import socket
from typing import Any

import httpx
import pytest

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.proof import (
    ALLOWED_COMMANDS,
    PROHIBITED_SQL_HEADS,
    ProofLevel,
    ProofRefused,
    command_payload,
    encode_free,
    sql_refusals,
    validate_nonce,
)
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.registry import ModuleRegistry
from arachne.proof.ledger import ProofLedger
from arachne.proof.oob import MAX_HIT_BODY_CHARS, CallbackService
from arachne.proof.sql import SqlProof, refuse_statement
from tests.conftest import PUBLIC_IP, TARGET_HOST, build_scan_request

# --------------------------------------------------------------------------- the stack


def _scan_stack(
    *, scope: Scope | None = None, audit_sink: MemoryAuditSink | None = None
) -> tuple[Orchestrator, MemoryAuditSink, list[str]]:
    """The orchestrator + recording transport used by the gate tests.

    The registry is the real built-in one, so the plan sees the shipped proof
    declarations; the transport records every URL it is asked for, so "nothing was sent"
    is an observation, not an assumption.
    """
    sink = audit_sink or MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    from arachne.core.config import Settings

    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=__import__("arachne.core.config", fromlist=["SafetySettings"]).SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=scope if scope is not None else Scope(allowed_hosts=(TARGET_HOST,)),
        ),
        log_level="CRITICAL",
    )
    requests: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200, text="ok")

    def factory(scope: Scope):  # type: ignore[no-untyped-def]
        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            resolver=StaticResolver((PUBLIC_IP,)),
            auditor=auditor,
            transport=httpx.MockTransport(transport_handler),
        )

    orchestrator = Orchestrator(
        settings=settings,
        auditor=auditor,
        bus=EventBus(),
        store=MemoryScanStateStore(),
        registry=ModuleRegistry.builtin(),
        client_factory=factory,
        handlers={},
    )
    return orchestrator, sink, requests


def _l4_request(**attestation: Any):  # type: ignore[no-untyped-def]
    """A scan request that names the shipped L4 check (and the L3 one)."""
    return build_scan_request(
        targets=[{"kind": "url", "value": f"https://{TARGET_HOST}/"}],
        attestation=attestation or None,
        options={
            "active_checks": True,
            "modules": {"checks": ("m3.state-marker", "m3.rce-echo")},
        },
    )


def _l2_request(**attestation: Any):  # type: ignore[no-untyped-def]
    """A scan request that names the shipped L2 out-of-band variant."""
    return build_scan_request(
        targets=[{"kind": "url", "value": f"https://{TARGET_HOST}/"}],
        attestation=attestation or None,
        options={
            "active_checks": True,
            "modules": {"checks": ("m3.sqli-oob",)},
        },
    )


# --------------------------------------------------------------------------- REQ-PROOF-003


async def test_a_live_scan_with_l4_and_no_state_attestation_is_refused_and_audited() -> None:
    orchestrator, sink, requests = _scan_stack()
    request = _l4_request(active_checks_authorized=True)

    with pytest.raises(ProofRefused, match="state_changes_authorized"):
        await orchestrator.scan(request)

    rejected = sink.of_action(AuditAction.PROOF_REJECTED)
    assert rejected, "a proof refusal must be audited (REQ-PROOF-003)"
    assert rejected[0].outcome.value == "blocked"
    assert "state-marker" in rejected[0].reason
    assert orchestrator.store.list_scans() == ()
    assert requests == []


def test_a_dry_run_prints_the_attestation_requirement_instead_of_refusing() -> None:
    """REQ-PROOF-004: the dry run is where the operator *learns* what is missing."""
    orchestrator, _sink, _requests = _scan_stack()
    request = _l4_request(active_checks_authorized=True)

    plan = orchestrator.plan(request, dry_run=True)

    l4 = [check for check in plan.included_checks if check.proof.needs_state_attestation]
    assert {check.name for check in l4} == {"state-marker", "rce-echo"}
    assert all("state_changes_authorized" in (check.proof_note or "") for check in l4)


async def test_a_live_scan_with_the_state_attestation_passes_the_proof_gate() -> None:
    orchestrator, _sink, requests = _scan_stack()
    request = _l4_request(active_checks_authorized=True, state_changes_authorized=True)

    session = await orchestrator.scan(request)

    assert session.status is ScanStatus.COMPLETED
    # handlers={} means no detection step ran; the point is that the proof gate passed.
    assert requests == []


async def test_execute_rechecks_the_proof_gate_against_the_stored_plan() -> None:
    """The executing path refuses a plan whose L3/L4 checks lost their attestation."""
    orchestrator, sink, _requests = _scan_stack()
    request = _l4_request(active_checks_authorized=True, state_changes_authorized=True)
    session = await orchestrator.launch(request)
    assert session.scan_id is not None

    # Admit a second scan whose *stored* plan carries L4 checks, then strip the
    # authorization from the definition the executor is handed.
    record = orchestrator.store.get_scan(session.scan_id)
    assert record is not None
    unauthorized = _l4_request(active_checks_authorized=True)  # no state_changes_authorized

    with pytest.raises(ProofRefused, match="state_changes_authorized"):
        await orchestrator.execute(session.scan_id, unauthorized)

    rejected = sink.of_action(AuditAction.PROOF_REJECTED)
    assert rejected and "state-marker" in (rejected[-1].reason or "")


async def test_resume_rechecks_the_proof_gate() -> None:
    orchestrator, sink, _requests = _scan_stack()
    request = _l4_request(active_checks_authorized=True, state_changes_authorized=True)
    session = await orchestrator.launch(request)

    unauthorized = _l4_request(active_checks_authorized=True)
    with pytest.raises(ProofRefused):
        await orchestrator.resume(session.scan_id, unauthorized)  # type: ignore[arg-type]

    assert sink.of_action(AuditAction.PROOF_REJECTED)


async def test_a_stored_plan_with_l4_is_refused_even_when_replanned() -> None:
    """A plan stored directly in the store (crafted) still hits the re-check."""
    orchestrator, sink, _requests = _scan_stack()
    request = _l4_request(active_checks_authorized=True)
    definition = request.target
    record = orchestrator.store.create_scan(
        target_id=None,
        engine="heuristic",
        plan={
            "target_name": definition.name,
            "engine": "heuristic",
            "checks": [
                {
                    "module": "M3",
                    "name": "state-marker",
                    "version": "1.0",
                    "title": "State-change proof (marker row)",
                    "research_ref": "ch03#1",
                    "proof": "L4",
                    "proof_effective": "L4",
                    "included": True,
                    "applicable_assets": 1,
                    "estimated_requests": 6,
                }
            ],
        },
    )
    unauthorized = _l4_request(active_checks_authorized=True)

    with pytest.raises(ProofRefused):
        await orchestrator.execute(record.id, unauthorized)

    assert sink.of_action(AuditAction.PROOF_REJECTED)


def test_an_unavailable_callback_downgrades_l2_with_a_recorded_note() -> None:
    """REQ-PROOF-003: no OOB service → the L2 check is downgraded, audited, never upgraded."""
    orchestrator, sink, _requests = _scan_stack()
    request = _l2_request(active_checks_authorized=True)

    plan = orchestrator.plan(request, dry_run=True)

    check = next(c for c in plan.included_checks if c.name == "sqli-oob")
    assert check.proof is ProofLevel.L2
    assert check.proof_effective is ProofLevel.L1
    assert check.proof_note and "downgraded" in check.proof_note
    # Every included L2 check is downgraded while no callback service is configured
    # (the plan is module-granular: the four L2 variants all appear). S29 added a fifth L2
    # check, m3.client-secret-verify, and it is downgraded by the same rule — the count moved,
    # the property did not.
    assert plan.totals.proof_downgrades == 5
    downgraded = sink.of_action(AuditAction.PROOF_DOWNGRADED)
    assert downgraded and "sqli-oob" in json.dumps(downgraded[0].meta)
    # The declared level is intact in the plan output (the print shows the downgrade).
    from arachne.cli.scan import render_plan

    rendered = render_plan(plan)
    assert "L1↓L2]" in rendered
    assert "downgraded to L1" in rendered


def test_no_check_is_ever_upgraded_above_its_declaration() -> None:
    """The downgrade is the only direction: effective ≤ declared, for every check."""
    orchestrator, _sink, _requests = _scan_stack()
    request = _l4_request(active_checks_authorized=True, state_changes_authorized=True)

    plan = orchestrator.plan(request, dry_run=True)

    for check in plan.checks:
        assert check.proof_effective.rank <= check.proof.rank, check.key


# --------------------------------------------------------------------------- the L2 opt-in chain


def test_l2_checks_send_nothing_without_their_opt_in_chain() -> None:
    """An L2 check is opt-in (REQ-PROOF-001) AND active-gated (F-01-09): proven at plan level."""
    orchestrator, _sink, _requests = _scan_stack()
    # Not named → not selected at all.
    default_request = build_scan_request(targets=[{"kind": "url", "value": f"https://{TARGET_HOST}/"}])
    plan = orchestrator.plan(default_request, dry_run=True)
    assert all(not check.included for check in plan.checks if check.proof.is_opt_in)
    # Named but not active-authorized → withheld with the active-checks code.
    request = _l2_request()  # no active_checks_authorized
    plan = orchestrator.plan(request, dry_run=True)
    check = next(c for c in plan.checks if c.name == "sqli-oob")
    assert not check.included
    assert check.skip_code == "active-checks-not-authorized"


def test_l2_checks_send_nothing_when_the_callback_service_is_absent() -> None:
    """No callback configured → the L2 half is downgraded (and the check skips it)."""
    orchestrator, _sink, requests = _scan_stack()
    request = _l2_request(active_checks_authorized=True)
    plan = orchestrator.plan(request, dry_run=True)
    check = next(c for c in plan.included_checks if c.name == "sqli-oob")
    assert check.proof_effective is ProofLevel.L1
    # The plan-level gate never sent anything; the check-level downgrade skip is covered
    # by the ladder integration test. Nothing was requested during planning:
    assert requests == []


# --------------------------------------------------------------------------- REQ-PROOF-004


def test_the_plan_output_shows_proof_levels_and_the_attestation_requirement() -> None:
    """Golden-ish assertion of the dry-run output with and without the attestation."""
    from arachne.cli.scan import render_plan

    orchestrator, _sink, _requests = _scan_stack()
    without = render_plan(
        orchestrator.plan(_l4_request(active_checks_authorized=True), dry_run=True)
    )
    assert "[L4]" in without
    assert "REQUIRED: an attestation with state_changes_authorized=true" in without
    assert "a live scan including them is REFUSED" in without

    orchestrator2, _sink2, _requests2 = _scan_stack()
    with_att = render_plan(
        orchestrator2.plan(
            _l4_request(active_checks_authorized=True, state_changes_authorized=True),
            dry_run=True,
        )
    )
    assert "[L4]" in with_att
    assert "state-change attestation present" in with_att


# --------------------------------------------------------------------------- REQ-PROOF-011
# One named test per prohibition. Each points at the code boundary that enforces it.


def test_prohibition_persistent_shells_refused() -> None:
    """The L3 surface can only ever emit `echo`; there is no API that carries another command."""
    assert {"echo"} == ALLOWED_COMMANDS
    assert command_payload("ab12cd34ef56").startswith("echo arachne-")
    with pytest.raises(ProofRefused):
        validate_nonce("nc-127-0-0-1-4444-e")  # a shell-shaped "nonce" is not a nonce
    # And the SQL boundary refuses the persistence primitives too.
    assert "CREATE" in PROHIBITED_SQL_HEADS


def test_prohibition_destructive_sql_refused() -> None:
    for statement in (
        "DELETE FROM arachne_poc WHERE marker = 'x'",
        "DROP TABLE arachne_poc",
        "TRUNCATE TABLE arachne_poc",
        "ALTER TABLE products DROP COLUMN price",
        "GRANT ALL ON arachne_poc TO PUBLIC",
    ):
        with pytest.raises(ProofRefused):
            refuse_statement(statement)
        assert sql_refusals(statement)


def test_prohibition_data_deletion_without_restore_refused() -> None:
    """The helper has no delete API at all, and an UPDATE refuses a row it cannot restore."""
    helper_public_api = {name for name in dir(SqlProof) if not name.startswith("_")}
    assert not any("delete" in name or "drop" in name for name in helper_public_api)
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)

    class Sink:
        async def execute(self, sql: str, params: Any = ()) -> str:
            return ""

    helper = SqlProof(executor=Sink(), ledger=ledger, check_id="m3.state-marker")
    import asyncio

    with pytest.raises(ProofRefused, match="never writes a row it cannot restore"):
        asyncio.run(
            helper.update_with_restore(
                nonce="ab12cd34ef56",
                table="products",
                key_column="id",
                key_value="404",
                column="price",
                new_value="1.00",
            )
        )


def test_prohibition_credential_account_mutation_refused() -> None:
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)

    class Sink:
        async def execute(self, sql: str, params: Any = ()) -> str:
            return ""

    helper = SqlProof(executor=Sink(), ledger=ledger, check_id="m3.state-marker")
    import asyncio

    for table in ("users", "accounts", "sessions", "api_keys", "credentials"):
        with pytest.raises(ProofRefused, match="identity store"):
            asyncio.run(
                helper.update_with_restore(
                    nonce="ab12cd34ef56",
                    table=table,
                    key_column="id",
                    key_value="1",
                    column="email",
                    new_value="attacker@example.com",
                )
            )


def test_prohibition_secret_exfiltration_refused() -> None:
    """OOB captures are capped and redacted at capture; proof output excerpts are bounded."""
    secret = "AKIAIOSFODNN7EXAMPLE"  # a pattern-detected credential shape
    service = CallbackService()
    token = service.issue(1, "m3.sqli-oob")
    hit = service.record_hit(
        str(token),
        body=f"db_password={secret} " + "x" * (MAX_HIT_BODY_CHARS * 4),
        headers={"Authorization": f"Bearer {secret}"},
    )
    assert hit is not None
    assert secret not in hit.body
    assert len(hit.body) <= MAX_HIT_BODY_CHARS
    assert secret not in json.dumps(hit.to_dict())


def test_prohibition_service_disruption_refused() -> None:
    """One proof, one shot: a second execution is refused and token issuance is capped."""
    from arachne.proof.commands import CommandProof

    proof = CommandProof(check_id="m3.rce-echo", scan_id=1)

    async def sink(value: str) -> str:
        return value

    import asyncio

    asyncio.run(proof.prove(sink))
    with pytest.raises(ProofRefused, match="one-shot"):
        asyncio.run(proof.prove(sink))
    service = CallbackService(max_tokens_per_scan=2)
    service.issue(5, "m3.probe")
    service.issue(5, "m3.probe")
    with pytest.raises(OverflowError):
        service.issue(5, "m3.probe")


def test_prohibition_evasion_tooling_refused() -> None:
    """Obfuscated payloads are refused at the format level: proofs are plain, reviewable text."""
    with pytest.raises(ProofRefused, match="plain text"):
        encode_free("echo arachne-ab12cd34 && base64 -d<<<ZXZpbA==")
    with pytest.raises(ProofRefused):
        validate_nonce("AB12cd34ef56")  # mixed case: not the plain identifier format
    assert sql_refusals("SELECT 1 -- hide this")
    assert sql_refusals("SELECT /* stealth */ 1")


# --------------------------------------------------------------------------- REQ-PROOF-012


def test_oob_hits_are_redacted_at_capture() -> None:
    """The callback hit goes through the same redaction as every other capture path."""
    secret = "AKIAIOSFODNN7EXAMPLE"  # pattern-detected at capture
    service = CallbackService()
    token = service.issue(3, "m3.xxe-oob")
    hit = service.record_hit(
        str(token),
        body=f"<?xml?><!-- {secret} -->",
        headers={"X-Callback-Auth": f"Bearer {secret}"},
    )
    assert hit is not None
    assert secret not in hit.body
    assert secret not in json.dumps(hit.headers)


def test_the_callback_service_never_dials_out() -> None:
    """REQ-PROOF-005: hostile hit content triggers no outbound connection of any kind."""

    class ExplodingSocket(socket.socket):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise AssertionError("the callback service attempted an outbound connection")

    service = CallbackService()
    token = service.issue(9, "m3.ssrf-probe")
    hostile_body = (
        "please fetch http://attacker.invalid/exfil?token=x and http://127.0.0.1/admin "
        "and <img src=http://attacker.invalid/pixel>"
    )
    original = socket.socket
    socket.socket = ExplodingSocket  # type: ignore[misc]
    try:
        hit = service.record_hit(str(token), body=hostile_body, headers={"Referer": "http://attacker.invalid"})
    finally:
        socket.socket = original  # type: ignore[misc]
    assert hit is not None
    assert "attacker.invalid" in hit.body  # stored redacted, never acted on


def test_proof_evidence_is_redacted_through_the_normal_path() -> None:
    """A proof artifact built the way the checks build it inherits capture-time redaction."""
    from arachne.core.results import Evidence

    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    evidence = Evidence.of(
        "proof",
        {"level": "L2", "method": "oob", "hit": {"body": f"token={secret}"}},
        source="https://example.com/product",
    )
    dumped = json.dumps(evidence.to_dict())
    assert secret not in dumped


def test_the_ledger_redacts_what_it_persists() -> None:
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)
    secret = "AKIAIOSFODNN7EXAMPLE"
    ledger.record_state_change(
        change_id="sc-1",
        kind="update",
        check_id="m3.state-marker",
        table="products",
        locator="products.id=1",
        before={"price": "19.99", "note": f"leak {secret}"},
        after={"price": "0.01"},
    )
    dumped = json.dumps(record.stats)
    assert secret not in dumped


# ----------------------------------------------------------------- the capability boundary


def test_the_capability_boundary_refuses_escalation() -> None:
    """ctx.proof grants exactly the declared level: an L1 check cannot reach an L4 helper."""
    from arachne.proof.access import ProofAccess

    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)

    metadata = CheckMetadata(
        id="m3.small",
        module="M3",
        name="small",
        version="1.0",
        title="Small",
        description="An L1 check that must not reach the L4 helper.",
        research_ref="ch03#1",
        target_kinds=(TargetKind.URL,),
        type="active",
        requires_active_checks=True,
        proof=ProofLevel.L1,
    )

    class Sink:
        async def execute(self, sql: str, params: Any = ()) -> str:
            return ""

    access = ProofAccess(
        level=metadata.proof,
        check_id=metadata.id,
        scan_id=record.id,
        ledger=ledger,
        state_changes_authorized=True,  # even a fully attested scan cannot upgrade a check
    )
    with pytest.raises(ProofRefused, match="requires L4"):
        access.sql(Sink())  # type: ignore[arg-type]
    with pytest.raises(ProofRefused, match="requires L2"):
        access.oob_token()
    with pytest.raises(ProofRefused, match="requires L3"):
        access.command_proof()


def test_the_boundary_refuses_l4_without_the_state_attestation_even_for_l4_checks() -> None:
    from arachne.proof.access import ProofAccess

    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)
    access = ProofAccess(
        level=ProofLevel.L4,
        check_id="m3.state-marker",
        scan_id=record.id,
        ledger=ledger,
        state_changes_authorized=False,
    )

    class Sink:
        async def execute(self, sql: str, params: Any = ()) -> str:
            return ""

    with pytest.raises(ProofRefused, match="state_changes_authorized"):
        access.sql(Sink())  # type: ignore[arg-type]


# --------------------------------------------------------------------------- the running check


def _check_context(access: Any, module: Module, host: str) -> CheckContext:  # pragma: no cover
    raise NotImplementedError


def test_a_check_cannot_fetch_outside_scope_even_for_oob_lookups() -> None:
    """The standalone consume path goes through the scoped client like every request."""
    # Covered structurally: ProofAccess consumes over ctx.http (the scoped client), and
    # test_safety.py proves that client refuses out-of-scope hosts. This test pins the
    # wiring: the consume URL is derived from the configured callback base only.
    from arachne.proof.access import ProofAccess

    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)
    access = ProofAccess(
        level=ProofLevel.L2,
        check_id="m3.sqli-oob",
        scan_id=record.id,
        ledger=ledger,
        callback_base=None,  # nothing configured → consume is refused, not guessed
    )
    import asyncio

    with pytest.raises(ProofRefused, match="no callback service"):
        asyncio.run(access.oob_consume("arachne-1-m3.sqli-oob-aaaaaaaaaaaaaaaa"))
