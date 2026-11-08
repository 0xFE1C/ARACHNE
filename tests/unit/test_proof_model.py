"""Unit tests for the proof ladder's pure model and helpers (S15, area PROOF).

REQ-PROOF-001 — the metadata declaration is unrepresentable-invalid: an L2+ check that
is not opt-in, or an L3/L4 check without the state-change attestation requirement,
cannot be constructed (and the registry re-checks construction bypasses).
REQ-PROOF-005 — token format ``arachne-<scan-id>-<check-id>-<nonce>``, uniqueness under
concurrent issuance, single-use matching in the service.
REQ-PROOF-007 — the L3 helper has no arbitrary command API and is one-shot.
REQ-PROOF-008/010 — the L4 SQL helper: INSERT-first, before-capture, auto-restore,
re-verification, write-ahead ledger, destructive-SQL refusal, cleanup pass.
REQ-PROOF-009 — the calm, self-identifying marker format.
"""

from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from dataclasses import replace

import pytest

from arachne.core.errors import ConfigurationError
from arachne.core.lifecycle import MemoryScanStateStore
from arachne.core.proof import (
    CallbackToken,
    ProofLevel,
    ProofRefused,
    command_payload,
    encode_free,
    parse_callback_token,
    poc_marker,
    sql_refusals,
    validate_nonce,
)
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.registry import ModuleGroup, ModuleRegistry
from arachne.proof.commands import CommandProof
from arachne.proof.ledger import ProofLedger
from arachne.proof.oob import CallbackService
from arachne.proof.sql import MARKER_TABLE, SqlProof


# --------------------------------------------------------------------------- REQ-PROOF-001
def _metadata(**overrides: object) -> CheckMetadata:
    base: dict[str, object] = {
        "id": "m3.probe",
        "module": "M3",
        "name": "probe",
        "version": "1.0",
        "title": "Probe",
        "description": "A probe check used by the proof-ladder tests.",
        "research_ref": "ch03#1",
        "target_kinds": (TargetKind.URL,),
        "type": "active",
        "requires_active_checks": True,
    }
    base.update(overrides)
    return CheckMetadata(**base)  # type: ignore[arg-type]


def test_l2_without_opt_in_is_unrepresentable() -> None:
    with pytest.raises(ConfigurationError, match="opt-in"):
        _metadata(proof=ProofLevel.L2)


def test_l3_without_state_attestation_is_unrepresentable() -> None:
    with pytest.raises(ConfigurationError, match="requires_state_attestation"):
        _metadata(proof=ProofLevel.L3, enabled_by_default=False)


def test_l4_requires_the_attestation_flag_and_opt_in() -> None:
    with pytest.raises(ConfigurationError, match="requires_state_attestation"):
        _metadata(proof=ProofLevel.L4, enabled_by_default=False)
    with pytest.raises(ConfigurationError, match="opt-in"):
        _metadata(proof=ProofLevel.L4, requires_state_attestation=True)


def test_l1_cannot_claim_the_state_attestation_flag() -> None:
    with pytest.raises(ConfigurationError, match="must stay False"):
        _metadata(proof=ProofLevel.L1, requires_state_attestation=True)


def test_a_valid_l4_declaration_constructs() -> None:
    metadata = _metadata(
        proof=ProofLevel.L4, enabled_by_default=False, requires_state_attestation=True
    )
    assert metadata.proof is ProofLevel.L4
    assert metadata.requires_state_attestation is True


def test_registry_rejects_a_construction_bypass() -> None:
    """REQ-PROOF-002: the registry re-validates, so a mutated declaration is fatal there."""

    metadata = _metadata(proof=ProofLevel.L1)
    # Simulate a hand-crafted instance that bypassed __post_init__ (a hostile plugin).
    object.__setattr__(metadata, "proof", ProofLevel.L2)

    hostile_metadata = metadata

    class Hostile(Module):
        metadata = hostile_metadata

        async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
            # Registration-only check: it is never iterated in these tests.
            raise NotImplementedError
            yield CheckResult(status="info", title="unused")  # type: ignore[unreachable]

    with pytest.raises(ConfigurationError, match="proof declaration"):
        ModuleGroup(id="M3", title="t", description="d", version="1.0", checks=(Hostile,))


def test_the_shipped_checks_are_annotated_l1() -> None:
    """REQ-PROOF-002: no non-ladder check reaches past L1, and the ladder rows are the L2+ set.

    Renamed from ``test_the_shipped_132_checks_are_annotated_l1`` when S19 added two checks;
    S23's cloud-posture row makes the shipped non-ladder set 136. S29 brings it to 145 (the ten
    depth checks minus the seventh L2+ row), and adds the one check that declares *below* L1:
    ``m1.mobile-artifact`` is **L0** because it contacts nothing at all. WP-07's three
    read-only MCP checks bring the non-ladder set to 148; WP-08's nine L1 breadth checks
    bring it to 157; WP-09's three L1 transport checks (mTLS, SMTP transport, HTTP/3)
    bring it to 160; WP-10's five L1 identity/AI-surface checks (AD CS and the four
    Agentic Top 10 reads) bring it to 165; WP-11's DOM-sink browser check (an L1 read of a
    page the scan already reaches) brings it to 166; WP-12's native image scanner and
    DigitalOcean posture check bring it to 168. The declaration is pinned here
    rather than merely permitted, so an accidental widening of any check's reach still fails.
    The number in a test name is churn, the property is not.
    """
    registry = ModuleRegistry.builtin()
    ladder = {m.id for m in registry.metadata() if m.proof.is_opt_in}
    original = [m for m in registry.metadata() if m.id not in ladder]
    # WP-20 adds the SSH credential check (REQ-CREDS-006), an active L1 check that reaches
    # the network behind the same scope gate as the SMB one -> 169. WP-25's twenty-six
    # WordPress checks are all L1 (one of them, m3.wp-cron-surface, is active because its
    # reachability probe is an OPTIONS) -> 195. WP-26's thirty CMS checks are all L1, and all
    # of them are plain GET probes -> 225. WP-27's twenty-five application-server checks are
    # all L1 GET probes too -> 250. WP-28's twenty-four API and modern-web checks are all L1 as
    # well (three of them an OPTIONS preflight, which is HTTP's own safe method) -> 274;
    # WP-29's twenty-four infrastructure-artifact checks are all L1 plain GET probes -> 298;
    # WP-30's twenty-four server/platform checks are all L1 reads too — twenty-one plain GET
    # probes and three that read the crawl's response headers without a request -> 322.
    # WP-31's thirty-one AWS posture checks are all L1 reads (a credentialed API read is
    # still a read) -> 353. WP-32's twenty-eight Azure/GCP/Kubernetes posture checks are all
    # L1 reads for the same reason, and none of them is opt-in -> 381. WP-33's thirty-one
    # exposed-service checks are all L1 reads too (an HTTP GET or one wire protocol read
    # command), and none of them is opt-in -> 412. WP-34's eight reconnaissance-breadth
    # checks and twenty-one AI-era serving checks are all L1 reads (a provider query, a crawl
    # read or one anonymous GET of a status document), and none of them is opt-in -> 441.
    assert len(original) == 441
    assert all(m.proof in {ProofLevel.L0, ProofLevel.L1} for m in original)
    assert {m.id for m in original if m.proof is ProofLevel.L0} == {"m1.mobile-artifact"}
    assert all(not m.requires_state_attestation for m in original)


# --------------------------------------------------------------------------- REQ-PROOF-005
def test_token_format_and_round_trip() -> None:
    token = CallbackToken(42, "m3.sqli-oob", "ab12cd34ef56ab12cd34ef56")
    assert str(token) == f"arachne-42-m3.sqli-oob-{token.nonce}"
    parsed = parse_callback_token(str(token))
    assert parsed == token
    assert parsed.scan_id == "42"
    assert parsed.check_id == "m3.sqli-oob"
    assert parsed.nonce == token.nonce


def test_token_rejects_metacharacters_and_short_nonces() -> None:
    with pytest.raises(ProofRefused):
        CallbackToken(42, "m3.probe", "abc;rm-rf-/")
    with pytest.raises(ProofRefused):
        CallbackToken(42, "m3.probe", "short")
    with pytest.raises(ProofRefused):
        CallbackToken("scan;id", "m3.probe", "ab12cd34ef56ab12cd34ef56")


def test_concurrent_scan_tokens_are_unique() -> None:
    """The acceptance property: tokens issued across concurrent scans never collide."""
    service = CallbackService()
    results: list[str] = []
    lock = threading.Lock()

    def issue(scan_id: int) -> None:
        local = [str(service.issue(scan_id, "m3.sqli-oob")) for _ in range(200)]
        with lock:
            results.extend(local)

    threads = [threading.Thread(target=issue, args=(scan,)) for scan in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 8 * 200
    assert len(set(results)) == len(results)
    for value in results:
        assert parse_callback_token(value).scan_id in {str(i) for i in range(8)}


def test_per_scan_issuance_is_capped() -> None:
    service = CallbackService(max_tokens_per_scan=4)
    for _ in range(4):
        service.issue(1, "m3.probe")
    with pytest.raises(OverflowError, match="cap"):
        service.issue(1, "m3.probe")
    service.issue(2, "m3.probe")  # another scan is unaffected


def test_hits_are_single_use_and_replays_are_refused() -> None:
    service = CallbackService()
    token = service.issue(7, "m3.sqli-oob")
    assert service.record_hit(str(token), body="ARACHNE_POC hit") is not None
    first = service.consume(str(token))
    assert first is not None
    assert service.consume(str(token)) is None  # single use
    assert service.probe(str(token)) is not None and service.probe(str(token)).consumed  # type: ignore[union-attr]
    # A replayed hit after consumption is refused too.
    assert service.record_hit(str(token), body="again") is None


def test_unknown_tokens_are_refused() -> None:
    service = CallbackService()
    assert service.record_hit("arachne-9-m3.ghost-aaaaaaaaaaaaaaaa", body="x") is not None
    assert service.consume("arachne-9-m3.ghost-bbbbbbbbbbbb") is None


# --------------------------------------------------------------------------- REQ-PROOF-009
def test_marker_is_calm_and_self_identifying() -> None:
    marker = poc_marker("ab12cd34ef56", "state-change probe")
    assert marker.startswith("ARACHNE_POC_ab12cd34ef56")
    assert "safe proof of state-change probe" in marker
    assert "see ARACHNE report" in marker
    lowered = marker.lower()
    assert not any(word in lowered for word in ("penetrated", "hacked", "pwned", "breached"))


def test_marker_refuses_fear_wording() -> None:
    with pytest.raises(ProofRefused, match="calm"):
        poc_marker("ab12cd34ef56", "Penetrated the database")


def test_nonce_format_refuses_obfuscation() -> None:
    with pytest.raises(ProofRefused):
        validate_nonce("Ab12Cd34Ef56!")  # not [a-z0-9]
    with pytest.raises(ProofRefused):
        validate_nonce("$(whoami)xx12")


# --------------------------------------------------------------------------- REQ-PROOF-007
def test_the_only_command_is_the_allowlisted_echo() -> None:
    proof = CommandProof(check_id="m3.rce-echo", scan_id=1)
    assert proof.payload == f"echo arachne-{proof.nonce}"
    assert command_payload(proof.nonce) == proof.payload
    # No API accepts a command string: payload is a property, prove() takes a sink.


def test_l3_proof_is_one_shot() -> None:
    proof = CommandProof(check_id="m3.rce-echo", scan_id=1)

    async def sink(value: str) -> str:
        return value

    import asyncio

    first = asyncio.run(proof.prove(sink))
    assert first.payload == proof.payload
    with pytest.raises(ProofRefused, match="one-shot"):
        asyncio.run(proof.prove(sink))


def test_l3_refuses_shell_shaped_nonces() -> None:
    with pytest.raises(ProofRefused):
        command_payload("a;rm-rf-/b1234")


def test_encode_free_refuses_obfuscated_payloads() -> None:
    with pytest.raises(ProofRefused, match="plain text"):
        encode_free("echo arachne-x && base64 -d<<<ZXZpbA==")
    assert encode_free("echo arachne-ab12cd34ef56") == "echo arachne-ab12cd34ef56"


# --------------------------------------------------------------------------- REQ-PROOF-008
class FakeExecutor:
    """A scripted executor over an in-memory table, for the L4 ritual tests."""

    def __init__(self) -> None:
        self.rows: dict[str, str] = {}
        self.executed: list[tuple[str, tuple[object, ...]]] = []
        self.fail_on: str | None = None

    async def execute(self, sql: str, params: object = ()) -> str:
        params_tuple = tuple(params) if isinstance(params, (list, tuple)) else (params,)
        self.executed.append((sql, params_tuple))
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError(f"executor failure on {self.fail_on}")
        head = sql.split(" ", 1)[0].upper()
        if head == "SELECT":
            marker = params_tuple[0] if params_tuple else None
            matches = [key for key in self.rows if marker is None or key == str(marker)]
            found = [self.rows[key] for key in matches]
            if sql.upper().startswith("SELECT MARKER"):
                return "\n".join(matches)
            return "\n".join(found)
        if head == "INSERT":
            marker, note = str(params_tuple[0]), str(params_tuple[1])
            self.rows[marker] = note
            return "ok"
        if head == "UPDATE":
            value, key = str(params_tuple[0]), str(params_tuple[1])
            if key in self.rows:
                self.rows[key] = value
                return "ok"
            return ""
        if head == "DELETE":
            key = str(params_tuple[0])
            if key in self.rows:
                del self.rows[key]
            return "ok"
        return ""


def _sql_proof(executor: FakeExecutor) -> tuple[SqlProof, ProofLedger]:
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)
    return SqlProof(executor=executor, ledger=ledger, check_id="m3.state-marker"), ledger


def test_insert_marker_writes_verifies_restores_and_reverifies() -> None:
    import asyncio

    executor = FakeExecutor()
    proof, ledger = _sql_proof(executor)
    record = asyncio.run(proof.insert_marker(nonce="ab12cd34ef56"))
    assert record.restored and record.restore_verified
    assert executor.rows == {}  # zero residue
    # The order proves the ritual: INSERT, verify, DELETE (own row), verify absence.
    heads = [sql.split(" ")[0].upper() for sql, _params in executor.executed]
    assert heads == ["INSERT", "SELECT", "DELETE", "SELECT"]
    assert all("arachne_poc" in sql for sql, _params in executor.executed)
    assert ledger.unrestored() == ()


def test_update_with_restore_captures_before_and_reverifies() -> None:
    import asyncio

    executor = FakeExecutor()
    executor.rows["anchor-product"] = "19.99"
    proof, _ledger = _sql_proof(executor)
    record = asyncio.run(
        proof.update_with_restore(
            nonce="ab12cd34ef56",
            table="products",
            key_column="name",
            key_value="anchor-product",
            column="price",
            new_value="0.01",
        )
    )
    assert record.before == {"price": "19.99"}
    assert record.restored and record.restore_verified
    assert executor.rows["anchor-product"] == "19.99"  # restored to the captured value


def test_update_refuses_a_row_it_cannot_restore() -> None:
    import asyncio

    executor = FakeExecutor()  # no such row
    proof, _ledger = _sql_proof(executor)
    with pytest.raises(ProofRefused, match="never writes a row it cannot restore"):
        asyncio.run(
            proof.update_with_restore(
                nonce="ab12cd34ef56",
                table="products",
                key_column="name",
                key_value="ghost",
                column="price",
                new_value="0.01",
            )
        )


def test_destructive_sql_is_refused_at_the_boundary() -> None:
    for statement in (
        "DELETE FROM arachne_poc",
        "DROP TABLE products",
        "TRUNCATE arachne_poc",
        "ALTER TABLE products ADD COLUMN x",
        "GRANT ALL ON products TO attacker",
        "SELECT 1; DROP TABLE products",
        "SELECT '-- comment",
        "SELECT 'quoted'",
    ):
        assert sql_refusals(statement), statement


def test_the_only_delete_is_the_own_marker_restore() -> None:
    """The one DELETE the helper can issue targets only its own marker row."""
    import asyncio

    executor = FakeExecutor()
    proof, _ledger = _sql_proof(executor)
    asyncio.run(proof.insert_marker(nonce="ab12cd34ef56"))
    deletes = [sql for sql, _params in executor.executed if sql.upper().startswith("DELETE")]
    expected_delete = f"DELETE FROM {MARKER_TABLE} WHERE marker = ?"  # noqa: S608 - comparison only
    assert deletes == [expected_delete]


def test_identity_store_tables_are_refused() -> None:
    import asyncio

    executor = FakeExecutor()
    proof, _ledger = _sql_proof(executor)
    for table in ("users", "credentials", "sessions", "api_keys", "tokens"):
        with pytest.raises(ProofRefused, match="identity store"):
            asyncio.run(
                proof.update_with_restore(
                    nonce="ab12cd34ef56",
                    table=table,
                    key_column="id",
                    key_value="1",
                    column="email",
                    new_value="attacker@example.com",
                )
            )


def test_a_failed_restore_leaves_restored_false_and_a_repair_instruction() -> None:
    """REQ-PROOF-010: the crash path leaves a durable unrestored row + instruction.

    A failed restore does not abort the check — the write-ahead row keeps
    ``restored=false`` and the repair instruction is derivable from the scan record.
    """
    import asyncio

    executor = FakeExecutor()
    proof, ledger = _sql_proof(executor)
    executor.fail_on = "DELETE"  # the restore path dies
    record = asyncio.run(proof.insert_marker(nonce="ab12cd34ef56"))
    assert record.restored is False
    assert record.error
    unrestored = ledger.unrestored()
    assert len(unrestored) == 1
    assert unrestored[0].restored is False
    instruction = unrestored[0].repair_instruction()
    assert "REPAIR REQUIRED" in instruction
    assert "arachne_poc" in instruction


def test_the_cleanup_pass_restores_leftovers() -> None:
    import asyncio

    executor = FakeExecutor()
    proof, ledger = _sql_proof(executor)
    executor.fail_on = "DELETE"
    asyncio.run(proof.insert_marker(nonce="ab12cd34ef56"))
    assert ledger.unrestored()
    executor.fail_on = None
    report = asyncio.run(ledger.run_cleanup_pass())
    assert report.attempted == 1 and report.restored == 1
    assert ledger.unrestored() == ()
    assert executor.rows == {}  # the residue is gone


def test_ledger_persists_with_the_scan_record() -> None:
    """REQ-PROOF-012: the nonce→probe map and cleanup status live in the scan's stats."""
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, record.id)
    token = str(CallbackToken(record.id, "m3.sqli-oob", "ab12cd34ef56"))
    ledger.record_oob_probe(token, check_id="m3.sqli-oob", nonce="ab12cd34ef56")
    ledger.record_state_change(
        change_id="sc-1",
        kind="insert-marker",
        check_id="m3.state-marker",
        table=MARKER_TABLE,
        locator=f"{MARKER_TABLE}.marker=x",
        before=None,
        after={"marker": "x"},
    )
    reloaded = ProofLedger(store, record.id)
    assert token in reloaded.oob_probes
    assert reloaded.unrestored()[0].change_id == "sc-1"
    stats = store.get_scan(record.id).stats  # type: ignore[union-attr]
    assert "proof" in stats and stats["proof"]["oob"][token]["check_id"] == "m3.sqli-oob"


def test_metadata_replace_revalidates_the_proof_declaration() -> None:
    """Even dataclasses.replace cannot produce a contradictory declaration."""
    metadata = _metadata(proof=ProofLevel.L2, enabled_by_default=False)
    with pytest.raises(ConfigurationError):
        replace(metadata, enabled_by_default=True)
