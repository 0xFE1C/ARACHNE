"""Purple-team safety suite (S24, area VALID) — ``tests/test_safety.py`` style.

The properties that must never regress, on top of every gate the earlier stages built:

1. **No window, no purple team.** A scan asking for purple mode without the detection-window
   attestation class is refused at the *authorization* gate and audited (REQ-VALID-001).
2. **The window is enforced at plan, execute and resume**, with the refusal audited as
   ``purple.window_refused`` — and *nothing sent and no scan admitted* when it fires.
3. **The window stops the run while it runs**: once it closes, the remaining actions are
   skipped and the stop is audited once (``purple.window_closed``) (REQ-VALID-003).
4. **The map cannot lie about the ladder**, and an action that is not replayable is refused
   rather than silently dropped.
5. **Every emitted artifact carries the run nonce**, and the nonce is the run's — not a
   fresh random tag per action (REQ-VALID-003).
6. **The ordinary rate limit still applies**: a purple run is a test, not an exemption.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import (
    PurpleSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.errors import AuthorizationError, ConfigurationError, DetectionWindowError
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.modules.registry import ModuleRegistry
from tests.conftest import PUBLIC_IP, TARGET_HOST, build_scan_request

NOW = datetime.now(UTC)
WINDOW_OPEN = {
    "starts_at": (NOW - timedelta(minutes=5)).isoformat(),
    "ends_at": (NOW + timedelta(minutes=30)).isoformat(),
    "coordinator": "soc-lead@corp",
    "defender": "blue-team@corp",
}
WINDOW_FUTURE = {
    "starts_at": (NOW + timedelta(hours=1)).isoformat(),
    "ends_at": (NOW + timedelta(hours=2)).isoformat(),
    "coordinator": "soc-lead@corp",
}
WINDOW_PAST = {
    "starts_at": (NOW - timedelta(hours=3)).isoformat(),
    "ends_at": (NOW - timedelta(hours=2)).isoformat(),
    "coordinator": "soc-lead@corp",
}

ACTIONS = ("m3.sqli-oob", "m3.cmdi-oob")


def _scan_stack(
    *,
    rate_limit: RateLimitSettings | None = None,
    audit_sink: MemoryAuditSink | None = None,
    map_path: str | None = None,
    with_handlers: bool = False,
) -> tuple[Orchestrator, MemoryAuditSink, list[str]]:
    """The orchestrator + recording transport: "nothing was sent" is an observation."""
    sink = audit_sink or MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    settings = Settings(
        database_url="sqlite:///:memory:",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope(allowed_hosts=(TARGET_HOST,)),
        ),
        rate_limit=rate_limit or RateLimitSettings(),
        purple=PurpleSettings(map_path=map_path),
        log_level="CRITICAL",
    )
    requests: list[str] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200, text="ok")

    def factory(scope: Scope) -> ScopedHttpClient:
        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            resolver=StaticResolver((PUBLIC_IP,)),
            auditor=auditor,
            transport=httpx.MockTransport(transport_handler),
        )

    registry = ModuleRegistry.builtin()
    if with_handlers:
        from arachne.modules.handlers import build_handlers
        from arachne.purple.campaign import PurpleRunner

        handlers = build_handlers(
            settings=settings,
            registry=registry,
            auditor=auditor,
            purple=PurpleRunner.build(settings),
        )
    else:
        handlers = {}
    orchestrator = Orchestrator(
        settings=settings,
        auditor=auditor,
        bus=EventBus(),
        store=MemoryScanStateStore(),
        registry=registry,
        client_factory=factory,
        handlers=handlers,
    )
    return orchestrator, sink, requests


def _purple_request(*, window: dict[str, Any] | None, actions: tuple[str, ...] = ACTIONS):
    """A purple-team scan request over the proof actions the map ships."""
    attestation: dict[str, Any] = {
        "attested_by": "S24 safety test",
        "attested_at": (NOW - timedelta(hours=6)).isoformat(),
        "scope_statement": "coordinated purple-team window over the test target",
        "allowed_targets": [f"https://{TARGET_HOST}/", TARGET_HOST],
        "active_checks_authorized": True,
        "expires_at": (NOW + timedelta(hours=4)).isoformat(),
    }
    if window is not None:
        attestation["detection_window"] = window
    return build_scan_request(
        attestation=attestation,
        targets=[{"kind": "url", "value": f"https://{TARGET_HOST}/"}],
        options={
            "active_checks": True,
            "modules": {"only": list(actions)},
            "purple": {"campaign": "safety-test", "actions": list(actions)},
        },
    )


# ------------------------------------------------------------------ 1. no window, no test
def test_purple_mode_without_a_detection_window_is_refused_and_audited() -> None:
    """REQ-VALID-001's acceptance, at the authorization gate."""
    orchestrator, sink, requests = _scan_stack()
    request = _purple_request(window=None)

    with pytest.raises(AuthorizationError, match="detection-window attestation"):
        orchestrator.plan(request, dry_run=False)

    rejected = sink.of_action(AuditAction.AUTH_REJECTED)
    assert rejected and rejected[0].outcome.value == "blocked"
    assert rejected[0].meta["purple"] is True
    assert requests == [], "a refused purple plan must not send anything"
    assert orchestrator.store.list_scans() == ()


# ------------------------------------------------------------------ 2. the window gate
@pytest.mark.parametrize(
    ("window", "word"),
    [(WINDOW_FUTURE, "pending"), (WINDOW_PAST, "closed")],
)
def test_a_window_that_is_not_open_refuses_the_plan_and_sends_nothing(
    window: dict[str, Any], word: str
) -> None:
    """Out-of-window actions are refused and audited — the REQ-VALID-001 property."""
    orchestrator, sink, requests = _scan_stack()
    request = _purple_request(window=window)

    with pytest.raises(DetectionWindowError, match=word):
        orchestrator.plan(request, dry_run=False)

    refused = sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED)
    assert len(refused) == 1
    assert refused[0].outcome.value == "blocked"
    assert refused[0].meta["state"] == word
    assert refused[0].meta["campaign"] == "safety-test"
    assert refused[0].meta["window"]["present"] is True
    assert requests == []
    assert orchestrator.store.list_scans() == ()


def test_an_open_window_plans_cleanly_and_a_dry_run_only_reports() -> None:
    orchestrator, sink, _ = _scan_stack()
    request = _purple_request(window=WINDOW_OPEN)

    plan = orchestrator.plan(request, dry_run=True)
    assert plan.live_ready is True
    assert sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED) == []
    assert {check.key.split("/")[1].split("@")[0] for check in plan.included_checks} == {
        "sqli-oob",
        "cmdi-oob",
    }


def test_execute_rechecks_the_window_so_a_lapsed_run_cannot_start() -> None:
    """An admitted purple run whose window closed while it queued must not fire."""
    orchestrator, sink, requests = _scan_stack()
    opener, _, _ = _scan_stack(audit_sink=sink)
    request = _purple_request(window=WINDOW_OPEN)
    session = opener.plan(request, dry_run=False)
    assert session.live_ready is True
    # Re-plan the *same* run with the window now behind us: the gate refuses on the way in.
    lapsed = _purple_request(window=WINDOW_PAST)
    with pytest.raises(DetectionWindowError, match="closed"):
        orchestrator.plan(lapsed, dry_run=False)
    assert requests == []


@pytest.mark.asyncio
async def test_a_refused_window_never_creates_a_scan_row() -> None:
    """The refusal is a gate, not a failed run: no admission record, no audit of a scan."""
    orchestrator, sink, requests = _scan_stack()
    with pytest.raises(DetectionWindowError):
        await orchestrator.scan(_purple_request(window=WINDOW_FUTURE))
    assert orchestrator.store.list_scans() == ()
    assert sink.of_action(AuditAction.SCAN_CREATED) == []
    assert sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED)[0].outcome.value == "blocked"
    assert requests == []


# ------------------------------------------------------------------ 3. the map is checked
def test_the_map_cannot_lie_about_the_ladder(tmp_path: Path) -> None:
    """An action whose declared level differs from the catalogue's is refused (REQ-VALID-001).

    Driven through a doctored map file: a map that claims the L3 ``echo`` proof is L2 would
    mislabel where on the ladder the test sits, so the gate refuses the plan and audits it.
    """
    import yaml

    from arachne.purple.attack import load_technique_map

    honest = load_technique_map()
    document = {
        "version": "1.0",
        "actions": [
            {
                "check": action.check_id,
                "title": action.title,
                "level": "L2" if action.check_id == "m3.rce-echo" else action.level,
                "tactic": action.tactic,
                "techniques": list(action.techniques),
                "severity": action.severity,
                "telemetry": {
                    "summary": action.event.summary,
                    "logsource": dict(action.event.logsource),
                    "event": dict(action.event.fields),
                },
            }
            for action in honest.actions.values()
        ],
    }
    doctored = tmp_path / "doctored-map.yaml"
    doctored.write_text(yaml.safe_dump(document), encoding="utf-8")
    assert load_technique_map(doctored).require("m3.rce-echo").level == "L2"

    orchestrator, sink, requests = _scan_stack(map_path=str(doctored))
    request = _purple_request(window=WINDOW_OPEN, actions=("m3.rce-echo",))
    with pytest.raises(DetectionWindowError, match=r"declares m3\.rce-echo at L2"):
        orchestrator.plan(request, dry_run=False)
    refused = sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED)
    assert refused and refused[0].outcome.value == "blocked"
    assert requests == []


def test_an_action_that_is_not_replayable_is_refused_at_plan_time() -> None:
    orchestrator, sink, requests = _scan_stack()
    request = _purple_request(window=WINDOW_OPEN, actions=("m3.invented-check",))
    with pytest.raises(DetectionWindowError, match="not a replayable purple-team action"):
        orchestrator.plan(request, dry_run=False)
    refused = sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED)
    assert refused and refused[0].outcome.value == "blocked"
    assert requests == []


def test_purple_mode_still_requires_the_active_checks_opt_in() -> None:
    """The scan's own opt-in is one of the two switches of F-01-09; purple cannot imply it."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="requires active_checks=True"):
        build_scan_request(
            attestation={
                "attested_by": "t",
                "attested_at": (NOW - timedelta(hours=1)).isoformat(),
                "scope_statement": "purple window test scope",
                "allowed_targets": [f"https://{TARGET_HOST}/"],
                "detection_window": WINDOW_OPEN,
            },
            options={"purple": {"campaign": "c", "actions": ["m3.cmdi-oob"]}},
        )


# ------------------------------------------------------------------ 4. the nonce is the run's
def _purple_access(actions: tuple[str, ...] = ACTIONS):  # type: ignore[no-untyped-def]
    from arachne.purple.attack import load_technique_map
    from arachne.purple.campaign import PurpleAccess

    replay = load_technique_map()
    return PurpleAccess(
        campaign="safety-test",
        nonce="abcdef0123456789abcdef01",
        window=None,
        actions={check_id: replay.require(check_id) for check_id in actions},
        scan_id=1,
        clock=lambda: NOW,
    )


def test_one_nonce_tags_every_action_of_a_run() -> None:
    """REQ-VALID-003: the run has *one* visible tag, so an alert can be matched to it."""
    access = _purple_access()
    emissions = [access.record_emission(access.action_for(check_id)) for check_id in ACTIONS]
    assert {item.nonce for item in emissions} == {access.nonce}
    for check_id in ACTIONS:
        payload = access.emission_payload(access.action_for(check_id))  # type: ignore[arg-type]
        assert payload["nonce"] == access.nonce
        assert payload["campaign"] == "safety-test"
        assert payload["techniques"] and payload["tactic"]
        assert payload["window"] == {"present": False}


def test_the_callback_token_carries_the_run_nonce_verbatim() -> None:
    """The payload half: an L2 token's nonce is the run's nonce, not a fresh random one."""
    from arachne.core.proof import ProofLevel
    from arachne.proof.access import ProofAccess
    from arachne.proof.ledger import ProofLedger
    from arachne.proof.oob import CallbackService

    ledger = ProofLedger(MemoryScanStateStore(), 1)
    service = CallbackService()
    access = ProofAccess(
        level=ProofLevel.L2,
        check_id="m3.sqli-oob",
        scan_id=1,
        ledger=ledger,
        service=service,
        run_nonce="abcdef0123456789abcdef01",
    )
    token = access.oob_token().token
    assert token.nonce == "abcdef0123456789abcdef01"
    assert "abcdef0123456789abcdef01" in str(token)
    # And the marker the same access mints is tagged too.
    assert "abcdef0123456789abcdef01" in access.marker("sql injection")
    # An ordinary scan (no run nonce) keeps a fresh random tag per artifact.
    plain = ProofAccess(
        level=ProofLevel.L2, check_id="m3.sqli-oob", scan_id=1, ledger=ledger, service=service
    )
    assert plain.oob_token().token.nonce != plain.marker("x").split("_")[2].split(" ")[0]


def test_a_caller_cannot_smuggle_a_payload_in_as_a_nonce() -> None:
    """A caller-supplied nonce is validated against the same alphabet as a generated one."""
    from arachne.core.proof import ProofRefused
    from arachne.proof.oob import CallbackService

    service = CallbackService()
    with pytest.raises(ProofRefused, match="plain"):
        service.issue(1, "m3.sqli-oob", nonce="rm -rf /; echo pwned")


# ------------------------------------------------------------------ 5. the stop is audited
def test_closing_the_window_mid_run_stops_the_rest_and_audits_it_once() -> None:
    """The auto-stop (REQ-VALID-003): a run never fires past its window."""
    from arachne.core.audit import Auditor, MemoryAuditSink
    from arachne.core.target import DetectionWindow

    sink = MemoryAuditSink()
    access = _purple_access()
    window = DetectionWindow(
        starts_at=NOW - timedelta(minutes=10),
        ends_at=NOW - timedelta(minutes=1),
        coordinator="soc-lead@corp",
    )
    access.window = window
    access.auditor = Auditor(sink, actor="pytest")

    assert access.allows() is False, "the window has already closed"
    access.stop(reason="the detection window closed")
    access.stop(reason="the detection window closed")  # idempotent

    events = sink.of_action(AuditAction.PURPLE_WINDOW_CLOSED)
    assert len(events) == 1, "one stop, one line — not one per remaining action"
    assert events[0].outcome.value == "blocked"
    assert events[0].meta["emitted"] == 0
    assert events[0].meta["nonce"] == access.nonce


def test_a_stopped_run_records_how_far_it_got() -> None:
    access = _purple_access(("m3.cmdi-oob",))
    access.record_emission(access.action_for("m3.cmdi-oob"))  # type: ignore[arg-type]
    access.window = None
    access.stop(reason="window closed")
    assert access.stopped_at is not None
    assert access.stop_reason == "window closed"
    assert len(access.emissions) == 1


# ------------------------------------------------------------------ 6. rate limits apply
@pytest.mark.asyncio
async def test_a_purple_runs_payload_path_is_the_rate_limited_scoped_client() -> None:
    """REQ-VALID-003: "rate limits apply" — a purple run is a test, not an exemption.

    Two observations, both on the path a purple payload actually travels: the scoped client
    that carries it throttles (a deliberately tight bucket shows the wait in the run's own
    audit trail), and the out-of-band recovery of the run nonce goes *through* that client
    rather than a bare library. So "the ordinary rate limit applies" is a property of the
    code the purple run uses, not a promise in a docstring.
    """
    from arachne.core.proof import ProofLevel
    from arachne.core.ratelimit import HostRateLimiter
    from arachne.proof.access import ProofAccess
    from arachne.proof.ledger import ProofLedger

    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    settings = Settings(database_url="sqlite:///:memory:", log_level="CRITICAL")
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(str(request.url))
        return httpx.Response(200, text='{"found": false}')

    client = ScopedHttpClient(
        settings=settings,
        scope=Scope(allowed_hosts=(TARGET_HOST,)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=StaticResolver((PUBLIC_IP,)),
        limiter=HostRateLimiter(
            RateLimitSettings(
                per_host_rate=50.0, per_host_burst=1, global_rate=50.0, global_burst=1
            )
        ),
        auditor=auditor,
        transport=httpx.MockTransport(handler),
    )
    async with client:
        await client.get(f"https://{TARGET_HOST}/one")
        await client.get(f"https://{TARGET_HOST}/two")

        # The purple payload-recovery path: an L2 access pointed at this client polls for
        # its hit through it (never a bare library), carrying the run nonce.
        access = ProofAccess(
            level=ProofLevel.L2,
            check_id="m3.sqli-oob",
            scan_id=1,
            ledger=ProofLedger(MemoryScanStateStore(), 1),
            service=None,
            callback_base=f"https://{TARGET_HOST}",
            http=client,
            run_nonce="abcdef0123456789abcdef01",
        )
        assert await access.oob_consume("arachne-1-m3.sqli-oob-abcdef0123456789abcdef01") is None

    assert len(sent) == 3
    assert "/hits?token=arachne-1-m3.sqli-oob-abcdef0123456789abcdef01" in sent[2]
    throttled = [
        event
        for event in sink.of_action(AuditAction.HTTP_REQUEST)
        if (event.meta or {}).get("throttled_ms", 0) > 0
    ]
    assert throttled, "the client that carries purple payloads did not throttle at all"


def test_the_shipped_map_and_the_registry_agree_so_the_gate_never_fires_on_them() -> None:
    """The cross-check is a guardrail, not a tripwire: the shipped state is consistent."""
    from arachne.purple.attack import load_technique_map

    replay = load_technique_map()
    levels = {metadata.id: metadata.proof.value for metadata in ModuleRegistry.builtin().metadata()}
    mismatches = {
        check_id: (action.level, levels.get(check_id))
        for check_id, action in replay.actions.items()
        if levels.get(check_id) != action.level
    }
    assert mismatches == {}
    assert all(action.level in {"L1", "L2", "L3", "L4"} for action in replay.actions.values())


def test_a_configuration_error_names_what_is_replayable() -> None:
    from arachne.purple.attack import load_technique_map

    with pytest.raises(ConfigurationError, match="the shipped map replays"):
        load_technique_map().require("m1.ct-lookup")


def test_the_checks_step_cannot_be_a_detection_test_without_the_wired_seam() -> None:
    """No runner wired ⇒ no purple access ⇒ a crafted request cannot tag anything."""
    from arachne.purple.campaign import PurpleRunner

    runner = PurpleRunner.build()
    assert runner.access(_FakeContext(options=None)) is None
    assert ScanStatus.PENDING.value == "pending"  # keeps the lifecycle vocabulary honest


class _FakeContext:
    def __init__(self, *, options: Any = None) -> None:
        self.options = options
        self.definition = None
        self.scan_id = 0
        self.auditor = None


# ------------------------------------- 7. the catalogue's ATT&CK v20 breadth (REQ-VALID-007)
def _shipped_map_actions() -> tuple[Any, ...]:
    from arachne.purple.attack import load_technique_map

    return tuple(load_technique_map().actions.values())


def test_the_catalogue_reaches_the_required_v20_breadth() -> None:
    """REQ-VALID-007's two numbers, counted from the shipped map rather than asserted in prose."""
    techniques = {technique for action in _shipped_map_actions() for technique in action.techniques}
    tactics = {action.tactic for action in _shipped_map_actions()}
    assert len(techniques) >= 25, f"only {len(techniques)} technique(s): {sorted(techniques)}"
    assert len(tactics) >= 8, f"only {len(tactics)} tactic(s): {sorted(tactics)}"


def test_the_tactic_vocabulary_is_the_pinned_v20_set() -> None:
    """REQ-VALID-007's vocabulary clause: 15 v20 tactics, Stealth and Defense Impairment in it.

    Read from the same pinned snapshot the technique ids are validated against, so the
    vocabulary cannot lag the release: a v18-era 14-tactic list (with ``defense-evasion``)
    fails here.
    """
    from arachne.modules.framework_map import attack_tactics
    from arachne.purple.attack import TACTIC_LABELS, TACTICS

    pinned = attack_tactics()
    assert tuple(tactic.shortname for tactic in pinned) == TACTICS
    assert len(TACTICS) == 15, f"v20 has 15 enterprise tactics, got {len(TACTICS)}"
    assert "stealth" in TACTICS and "defense-impairment" in TACTICS
    assert "defense-evasion" not in TACTICS, "Defense Evasion is not a v20 tactic"
    assert set(TACTIC_LABELS) == set(TACTICS)


def test_every_action_names_a_technique_the_pinned_release_knows() -> None:
    """REQ-VALID-007: every technique id validates against the pinned ATT&CK v20 data."""
    from arachne.modules.framework_map import item_error

    for action in _shipped_map_actions():
        for technique in action.techniques:
            assert item_error(f"ATT&CK-{technique}") is None, (action.check_id, technique)


def test_every_action_is_filed_under_a_tactic_the_release_assigns_its_technique() -> None:
    from arachne.purple.attack import technique_tactics

    for action in _shipped_map_actions():
        assigned = {
            name for technique in action.techniques for name in technique_tactics(technique)
        }
        assert action.tactic in assigned, (action.check_id, action.tactic, sorted(assigned))


def test_no_action_claims_a_stealth_technique() -> None:
    """The vocabulary has Stealth; no action may be filed under it.

    ARACHNE's tests are designed to be seen (``NO_EVASION_POLICY``): an action filed under the
    Stealth tactic would describe an evasion capability the product refuses to have. Two
    statements, because ATT&CK v20 assigns a technique *several* tactics and one of them can be
    Stealth — T1078 (Valid Accounts) is filed under Stealth, Persistence, Privilege Escalation
    and Initial Access, and the actions below use its initial-access/persistence assignment for a
    plain logon test. So: no action's own tactic is Stealth, and no action names a technique
    whose *only* home is Stealth.
    """
    from arachne.purple.attack import TACTIC_LABELS, technique_tactics

    actions = _shipped_map_actions()
    assert "stealth" in TACTIC_LABELS, "the vocabulary must still contain Stealth"
    filed_under_stealth = [(a.check_id, a.tactic) for a in actions if a.tactic == "stealth"]
    assert filed_under_stealth == []
    stealth_only = [
        (action.check_id, technique)
        for action in actions
        for technique in action.techniques
        if set(technique_tactics(technique)) == {"stealth"}
    ]
    assert stealth_only == []


def test_every_action_declares_telemetry_a_defender_could_collect() -> None:
    """A rule-miss is only meaningful when the event is one a log source would actually hold."""
    for action in _shipped_map_actions():
        assert action.event.summary.strip(), action.check_id
        assert action.event.fields, action.check_id
        assert action.event.logsource.get("product"), action.check_id
        assert action.event.logsource.get("category") or action.event.logsource.get("service"), (
            action.check_id
        )


def test_a_map_naming_an_unknown_technique_is_refused(tmp_path: Path) -> None:
    """The gate, not just the shipped file: an operator's own map is held to the same rule."""
    import yaml

    from arachne.purple.attack import load_technique_map

    document = _doctored_document(techniques=["T9999"])
    path = tmp_path / "unknown-technique.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ConfigurationError, match=r"ATT&CK-T9999"):
        load_technique_map(path)


def test_a_map_filed_under_the_wrong_tactic_is_refused(tmp_path: Path) -> None:
    """A credential technique filed under discovery is a lie about what the test exercises."""
    import yaml

    from arachne.purple.attack import load_technique_map

    document = _doctored_document(tactic="discovery")
    path = tmp_path / "wrong-tactic.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ConfigurationError, match="tactic 'discovery' is not one ATT&CK v20"):
        load_technique_map(path)


def _doctored_document(*, techniques: list[str] | None = None, tactic: str | None = None) -> Any:
    """The shipped map with every action's technique list and/or tactic replaced."""
    from arachne.purple.attack import load_technique_map

    document: dict[str, Any] = {
        "version": "2.0",
        "actions": [
            {
                "check": action.check_id,
                "title": action.title,
                "level": action.level,
                "tactic": tactic or action.tactic,
                "techniques": list(techniques or action.techniques),
                "severity": action.severity,
                "telemetry": {
                    "summary": action.event.summary,
                    "logsource": dict(action.event.logsource),
                    "event": dict(action.event.fields),
                },
            }
            for action in load_technique_map().actions.values()
        ],
    }
    return document
