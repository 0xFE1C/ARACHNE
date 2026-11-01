"""The built-in offline step handlers: recon seeding and endpoint discovery (F-01-02).

These two handlers are the module-free part of a live scan: they turn the declared target
definition into the asset inventory the checks consume. S3 wraps them (``modules.handlers``
runs the M1 checks after the seeding and keeps ``discovery_step`` as-is), so they must stay
offline, must record provenance, and must route every write through the scope guard.
"""

from __future__ import annotations

from tests.conftest import build_scan_request

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.events import Event, EventBus, EventType
from arachne.core.lifecycle import MemoryScanStateStore, StepContext, StepOutcome
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope
from arachne.core.steps import default_handlers, discovery_step, recon_step
from arachne.core.target import TargetKind, TargetSelector


def build_context(
    request, *, scope: Scope | None = None
) -> tuple[StepContext, MemoryScanStateStore, MemoryAuditSink, EventBus]:  # type: ignore[no-untyped-def]
    store = MemoryScanStateStore()
    record = store.create_scan(target_id=None, engine="heuristic", plan={})
    sink = MemoryAuditSink()
    bus = EventBus()
    context = StepContext(
        scan_id=record.id,
        step=ScanStep.RECON,
        definition=request.target,
        options=request.options,
        scope=scope or request.target.compile_scope(),
        store=store,
        bus=bus,
        auditor=Auditor(sink, actor="pytest"),
    )
    return context, store, sink, bus


# ------------------------------------------------------------------- seed mapping
def test_seed_mapping_covers_every_target_kind() -> None:
    from arachne.core.steps import seed_asset

    cases = {
        "domain": "domain",
        "domain_pattern": "domain_pattern",
        "url": "url",
        "ip": "host",
        "cidr": "network",
        "git": "git",
        "cloud": "cloud",
    }
    values = {
        "domain": "example.com",
        "domain_pattern": "*.example.com",
        "url": "https://example.com/",
        "ip": "93.184.216.34",
        "cidr": "192.0.2.0/30",
        "git": "https://github.com/o/r.git",
        "cloud": "aws:1234",
    }
    for kind, expected_kind in cases.items():
        asset_kind, value, meta = seed_asset(TargetSelector(kind=kind, value=values[kind]))
        assert asset_kind == expected_kind
        assert value == values[kind]
        assert meta["declared"] is True


def test_network_seed_records_the_prefix_length_and_a_bounded_host_count() -> None:
    from arachne.core.steps import seed_asset

    _, _, meta = seed_asset(TargetSelector(kind="cidr", value="192.0.2.0/30"))
    assert meta["prefixlen"] == 30
    assert meta["hosts"] == 4


def test_an_ipv6_network_seed_is_bounded() -> None:
    from arachne.core.steps import MAX_NETWORK_HOSTS, seed_asset

    _, _, meta = seed_asset(TargetSelector(kind="cidr", value="2001:db8::/32"))
    assert meta["hosts"] == MAX_NETWORK_HOSTS


# -------------------------------------------------------------------------- recon
async def test_recon_seeds_one_asset_per_target_and_announces_hosts() -> None:
    request = build_scan_request(
        targets=[
            {"kind": "domain", "value": "example.com"},
            {"kind": "url", "value": "https://api.example.com/"},
            {"kind": "cidr", "value": "192.0.2.0/30"},
            {"kind": "cloud", "value": "aws:1234"},
        ],
        attestation={"allowed_targets": ["example.com", "192.0.2.0/30", "aws:1234"]},
    )
    context, store, _, bus = build_context(request)

    outcome = await recon_step(context)

    assert outcome.stats["seeded_assets"] == 4
    assert outcome.stats["selectors"] == 4
    assets = store.list_assets(context.scan_id)
    assert [asset.kind for asset in assets] == ["domain", "url", "network", "cloud"]
    assert all(asset.meta["source"] == "target-definition" for asset in assets)

    discovered = bus.history(EventType.HOST_DISCOVERED)
    assert [event.payload["host"] for event in discovered] == ["example.com", "api.example.com"]
    assert all(event.payload["source"] == "target-definition" for event in discovered)


async def test_recon_reports_an_address_for_a_literal_host() -> None:
    request = build_scan_request(
        targets=[{"kind": "ip", "value": "93.184.216.34"}],
        attestation={"allowed_targets": ["93.184.216.34"]},
    )
    context, _, _, bus = build_context(request)

    await recon_step(context)

    event = bus.history(EventType.HOST_DISCOVERED)[0]
    assert event.payload["kind"] == "host"
    assert event.payload["addresses"] == ["93.184.216.34"]


async def test_recon_discards_a_target_outside_the_scope() -> None:
    request = build_scan_request(targets=[{"kind": "domain", "value": "example.com"}])
    context, store, sink, bus = build_context(
        request, scope=Scope(allowed_hosts=("other.example",))
    )

    outcome = await recon_step(context)

    assert outcome.stats["seeded_assets"] == 0
    assert store.list_assets(context.scan_id) == ()
    assert bus.history(EventType.OUT_OF_SCOPE_DISCARDED)
    assert sink.of_action(AuditAction.SCOPE_DISCARDED)


async def test_recon_emits_nothing_for_targets_without_a_host() -> None:
    request = build_scan_request(
        targets=[{"kind": "cidr", "value": "192.0.2.0/30"}],
        attestation={"allowed_targets": ["192.0.2.0/30"]},
    )
    context, _, _, bus = build_context(request)
    await recon_step(context)
    assert bus.history(EventType.HOST_DISCOVERED) == ()


# ---------------------------------------------------------------------- discovery
async def test_discovery_derives_candidates_for_each_seeded_host() -> None:
    request = build_scan_request(targets=[{"kind": "domain", "value": "example.com"}])
    context, store, _, _ = build_context(request)
    await recon_step(context)
    context.step = ScanStep.DISCOVERY

    outcome = await discovery_step(context)

    assert outcome.stats["recorded"] == 2  # https and http candidates
    urls = [asset.value for asset in store.list_assets(context.scan_id) if asset.kind == "url"]
    assert urls == ["https://example.com/", "http://example.com/"]


async def test_discovery_keeps_a_declared_url_and_does_not_duplicate_it() -> None:
    request = build_scan_request(targets=[{"kind": "url", "value": "https://example.com/app"}])
    context, store, _, _ = build_context(request)
    await recon_step(context)
    context.step = ScanStep.DISCOVERY

    outcome = await discovery_step(context)

    urls = [asset.value for asset in store.list_assets(context.scan_id) if asset.kind == "url"]
    assert urls == ["https://example.com/app"]  # unchanged, not duplicated
    assert outcome.stats["recorded"] == 0
    assert outcome.stats["endpoint_candidates"] >= 1


async def test_discovery_discards_candidates_the_scope_excludes() -> None:
    request = build_scan_request(targets=[{"kind": "domain", "value": "example.com"}])
    # The host is in scope, but plaintext HTTP is explicitly excluded: the derived http://
    # candidate must be discarded rather than recorded.
    scope = Scope(allowed_domains=("example.com",), excluded_url_prefixes=("http://example.com/",))
    context, store, _, bus = build_context(request, scope=scope)
    await recon_step(context)
    context.step = ScanStep.DISCOVERY

    outcome = await discovery_step(context)

    assert outcome.stats["discarded"] == 1
    assert bus.history(EventType.OUT_OF_SCOPE_DISCARDED)
    urls = [asset.value for asset in store.list_assets(context.scan_id) if asset.kind == "url"]
    assert urls == ["https://example.com/"]


async def test_discovery_is_idempotent_across_runs() -> None:
    request = build_scan_request(targets=[{"kind": "domain", "value": "example.com"}])
    context, store, _, _ = build_context(request)
    await recon_step(context)
    context.step = ScanStep.DISCOVERY
    await discovery_step(context)
    before = len(store.list_assets(context.scan_id))

    await discovery_step(context)

    assert len(store.list_assets(context.scan_id)) == before


async def test_discovery_of_a_network_only_target_finds_no_endpoints() -> None:
    """Hosts inside a range are not guessed: only a module's host discovery can add them."""
    request = build_scan_request(
        targets=[{"kind": "cidr", "value": "192.0.2.0/30"}],
        attestation={"allowed_targets": ["192.0.2.0/30"]},
    )
    context, store, _, _ = build_context(request)
    await recon_step(context)
    context.step = ScanStep.DISCOVERY

    outcome = await discovery_step(context)

    assert outcome.stats["endpoint_candidates"] == 0
    assert not [asset for asset in store.list_assets(context.scan_id) if asset.kind == "url"]


# ------------------------------------------------------------------------ registry
def test_default_handlers_are_the_module_free_subset() -> None:
    """``core.steps.default_handlers`` stays the offline pair; the module-backed set lives in
    ``arachne.modules.handlers`` and is what ``Orchestrator`` installs by default (S3)."""
    handlers = default_handlers()
    assert set(handlers) == {ScanStep.RECON, ScanStep.DISCOVERY}
    assert handlers[ScanStep.RECON] is recon_step
    assert handlers[ScanStep.DISCOVERY] is discovery_step


def test_default_handlers_return_a_fresh_mapping() -> None:
    first = default_handlers()
    first.clear()
    assert set(default_handlers()) == {ScanStep.RECON, ScanStep.DISCOVERY}


def test_step_outcome_defaults_are_empty_and_not_skipped() -> None:
    outcome = StepOutcome()
    assert outcome.stats == {} and outcome.skipped is False and outcome.note is None


def test_target_kind_vocabulary_matches_the_seed_mapping() -> None:
    assert {kind.value for kind in TargetKind} == {
        "domain",
        "domain_pattern",
        "url",
        "ip",
        "cidr",
        "git",
        "cloud",
        # S29 (REQ-DEPTH-005): a local artifact (APK/IPA) analyzed offline. It is a target kind
        # so that it inherits the same deny-by-default scope gate as every other input.
        "artifact",
    }
    assert Event.host_discovered(scan_id=1, host="h", kind="host").type is EventType.HOST_DISCOVERED
