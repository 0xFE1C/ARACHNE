"""The module registry (F-02-10, F-02-09) and its bridge to the planning catalogue.

The registry is what makes "modules can be enabled/disabled per scan" and "installed checks
are discovered with their versions" true, so the tests here are about the two ways it can
quietly go wrong: an ambiguous identity (two implementations for one check id, which would
make a plan describe work that cannot run) and a selection rule that disagrees with what the
pipeline actually executes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence

import pytest
from tests.helpers.checks import asset_for

from arachne.core.catalog import CheckSpec, PlanningCatalog, load_catalog
from arachne.core.errors import ConfigurationError
from arachne.core.planner import MODULE_STEP, ScanStep
from arachne.core.results import CheckResult
from arachne.core.target import ModuleSelection, TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.registry import (
    ENTRY_POINT_GROUP,
    ModuleGroup,
    ModuleRegistry,
    catalog_from_registry,
)


def make_metadata(check_id: str, **overrides: object) -> CheckMetadata:
    module, _, name = check_id.partition(".")
    base: dict[str, object] = {
        "id": check_id,
        "module": module.upper(),
        "name": name,
        "version": "1.0",
        "title": f"{name} check",
        "description": f"A test check named {name}.",
        "research_ref": "ch02#1",
        "target_kinds": (TargetKind.DOMAIN,),
        # REQ-DET-002: the registry refuses an unmapped check, so every synthetic check names
        # one framework item.
        "framework": ("CWE-200",),
    }
    return CheckMetadata(**{**base, **overrides})  # type: ignore[arg-type]


def make_check(check_id: str, **overrides: object) -> type[Module]:
    """Build a real :class:`Module` subclass (metadata is validated at class creation)."""
    metadata = make_metadata(check_id, **overrides)

    async def run(self: Module, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        yield ctx.info(f"{metadata.id} ran")  # pragma: no cover - never executed here

    return type(  # type: ignore[return-value]
        f"Check_{check_id.replace('.', '_')}",
        (Module,),
        {"metadata": metadata, "run": run},
    )


def make_group(module_id: str, *check_ids: str, version: str = "9.9") -> ModuleGroup:
    return ModuleGroup(
        id=module_id,
        title=f"{module_id} test module",
        description="A module that exists only in this test.",
        version=version,
        checks=tuple(make_check(check_id) for check_id in check_ids),
    )


# ------------------------------------------------------------------ construction
def test_builtin_registry_exposes_the_shipped_modules() -> None:
    """M1 (S3), M2 (S4), M3 (S6) and M4 (S7) ship today; M5-M6 arrive later."""
    registry = ModuleRegistry.builtin()
    assert registry.module_ids() == ("M1", "M2", "M3", "M4", "M5", "M6")
    # S15 added the six proof-ladder checks (4x L2 variants + L3 rce-echo + L4
    # state-marker) to M3's 34 -> 40 checks; 129 + 6 = 135. S18 adds three opt-in M1 intel
    # checks (service-exposure-drift, ct-surprise, breach-exposure) -> 138. S19 adds two
    # opt-in M3 credentialed checks (authenticated-surface, session-logout) and one
    # opt-in M2 credentialed host check (smb-auth) -> 141. S23 adds the M5 continuous
    # cloud-config posture check (m5.cloud-posture) -> 142. S29 adds the depth-expansion
    # family: two opt-in M3 GraphQL probes, two opt-in M3 WebSocket probes, one opt-in L2 M3
    # client-secret check, three default-on M2 gRPC/HTTP-2 posture checks, one opt-in M2
    # OT/ICS protocol probe and one opt-in M1 mobile-artifact check -> 152. WP-07 adds the
    # read-only MCP family to M6 (token-audience, session-auth, oauth-metadata), all
    # default-on L1 GET-only checks -> 155. WP-08 adds the four CWE Top 25 emitters and the
    # five injection families (REQ-DET-004/009), all default-on active L1 checks -> 164.
    # WP-09 adds the mTLS, SMTP-transport and HTTP/3 transport checks (REQ-DET-006/011/012),
    # all default-on active L1 checks -> 167. WP-10 adds the read-only AD CS enumeration
    # (REQ-DET-014) and the four Agentic Top 10 surface checks (REQ-DET-013) -> 172.
    # WP-11 adds the DOM-sink browser check (REQ-DET-015), a default-on active L1 check whose
    # browser is an optional extra and an operator opt-in -> 173. WP-12 adds the native image
    # scanner (REQ-DET-016) and the DigitalOcean read-only posture check (REQ-DET-017), both
    # default-on L1 checks with an active request path -> 175. WP-20 adds the SSH
    # credential check (REQ-CREDS-006), opt-in like the SMB one -> 176. WP-25 adds the
    # WordPress ecosystem family (REQ-DET-018), all default-on read-only L1 probes -> 202.
    # WP-26 adds the CMS family B (REQ-DET-019) — the Joomla, Drupal, Moodle, PrestaShop and
    # Magento checks, all default-on read-only L1 GET probes -> 232. WP-27 adds the
    # application-server and framework family (REQ-DET-020) — the Spring Boot, Django, Rails,
    # Laravel, Tomcat, JBoss, WebLogic, ColdFusion and IIS checks, all default-on read-only L1
    # GET probes -> 257. WP-28 adds the API and modern-web surface family (REQ-DET-021) — the
    # OpenAPI/Swagger, GraphQL, browser-facing gRPC, WebSocket-origin, serverless/edge and CORS
    # checks, all default-on L1 reads (three of them an OPTIONS preflight) -> 281. WP-29 adds
    # the source-control, CI and infrastructure-artifact family (REQ-DET-022) — the git
    # reflog and credential store, the CI pipeline definitions, Terraform state/plan/lock,
    # cloud credential files, container and orchestration manifests, editor residue, the
    # credential and authorization files and the environment-file variants, all default-on
    # read-only L1 GET probes -> 305. WP-30 adds the server, platform and runtime-configuration
    # family (REQ-DET-023) — the nginx, Apache, IIS and Caddy default pages and configuration
    # files, the machine-readable directory indexes, the Docker/Podman version endpoints, the
    # Kubernetes Dashboard, kubelet, registry catalogue and registry dashboards, the ActiveMQ,
    # NATS, EMQX, RocketMQ, Kafka UI and Pulsar consoles, and the three header/cookie/caching
    # defaults checks, all default-on read-only L1 reads -> 329. WP-31 adds the AWS read-only
    # service posture family (REQ-DET-024) — thirty-one credential-gated L1 reads across S3,
    # IAM, EC2 and instance metadata, RDS, EKS, Lambda, CloudTrail, KMS, SQS/SNS, ECR and the
    # account-level defaults -> 360.
    assert len(registry.checks()) == 360
    # M1's code-secret-mining, M2's SNMP and ICS checks, M4's metadata-ssrf and
    # default-credentials checks, M3's ssrf-probe, M5's imds-ssrf / azure-mi-audit and
    # M6's deception-listeners / ad-attack-path, S13's m1.bucket-hunt, S15's six
    # proof-ladder checks and S19's two credentialed M3 checks are opt-in. S23's
    # m5.cloud-posture is default-on (it only ever GETs a declared snapshot endpoint).
    # S29's seven opt-in additions are the four GraphQL/WebSocket probes, the L2
    # client-secret check, the OT/ICS protocol probe and the mobile-artifact check. WP-20's
    # SSH credential check is opt-in like the SMB one -> 31.
    assert registry.totals()["opt_in_checks"] == 31
    # WP-09's three new checks are active and WP-10 adds four active AD CS / ASI ones
    # (the four agentic checks are hybrid reads and are not counted as active), so the
    # active count rises with the total. WP-11's m3.dom-xss is active too (it navigates with
    # a marker), and WP-12's m5.image-scan and m5.do-posture both request the target, so the
    # count rises by three across those two work packages.
    # WP-20's m2.ssh-auth is active as well (it authenticates) -> 99. WP-25's
    # m3.wp-cron-surface is active because it is the family's one non-GET interaction (the
    # OPTIONS reachability probe that cannot trigger the job it reports) -> 100. WP-26's
    # thirty CMS checks are all plain GETs, so the active count does not move. WP-27's
    # twenty-five application-server checks are all plain GETs too. WP-28's three
    # OPTIONS-preflight checks (the gRPC-Web preflight and the two CORS preflight readings) are
    # active for the same reason m3.wp-cron-surface is -> 103. WP-29's twenty-four
    # infrastructure-artifact checks are all plain GETs, so the active count does not move.
    # WP-30's twenty-four server checks are plain GETs too. WP-31's thirty-one AWS posture
    # checks are all active (they make a credentialed API read) -> 134.
    assert registry.totals()["active_checks"] == 134
    # S15: the six L2+ declarations are exactly the proof ladder's opt-in rows. S29 adds one
    # more: m3.client-secret-verify, the L2 dynamic verification of a client-side credential.
    assert registry.totals()["proof_l2plus"] == 7
    assert registry.group("M2").step is ScanStep.DISCOVERY  # type: ignore[union-attr]
    assert registry.group("M3").step is ScanStep.CHECKS  # type: ignore[union-attr]


def test_discover_without_entry_points_equals_builtin() -> None:
    assert (
        ModuleRegistry.discover(include_entry_points=False).module_ids()
        == ModuleRegistry.builtin().module_ids()
    )


def test_a_group_refuses_a_check_that_names_another_module() -> None:
    with pytest.raises(ConfigurationError, match="is registered under"):
        ModuleGroup(
            id="M2",
            title="M2",
            description="d",
            version="1.0",
            checks=(make_check("m3.mismatch"),),
        )


def test_a_group_refuses_an_unknown_module_id() -> None:
    with pytest.raises(ConfigurationError, match="not one of"):
        ModuleGroup(id="M7", title="M7", description="d", version="1.0", checks=())


def test_duplicate_module_ids_are_fatal() -> None:
    with pytest.raises(ConfigurationError, match="module group 'M2' is registered twice"):
        ModuleRegistry([make_group("M2", "m2.alpha"), make_group("M2", "m2.beta")])


def test_duplicate_check_ids_are_fatal(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Two implementations of one check id would make a plan describe work that cannot run."""
    from arachne.modules.registry import _merge_by_module  # the plugin merge path

    first = make_group("M2", "m2.dup")
    second = ModuleGroup(
        id="M2",
        title="d",
        description="d",
        version="1.0",
        checks=(make_check("m2.dup"),),
        origin="plugin",
    )
    merged = _merge_by_module([first, second])
    assert len(merged) == 1
    with pytest.raises(ConfigurationError, match=r"check id 'm2\.dup' is registered twice"):
        ModuleRegistry(merged)


def test_lookup_helpers() -> None:
    registry = ModuleRegistry([make_group("M2", "m2.alpha", "m2.beta", version="2.1")])
    assert registry.check_ids() == ("m2.alpha", "m2.beta")
    assert registry.get("m2.alpha") is not None
    assert registry.get("m2.absent") is None
    assert registry.group("m2") is not None
    assert registry.check_versions() == {
        "m2.alpha": "1.0",
        "m2.beta": "1.0",
        "M2": "2.1",
    }
    assert registry.totals()["checks"] == 2
    assert registry.step_has_checks(ScanStep.DISCOVERY)
    assert not registry.step_has_checks(ScanStep.REPORTING)


def test_summary_is_json_safe_and_carries_versions() -> None:
    registry = ModuleRegistry([make_group("M2", "m2.alpha")])
    payload = registry.summary()
    assert payload[0]["id"] == "M2"
    assert payload[0]["version"] == "9.9"
    assert payload[0]["step"] == "discovery"
    assert payload[0]["checks"][0]["id"] == "m2.alpha"
    assert payload[0]["checks"][0]["target_kinds"] == ["domain"]


# ------------------------------------------------------------------ plugin discovery (F-09-01)
class FakeEntryPoint:
    def __init__(self, name: str, loaded: object) -> None:
        self.name = name
        self._loaded = loaded

    def load(self) -> object:
        return self._loaded


def test_entry_point_group_discovery_accepts_groups_and_checks(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """A plugin may export a group, one check, or a list of either (F-02-10, F-09-01)."""
    plugin_check = make_check("m3.plugin-check")
    group = make_group("M4", "m4.plugin-alpha", version="0.3")
    fake = (
        FakeEntryPoint("alpha", group),
        FakeEntryPoint("beta", plugin_check),
        FakeEntryPoint("gamma", [make_check("m3.other")]),
    )
    monkeypatch.setattr(
        "arachne.modules.registry.entry_points", lambda **kwargs: fake, raising=True
    )

    registry = ModuleRegistry.discover()
    assert registry.module_ids() == ("M1", "M2", "M3", "M4", "M5", "M6")
    assert registry.get("m4.plugin-alpha") is not None
    assert registry.get("m3.plugin-check") is not None
    assert registry.get("m3.other") is not None
    # M4 is a shipped group now, so a plugin claiming the same id contributes to it.
    assert registry.group("M4").origin == "builtin+alpha"  # type: ignore[union-attr]


def test_a_plugin_extends_an_existing_module(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Adding one check to M1 must not mean duplicating the M1 group."""
    monkeypatch.setattr(
        "arachne.modules.registry.entry_points",
        lambda **kwargs: (FakeEntryPoint("extra", make_check("m1.extra")),),
        raising=True,
    )
    registry = ModuleRegistry.discover()
    assert registry.module_ids() == ("M1", "M2", "M3", "M4", "M5", "M6")
    # The shipped set (329 at WP-30) plus the plugin's one extra check.
    assert len(registry.checks()) == 361
    assert registry.group("M1").origin == "builtin+extra"  # type: ignore[union-attr]


def test_a_broken_plugin_is_reported_not_ignored(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    class Broken:
        name = "broken"

        def load(self) -> object:
            raise RuntimeError("no entry point for you")

    monkeypatch.setattr("arachne.modules.registry.entry_points", lambda **kwargs: (Broken(),))
    with pytest.raises(ConfigurationError, match="failed to load"):
        ModuleRegistry.discover()


def test_a_plugin_that_returns_nonsense_is_reported(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        "arachne.modules.registry.entry_points",
        lambda **kwargs: (FakeEntryPoint("odd", object()),),
        raising=True,
    )
    with pytest.raises(ConfigurationError, match="must resolve to a ModuleGroup"):
        ModuleRegistry.discover()


def test_the_entry_point_group_name_is_stable() -> None:
    assert ENTRY_POINT_GROUP == "arachne.modules"


# ------------------------------------------------------------------ selection (F-02-09)
def test_selection_defaults_exclude_opt_in_and_active_checks() -> None:
    registry = ModuleRegistry.builtin()
    selected = registry.select(ModuleSelection())
    ids = {check.metadata.id for check in selected}
    assert "m1.ct-lookup" in ids
    assert "m1.code-secret-mining" not in ids  # opt-in (token budgeted)


def test_selection_honours_module_enable_and_disable() -> None:
    registry = ModuleRegistry([make_group("M2", "m2.alpha"), make_group("M3", "m3.beta")])
    assert {c.metadata.id for c in registry.select(ModuleSelection(enabled=("M3",)))} == {"m3.beta"}
    assert {c.metadata.id for c in registry.select(ModuleSelection(disabled=("M2",)))} == {
        "m3.beta"
    }
    # A disable beats an enable of the same module (the more specific declaration wins).
    assert registry.select(ModuleSelection(enabled=("M2",), disabled=("M2",))) == ()


def test_an_explicit_check_list_is_an_allowlist() -> None:
    registry = ModuleRegistry.builtin()
    selected = registry.select(
        ModuleSelection(), check_ids=("m1.code-secret-mining", "m1.ct-lookup")
    )
    assert {c.metadata.id for c in selected} == {"m1.code-secret-mining", "m1.ct-lookup"}


def test_active_checks_need_the_switch() -> None:
    active = make_check("m2.active", type="active", requires_active_checks=True)
    registry = ModuleRegistry([ModuleGroup("M2", "d", "d", "1.0", (active,))])
    assert registry.select(ModuleSelection()) == ()
    assert registry.select(ModuleSelection(), active_checks_allowed=True) == (active,)


def test_every_selected_check_belongs_to_a_pipeline_step() -> None:
    for check in ModuleRegistry.builtin().select(ModuleSelection()):
        assert MODULE_STEP[check.metadata.module] in set(ScanStep)


# ------------------------------------------------------------------ catalogue bridge
def test_catalog_from_registry_round_trips_the_metadata() -> None:
    catalog = catalog_from_registry(ModuleRegistry.builtin())
    assert isinstance(catalog, PlanningCatalog)
    assert catalog.catalog_version == "registry-1.0"
    by_key = {check.key: check for check in catalog.checks}
    for metadata in ModuleRegistry.builtin().metadata():
        spec = by_key[metadata.key]
        assert spec.title == metadata.title
        assert spec.description == metadata.description
        assert spec.research_ref == metadata.research_ref
        assert spec.cwe == metadata.cwe
        assert spec.target_kinds == metadata.target_kinds
        assert spec.estimated_requests == metadata.estimated_requests
        assert spec.requires_active_checks == metadata.requires_active_checks


def test_catalog_from_an_empty_registry_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="no checks"):
        catalog_from_registry(ModuleRegistry())


# ------------------------------------------------------------------ drift gate
def test_the_shipped_catalogue_and_the_registry_agree() -> None:
    """The planner's data file and the executable registry must describe the same checks.

    The catalogue is data (so ``--dry-run`` needs no detection code) and the registry is the
    code; this is the assertion that keeps them from drifting, which is the only way a plan
    can stay honest about what a scan will run (and about request counts).
    """
    shipped = {check.key: check for check in load_catalog().checks}
    for metadata in ModuleRegistry.builtin().metadata():
        assert metadata.key in shipped, f"{metadata.key} is implemented but not in the catalogue"
        spec: CheckSpec = shipped[metadata.key]
        assert spec.title == metadata.title
        assert spec.description == metadata.description
        assert spec.research_ref == metadata.research_ref
        assert spec.cwe == metadata.cwe
        assert spec.target_kinds == metadata.target_kinds
        assert spec.estimated_requests == metadata.estimated_requests
        assert spec.requires_active_checks == metadata.requires_active_checks
        # S15 (REQ-PROOF-001/002): the proof declaration is part of the plan-time truth.
        assert spec.proof == metadata.proof
        assert spec.requires_state_attestation == metadata.requires_state_attestation


def test_every_catalogue_row_is_implemented_after_s11() -> None:
    """M1-M6 all ship; the catalogue must not still plan a check with no implementation.

    Through S10 the catalogue carried planned-only M6 rows so ``--dry-run`` could describe the
    later phase. S11 implements M6, so the planned-only set is now empty — a row that is
    planned but unimplemented would make the plan describe work that cannot run.
    """
    implemented = {metadata.key for metadata in ModuleRegistry.builtin().metadata()}
    catalogue_keys = {check.key for check in load_catalog().checks}
    assert catalogue_keys - implemented == set()


def test_a_check_runs_through_the_registry_selection_into_a_step() -> None:
    """End-to-end shape check: registry → selection → step mapping → a runnable instance."""
    registry = ModuleRegistry.builtin()
    selected: Sequence[type[Module]] = registry.select(ModuleSelection())
    recon = [c for c in selected if MODULE_STEP[c.metadata.module] is ScanStep.RECON]
    # Every M1 check that is not opt-in is selected for the recon step, and none of M2's
    # active checks are (F-01-09: they need the explicit active-checks opt-in).
    assert {c.metadata.id for c in recon} == {
        c.metadata.id
        for c in registry.checks()
        if c.metadata.module == "M1" and c.metadata.enabled_by_default
    }
    for check in recon:
        instance = check()
        assert instance.metadata.id and instance.name == instance.metadata.name
        assert callable(instance.run)
        assert (
            instance.supports(asset_for("domain", "example.com"))
            or instance.supports(asset_for("host", "93.184.216.34"))
            or instance.supports(asset_for("url", "https://example.com/"))
        )


def test_m2_is_selected_only_with_the_active_checks_switch() -> None:
    """M2 is active by nature, so F-01-09 withholds it from a default scan."""
    registry = ModuleRegistry.builtin()
    default_ids = {c.metadata.id for c in registry.select(ModuleSelection())}
    # The M2 checks that run by default are the hybrid ones: they correlate what the other
    # checks established (cve-correlate) or read a plain GET response (http-fingerprint,
    # favicon-hash), so F-01-09 does not apply to them.
    assert {check for check in default_ids if check.startswith("m2.")} == {
        "m2.cve-correlate",
        "m2.favicon-hash",
        "m2.http-fingerprint",
    }
    opted_in = registry.select(ModuleSelection(), active_checks_allowed=True)
    m2_ids = {c.metadata.id for c in opted_in if c.metadata.module == "M2"}
    # Everything except the two extra opt-in checks (UDP/ICS) and cve-correlate, which is
    # hybrid and therefore runs without the switch.
    assert "m2.port-scan" in m2_ids and "m2.tls-deep-scan" in m2_ids
    assert "m2.snmp-enum" not in m2_ids and "m2.ics-probe" not in m2_ids
    assert "m2.cve-correlate" in default_ids
    # The UDP/ICS checks stay out even with the active switch: they need their own opt-in
    # (ARACHNE_NET_ALLOW_UDP for SNMP's datagrams, and an explicit --check opt-in for ICS).
    assert "m2.snmp-enum" in {
        c.metadata.id
        for c in registry.select(
            ModuleSelection(), check_ids=("m2.snmp-enum",), active_checks_allowed=True
        )
    }
