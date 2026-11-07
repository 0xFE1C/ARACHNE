"""The generated coverage ledger (REQ-DET-001, REQ-DET-003, REQ-DET-005).

The ledger is the one artefact that can overstate coverage, so the assertions are about its
*correspondence* to the registry rather than its formatting:

* one record per registered check, no extras and no misses;
* every pre-existing check mapped to a WSTG or API item (the REQ-DET-002 burn-down is 0);
* all 97 WSTG ids in exactly one state, with ≥68 mapped;
* all ten API Top 10 items mapped;
* a committed ledger that is byte-identical to generated output, and a stale one that fails
  naming the check id that moved.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.coverage import (
    build_ledger,
    check_ledger,
    default_ledger_paths,
    render_ledger_json,
    render_ledger_markdown,
)
from arachne.modules.registry import ModuleGroup, ModuleRegistry

runner = CliRunner()

#: WP-08's nine breadth checks (REQ-DET-004/009); they are excluded when pinning the 152
#: checks that predate WP-07, so the original baseline remains asserted explicitly.
WP08_IDS: frozenset[str] = frozenset(
    {
        "m3.ldap-injection",
        "m3.xpath-injection",
        "m3.code-injection-oracle",
        "m3.argument-injection",
        "m3.host-header-injection",
        "m3.email-header-injection",
        "m3.cache-deception",
        "m3.authz-bypass",
        "m3.input-validation-audit",
    }
)

#: WP-09's three protocol-surface checks (REQ-DET-006/011/012); excluded for the same reason.
WP09_IDS: frozenset[str] = frozenset({"m2.tls-mutual-auth", "m2.smtp-transport", "m2.http3-probe"})

#: WP-10's identity-and-AI-surface checks (REQ-DET-013/014); excluded for the same reason.
WP10_IDS: frozenset[str] = frozenset(
    {
        "m2.adcs-enum",
        "m6.agentic-tool-manifest",
        "m6.agentic-memory-store",
        "m6.agentic-human-trust",
        "m6.agentic-rogue-runtime",
    }
)

#: WP-11's browser check (REQ-DET-015); excluded for the same reason.
WP11_IDS: frozenset[str] = frozenset({"m3.dom-xss"})

#: WP-12's image and cloud-breadth checks (REQ-DET-016/017); excluded for the same reason.
WP12_IDS: frozenset[str] = frozenset({"m5.image-scan", "m5.do-posture"})

#: WP-20's SSH credential check (REQ-CREDS-006); excluded for the same reason. It shares
#: ``ch02#24`` with ``m2.ssh-enum`` because it establishes the same inventory fact *with* a
#: credential, so it adds a check without adding a research item.
WP20_IDS: frozenset[str] = frozenset({"m2.ssh-auth"})

#: WP-25's WordPress ecosystem family (REQ-DET-018); excluded for the same reason. Every one
#: cites ``ch03#19``/``ch03#31``/``ch03#35``, methods the corpus already mapped, so the family
#: adds twenty-six checks without adding a research item.
WP25_IDS: frozenset[str] = frozenset(
    {
        "m3.wp-config-backup",
        "m3.wp-config-source",
        "m3.wp-xmlrpc-surface",
        "m3.wp-xmlrpc-rsd",
        "m3.wp-rest-index",
        "m3.wp-rest-users",
        "m3.wp-rest-user-record",
        "m3.wp-rest-route-param",
        "m3.wp-rest-settings-unauth",
        "m3.wp-uploads-listing",
        "m3.wp-plugins-listing",
        "m3.wp-themes-listing",
        "m3.wp-plugin-readme",
        "m3.wp-theme-stylesheet",
        "m3.wp-readme-version",
        "m3.wp-asset-version",
        "m3.wp-debug-log",
        "m3.wp-installer-residue",
        "m3.wp-upgrade-residue",
        "m3.wp-admin-ajax-surface",
        "m3.wp-cron-surface",
        "m3.wp-author-enumeration",
        "m3.wp-user-sitemap",
        "m3.wp-registration-open",
        "m3.wp-app-password-surface",
        "m3.wp-rest-app-passwords",
    }
)

#: WP-26's CMS family B (REQ-DET-019); excluded for the same reason. Every one cites
#: ``ch03#19`` or ``ch03#31``, methods the corpus already mapped, so the family adds thirty
#: checks without adding a research item.
WP26_IDS: frozenset[str] = frozenset(
    {
        f"m3.{cms}-{name}"
        for cms in ("joomla", "drupal", "moodle", "prestashop", "magento")
        for name in (
            "config-source",
            "config-backup",
            "admin-surface",
            "version-disclosure",
            "installer-residue",
            "api-surface",
        )
    }
)

#: WP-27's application-server and framework family (REQ-DET-020); excluded for the same reason.
#: Every one cites ``ch03#19`` or ``ch03#31``, methods the corpus already mapped, so the family
#: adds twenty-five checks without adding a research item.
WP27_IDS: frozenset[str] = frozenset(
    {
        "m3.spring-boot-actuator-index",
        "m3.spring-boot-actuator-env",
        "m3.spring-boot-heapdump",
        "m3.django-debug-page",
        "m3.django-debug-toolbar",
        "m3.django-media-listing",
        "m3.rails-info-properties",
        "m3.rails-info-routes",
        "m3.laravel-debug-page",
        "m3.laravel-ignition-surface",
        "m3.tomcat-manager-surface",
        "m3.tomcat-host-manager-surface",
        "m3.tomcat-examples-surface",
        "m3.jboss-jmx-console",
        "m3.jboss-web-console",
        "m3.jboss-admin-console",
        "m3.weblogic-console",
        "m3.weblogic-uddi-explorer",
        "m3.weblogic-wsat",
        "m3.coldfusion-administrator",
        "m3.coldfusion-scripts-directory",
        "m3.coldfusion-version-disclosure",
        "m3.iis-short-name-disclosure",
        "m3.iis-trace-viewer",
        "m3.iis-legacy-password-surface",
    }
)

#: WP-28's API and modern-web surface family (REQ-DET-021); excluded for the same reason. Every
#: one cites ``ch03#23``, ``ch03#31``, ``ch03#32`` or ``ch03#33``, methods the corpus already
#: mapped, so the family adds twenty-four checks without adding a research item.
WP28_IDS: frozenset[str] = frozenset(
    {
        "m3.openapi-document-exposed",
        "m3.swagger-document-exposed",
        "m3.swagger-ui-exposed",
        "m3.redoc-exposed",
        "m3.swagger-resources-index",
        "m3.openapi-operation-unauth",
        "m3.graphql-introspection-get",
        "m3.graphql-suggestion-disclosure",
        "m3.graphql-ide-exposed",
        "m3.graphql-mutation-surface",
        "m3.grpc-connect-endpoint",
        "m3.grpc-web-preflight",
        "m3.websocket-origin-null",
        "m3.websocket-origin-sibling",
        "m3.websocket-origin-suffix-spoof",
        "m3.netlify-function-endpoint",
        "m3.vercel-function-endpoint",
        "m3.gcf-function-endpoint",
        "m3.openfaas-gateway-exposed",
        "m3.edge-function-sourcemap",
        "m3.cors-subdomain-trust",
        "m3.cors-suffix-spoof",
        "m3.cors-preflight-methods",
        "m3.cors-preflight-headers",
    }
)

#: WP-29's source-control, CI and infrastructure-artifact family (REQ-DET-022); excluded for
#: the same reason. Every one cites ``ch04#1``, ``ch04#2``, ``ch04#3``, ``ch04#15`` or
#: ``ch04#24``, methods the corpus already mapped, so the family adds twenty-four checks
#: without adding a research item.
WP29_IDS: frozenset[str] = frozenset(
    {
        "m4.app-config-secret-exposed",
        "m4.authorization-file-exposed",
        "m4.aws-credential-file-exposed",
        "m4.ci-pipeline-definition-exposed",
        "m4.ci-pipeline-secret-exposed",
        "m4.cloud-cli-credential-exposed",
        "m4.cloud-service-account-key-exposed",
        "m4.container-compose-exposed",
        "m4.dockerfile-exposed",
        "m4.editor-backup-residue-exposed",
        "m4.env-secret-file-exposed",
        "m4.env-variant-exposed",
        "m4.git-credentials-exposed",
        "m4.git-reflog-exposure",
        "m4.github-workflow-exposed",
        "m4.legacy-vcs-metadata",
        "m4.orchestration-manifest-exposed",
        "m4.os-metadata-residue-exposed",
        "m4.package-manager-credential-exposed",
        "m4.registry-auth-exposed",
        "m4.terraform-lock-exposed",
        "m4.terraform-plan-exposed",
        "m4.terraform-state-exposed",
        "m4.vim-swap-exposed",
    }
)


#: WP-30's server, platform and runtime-configuration family (REQ-DET-023); excluded for the
#: same reason. Every one cites ``ch04#7``, ``ch04#9``, ``ch04#11``, ``ch04#12``, ``ch04#16``,
#: ``ch04#18`` or ``ch04#22``, methods the corpus already mapped, so the family adds
#: twenty-four checks without adding a research item.
WP30_IDS: frozenset[str] = frozenset(
    {
        "m4.activemq-console-exposed",
        "m4.apache-config-file-exposed",
        "m4.apache-default-page",
        "m4.apache-htpasswd-exposed",
        "m4.autoindex-json-exposed",
        "m4.autoindex-xml-exposed",
        "m4.broker-console-exposed",
        "m4.cacheable-session-response",
        "m4.caddy-admin-api-exposed",
        "m4.caddy-config-file-exposed",
        "m4.docker-api-exposed",
        "m4.iis-applicationhost-exposed",
        "m4.iis-default-page",
        "m4.kubelet-readonly-exposed",
        "m4.kubernetes-dashboard-exposed",
        "m4.nats-monitoring-exposed",
        "m4.nginx-config-file-exposed",
        "m4.nginx-default-page",
        "m4.nginx-stub-status-exposed",
        "m4.podman-api-exposed",
        "m4.registry-catalog-exposed",
        "m4.registry-dashboard-exposed",
        "m4.server-version-disclosure",
        "m4.stack-header-disclosure",
    }
)


@pytest.fixture(scope="module")
def registry() -> ModuleRegistry:
    return ModuleRegistry.discover()


@pytest.fixture(scope="module")
def ledger(registry: ModuleRegistry):  # type: ignore[no-untyped-def]
    return build_ledger(registry, generated_at="2026-11-02")


# ------------------------------------------------------------------ records == registry
def test_the_record_set_equals_the_registry_exactly(ledger, registry: ModuleRegistry) -> None:  # type: ignore[no-untyped-def]
    assert [record.id for record in ledger.records] == [
        metadata.id for metadata in registry.metadata()
    ]
    assert ledger.check_count == len(registry.checks())


def test_every_record_carries_the_required_fields(ledger) -> None:  # type: ignore[no-untyped-def]
    for record in ledger.records:
        assert record.id and record.module and record.title
        assert record.proof in {"L0", "L1", "L2", "L3", "L4"}
        assert record.target_kinds
        assert record.framework
        assert record.last_verified == "2026-11-02"


def test_the_ledger_states_its_timestamp_registry_version_and_framework_versions(
    ledger,
) -> None:  # type: ignore[no-untyped-def]
    payload = ledger.to_dict()
    assert payload["generated_at"] == "2026-11-02"
    assert payload["registry_version"] == "registry-1.0"
    assert payload["registry_digest"].startswith("sha256:")
    assert payload["framework_versions"]["WSTG"] == "4.2"
    assert payload["framework_versions"]["API"] == "2023"


def test_the_json_document_has_a_checks_array(ledger) -> None:  # type: ignore[no-untyped-def]
    payload = json.loads(render_ledger_json(ledger))
    assert isinstance(payload["checks"], list)
    assert len(payload["checks"]) == ledger.check_count


# ------------------------------------------------------------------ REQ-DET-002 burn-down
def test_no_check_is_mapped_only_to_a_cwe(ledger) -> None:  # type: ignore[no-untyped-def]
    assert ledger.cwe_only == ()


def test_every_check_names_a_wstg_or_api_item(ledger) -> None:  # type: ignore[no-untyped-def]
    for record in ledger.records:
        assert any(item.startswith(("WSTG-", "API")) for item in record.framework), record.id


def test_the_original_152_checks_are_all_present_and_mapped(ledger) -> None:  # type: ignore[no-untyped-def]
    """REQ-DET-002's "all 152 existing checks" set, before the later additions."""
    ids = {record.id for record in ledger.records}
    mcp = {record.id for record in ledger.records if record.id.startswith("m6.mcp-")}
    wp08 = {record.id for record in ledger.records if record.id in WP08_IDS}
    wp09 = {record.id for record in ledger.records if record.id in WP09_IDS}
    wp10 = {record.id for record in ledger.records if record.id in WP10_IDS}
    wp11 = {record.id for record in ledger.records if record.id in WP11_IDS}
    wp12 = {record.id for record in ledger.records if record.id in WP12_IDS}
    wp20 = {record.id for record in ledger.records if record.id in WP20_IDS}
    wp25 = {record.id for record in ledger.records if record.id in WP25_IDS}
    wp26 = {record.id for record in ledger.records if record.id in WP26_IDS}
    wp27 = {record.id for record in ledger.records if record.id in WP27_IDS}
    wp28 = {record.id for record in ledger.records if record.id in WP28_IDS}
    wp29 = {record.id for record in ledger.records if record.id in WP29_IDS}
    wp30 = {record.id for record in ledger.records if record.id in WP30_IDS}
    assert (
        len(
            ids
            - mcp
            - wp08
            - wp09
            - wp10
            - wp11
            - wp12
            - wp20
            - wp25
            - wp26
            - wp27
            - wp28
            - wp29
            - wp30
        )
        == 152
    )
    assert len(mcp) == 3
    assert len(wp08) == 9
    assert len(wp10) == 5
    assert len(wp11) == 1
    assert len(wp12) == 2
    assert len(wp20) == 1
    assert len(wp25) == 26
    assert len(wp26) == 30
    assert len(wp27) == 25
    assert len(wp28) == 24
    assert len(wp29) == 24
    assert len(wp30) == 24


# ------------------------------------------------------------------ REQ-DET-003 WSTG
def test_all_97_wstg_ids_are_accounted_for_exactly_once(ledger) -> None:  # type: ignore[no-untyped-def]
    ids = [item["id"] for item in ledger.wstg_items]
    assert len(ids) == 97
    assert len(set(ids)) == 97
    assert {item["state"] for item in ledger.wstg_items} <= {
        "mapped",
        "out_of_scope",
        "gap",
    }


def test_at_least_68_of_97_wstg_ids_are_mapped(ledger) -> None:  # type: ignore[no-untyped-def]
    counts = ledger.wstg_counts()
    assert counts["total"] == 97
    assert counts["mapped"] >= 68
    assert counts["mapped"] + counts["out_of_scope"] + counts["gap"] == 97


def test_every_out_of_scope_item_carries_a_reason(ledger) -> None:  # type: ignore[no-untyped-def]
    for item in ledger.wstg_items:
        if item["state"] == "out_of_scope":
            assert item.get("reason")


def test_a_gap_names_no_check_and_a_mapped_item_names_one(ledger) -> None:  # type: ignore[no-untyped-def]
    for item in ledger.wstg_items:
        if item["state"] == "gap":
            assert item["checks"] == []
        if item["state"] == "mapped":
            assert item["checks"]


# ------------------------------------------------------------------ REQ-DET-005 API
def test_the_api_top10_is_mapped_ten_of_ten(ledger) -> None:  # type: ignore[no-untyped-def]
    assert ledger.api_counts() == {"mapped": 10, "total": 10}


# ------------------------------------------------------------------ REQ-DET-004 CWE Top 25
def test_the_cwe_top25_is_covered_eighteen_of_eighteen_in_scope(ledger) -> None:  # type: ignore[no-untyped-def]
    """REQ-DET-004: ``cwe_top25.in_scope.covered = 18 / 18``, and 18/25 overall."""
    assert ledger.cwe_version == "2025"
    counts = ledger.cwe_counts()
    assert counts["in_scope"] == {"covered": 18, "total": 18, "percent": 100.0}
    assert counts["all"] == {"covered": 18, "total": 25, "percent": 72.0}


def test_the_cwe_top25_lists_all_25_ids_exactly_once(ledger) -> None:  # type: ignore[no-untyped-def]
    ids = [item["id"] for item in ledger.cwe_items]
    assert len(ids) == 25
    assert len(set(ids)) == 25


def test_the_json_carries_the_cwe_top25_tally(ledger) -> None:  # type: ignore[no-untyped-def]
    document = ledger.to_dict()
    assert document["cwe_top25"]["version"] == "2025"
    assert document["cwe_top25"]["in_scope"]["covered"] == 18
    assert len(document["cwe_top25"]["items"]) == 25


def test_the_out_of_scope_top25_items_are_the_seven_memory_safety_classes(
    ledger,  # type: ignore[no-untyped-def]
) -> None:
    out_of_scope = [item for item in ledger.cwe_items if not item["in_scope"]]
    assert {item["id"] for item in out_of_scope} == {
        "CWE-787",
        "CWE-416",
        "CWE-125",
        "CWE-120",
        "CWE-476",
        "CWE-121",
        "CWE-122",
    }
    for item in out_of_scope:
        assert item["reason"]
        assert item["checks"] == []
        assert item["covered"] is False


def test_the_four_wp08_cwes_are_emitted_by_their_new_checks(ledger) -> None:  # type: ignore[no-untyped-def]
    by_id = {item["id"]: item for item in ledger.cwe_items}
    expected = {
        "CWE-94": "m3.code-injection-oracle",
        "CWE-863": "m3.authz-bypass",
        "CWE-20": "m3.input-validation-audit",
        "CWE-77": "m3.argument-injection",
    }
    for cwe, check in expected.items():
        assert check in by_id[cwe]["checks"], (cwe, by_id[cwe]["checks"])


def test_the_five_injection_families_carry_their_cwe(ledger) -> None:  # type: ignore[no-untyped-def]
    by_id = {record.id: record for record in ledger.records}
    expected = {
        "m3.ldap-injection": "CWE-90",
        "m3.xpath-injection": "CWE-643",
        "m3.host-header-injection": "CWE-644",
        "m3.email-header-injection": "CWE-93",
        "m3.cache-deception": "CWE-524",
    }
    for check_id, cwe in expected.items():
        assert by_id[check_id].cwe == cwe
        assert cwe in by_id[check_id].framework


def test_the_mcp_family_is_registered_and_mapped() -> None:
    metadata = {item.id: item for item in ModuleRegistry.builtin().metadata()}
    for check_id in ("m6.mcp-token-audience", "m6.mcp-session-auth", "m6.mcp-oauth-metadata"):
        assert check_id in metadata
        assert metadata[check_id].proof.value in {"L0", "L1"}
        assert metadata[check_id].enabled_by_default  # opt-out-able


# ------------------------------------------------------------------ the committed artefact
def test_the_committed_ledger_is_current() -> None:
    """G3 clause 1: the committed ledger is byte-identical to generated output in CI."""
    ok, differences = check_ledger(*default_ledger_paths())
    assert ok, differences


def test_the_markdown_is_deterministic(ledger) -> None:  # type: ignore[no-untyped-def]
    assert render_ledger_markdown(ledger) == render_ledger_markdown(
        build_ledger(ModuleRegistry.discover(), generated_at="2026-11-02")
    )


def test_a_stale_ledger_fails_naming_the_check_id(tmp_path: Path, registry: ModuleRegistry) -> None:
    """Adding a check without regenerating fails the build with the check id in the message."""
    ledger = build_ledger(registry, generated_at="2026-11-02")
    json_path = tmp_path / "coverage-ledger.json"
    markdown_path = tmp_path / "coverage-ledger.md"
    json_path.write_text(render_ledger_json(ledger), encoding="utf-8")
    markdown_path.write_text(render_ledger_markdown(ledger), encoding="utf-8")
    assert check_ledger(json_path, markdown_path, registry=registry)[0]

    class LedgerProbe(Module):
        metadata = CheckMetadata(
            id="m1.ledger-probe",
            module="M1",
            name="ledger-probe",
            version="1.0",
            title="Ledger probe",
            description="A check added without regenerating the ledger.",
            research_ref="ch01#1",
            framework=("WSTG-INFO-01",),
            target_kinds=(TargetKind.DOMAIN,),
        )

        async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
            yield ctx.info("never")  # pragma: no cover

    grown = ModuleRegistry.discover(
        include_entry_points=False,
        extra_groups=[
            ModuleGroup(
                id="M1",
                title="M1",
                description="test",
                version="1.0",
                checks=(LedgerProbe,),
            )
        ],
    )
    ok, differences = check_ledger(json_path, markdown_path, registry=grown)
    assert not ok
    assert any("m1.ledger-probe" in difference for difference in differences)


def test_the_cli_emits_the_same_records(registry: ModuleRegistry) -> None:
    result = runner.invoke(app, ["coverage", "ledger", "--format", "json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert len(payload["checks"]) == len(registry.checks())


def test_the_cli_check_mode_passes_on_the_committed_ledger() -> None:
    result = runner.invoke(app, ["coverage", "ledger", "--check"])
    assert result.exit_code == 0, result.output
    assert "up to date" in result.output
