"""The plugin contract (F-02-01): metadata, assets, and the M1 inventory.

These tests pin the properties a plugin author and the framework depend on:

* metadata is validated when a class is defined (a bad id or an active check without an
  opt-in is a programming error, not a runtime surprise);
* an asset's applicability mapping is total (a declared ``ip`` target and an ``ip``-scoped
  check can never disagree);
* the M1 module group is complete, versioned, and its metadata matches .
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from tests.helpers.checks import asset_for, make_step_context, run_check

from arachne.core.errors import ConfigurationError
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import ASSET_KINDS, Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext, mask_secret
from arachne.modules.m1 import M1, M1_CHECKS


# ------------------------------------------------------------------ metadata validation
def metadata(**overrides: object) -> CheckMetadata:
    base: dict[str, object] = {
        "id": "m1.test-check",
        "module": "M1",
        "name": "test-check",
        "version": "1.0",
        "title": "Test check",
        "description": "A check that exists only in this test.",
        "research_ref": "ch01#1",
        "target_kinds": (TargetKind.DOMAIN,),
    }
    return CheckMetadata(**{**base, **overrides})  # type: ignore[arg-type]


def test_valid_metadata_derives_its_keys() -> None:
    item = metadata()
    assert item.key == "M1/test-check@1.0"
    assert item.supports_kind(TargetKind.DOMAIN)
    assert not item.supports_kind(TargetKind.CIDR)
    assert not item.is_opt_in


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("id", "m1.other", "must equal"),
        ("module", "M9", "not a module id"),
        ("name", "Test_Check", "kebab-case"),
        ("research_ref", "chapter-1", "corpus reference"),
        ("cwe", "200", "CWE-NNN"),
        ("cve", "CVE-2021", "CVE-YYYY"),
        ("target_kinds", (), "target_kinds is empty"),
        ("estimated_requests", -1, ">= 0"),
        ("title", "", "title and description"),
    ],
)
def test_bad_metadata_is_refused(field: str, value: object, message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        metadata(**{field: value})


def test_an_active_check_must_require_an_opt_in() -> None:
    """F-01-09: an active check that does not demand an opt-in would bypass the gate."""
    with pytest.raises(ConfigurationError, match="requires_active_checks=True"):
        metadata(type="active")


def test_an_unsafe_active_check_has_no_place_in_a_detector() -> None:
    with pytest.raises(ConfigurationError, match="safe=False"):
        metadata(type="active", requires_active_checks=True, safe=False)


def test_module_subclass_must_declare_metadata() -> None:
    with pytest.raises(ConfigurationError, match="does not declare check metadata"):

        class Undeclared(Module):
            async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
                yield ctx.info("never")  # pragma: no cover - construction fails above


# ------------------------------------------------------------------ the §5 surface
def test_module_exposes_the_contract_attributes() -> None:
    check = M1_CHECKS[0]()
    assert check.name == check.metadata.name
    assert check.version == check.metadata.version
    assert check.description == check.metadata.description
    assert check.research_ref == check.metadata.research_ref


def test_supports_is_target_kind_driven_and_understands_asset_kinds() -> None:
    from arachne.modules.m1 import CtLookup, InternetDbTriage

    lookup = CtLookup()
    assert lookup.supports(asset_for("domain", "example.com"))
    assert lookup.supports(asset_for("domain_pattern", "*.example.com"))
    assert not lookup.supports(asset_for("host", "93.184.216.34"))
    assert not lookup.supports(asset_for("network", "192.0.2.0/24"))

    triage = InternetDbTriage()
    assert triage.supports(asset_for("host", "93.184.216.34"))
    assert triage.supports(asset_for("network", "192.0.2.0/24"))
    assert not triage.supports(asset_for("domain", "example.com"))


def test_asset_selector_kind_maps_the_seed_vocabulary() -> None:
    """``core.steps.seed_asset`` writes ``host``/``network``; checks declare ``ip``/``cidr``."""
    assert asset_for("host", "93.184.216.34").selector_kind() is TargetKind.IP
    assert asset_for("host", "mail.example.com").selector_kind() is TargetKind.DOMAIN
    assert asset_for("network", "192.0.2.0/30").selector_kind() is TargetKind.CIDR
    assert asset_for("domain", "example.com").selector_kind() is TargetKind.DOMAIN
    assert asset_for("domain_pattern", "*.example.com").selector_kind() is TargetKind.DOMAIN_PATTERN
    assert asset_for("url", "https://example.com/").selector_kind() is TargetKind.URL
    assert asset_for("git", "https://github.com/o/r.git").selector_kind() is TargetKind.GIT
    assert asset_for("cloud", "aws:123").selector_kind() is TargetKind.CLOUD


def test_asset_rejects_an_unknown_kind_and_an_empty_value() -> None:
    with pytest.raises(ConfigurationError, match="unknown asset kind"):
        Asset.from_meta("wormhole", "x")
    with pytest.raises(ConfigurationError, match="must not be empty"):
        Asset.from_meta("domain", "")


def test_asset_helpers() -> None:
    asset = asset_for("domain_pattern", "*.example.com")
    assert asset.query_name == "example.com"
    assert asset.host == "*.example.com"
    assert asset.key == "domain_pattern:*.example.com"
    assert asset.declared is True
    assert asset.to_dict()["kind"] == "domain_pattern"


def test_every_asset_kind_has_a_selector_kind_or_is_a_reference() -> None:
    """A new asset kind must be mapped deliberately (fail closed if it is not)."""
    for kind in sorted(ASSET_KINDS):
        if kind == "bucket":
            continue
        sample = {
            "domain": "example.com",
            "domain_pattern": "*.example.com",
            "host": "example.com",
            "url": "https://example.com/",
            "network": "192.0.2.0/30",
            "git": "https://github.com/o/r.git",
            "cloud": "aws:123",
            # S29 (REQ-DEPTH-005): a local artifact. Mapping it to TargetKind.ARTIFACT is what
            # makes the artifact scope dimension reachable from a declared target.
            "artifact": "/srv/builds/app.apk",
        }[kind]
        assert asset_for(kind, sample).selector_kind() is not None


# ------------------------------------------------------------------ result helpers
async def test_context_result_helpers_tag_and_route() -> None:
    from arachne.modules.m1 import CtLookup

    results, memory = await run_check(CtLookup, asset_for("domain", "example.com"), osint=None)
    assert len(results) == 1
    result = results[0]
    assert result.status == "info"
    assert result.module == "M1"
    assert result.check == "M1/ct-lookup@1.0"
    assert "not run" in result.title
    # A skipped check leaves a machine-readable marker instead of relying on prose.
    assert any(item.payload.get("skipped") for item in result.evidence)
    # The check itself audits nothing here: recording and auditing a run is the checks step's
    # job (modules.handlers), which keeps a check from being able to silence the trail.
    assert memory.actions() == []
    assert [record.value for record in memory.store.list_assets(memory.scan_id)] == ["example.com"]


def test_check_context_builders_cover_every_status() -> None:
    step, _memory = make_step_context()
    from arachne.modules.m1 import CtLookup

    context = CheckContext(step=step, module=CtLookup(), asset=asset_for("domain", "example.com"))
    assert context.info("i").status == "info"
    assert context.candidate("c").status == "vulnerable"
    assert context.clean("n").status == "not_vulnerable"
    assert context.skipped("why").status == "info"
    error = context.error(ValueError("boom"))
    assert error.status == "error"
    assert error.check == "M1/ct-lookup@1.0"
    assert "boom" in (error.detail or "")
    # A candidate inherits the check's CWE unless it states its own.
    assert context.candidate("x").cwe == CtLookup.metadata.cwe


def test_mask_secret_never_reveals_a_usable_value() -> None:
    value = "AKIAIOSFODNN7EXAMPLE"
    masked = mask_secret(value)
    assert value not in masked
    assert masked.startswith("AKIA")
    assert "20 chars" in masked
    assert mask_secret("short") == "[masked:5 chars]"


# ------------------------------------------------------------------ the M1 module group
def test_m1_is_complete_versioned_and_in_step_order() -> None:
    assert M1.id == "M1"
    assert M1.version == "1.2.0"
    assert M1.research_chapter == "ch01"
    assert len(M1.checks) == 17
    assert all(check.metadata.module == "M1" for check in M1.checks)


def test_every_m1_check_maps_to_a_real_research_method() -> None:
    """Traceability (principle #5): the refs must exist in ch01."""
    from arachne.modules.coverage import default_research_dir, parse_research_methods

    research = default_research_dir()
    if research is None:  # pragma: no cover - the corpus lives beside the code
        pytest.skip("research corpus is not available in this checkout")
    known = {method.ref for method in parse_research_methods(research)}
    for check in M1.checks:
        ref = check.metadata.research_ref
        for part in ref.split("#")[1].split("-"):
            assert f"ch01#{part}" in known, f"{check.metadata.id} references {ref}"


def test_m1_check_ids_and_defaults() -> None:
    expected = {
        "m1.dork-sweep": ("ch01#1", True),
        "m1.code-secret-mining": ("ch01#2", False),
        "m1.internetdb-triage": ("ch01#5", True),
        "m1.ct-lookup": ("ch01#8", True),
        "m1.passive-dns": ("ch01#11", True),
        "m1.subdomain-passive": ("ch01#13", True),
        "m1.webarchive-harvest": ("ch01#14-16", True),
        "m1.email-harvest": ("ch01#17", True),
        "m1.doc-metadata": ("ch01#22", True),
        "m1.favicon-hash": ("ch01#23", True),
        "m1.dns-txt-mining": ("ch01#25", True),
        "m1.js-asset-scan": ("ch01#26", True),
        "m1.bucket-hunt": ("ch01#30", False),
        "m1.service-exposure-drift": ("ch01#3-4", False),
        "m1.ct-surprise": ("ch01#8-9", False),
        "m1.breach-exposure": ("ch01#18", False),
        # S29 (REQ-DEPTH-005): the offline mobile-artifact analysis. Opt-in: reading a local
        # file is a scope decision of its own (Scope.allowed_artifacts).
        "m1.mobile-artifact": ("ch01#26", False),
    }
    actual = {
        check.metadata.id: (check.metadata.research_ref, check.metadata.enabled_by_default)
        for check in M1.checks
    }
    assert actual == expected
    # Six checks are opt-in: the token-budgeted code search (it names its credential), the
    # bucket hunt (third-party provider hosts, so it also needs --active-checks), since S18 the
    # three intel checks whose providers nobody enables implicitly, and since S29 the offline
    # mobile-artifact analysis (reading a local file is its own scope decision).
    opted_in = [c.metadata for c in M1.checks if c.metadata.is_opt_in]
    assert [item.id for item in opted_in] == [
        "m1.code-secret-mining",
        "m1.bucket-hunt",
        "m1.service-exposure-drift",
        "m1.ct-surprise",
        "m1.breach-exposure",
        "m1.mobile-artifact",
    ]
    assert opted_in[0].requires_credentials == ("github_token",)
    assert opted_in[2].requires_credentials == ("shodan_api_key",)


def test_m1_is_passive_except_the_read_only_hybrids() -> None:
    """safety: passive, or a hybrid that only reads public content."""
    hybrids = {c.metadata.id for c in M1.checks if c.metadata.type == "hybrid"}
    assert hybrids == {
        "m1.js-asset-scan",
        "m1.favicon-hash",
        "m1.doc-metadata",
    }
    assert all(c.metadata.safe for c in M1.checks)
    # The one active M1 check is the bucket hunt, which probes third-party provider hosts;
    # it is opt-in *and* gated by --active-checks (F-01-09, S13 — mirrors m5.bucket-enumerator).
    active = {c.metadata.id for c in M1.checks if c.metadata.requires_active_checks}
    assert active == {"m1.bucket-hunt"}
    assert all(
        not c.metadata.enabled_by_default for c in M1.checks if c.metadata.requires_active_checks
    )
