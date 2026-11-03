"""Acceptance for the cloud-provider coverage ledger and its operation allowlist (REQ-DET-017).

The requirement's two halves are both asserted here: every named provider is either supported
by a registered check or ``not_supported`` with a reason, and every declared operation is a
read. ``problems`` is driven against the live registry, then broken on purpose so the checker
is proven to bite.
"""

from __future__ import annotations

import dataclasses

import pytest

from arachne.modules.cloud_providers import (
    CLOUD_PROVIDER_MATRIX,
    CloudProviderEntry,
    by_provider,
    counts,
    operation_offenders,
    problems,
    to_dict,
)
from arachne.modules.coverage import build_ledger, render_ledger_markdown
from arachne.modules.registry import ModuleRegistry


def _registry_ids() -> set[str]:
    return set(ModuleRegistry.discover().check_ids())


# --------------------------------------------------------------------------- the live product
def test_the_live_registry_agrees_with_the_provider_matrix() -> None:
    assert problems(_registry_ids()) == ()


def test_three_new_providers_are_each_covered_or_explicitly_unsupported() -> None:
    table = by_provider()
    assert {"oci", "alibaba", "digitalocean"} <= set(table)
    for name in ("oci", "alibaba"):
        entry = table[name]
        assert entry.state == "not_supported"
        assert entry.reason.strip()
        assert entry.check_ids == ()
    assert table["digitalocean"].state == "supported"
    assert table["digitalocean"].check_ids == ("m5.do-posture",)


def test_digitalocean_declares_only_read_operations() -> None:
    entry = by_provider()["digitalocean"]
    assert entry.operations
    assert {method for method, _path in entry.operations} == {"GET"}


def test_every_declared_operation_stays_inside_the_provider_paths() -> None:
    """A check's issued operations that are not declared are a finding of the allowlist test."""
    entry = by_provider()["digitalocean"]
    used = [
        ("GET", "/v2/droplets"),
        ("GET", "/v2/databases"),
        ("GET", "/v2/load_balancers"),
        ("GET", "/v2/firewalls"),
    ]
    assert operation_offenders(entry, used) == ()
    assert operation_offenders(entry, [("GET", "/v2/account")]) == ("GET /v2/account",)
    assert operation_offenders(entry, [("DELETE", "/v2/droplets")]) == ("DELETE /v2/droplets",)


# --------------------------------------------------------------------------- unrepresentable
def test_a_write_operation_is_unrepresentable() -> None:
    with pytest.raises(ValueError, match="not a read"):
        CloudProviderEntry(
            provider="x",
            display="X",
            state="supported",
            check_ids=("m5.do-posture",),
            reason="r",
            operations=(("DELETE", "/v2/droplets"),),
        )


def test_a_relative_operation_path_is_refused() -> None:
    with pytest.raises(ValueError, match="absolute"):
        CloudProviderEntry(
            provider="x",
            display="X",
            state="supported",
            check_ids=("m5.do-posture",),
            reason="r",
            operations=(("GET", "v2/droplets"),),
        )


# --------------------------------------------------------------------------- the checker bites
def _replace(index: int, **changes: object) -> tuple[CloudProviderEntry, ...]:
    entries = list(CLOUD_PROVIDER_MATRIX)
    entries[index] = dataclasses.replace(entries[index], **changes)  # type: ignore[arg-type]
    return tuple(entries)


def test_a_supported_provider_with_no_check_is_a_problem() -> None:
    broken = _replace(3, check_ids=())
    assert any("names no check" in item for item in problems(_registry_ids(), broken))


def test_a_supported_provider_naming_an_unregistered_check_is_a_problem() -> None:
    broken = _replace(3, check_ids=("m5.not-a-check",))
    assert any("unregistered check" in item for item in problems(_registry_ids(), broken))


def test_a_not_supported_provider_without_a_reason_is_a_problem() -> None:
    broken = _replace(4, reason="   ")
    assert any("without a reason" in item for item in problems(_registry_ids(), broken))


def test_a_not_supported_provider_that_names_checks_is_a_problem() -> None:
    broken = _replace(4, check_ids=("m5.do-posture",))
    assert any("but names checks" in item for item in problems(_registry_ids(), broken))


def test_a_duplicate_provider_row_is_a_problem() -> None:
    duplicated = (*CLOUD_PROVIDER_MATRIX, CLOUD_PROVIDER_MATRIX[0])
    assert any("more than one row" in item for item in problems(_registry_ids(), duplicated))


# --------------------------------------------------------------------------- the ledger
def test_the_coverage_ledger_reports_every_provider() -> None:
    ledger = build_ledger(generated_at="2026-11-03")
    payload = ledger.to_dict()["cloud_providers"]
    assert payload["supported_count"] == 4
    assert payload["not_supported_count"] == 2
    assert set(payload["supported"]) == {"aws", "azure", "gcp", "digitalocean"}
    assert set(payload["not_supported"]) == {"oci", "alibaba"}
    by_name = {item["provider"]: item for item in payload["items"]}
    for name in ("oci", "alibaba"):
        assert by_name[name]["reason"], "a not_supported provider must state why"
    document = render_ledger_markdown(ledger)
    assert "## Cloud providers (REQ-DET-017)" in document
    assert "`oci` | not_supported" in document
    assert "`digitalocean` | supported" in document


def test_the_counts_and_serialisation_agree() -> None:
    payload = to_dict()
    assert counts()["supported_count"] == payload["supported_count"]
    assert len(payload["items"]) == len(CLOUD_PROVIDER_MATRIX)
    assert {item["provider"] for item in payload["items"]} == set(by_provider())
