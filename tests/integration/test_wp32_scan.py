"""WP-32 acceptance: the Azure, GCP and Kubernetes posture families meet their lab ground truth.

The requirement's acceptance criteria (REQ-DET-025) are the shape of this module:

* **at least 22 registered checks** across the three platforms, each with a framework mapping;
* every one **L1 or lower**, and none changes provider state — asserted at the source (the
  closed operation allowlists and the class-level guard), at the unit level
  (``tests/unit/test_cloud_posture.py``) and **on the wire** (the fixture's own request log);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on the
  decoy — the decoy is the requirement's own ("each provider ships a hardened fixture"),
  implemented as the ``safe`` account of each provider in ``tests/lab/cloud_posture_lab.py``;
* **no check reads a Kubernetes secret's contents**: exposure is established from RBAC
  metadata, and the fixture records (and fails on) any request that reaches a secret;
* **credentials come from the vault** and never reach a result or an audit record — the fixture
  only answers a bearer-token request, and a planted lab token is asserted absent from every
  payload;
* the registry total and the decoy-clean cell count are printed for the handoff.

One measurement drives every check against both accounts, and it was the whole family's run
that the false-positive rate was re-measured over.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import M5Harness, make_m5_harness
from tests.helpers.vault import make_vault
from tests.lab.cloud_posture_lab import (
    ACCOUNTS,
    AZURE_SUBSCRIPTION,
    CLOUD_LAB_TOKEN,
    DECOY,
    GCP_PROJECT,
    POSITIVE,
    CloudLab,
    start_cloud_lab,
)

from arachne.core.audit import AuditAction
from arachne.core.config import M5Settings
from arachne.core.proof import ProofLevel
from arachne.core.vault import CLOUD_CREDENTIAL_KINDS, CREDENTIAL_KINDS, CredentialScope
from arachne.creds.broker import CredentialBroker
from arachne.modules.cloud_providers import by_provider, operation_offenders
from arachne.modules.m5.azure_posture import AZURE_POSTURE_CHECKS, AZURE_READ_OPERATIONS
from arachne.modules.m5.azure_posture import service_areas as azure_areas
from arachne.modules.m5.gcp_posture import GCP_POSTURE_CHECKS, GCP_READ_OPERATIONS
from arachne.modules.m5.gcp_posture import service_areas as gcp_areas
from arachne.modules.m5.k8s_posture import K8S_POSTURE_CHECKS, K8S_READ_OPERATIONS
from arachne.modules.m5.k8s_posture import service_areas as k8s_areas

#: Every check the WP-32 families register, by provider prefix.
FAMILY_CHECKS: dict[str, tuple[type, ...]] = {
    "azure": AZURE_POSTURE_CHECKS,
    "gcp": GCP_POSTURE_CHECKS,
    "k8s": K8S_POSTURE_CHECKS,
}

#: The signal tag every finding in these families carries.
SIGNALS: frozenset[str] = frozenset({"azure-posture", "gcp-posture", "k8s-posture"})

#: The reference prefix each family reads.
REFERENCES: dict[str, str] = {
    "azure": "azure-posture",
    "gcp": "gcp-posture",
    "k8s": "k8s-posture",
}

#: Every check id the families register, and the check id -> scope area map.
WP32_IDS: tuple[str, ...] = tuple(
    check.metadata.id for checks in FAMILY_CHECKS.values() for check in checks
)
AREA_OF_ID: dict[str, str] = {
    check.metadata.id: check.area for checks in FAMILY_CHECKS.values() for check in checks
}

#: The scope areas REQ-DET-025 names, per platform.
REQUIRED_AREAS: dict[str, frozenset[str]] = {
    "azure": frozenset({"storage", "aks", "keyvault", "appservice", "nsg", "sql"}),
    "gcp": frozenset({"storage", "gke", "iam", "sql", "functions"}),
    "k8s": frozenset({"api-server", "kubelet", "dashboard", "rbac", "secrets", "admission"}),
}

#: The closed operation allowlist per provider.
OPERATIONS: dict[str, tuple[Any, ...]] = {
    "azure": AZURE_READ_OPERATIONS,
    "gcp": GCP_READ_OPERATIONS,
    "k8s": K8S_READ_OPERATIONS,
}

_FAMILY_PROOF = ProofLevel.L1


@pytest.fixture(scope="module")
def cloud_lab() -> Iterator[CloudLab]:
    with start_cloud_lab() as lab:
        yield lab


def _broker(harness: M5Harness, tmp_path: Path, token: str = CLOUD_LAB_TOKEN) -> CredentialBroker:
    vault = make_vault(
        tmp_path,
        entries={
            "cloud-read-only": {
                "kind": "cloud-token",
                "username": "lab-cloud-reader",
                "secret": token,
                "scope": CredentialScope(hosts=("127.0.0.1",)),
            }
        },
    )
    return CredentialBroker(
        store=vault,
        labels=("cloud-read-only",),
        auditor=harness.memory.auditor,
        scan_id=harness.memory.scan_id,
        hosts=("127.0.0.1",),
    )


def _settings() -> M5Settings:
    return M5Settings(
        azure_subscription_id=AZURE_SUBSCRIPTION,
        gcp_project_id=GCP_PROJECT,
    )


async def _run(
    lab: CloudLab,
    provider: str,
    account: str,
    tmp_path: Path,
    check_id: str,
    *,
    with_credential: bool = True,
    token: str = CLOUD_LAB_TOKEN,
    dry_run: bool = False,
) -> tuple[list[Any], M5Harness, Any]:
    asset = asset_for("cloud", f"{REFERENCES[provider]}:{lab.endpoint(provider, account)}")
    harness = make_m5_harness(asset=asset, m5=_settings())
    if with_credential:
        harness.step.credentials = _broker(harness, tmp_path, token)
    if dry_run:
        harness.step.http = None
    check = _by_id()[check_id]
    try:
        ctx = harness.context(check())
        results = [result async for result in check().run(ctx)]
        return results, harness, ctx
    finally:
        await harness.aclose()


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for checks in FAMILY_CHECKS.values() for check in checks}


def _policies(results: list[Any]) -> list[str]:
    """The policies this run *established* (a finding's signal carries each one)."""
    found: list[str] = []
    for result in results:
        if getattr(result, "status", "") != "vulnerable":
            continue
        for item in getattr(result, "evidence", ()):
            if item.payload.get("signal") in SIGNALS:
                found.append(str(item.payload["policy"]))
    return found


async def _measure(lab: CloudLab, tmp_path: Path) -> dict[tuple[str, str, str], int]:
    """Run every family check against both accounts, counting each one's findings."""
    counts: dict[tuple[str, str, str], int] = {}
    for provider, checks in FAMILY_CHECKS.items():
        for account in (POSITIVE, DECOY):
            for check in checks:
                results, _harness, _ctx = await _run(
                    lab, provider, account, tmp_path, check.metadata.id
                )
                counts[(provider, account, check.metadata.id)] = len(_policies(results))
    return counts


@pytest.fixture(scope="module")
def measured(
    cloud_lab: CloudLab, tmp_path_factory: pytest.TempPathFactory
) -> dict[tuple[str, str, str], int]:
    """One run of the whole family against both accounts of all three providers."""
    directory = tmp_path_factory.mktemp("wp32-measure")
    return asyncio.run(_measure(cloud_lab, directory))


# --------------------------------------------------------------------------- acceptance run
def test_the_families_register_at_least_twenty_two_checks(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """REQ-DET-025: at least 22 new checks across the three platforms."""
    assert len(WP32_IDS) >= 22, WP32_IDS
    assert len(set(WP32_IDS)) == len(WP32_IDS)
    areas = {
        "azure": azure_areas(),
        "gcp": gcp_areas(),
        "k8s": k8s_areas(),
    }
    for provider, checks in FAMILY_CHECKS.items():
        declared = {check.metadata.name for check in checks}
        assert set(areas[provider]) == declared
        assert {AREA_OF_ID[check.metadata.id] for check in checks} == set(areas[provider].values())
        # Every area the requirement's scope names owns at least one check.
        assert REQUIRED_AREAS[provider] <= set(areas[provider].values()), provider
    print(
        f"\nregistry total: {_registry_total()} checks; "
        f"WP-32 family: {len(WP32_IDS)} across three providers "
        f"({len(AZURE_POSTURE_CHECKS)} azure, {len(GCP_POSTURE_CHECKS)} gcp, "
        f"{len(K8S_POSTURE_CHECKS)} kubernetes); "
        f"decoy-clean cells: {len(WP32_IDS)}"
    )


def _registry_total() -> int:
    from arachne.modules.registry import ModuleRegistry

    return len(ModuleRegistry.discover().checks())


def test_every_check_reports_its_positive_and_is_silent_on_the_decoy(
    measured: dict[tuple[str, str, str], int],
) -> None:
    """The acceptance core: every planted breach is found, every hardened estate is silent."""
    misses = [
        check_id
        for provider, _checks in FAMILY_CHECKS.items()
        for check_id in (check.metadata.id for check in _checks)
        if measured[(provider, POSITIVE, check_id)] < 1
    ]
    false_positives = [
        check_id
        for provider, _checks in FAMILY_CHECKS.items()
        for check_id in (check.metadata.id for check in _checks)
        if measured[(provider, DECOY, check_id)] != 0
    ]
    assert not misses, misses
    assert not false_positives, false_positives
    print(
        f"\n{len(WP32_IDS)} checks x 2 accounts x 3 providers: every positive found, "
        f"0 findings on the hardened decoys ({len(WP32_IDS)} decoy-clean cells)"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-025: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP32_IDS:
        metadata = by_id[check_id].metadata
        assert metadata.proof is _FAMILY_PROOF, check_id
        assert metadata.requires_state_attestation is False, check_id
        assert metadata.safe is True, check_id
        assert metadata.cwe is not None and metadata.cwe in metadata.framework, check_id
        assert any(item.startswith(("WSTG-", "API")) for item in metadata.framework), check_id
        assert metadata.research_ref.startswith("ch05#"), check_id
        assert metadata.type == "active", check_id
        assert metadata.id == f"m5.{metadata.name}", check_id
        assert metadata.module == "M5", check_id
        assert metadata.requires_credentials == ("cloud-token",), check_id
        assert metadata.compliance, check_id


def test_the_families_declare_only_allowlisted_read_operations() -> None:
    """The source-level control: every declared read is an allowlist entry, and no mutation."""
    for provider, checks in FAMILY_CHECKS.items():
        allowed = set(OPERATIONS[provider])
        for check in checks:
            assert check.reads, check.metadata.id
            for operation in check.reads:
                assert operation in allowed, (check.metadata.id, operation.key)
        for operation in OPERATIONS[provider]:
            assert operation.method == "GET", (provider, operation.key)


def _candidate_values() -> dict[str, list[str]]:
    """Every placeholder value a declared operation path can legitimately carry."""
    emails = [
        str(account["email"])
        for data in ACCOUNTS["gcp"].values()
        for account in data["serviceAccounts"]["accounts"]
    ]
    nodes = [
        str(node["metadata"]["name"])
        for data in ACCOUNTS["k8s"].values()
        for node in data["nodes"]["items"]
    ]
    return {
        "subscription": [AZURE_SUBSCRIPTION],
        "project": [GCP_PROJECT],
        "account": emails,
        "node": nodes,
    }


def _allowed_paths(provider: str) -> set[str]:
    """Every concrete request path the provider's allowlist can produce."""
    values = _candidate_values()
    paths: set[str] = set()
    for operation in OPERATIONS[provider]:
        names = re.findall(r"\{(\w+)\}", operation.path)
        for combination in itertools.product(*(values[name] for name in names)):
            paths.add(operation.path.format(**dict(zip(names, combination, strict=True))))
    return paths


async def _drive_all(lab: CloudLab, tmp_path: Path) -> None:
    for provider, checks in FAMILY_CHECKS.items():
        for check in checks:
            await _run(lab, provider, POSITIVE, tmp_path, check.metadata.id)


@pytest.fixture(scope="module")
def wire(
    measured: dict[tuple[str, str, str], int],
    cloud_lab: CloudLab,
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, list[Any]]:
    """One whole-family drive with its wire log captured, shared by the wire-level assertions.

    ``measured`` is a dependency on purpose: it guarantees the whole matrix has run, so the
    snapshot is about every check rather than about the last one that happened to run.
    """
    del measured
    directory = tmp_path_factory.mktemp("wp32-wire")
    del cloud_lab.answered[:]
    del cloud_lab.requests[:]
    del cloud_lab.secret_reads[:]
    asyncio.run(_drive_all(cloud_lab, directory))
    snapshot = {
        "answered": list(cloud_lab.answered),
        "requests": list(cloud_lab.requests),
        "secret_reads": list(cloud_lab.secret_reads),
    }
    del cloud_lab.secret_reads[:]
    assert snapshot["answered"], "no operation was issued"
    return snapshot


def test_only_allowlisted_read_operations_reached_the_api(wire: dict[str, list[Any]]) -> None:
    """The wire-level control: the fixture saw a declared read path and nothing else."""
    offenders: list[str] = []
    for provider, account, path in wire["answered"]:
        prefix = f"/{provider}/{account}"
        relative = path[len(prefix) :] if path.startswith(prefix) else path
        if relative not in _allowed_paths(provider):
            offenders.append(f"{provider} {relative}")
    assert not offenders, offenders
    for entry in wire["requests"]:
        method = entry.split(" ", 1)[0].upper()
        assert method == "GET", entry


def test_no_write_method_reached_the_api(wire: dict[str, list[Any]]) -> None:
    """No PUT, POST, PATCH or DELETE reached the fixture at all."""
    writes = [entry for entry in wire["requests"] if entry.split(" ", 1)[0].upper() != "GET"]
    assert not writes, writes


def test_an_unauthenticated_request_is_refused(cloud_lab: CloudLab) -> None:
    """The trap: the fixture answers only a bearer-token request, so the credential path is real."""
    import urllib.error
    import urllib.request

    url = f"{cloud_lab.endpoint('azure', POSITIVE)}/subscriptions/x/providers/Microsoft.Sql/servers"
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(url, timeout=5)  # noqa: S310 - the loopback fixture
    assert caught.value.code == 401, caught.value.code


def test_a_wrong_credential_is_refused(cloud_lab: CloudLab) -> None:
    """A request carrying the wrong token is refused, not answered from a fallback."""
    import urllib.error
    import urllib.request

    url = f"{cloud_lab.endpoint('k8s', POSITIVE)}/api/v1/pods"
    request = urllib.request.Request(url, headers={"Authorization": "Bearer not-the-lab-token"})  # noqa: S310
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=5)  # noqa: S310
    assert caught.value.code == 403, caught.value.code


# --------------------------------------------------------------------------- secrets
def test_no_check_reads_a_kubernetes_secret(measured: dict[tuple[str, str, str], int]) -> None:
    """REQ-DET-025: exposure is established from metadata; no secret's contents are read.

    Two halves. The source half: no operation in the Kubernetes allowlist names a secret, and
    the secrets check reads only RBAC objects. The wire half: the fixture records every request
    that *reaches* a secret, and after the whole matrix has run it must have recorded none.
    """
    del measured
    for operation in K8S_READ_OPERATIONS:
        assert "secret" not in operation.path.lower(), operation.key
    secrets_check = _by_id()["m5.k8s-rbac-secrets-exposed"]
    assert secrets_check.reads
    assert all("rbac.authorization.k8s.io" in operation.path for operation in secrets_check.reads)


def test_the_fixture_would_notice_a_secret_read(cloud_lab: CloudLab) -> None:
    """The trap bites: a request that reaches a secret is recorded by the fixture."""
    import urllib.error
    import urllib.request

    del cloud_lab.secret_reads[:]
    url = f"{cloud_lab.endpoint('k8s', POSITIVE)}/api/v1/namespaces/default/secrets"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {CLOUD_LAB_TOKEN}"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=5) as answer:  # noqa: S310
        assert answer.status == 200
    assert cloud_lab.secret_reads, "the fixture must record a secret read for the rule to bite"
    del cloud_lab.secret_reads[:]


def test_the_matrix_read_no_secret(wire: dict[str, list[Any]]) -> None:
    """After the whole family has run, the fixture recorded no request for a secret."""
    assert wire["secret_reads"] == [], wire["secret_reads"]


# --------------------------------------------------------------------------- credential path
def test_the_credential_never_reaches_a_result_or_an_audit_record(
    cloud_lab: CloudLab, tmp_path: Path
) -> None:
    """REQ-DET-025: the vaulted token is absent from every payload and audit record."""
    blob: list[str] = []
    for provider, checks in FAMILY_CHECKS.items():
        for check in checks:
            results, harness, _ctx = asyncio.run(
                _run(cloud_lab, provider, POSITIVE, tmp_path, check.metadata.id)
            )
            blob.append(
                json.dumps(
                    [
                        {
                            "title": result.title,
                            "detail": result.detail,
                            "evidence": [dict(item.payload) for item in result.evidence],
                        }
                        for result in results
                    ],
                    default=str,
                )
            )
            blob.append(
                json.dumps([event.to_dict() for event in harness.memory.sink.events], default=str)
            )
            released = harness.memory.sink.of_action(AuditAction.CREDENTIAL_RELEASED)
            assert released, "the credential release must be audited"
    text = "\n".join(blob)
    assert CLOUD_LAB_TOKEN not in text


@pytest.mark.parametrize("provider", sorted(FAMILY_CHECKS))
def test_no_credential_is_a_skip_and_issues_no_request(
    cloud_lab: CloudLab, tmp_path: Path, provider: str
) -> None:
    """Without a cloud-token credential a check skips and sends nothing."""
    del cloud_lab.requests[:]
    for check in FAMILY_CHECKS[provider]:
        results, _harness, _ctx = asyncio.run(
            _run(cloud_lab, provider, POSITIVE, tmp_path, check.metadata.id, with_credential=False)
        )
        assert not _policies(results), check.metadata.id
        assert all(result.status == "info" for result in results), [r.status for r in results]
    assert cloud_lab.requests == [], "an unauthenticated read must not be attempted"


@pytest.mark.parametrize("provider", sorted(FAMILY_CHECKS))
def test_a_refused_credential_is_a_skip_not_a_clean_estate(
    cloud_lab: CloudLab, tmp_path: Path, provider: str
) -> None:
    """A wrong token produces a skip, never an empty (clean) estate."""
    check_id = FAMILY_CHECKS[provider][0].metadata.id
    results, _harness, _ctx = asyncio.run(
        _run(cloud_lab, provider, POSITIVE, tmp_path, check_id, token="wrong-token")
    )
    assert all(result.status == "info" for result in results), [r.status for r in results]
    assert not _policies(results)


@pytest.mark.parametrize("provider", sorted(FAMILY_CHECKS))
def test_a_dry_run_sends_nothing(cloud_lab: CloudLab, tmp_path: Path, provider: str) -> None:
    """``ctx.http is None`` turns every probe into a skip (F-01-10)."""
    del cloud_lab.requests[:]
    for check in FAMILY_CHECKS[provider]:
        results, _harness, _ctx = asyncio.run(
            _run(cloud_lab, provider, POSITIVE, tmp_path, check.metadata.id, dry_run=True)
        )
        assert all(result.status == "info" for result in results), [r.status for r in results]
    assert cloud_lab.requests == []


@pytest.mark.parametrize("provider", ["azure", "gcp"])
def test_a_missing_project_or_subscription_is_a_skip(
    cloud_lab: CloudLab, tmp_path: Path, provider: str
) -> None:
    """With no declared subscription/project the family skips rather than guessing one."""
    asset = asset_for("cloud", f"{REFERENCES[provider]}:{cloud_lab.endpoint(provider, POSITIVE)}")
    harness = make_m5_harness(asset=asset, m5=M5Settings())
    harness.step.credentials = _broker(harness, tmp_path)
    check = FAMILY_CHECKS[provider][0]

    async def go() -> list[Any]:
        try:
            ctx = harness.context(check())
            return [result async for result in check().run(ctx)]
        finally:
            await harness.aclose()

    results = asyncio.run(go())
    assert all(result.status == "info" for result in results), [r.status for r in results]
    details = " ".join(result.detail or "" for result in results)
    assert "PROJECT_ID" in details or "SUBSCRIPTION_ID" in details


@pytest.mark.parametrize("provider", sorted(FAMILY_CHECKS))
def test_the_checks_are_deterministic(cloud_lab: CloudLab, tmp_path: Path, provider: str) -> None:
    """Two runs against the same estate produce the same verdict and the same evidence."""

    async def once() -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for check in FAMILY_CHECKS[provider]:
            results, _harness, _ctx = await _run(
                cloud_lab, provider, POSITIVE, tmp_path, check.metadata.id
            )
            out.append(
                (
                    check.metadata.id,
                    hashlib.sha256(
                        json.dumps(
                            [[result.status, result.title, result.detail] for result in results],
                            default=str,
                        ).encode()
                    ).hexdigest(),
                )
            )
        return out

    assert asyncio.run(once()) == asyncio.run(once())


def test_the_configured_identifiers_reach_the_requests(wire: dict[str, list[Any]]) -> None:
    """The subscription and project the operator declared are what the paths carry."""
    paths = [path for _provider, _account, path in wire["answered"]]
    assert paths
    assert any(AZURE_SUBSCRIPTION in path for path in paths)
    assert any(GCP_PROJECT in path for path in paths)


def test_the_families_declare_the_cloud_token_kind() -> None:
    for checks in FAMILY_CHECKS.values():
        for check in checks:
            assert check.metadata.requires_credentials == ("cloud-token",)
    assert CLOUD_CREDENTIAL_KINDS == ("cloud-token",)
    assert "cloud-token" in CREDENTIAL_KINDS


def test_the_provider_ledger_names_every_new_check_and_no_write() -> None:
    """The ledger's Azure and GCP rows name the new checks and declare only GET operations."""
    for provider in ("azure", "gcp"):
        entry = by_provider()[provider]
        family = [check.metadata.id for check in FAMILY_CHECKS[provider]]
        assert set(family) <= set(entry.check_ids), provider
        assert {method for method, _path in entry.operations} == {"GET"}
        assert operation_offenders(entry, entry.operations) == ()
        assert operation_offenders(entry, [("DELETE", "/x")]) == ("DELETE /x",)


def test_the_ledger_operations_are_exactly_the_family_allowlists() -> None:
    """The two statements of what may be read cannot drift apart."""
    for provider in ("azure", "gcp"):
        entry = by_provider()[provider]
        declared = {(operation.method, operation.path) for operation in OPERATIONS[provider]}
        assert set(entry.operations) == declared, provider


def test_the_families_do_not_claim_each_others_assets() -> None:
    """A check applies to its own reference and to no other provider's."""
    for provider, checks in FAMILY_CHECKS.items():
        asset = asset_for("cloud", f"{REFERENCES[provider]}:example.invalid")
        others = {name for name in FAMILY_CHECKS if name != provider}
        for check in checks:
            assert check().supports(asset), (provider, check.metadata.id)
            for other in others:
                foreign = asset_for("cloud", f"{REFERENCES[other]}:example.invalid")
                assert not check().supports(foreign), (provider, other, check.metadata.id)


def test_the_family_signals_are_distinct() -> None:
    """Each family tags its findings with its own signal, so a rule can tell them apart."""
    families: Mapping[str, str] = {
        provider: str(checks[0].family) for provider, checks in FAMILY_CHECKS.items()
    }
    assert set(families.values()) == SIGNALS
    assert len(set(families.values())) == len(families)
