"""Acceptance: the DigitalOcean read-only posture check against a fixture API (REQ-DET-017).

The fixture needs the bearer token, so these tests also prove the credential path: a
missing or refused token is a skip, never an unauthenticated read; the token never appears in
a result or an audit record; and the only operations issued are the read-only ones the
provider ledger declares.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import make_m5_harness
from tests.helpers.vault import make_vault
from tests.lab.cloud_provider_lab import (
    DIGITALOCEAN_TOKEN,
    DigitalOceanLab,
    start_digitalocean_lab,
)

from arachne.core.audit import AuditAction
from arachne.core.vault import CLOUD_CREDENTIAL_KINDS, CredentialScope
from arachne.creds.broker import CredentialBroker
from arachne.modules.cloud_providers import by_provider, operation_offenders
from arachne.modules.m5.provider_posture import DigitalOceanPosture

PROVIDER = by_provider()["digitalocean"]


@pytest.fixture(scope="module")
def do_lab() -> Iterator[DigitalOceanLab]:
    with start_digitalocean_lab() as lab:
        yield lab


def _broker(harness, tmp_path: Path, secret: str = DIGITALOCEAN_TOKEN):  # type: ignore[no-untyped-def]
    vault = make_vault(
        tmp_path,
        entries={
            "do-account": {
                "kind": "cloud-token",
                "username": "api",
                "secret": secret,
                "scope": CredentialScope(hosts=("127.0.0.1",)),
            }
        },
    )
    return CredentialBroker(
        store=vault,
        labels=("do-account",),
        auditor=harness.memory.auditor,
        scan_id=harness.memory.scan_id,
        hosts=("127.0.0.1",),
    )


async def _run(lab: DigitalOceanLab, account: str, tmp_path: Path, *, with_credential: bool = True):  # type: ignore[no-untyped-def]
    asset = asset_for("cloud", f"digitalocean:{lab.endpoint(account)}")
    harness = make_m5_harness(asset=asset)
    if with_credential:
        harness.step.credentials = _broker(harness, tmp_path)
    try:
        ctx = harness.context(DigitalOceanPosture())
        results = [result async for result in DigitalOceanPosture().run(ctx)]
        return results, harness, ctx
    finally:
        await harness.aclose()


def _policies(results: list[object]) -> list[str]:
    found: list[str] = []
    for result in results:
        if getattr(result, "status", "") != "vulnerable":
            continue
        for item in getattr(result, "evidence", ()):
            if item.payload.get("signal") == "cloud-provider-posture":
                found.append(str(item.payload["policy"]))
    return found


async def test_the_risky_account_reports_each_posture_condition(
    do_lab: DigitalOceanLab, tmp_path: Path
) -> None:
    results, _harness, _ctx = await _run(do_lab, "risky", tmp_path)
    policies = set(_policies(results))
    assert {
        "do-database-public",
        "do-database-no-trusted-sources",
        "do-firewall-open-ssh",
        "do-loadbalancer-plaintext",
    } <= policies


async def test_the_hardened_account_is_a_clean_decoy(
    do_lab: DigitalOceanLab, tmp_path: Path
) -> None:
    results, _harness, _ctx = await _run(do_lab, "safe", tmp_path)
    assert _policies(results) == []
    assert any(result.status == "not_vulnerable" for result in results)
    assert not any(result.status == "error" for result in results), results


async def test_only_the_operations_in_the_provider_allowlist_are_issued(
    do_lab: DigitalOceanLab, tmp_path: Path
) -> None:
    del do_lab.requests[:]
    await _run(do_lab, "risky", tmp_path)
    issued = [(request.split(" ", 1)[0], request.split(" ", 1)[1]) for request in do_lab.requests]
    # The fixture prefixes the account path; the provider paths are the suffix.
    normalised = [(method, path.split("/risky", 1)[-1]) for method, path in issued]
    assert normalised, "no request was issued"
    assert operation_offenders(PROVIDER, normalised) == ()
    assert all(method == "GET" for method, _path in normalised)


async def test_no_write_method_reaches_the_provider(
    do_lab: DigitalOceanLab, tmp_path: Path
) -> None:
    del do_lab.requests[:]
    await _run(do_lab, "risky", tmp_path)
    assert not [request for request in do_lab.requests if not request.startswith("GET ")]


async def test_the_token_never_reaches_a_result_or_an_audit_record(
    do_lab: DigitalOceanLab, tmp_path: Path
) -> None:
    results, harness, _ctx = await _run(do_lab, "risky", tmp_path)
    blob = json.dumps(
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
    assert DIGITALOCEAN_TOKEN not in blob
    audit_blob = json.dumps([event.to_dict() for event in harness.memory.sink.events], default=str)
    assert DIGITALOCEAN_TOKEN not in audit_blob
    released = harness.memory.sink.of_action(AuditAction.CREDENTIAL_RELEASED)
    assert released, "the credential release must be audited"


async def test_no_credential_is_a_skip_and_issues_no_request(
    do_lab: DigitalOceanLab, tmp_path: Path
) -> None:
    del do_lab.requests[:]
    results, _harness, _ctx = await _run(do_lab, "risky", tmp_path, with_credential=False)
    assert [result.title for result in results if result.status == "info"]
    assert not any(result.status == "vulnerable" for result in results)
    assert do_lab.requests == [], "an unauthenticated read must not be attempted"


async def test_a_refused_token_is_a_skip_not_an_empty_account(
    do_lab: DigitalOceanLab, tmp_path: Path
) -> None:
    results, _harness, _ctx = await _run(do_lab, "risky", tmp_path, with_credential=True)
    # The correct token works; a wrong one must not fall back to an unauthenticated read.
    assert any(result.status == "vulnerable" for result in results)
    other = tmp_path / "other"
    other.mkdir()
    results, _harness, _ctx = await _run_bad_token(do_lab, other)
    assert all(result.status == "info" for result in results), [r.title for r in results]
    assert not any(result.status == "vulnerable" for result in results)


async def _run_bad_token(lab: DigitalOceanLab, tmp_path: Path):  # type: ignore[no-untyped-def]
    asset = asset_for("cloud", f"digitalocean:{lab.endpoint('risky')}")
    harness = make_m5_harness(asset=asset)
    harness.step.credentials = _broker(harness, tmp_path, secret="wrong-token")
    try:
        ctx = harness.context(DigitalOceanPosture())
        return [result async for result in DigitalOceanPosture().run(ctx)], harness, ctx
    finally:
        await harness.aclose()


def test_the_check_declares_the_cloud_token_kind() -> None:
    assert DigitalOceanPosture.metadata.requires_credentials == ("cloud-token",)
    assert CLOUD_CREDENTIAL_KINDS == ("cloud-token",)
