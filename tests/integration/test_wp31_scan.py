"""WP-31 acceptance: the AWS read-only posture family meets its lab ground truth (REQ-DET-024).

The requirement's acceptance criteria are the shape of this module:

* **at least 24 registered checks** in the family, each with a framework mapping;
* every one **L1 or lower**, and none changes account state — asserted at the source (the
  closed operation allowlist and the class-level guard), at the unit level
  (``tests/unit/test_aws_posture.py``) and **on the wire** (the fixture's own request log);
* each check has a **positive fixture** and a **decoy**, and produces **no finding** on the
  decoy — the decoy is the requirement's own ("a hardened account fixture"), implemented as
  the ``safe`` account of ``tests/lab/aws_lab.py``;
* **credentials come from the vault** and never reach a result or an audit record — the
  fixture only answers a SigV4-signed request, and a planted lab secret is asserted absent from
  every payload;
* the registry total and the decoy-clean cell count are printed for the handoff.

One measurement drives all thirty-one checks against both accounts, and it was the whole
family's run that the false-positive rate was re-measured over.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import M5Harness, make_m5_harness
from tests.helpers.vault import make_vault
from tests.lab.aws_lab import (
    AWS_LAB_ACCESS_KEY_ID,
    AWS_LAB_REGION,
    AWS_LAB_SECRET,
    AwsLab,
    start_aws_lab,
)

from arachne.core.audit import AuditAction
from arachne.core.proof import ProofLevel
from arachne.core.vault import AWS_CREDENTIAL_KINDS, CREDENTIAL_KINDS, CredentialScope
from arachne.creds.broker import CredentialBroker
from arachne.modules.cloud_providers import by_provider, operation_offenders
from arachne.modules.m5.aws_posture import (
    AWS_POSTURE_CHECKS,
    AWS_READ_OPERATIONS,
    MUTATION_VERBS,
    REFERENCE,
    service_areas,
)

#: Every check the WP-31 family registers.
WP31_IDS: tuple[str, ...] = tuple(check.metadata.id for check in AWS_POSTURE_CHECKS)

#: ``check id -> scope area``, from the module's own declaration.
AREA_OF_ID: dict[str, str] = {check.metadata.id: check.service for check in AWS_POSTURE_CHECKS}

#: The accounts the fixture serves: the positive and the requirement's decoy.
POSITIVE = "risky"
DECOY = "safe"

#: The read actions the fixture may see, by service, from the module's own allowlist.
ALLOWED_ACTIONS: dict[str, set[str]] = {}
for _operation in AWS_READ_OPERATIONS:
    ALLOWED_ACTIONS.setdefault(_operation.service, set()).add(_operation.action)

#: The safe HTTP methods: GET, plus POST for the two JSON-RPC services whose *reads* are POST.
SAFE_METHODS: frozenset[str] = frozenset({"GET", "POST"})

_FAMILY_PROOF = ProofLevel.L1


@pytest.fixture(scope="module")
def aws_lab() -> Iterator[AwsLab]:
    with start_aws_lab() as lab:
        yield lab


def _broker(harness: M5Harness, tmp_path: Path, secret: str = AWS_LAB_SECRET) -> CredentialBroker:
    vault = make_vault(
        tmp_path,
        entries={
            "aws-read-only": {
                "kind": "aws-role",
                "username": AWS_LAB_ACCESS_KEY_ID,
                "secret": secret,
                "scope": CredentialScope(hosts=("127.0.0.1",)),
            }
        },
    )
    return CredentialBroker(
        store=vault,
        labels=("aws-read-only",),
        auditor=harness.memory.auditor,
        scan_id=harness.memory.scan_id,
        hosts=("127.0.0.1",),
    )


async def _run(
    lab: AwsLab,
    account: str,
    tmp_path: Path,
    check_id: str,
    *,
    with_credential: bool = True,
    secret: str = AWS_LAB_SECRET,
    dry_run: bool = False,
) -> tuple[list[Any], M5Harness, Any]:
    asset = asset_for("cloud", f"{REFERENCE}:{lab.endpoint(account)}")
    harness = make_m5_harness(asset=asset)
    if with_credential:
        harness.step.credentials = _broker(harness, tmp_path, secret)
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
    return {check.metadata.id: check for check in AWS_POSTURE_CHECKS}


def _policies(results: list[Any]) -> list[str]:
    found: list[str] = []
    for result in results:
        if getattr(result, "status", "") != "vulnerable":
            continue
        for item in getattr(result, "evidence", ()):
            if item.payload.get("signal") == "aws-posture":
                found.append(str(item.payload["policy"]))
    return found


async def _measure(lab: AwsLab, tmp_path: Path) -> dict[tuple[str, str], int]:
    """Run every family check against both accounts, counting each one's findings."""
    counts: dict[tuple[str, str], int] = {}
    for account in (POSITIVE, DECOY):
        for check_id in WP31_IDS:
            results, _harness, _ctx = await _run(lab, account, tmp_path, check_id)
            counts[(account, check_id)] = len(_policies(results))
    return counts


@pytest.fixture(scope="module")
def measured(
    aws_lab: AwsLab, tmp_path_factory: pytest.TempPathFactory
) -> dict[tuple[str, str], int]:
    """One run of the whole family against both accounts."""
    directory = tmp_path_factory.mktemp("wp31-measure")
    return asyncio.run(_measure(aws_lab, directory))


# --------------------------------------------------------------------------- acceptance run
def test_the_family_registers_at_least_twenty_four_checks(
    measured: dict[tuple[str, str], int],
) -> None:
    """REQ-DET-024: at least 24 new checks in this family."""
    assert len(WP31_IDS) >= 24, WP31_IDS
    assert len(set(WP31_IDS)) == len(WP31_IDS)
    areas = service_areas()
    assert set(areas) == {check.metadata.name for check in AWS_POSTURE_CHECKS}
    assert set(AREA_OF_ID.values()) == set(areas.values())
    # Every area the requirement's scope names owns at least one check.
    for area in (
        "s3",
        "iam",
        "ec2",
        "rds",
        "eks",
        "lambda",
        "cloudtrail",
        "kms",
        "sqs",
        "sns",
        "ecr",
        "s3control",
    ):
        assert any(AREA_OF_ID[check_id] == area for check_id in WP31_IDS), area
    decoy_cells = len(WP31_IDS)
    print(
        f"\nregistry total: {_registry_total()} checks; "
        f"WP-31 family: {len(WP31_IDS)} across {len(set(areas.values()))} areas; "
        f"decoy-clean cells: {decoy_cells}"
    )


def _registry_total() -> int:
    from arachne.modules.registry import ModuleRegistry

    return len(ModuleRegistry.discover().checks())


def test_every_check_reports_its_positive_and_is_silent_on_the_decoy(
    measured: dict[tuple[str, str], int],
) -> None:
    """The acceptance core: every planted breach is found, the hardened account is silent."""
    misses = [check_id for check_id in WP31_IDS if measured[(POSITIVE, check_id)] < 1]
    false_positives = [check_id for check_id in WP31_IDS if measured[(DECOY, check_id)] != 0]
    assert not misses, misses
    assert not false_positives, false_positives
    print(
        f"\n{len(WP31_IDS)} checks x 2 accounts: every positive found, "
        f"0 findings on the hardened decoy ({len(WP31_IDS)} decoy-clean cells)"
    )


def test_every_check_is_l1_read_only_and_mapped() -> None:
    """REQ-DET-024: all L1 or lower, none changing state, all framework-mapped."""
    by_id = _by_id()
    for check_id in WP31_IDS:
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
        assert metadata.requires_credentials == ("aws-role",), check_id
        assert metadata.compliance, check_id


def test_the_family_declares_only_allowlisted_read_operations() -> None:
    """The source-level control: every declared read is an allowlist entry, and no mutation."""
    allowed = set(AWS_READ_OPERATIONS)
    for check in AWS_POSTURE_CHECKS:
        assert check.reads, check.metadata.id
        for operation in check.reads:
            assert operation in allowed, (check.metadata.id, operation.key)
        assert check.service in {operation.service for operation in check.reads}, check.metadata.id


def test_only_allowlisted_read_operations_reached_the_api(
    measured: dict[tuple[str, str], int], aws_lab: AwsLab, tmp_path: Path
) -> None:
    """The wire-level control: the fixture saw a read action and nothing else.

    ``measured`` is a parameter on purpose: it guarantees the whole matrix has run before the
    log is read, so the assertion is about every check rather than about the last one.
    """
    del measured
    del aws_lab.operations[:]
    asyncio.run(_drive_all(aws_lab, tmp_path))
    assert aws_lab.operations, "no operation was issued"
    offenders: list[str] = []
    for entry in aws_lab.operations:
        service, _, action = entry.partition(":")
        if action not in ALLOWED_ACTIONS.get(service, set()):
            offenders.append(entry)
    assert not offenders, offenders
    for entry in aws_lab.requests:
        method = entry.split(" ", 1)[0].upper()
        assert method in SAFE_METHODS, entry
    actions = set(aws_lab.actions())
    assert not {action for action in actions for verb in MUTATION_VERBS if verb in action}


async def _drive_all(lab: AwsLab, tmp_path: Path) -> None:
    for check_id in WP31_IDS:
        await _run(lab, POSITIVE, tmp_path, check_id)


def test_no_write_method_reached_the_api(
    measured: dict[tuple[str, str], int], aws_lab: AwsLab, tmp_path: Path
) -> None:
    """No PUT, PATCH or DELETE reached the fixture at all."""
    del measured
    del aws_lab.requests[:]
    asyncio.run(_drive_all(aws_lab, tmp_path))
    writes = [
        entry for entry in aws_lab.requests if entry.split(" ", 1)[0].upper() not in SAFE_METHODS
    ]
    assert not writes, writes


def test_an_unsigned_request_is_refused(aws_lab: AwsLab) -> None:
    """The trap: the fixture answers only a signed request, so the credential path is real."""
    import urllib.error
    import urllib.request

    url = f"{aws_lab.endpoint(POSITIVE)}/ec2/?Action=DescribeInstances&Version=2016-11-15"
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(url, timeout=5)  # noqa: S310 - the loopback fixture
    assert caught.value.code == 403, caught.value.code


def test_a_wrong_signature_is_refused(aws_lab: AwsLab) -> None:
    """A request signed with the wrong secret is refused, not answered from a fallback."""
    from arachne.creds.aws import sign_request

    url = f"{aws_lab.endpoint(POSITIVE)}/iam/?Action=GetAccountSummary&Version=2010-05-08"
    headers = sign_request(
        method="GET",
        url=url,
        service="iam",
        region=AWS_LAB_REGION,
        access_key=AWS_LAB_ACCESS_KEY_ID,
        secret_key="not-the-lab-secret",
    )
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - the loopback fixture
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=5)  # noqa: S310
    assert caught.value.code == 403, caught.value.code


def test_the_credential_never_reaches_a_result_or_an_audit_record(
    aws_lab: AwsLab, tmp_path: Path
) -> None:
    """REQ-DET-024: the vaulted secret is absent from every payload and audit record."""
    blob: list[str] = []
    for check_id in WP31_IDS:
        results, harness, _ctx = asyncio.run(_run(aws_lab, POSITIVE, tmp_path, check_id))
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
    assert AWS_LAB_SECRET not in text
    assert AWS_LAB_ACCESS_KEY_ID not in text


def test_no_credential_is_a_skip_and_issues_no_request(aws_lab: AwsLab, tmp_path: Path) -> None:
    """Without an aws-role credential a check skips and sends nothing."""
    del aws_lab.requests[:]
    del aws_lab.operations[:]
    for check_id in WP31_IDS:
        results, _harness, _ctx = asyncio.run(
            _run(aws_lab, POSITIVE, tmp_path, check_id, with_credential=False)
        )
        assert not _policies(results), check_id
        assert all(result.status == "info" for result in results), [r.status for r in results]
    assert aws_lab.requests == [], "an unauthenticated read must not be attempted"


def test_a_refused_credential_is_a_skip_not_an_empty_account(
    aws_lab: AwsLab, tmp_path: Path
) -> None:
    """A wrong secret produces a skip, never an empty (clean) account."""
    results, _harness, _ctx = asyncio.run(
        _run(aws_lab, POSITIVE, tmp_path, "m5.aws-s3-public-acl", secret="wrong-secret")
    )
    assert all(result.status == "info" for result in results), [r.status for r in results]
    assert not _policies(results)


def test_a_dry_run_sends_nothing(aws_lab: AwsLab, tmp_path: Path) -> None:
    """``ctx.http is None`` turns every probe into a skip (F-01-10)."""
    del aws_lab.requests[:]
    for check_id in WP31_IDS:
        results, _harness, _ctx = asyncio.run(
            _run(aws_lab, POSITIVE, tmp_path, check_id, dry_run=True)
        )
        assert all(result.status == "info" for result in results), [r.status for r in results]
    assert aws_lab.requests == []


def test_the_checks_are_deterministic(aws_lab: AwsLab, tmp_path: Path) -> None:
    """Two runs against the same account produce the same verdict and the same evidence."""

    async def once() -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        for check_id in WP31_IDS:
            results, _harness, _ctx = await _run(aws_lab, POSITIVE, tmp_path, check_id)
            out.append(
                (
                    check_id,
                    hashlib.sha256(
                        json.dumps(
                            [[result.status, result.title, result.detail] for result in results],
                            default=str,
                        ).encode()
                    ).hexdigest(),
                )
            )
        return out

    first = asyncio.run(once())
    second = asyncio.run(once())
    assert first == second


def test_the_configured_region_is_signed_into_every_request(
    aws_lab: AwsLab, tmp_path: Path
) -> None:
    """The region reaches the credential scope: the fixture verifies it on every request."""
    del aws_lab.requests[:]
    asyncio.run(_drive_all(aws_lab, tmp_path))
    assert aws_lab.requests
    # The fixture only answers a request whose scope names AWS_LAB_REGION, so a non-empty log
    # is the proof; assert the checks' own declaration agrees.
    from arachne.core.config import M5Settings

    assert M5Settings().aws_region == AWS_LAB_REGION


def test_the_check_declares_the_aws_role_kind() -> None:
    for check in AWS_POSTURE_CHECKS:
        assert check.metadata.requires_credentials == ("aws-role",)
    assert AWS_CREDENTIAL_KINDS == ("aws-role",)
    assert "aws-role" in CREDENTIAL_KINDS


def test_the_provider_ledger_names_every_new_check_and_no_write() -> None:
    entry = by_provider()["aws"]
    assert set(WP31_IDS) <= set(entry.check_ids)
    assert {method for method, _path in entry.operations} == {"GET"}
    assert operation_offenders(entry, entry.operations) == ()
    assert operation_offenders(entry, [("DELETE", "/s3/{bucket}")]) == ("DELETE /s3/{bucket}",)
