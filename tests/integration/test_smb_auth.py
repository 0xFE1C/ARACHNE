"""Acceptance: credentialed SMB verification against the protocol lab (S19, REQ-CREDS-004).

REQ-CREDS-004's accept criterion is "a protocol-lab test with valid and invalid credentials", so
this runs the real check over a real socket against ``tests/lab/arachne_lab.py``'s SMB service,
which verifies an NTLMv2 response the way a server does (recomputing the HMAC with the password
it holds). Three properties are asserted beyond "it works":

* a valid credential is reported as accepted, an invalid one as refused, and the finding names
  the peer's own NTSTATUS rather than a guess;
* the credential never appears in the result or its evidence — the broker supplies it for one
  exchange and the check receives a verdict (REQ-CREDS-002);
* a credential whose scope does not cover the target is refused before any byte is sent
  (REQ-CREDS-005).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.checks import asset_for, make_step_context, settings_for_checks
from tests.helpers.vault import LAB_PASSPHRASE, make_vault
from tests.lab.arachne_lab import (
    LAB_SMB_PASSWORD,
    LAB_SMB_USER,
    LabFixture,
    m2_lab,
)

from arachne.core.config import RateLimitSettings, SafetySettings
from arachne.core.net import ScopedNetClient
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.vault import CredentialScope
from arachne.creds.broker import CredentialBroker
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m2.credentialed import SmbAuth
from arachne.modules.m2.inventory import NetworkInventory

pytestmark = pytest.mark.integration

HOST = "127.0.0.1"


@pytest.fixture()
def lab() -> AsyncIterator[LabFixture]:
    with m2_lab(include_udp=False) as fixture:
        yield fixture


async def run_check(
    lab: LabFixture,
    tmp_path: Path,
    *,
    password: str = LAB_SMB_PASSWORD,
    scope_hosts: tuple[str, ...] = (HOST,),
) -> tuple[list[Any], Any, Any]:
    """Run ``m2.smb-auth`` over a real socket against the lab's SMB service."""
    settings = settings_for_checks(
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
    )
    port = lab.services["smb"].port
    client = ScopedNetClient(
        settings=settings,
        scope=Scope(allowed_hosts=(HOST,)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        auditor=None,
    )
    inventory = NetworkInventory(max_hosts=4, max_ports=32)
    record = inventory.host(HOST, declared=True)
    record.alive = True
    inventory.add_service(HOST, port, service="smb")

    vault = make_vault(
        tmp_path,
        entries={
            "hosts": {
                "kind": "smb",
                "username": LAB_SMB_USER,
                "secret": password,
                "scope": CredentialScope(hosts=scope_hosts),
                "extra": {"domain": "LAB"},
            }
        },
    )
    step, memory = make_step_context(seed=[("host", HOST)])
    step.net = client
    step.inventory = inventory
    step.step = ScanStep.DISCOVERY
    step.credentials = CredentialBroker(
        store=vault,
        labels=("hosts",),
        auditor=memory.auditor,
        scan_id=memory.scan_id,
        hosts=(HOST,),
    )
    check = SmbAuth()
    context = CheckContext(
        step=step,
        module=check,
        asset=asset_for("host", HOST),
        config=ModuleConfig(),
    )
    results = [result async for result in check.run(context)]
    try:
        return results, memory, check
    finally:
        await client.aclose()


def evidence_text(results: list[Any]) -> str:
    return " ".join(
        json.dumps(dict(item.payload), default=str)
        for result in results
        for item in result.evidence
    )


async def test_valid_credentials_are_accepted(lab: LabFixture, tmp_path: Path) -> None:
    results, memory, _check = await run_check(lab, tmp_path)
    assert len(results) == 1
    result = results[0]
    assert result.status == "info"
    assert "accepted" in result.title.lower()
    assert "STATUS_SUCCESS" in (result.detail or "")
    ledger = evidence_text(results)
    assert '"accepted": true' in ledger
    assert '"nt_status": "STATUS_SUCCESS"' in ledger
    # The credential itself is nowhere in the result.
    assert LAB_SMB_PASSWORD not in ledger
    assert LAB_SMB_USER not in ledger
    # The broker audited the release and the verdict.
    actions = [event.action.value for event in memory.sink.events]
    assert "credential.released" in actions


async def test_invalid_credentials_are_refused(lab: LabFixture, tmp_path: Path) -> None:
    results, _memory, _check = await run_check(lab, tmp_path, password="not-the-password")
    assert len(results) == 1
    result = results[0]
    assert result.status == "info"
    assert "refused" in result.title.lower()
    assert "STATUS_LOGON_FAILURE" in (result.detail or "")
    ledger = evidence_text(results)
    assert '"accepted": false' in ledger
    assert LAB_SMB_PASSWORD not in ledger


async def test_a_credential_outside_its_scope_sends_nothing(
    lab: LabFixture, tmp_path: Path
) -> None:
    port = lab.services["smb"].port
    results, memory, _check = await run_check(
        lab, tmp_path, scope_hosts=("other.example.com",)
    )
    assert len(results) == 1
    assert results[0].status == "info"  # a skipped result, with the reason in the note
    note = results[0].evidence[0].payload
    assert note["skipped"] is True and "no SMB credential" in note["reason"]
    actions = [event.action.value for event in memory.sink.events]
    assert "credential.released" not in actions
    assert "credential.scope_rejected" in actions
    del port


async def test_the_check_is_opt_in_and_declares_its_credential_kind() -> None:
    metadata = SmbAuth.metadata
    assert metadata.enabled_by_default is False
    assert metadata.requires_active_checks is True
    assert metadata.requires_credentials == ("smb",)
    assert metadata.type == "active"


async def test_the_vault_material_is_dropped_after_the_attempt(
    lab: LabFixture, tmp_path: Path
) -> None:
    """The broker hands the material to exactly one attempt and keeps no copy on the result."""
    results, memory, _check = await run_check(lab, tmp_path)
    released = [e for e in memory.sink.events if e.action.value == "credential.released"]
    assert released and released[0].meta["label"] == "hosts"
    assert LAB_SMB_PASSWORD not in json.dumps(released[0].to_dict(), default=str)
    assert LAB_SMB_PASSWORD not in evidence_text(results)


async def test_the_lab_secret_is_not_in_the_vault_file(tmp_path: Path) -> None:
    """Encrypted at rest, asserted on the bytes: the file is ciphertext, not a JSON blob."""
    make_vault(
        tmp_path,
        entries={
            "hosts": {
                "kind": "smb",
                "username": LAB_SMB_USER,
                "secret": LAB_SMB_PASSWORD,
                "scope": CredentialScope(hosts=(HOST,)),
            }
        },
    )
    raw = (tmp_path / "credentials.enc").read_bytes()
    assert LAB_SMB_PASSWORD.encode() not in raw
    assert LAB_SMB_USER.encode() not in raw
    assert LAB_PASSPHRASE.encode() not in raw
    # ...and it is still readable with the key, so the assertion above is about encryption.
    from arachne.core.vault import FileCredentialVault

    assert FileCredentialVault(
        tmp_path / "credentials.enc", passphrase=LAB_PASSPHRASE
    ).labels() == ("hosts",)
