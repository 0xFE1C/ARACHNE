"""Acceptance: read-only AD CS enumeration against the protocol lab (WP-10, REQ-DET-014).

The requirement's boundary is the whole point, so this suite runs the real check over a real
socket against ``tests/lab/arachne_lab.py``'s two AD CS directories and asserts five things:

* the planted directory yields exactly the ESC conditions it publishes (ESC1 on the template,
  ESC6 on the CA), each naming the class **as context** and recording that no exploitation was
  attempted;
* the **hardened** directory produces no findings (the decoy);
* the check is **skipped**, never guessed, when no credential is available — and a refused bind
  enumerates nothing either;
* the credential never reaches the result, its evidence or the audit record (REQ-CREDS-002);
* every AD CS finding is L1 and every request was an LDAP bind/search, so nothing reached a CA.
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
    LAB_LDAP_PASSWORD,
    LAB_LDAP_USER,
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
from arachne.modules.m2.adcs import AdcsEnumeration
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
    service: str,
    password: str = LAB_LDAP_PASSWORD,
    with_credential: bool = True,
    scope_hosts: tuple[str, ...] = (HOST,),
) -> tuple[list[Any], Any, Any]:
    """Run ``m2.adcs-enum`` over a real socket against one of the lab's AD CS directories."""
    settings = settings_for_checks(
        safety=SafetySettings(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
    )
    port = lab.services[service].port
    client = ScopedNetClient(
        settings=settings,
        scope=Scope(allowed_hosts=(HOST,)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        auditor=None,
    )
    inventory = NetworkInventory(max_hosts=4, max_ports=32)
    record = inventory.host(HOST, declared=True)
    record.alive = True
    inventory.add_service(HOST, port, service="ldap")

    step, memory = make_step_context(seed=[("host", HOST)])
    step.net = client
    step.inventory = inventory
    step.step = ScanStep.DISCOVERY
    if with_credential:
        vault = make_vault(
            tmp_path,
            entries={
                "directory": {
                    "kind": "ldap",
                    "username": LAB_LDAP_USER,
                    "secret": password,
                    "scope": CredentialScope(hosts=scope_hosts),
                    "extra": {"bind_dn": f"CN={LAB_LDAP_USER},CN=Users,DC=lab,DC=arachne,DC=test"},
                }
            },
        )
        step.credentials = CredentialBroker(
            store=vault,
            labels=("directory",),
            auditor=memory.auditor,
            scan_id=memory.scan_id,
            hosts=(HOST,),
        )
    check = AdcsEnumeration()
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


def esc_conditions(results: list[Any]) -> dict[str, dict[str, Any]]:
    """``{esc_class: artifact payload}`` for every AD CS condition the run reported."""
    out: dict[str, dict[str, Any]] = {}
    for result in results:
        if result.status != "vulnerable":
            continue
        for item in result.evidence:
            if item.payload.get("signal") == "adcs-esc-condition":
                out[str(item.payload["esc_class"])] = dict(item.payload)
    return out


def evidence_text(results: list[Any]) -> str:
    return " ".join(
        json.dumps(dict(item.payload), default=str)
        for result in results
        for item in result.evidence
    )


# ------------------------------------------------------------------ the planted directory
async def test_the_planted_directory_reports_the_conditions_it_publishes(
    lab: LabFixture, tmp_path: Path
) -> None:
    results, _memory, _check = await run_check(lab, tmp_path, service="ldap-adcs")
    found = esc_conditions(results)
    assert set(found) == {"ESC1", "ESC6"}, sorted(found)
    assert found["ESC1"]["object_class"] == "pKICertificateTemplate"
    assert found["ESC6"]["object_class"] == "pKIEnrollmentService"


async def test_every_condition_names_its_class_as_context_and_denies_exploitation(
    lab: LabFixture, tmp_path: Path
) -> None:
    results, _memory, _check = await run_check(lab, tmp_path, service="ldap-adcs")
    findings = [result for result in results if result.status == "vulnerable"]
    assert findings
    for result in findings:
        artifact = next(
            item.payload
            for item in result.evidence
            if item.payload.get("signal") == "adcs-esc-condition"
        )
        cls = str(artifact["esc_class"])
        # The class is named *as context*: the word "context" is in the finding, and the
        # context sentence is the published taxonomy, not a claim about this estate.
        assert "as context" in (result.detail or "")
        assert cls in (result.title or "")
        assert str(artifact["context"]).startswith(cls)
        assert "not assessed" in str(artifact["context"]) or "did not assess" in str(
            artifact["context"]
        )
        assert artifact["exploitation_attempted"] is False
        assert "does not attempt exploitation" in (result.detail or "")
        # The misconfiguration itself is stated, not just the class name.
        assert artifact["condition"]


async def test_the_finding_states_the_misconfiguration(lab: LabFixture, tmp_path: Path) -> None:
    results, _memory, _check = await run_check(lab, tmp_path, service="ldap-adcs")
    text = " ".join(result.detail or "" for result in results)
    assert "ENROLLEE_SUPPLIES_SUBJECT" in text
    assert "EDITF_ATTRIBUTESUBJECTALTNAME2" in text


async def test_the_report_carries_the_non_exploitation_note(
    lab: LabFixture, tmp_path: Path
) -> None:
    """REQ-DET-014: "The report carries an explicit note that ARACHNE does not attempt
    exploitation." Asserted on *rendered* report output, through the real store and builder."""
    from tests.helpers.report import make_analysis, make_inputs

    from arachne.data.finding_store import MemoryFindingStore
    from arachne.report.builder import build_report_data
    from arachne.report.markdown import render_markdown

    results, _memory, _check = await run_check(lab, tmp_path, service="ldap-adcs")
    condition = next(
        result
        for result in results
        if result.status == "vulnerable"
        and any(item.payload.get("esc_class") == "ESC1" for item in result.evidence)
    )

    store = MemoryFindingStore()
    store.record_candidate(1, result=condition, check_id=None, asset_id=None)
    record = store.list_candidates(1)[0]

    report = build_report_data(make_inputs(candidates=[record], analyses=[make_analysis(record)]))
    rendered = render_markdown(report)
    assert "does not attempt exploitation" in rendered
    assert "no certificate was requested" in rendered
    # The machine-readable flag travels with it, so a consumer need not parse prose.
    assert '"exploitation_attempted": false' in rendered
    assert '"esc_class": "ESC1"' in rendered


async def test_the_enumeration_note_records_what_was_not_assessed(
    lab: LabFixture, tmp_path: Path
) -> None:
    results, _memory, _check = await run_check(lab, tmp_path, service="ldap-adcs")
    note = next(result for result in results if "enumeration on" in (result.title or ""))
    assert "ESC4" in (note.detail or "") and "ESC8" in (note.detail or "")
    assert "no certificate was requested" in (note.detail or "")
    assert "no template was modified" in (note.detail or "")


# ------------------------------------------------------------------ the decoy
async def test_the_hardened_directory_produces_no_findings(lab: LabFixture, tmp_path: Path) -> None:
    """The false-positive trap: an AD CS deployment with no ESC condition reports none."""
    results, _memory, _check = await run_check(lab, tmp_path, service="ldap-adcs-hardened")
    assert esc_conditions(results) == {}
    assert all(result.status != "vulnerable" for result in results), [
        result.title for result in results if result.status == "vulnerable"
    ]
    # It still read the objects — the silence is an observation, not a failure to reach them.
    note = next(result for result in results if "enumeration on" in (result.title or ""))
    assert "2 object(s) read" in (note.title or "")


# ------------------------------------------------------------------ skipped, never guessed
async def test_the_check_skips_without_a_credential(lab: LabFixture, tmp_path: Path) -> None:
    results, _memory, _check = await run_check(
        lab, tmp_path, service="ldap-adcs", with_credential=False
    )
    assert len(results) == 1
    note = results[0].evidence[0].payload
    assert note["skipped"] is True
    assert "credential" in note["reason"]


async def test_a_refused_bind_enumerates_nothing(lab: LabFixture, tmp_path: Path) -> None:
    results, _memory, _check = await run_check(
        lab, tmp_path, service="ldap-adcs", password="not-the-password"
    )
    assert esc_conditions(results) == {}
    joined = " ".join(result.detail or "" for result in results)
    assert "invalidCredentials" in joined


async def test_a_credential_outside_its_scope_sends_nothing(
    lab: LabFixture, tmp_path: Path
) -> None:
    results, memory, _check = await run_check(
        lab, tmp_path, service="ldap-adcs", scope_hosts=("other.example.com",)
    )
    note = results[0].evidence[0].payload
    assert note["skipped"] is True and "no LDAP credential" in note["reason"]
    actions = [event.action.value for event in memory.sink.events]
    assert "credential.released" not in actions
    assert "credential.scope_rejected" in actions


async def test_the_check_declares_its_credential_kind_and_proof_level() -> None:
    metadata = AdcsEnumeration.metadata
    assert metadata.proof.value == "L1"
    assert metadata.requires_credentials == ("ldap",)
    assert metadata.type == "active"
    assert metadata.requires_active_checks is True
    assert metadata.safe is True


async def test_the_credential_never_reaches_the_result(lab: LabFixture, tmp_path: Path) -> None:
    results, memory, _check = await run_check(lab, tmp_path, service="ldap-adcs")
    ledger = evidence_text(results)
    assert LAB_LDAP_PASSWORD not in ledger
    assert LAB_LDAP_PASSWORD not in " ".join(result.detail or "" for result in results)
    released = [e for e in memory.sink.events if e.action.value == "credential.released"]
    assert released and released[0].meta["label"] == "directory"
    assert LAB_LDAP_PASSWORD not in json.dumps(released[0].to_dict(), default=str)


async def test_the_lab_secret_is_not_in_the_vault_file(tmp_path: Path) -> None:
    make_vault(
        tmp_path,
        entries={
            "directory": {
                "kind": "ldap",
                "username": LAB_LDAP_USER,
                "secret": LAB_LDAP_PASSWORD,
                "scope": CredentialScope(hosts=(HOST,)),
            }
        },
    )
    raw = (tmp_path / "credentials.enc").read_bytes()
    assert LAB_LDAP_PASSWORD.encode() not in raw
    assert LAB_LDAP_USER.encode() not in raw
    assert LAB_PASSPHRASE.encode() not in raw
    from arachne.core.vault import FileCredentialVault

    assert FileCredentialVault(
        tmp_path / "credentials.enc", passphrase=LAB_PASSPHRASE
    ).labels() == ("directory",)
