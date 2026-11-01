"""Acceptance: internal agent mode — credentialed scanning from inside the target network.

REQ-CREDS-003 asks for an S16 agent that can be deployed **inside** the target network, pulling
jobs and pushing findings through the same gates. The properties that make that safe are what
this module verifies, on a real queue and a real agent loop:

* the node authenticates with **its own** vault — a credential label travels in the scan
  request, the material never leaves the node, and a label this node does not hold is refused
  and audited rather than fetched from a central store (``credential.unresolved``);
* every gate is still evaluated **on the executing node**: the deployment scope, the
  authorization attestation and the proof gate are the same code path as an external agent's
  (REQ-SCALE-008 + REQ-CREDS-005);
* the mode is on the audit trail (``agent.mode``) with the vault's location, so "was this scan
  run from inside the network?" is answerable afterwards;
* the control plane sees labels only — the scan request document carries ``credentials:
  ["portal"]`` and no material.

The scans here run over a *subset* handler set (one credentialed check) so the test measures the
agent path rather than the M3 suite; the authenticated-visit behaviour has its own acceptance
test in ``test_credentials.py``.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from tests.helpers.distributed import DistributedStack, build_stack, distributed_settings
from tests.helpers.vault import LAB_PASSPHRASE, make_vault, portal_credential
from tests.lab.web_lab import LAB_PASSWORDS, WebLab, start_web_lab

from arachne.agent.control import DirectControlPlane
from arachne.agent.runner import AgentLoop, build_executor
from arachne.agent.service import AgentService
from arachne.core.audit import AuditAction
from arachne.core.config import (
    RateLimitSettings,
    SafetySettings,
    Settings,
    UrlSafetyPolicy,
    VaultSettings,
)
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope
from arachne.core.target import ScanRequest, TargetDefinition
from arachne.data.services import build_orchestrator
from arachne.modules.handlers import build_handlers
from arachne.modules.m3.authenticated import AuthenticatedSurface
from arachne.modules.registry import ModuleGroup, ModuleRegistry

pytestmark = pytest.mark.integration

#: The one check these scans run: the credentialed surface comparison, which *skips* without a
#: session — so "a session was established on this node" is observable from the step's stats.
CHECKS: tuple[Any, ...] = (AuthenticatedSurface,)

#: The checks the subset registry holds, by the ids ``ModuleSelection`` names.
SUBSET_REGISTRY = ModuleRegistry(
    [
        ModuleGroup(
            id="M3",
            title="Web Application",
            description="internal-agent-mode subset",
            version="2.2.0",
            checks=CHECKS,
            research_chapter="ch03",
        )
    ]
)


@pytest.fixture()
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def make_settings(
    db_path: Path, *, vault_path: Path | None = None, scope: Scope | None = None
) -> Settings:
    """Distributed settings for one agent node, with an optional node-local vault."""
    base = distributed_settings(db_path, mode="internal")
    return dataclasses.replace(
        base,
        actor="internal-agent-test",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=scope or Scope(),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
        vault=(
            VaultSettings(path=str(vault_path), key=SecretStr(LAB_PASSPHRASE))
            if vault_path is not None
            else VaultSettings()
        ),
    )


def node_handlers(stack: DistributedStack) -> dict[ScanStep, Any]:
    """The handler set this node runs: the real checks step over one credentialed check."""
    return build_handlers(
        settings=stack.settings,
        registry=SUBSET_REGISTRY,
        findings=stack.services.findings,
        auditor=stack.services.auditor,
        vault=stack.services.credentials,
    )


def scan_request(lab: WebLab, *, labels: tuple[str, ...] = ("portal",)) -> ScanRequest:
    definition = TargetDefinition(
        name="internal-lab",
        targets=({"kind": "url", "value": lab.base_url},),  # type: ignore[arg-type]
        attestation={
            "attested_by": "S19 builder <s19@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": "Internal lab fixture on loopback",
            "allowed_targets": [lab.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-S19-INTERNAL",
            "active_checks_authorized": True,
        },
    )
    return ScanRequest.model_validate(
        {
            "target": definition.model_dump(mode="json"),
            "options": {
                "active_checks": True,
                "modules": {"enabled": ["M3"], "checks": ["m3.authenticated-surface"]},
                "credentials": list(labels),
            },
        }
    )


async def run_agent(stack: DistributedStack, *, name: str = "internal-1") -> None:
    """Lease and execute everything queued, as an internal-mode agent would."""
    control = DirectControlPlane(
        AgentService(stack.services, settings=stack.settings), principal="test"
    )
    loop = AgentLoop(
        control,
        name=name,
        executor=build_executor(
            stack.services,
            name=name,
            handlers=node_handlers(stack),
            pipeline=(ScanStep.RECON, ScanStep.DISCOVERY, ScanStep.CHECKS),
            mode="internal",
        ),
        poll_interval_s=0.01,
        heartbeat_interval_s=0.05,
    )
    await loop.run_until_drained(max_scans=5)


async def admit(stack: DistributedStack, request: ScanRequest) -> int:
    """Admit centrally and enqueue, as the producer (API/scheduler) does."""
    orchestrator = build_orchestrator(stack.services)
    session = await orchestrator.launch(request, requested_by="test")
    assert stack.services.queue is not None
    stack.services.queue.enqueue(session.scan_id, requested_by="test")
    return session.scan_id


async def test_an_internal_agent_authenticates_with_its_own_vault(
    lab: WebLab, tmp_path: Path
) -> None:
    """The label travels; the material stays. The node resolves it after leasing."""
    vault = make_vault(
        tmp_path,
        entries={
            "portal": portal_credential(
                lab.base_url, username="carol", password=LAB_PASSWORDS["carol"]
            )
        },
    )
    del vault  # the node reads the file on its own; this handle is not what the agent uses
    settings = make_settings(tmp_path / "internal.db", vault_path=tmp_path / "credentials.enc")
    stack = build_stack(tmp_path / "internal.db", settings=settings)
    try:
        assert stack.services.credentials is not None
        assert stack.services.credentials.labels() == ("portal",)
        scan_id = await admit(stack, scan_request(lab))

        await run_agent(stack)

        modes = stack.events_of(AuditAction.AGENT_MODE)
        assert modes and modes[0].meta["mode"] == "internal"
        assert modes[0].meta["vault"] == "local"
        established = stack.events_of(AuditAction.AUTH_SESSION_ESTABLISHED)
        assert established, stack.actions()
        assert established[0].meta["label"] == "portal"
        record = stack.services.store.get_scan(scan_id)
        assert record is not None
        checks_state = record.step_state(ScanStep.CHECKS)
        assert checks_state is not None
        session_state = (checks_state.stats or {}).get("credentials", {}).get("session")
        assert session_state is not None and session_state["authenticated"] is True
    finally:
        stack.close()


async def test_a_label_the_node_does_not_hold_is_refused_not_borrowed(
    lab: WebLab, tmp_path: Path
) -> None:
    """No vault on the node: the scan runs unauthenticated and the refusal is on the trail."""
    stack = build_stack(tmp_path / "novault.db", settings=make_settings(tmp_path / "novault.db"))
    try:
        assert stack.services.credentials is None
        scan_id = await admit(stack, scan_request(lab))

        await run_agent(stack)

        unresolved = stack.events_of(AuditAction.CREDENTIAL_UNRESOLVED)
        assert unresolved, stack.actions()
        assert "vault" in (unresolved[0].reason or "")
        assert stack.events_of(AuditAction.AUTH_SESSION_ESTABLISHED) == []
        record = stack.services.store.get_scan(scan_id)
        assert record is not None and record.status.value == "completed"
    finally:
        stack.close()


async def test_the_control_plane_carries_labels_and_never_material(
    lab: WebLab, tmp_path: Path
) -> None:
    """The scan document — what the queue and an HTTP control plane carry — holds a label only."""
    stack = build_stack(tmp_path / "labels.db", settings=make_settings(tmp_path / "labels.db"))
    try:
        scan_id = await admit(stack, scan_request(lab))
        record = stack.services.store.get_scan(scan_id)
        assert record is not None and record.request_json is not None
        document = record.request_json
        assert document["options"]["credentials"] == ["portal"]
        serialized = json.dumps(document)
        assert LAB_PASSWORDS["carol"] not in serialized
        assert "carol" not in serialized
        # The queue row carries the scan id and the requester, never a credential.
        assert stack.services.queue is not None
        entry = stack.services.queue.entry_for(scan_id)
        assert entry is not None and entry.requested_by == "test"
    finally:
        stack.close()


async def test_an_internal_agent_still_refuses_a_scan_outside_its_scope(
    lab: WebLab, tmp_path: Path
) -> None:
    """The mode relaxes nothing: a target outside the node's allowlist is refused on the node."""
    db_path = tmp_path / "scope.db"
    producer = build_stack(db_path, settings=make_settings(db_path))
    try:
        scan_id = await admit(producer, scan_request(lab))
    finally:
        producer.close()

    # A second node with its own, narrower deployment allowlist: the gate must be re-evaluated
    # there (REQ-SCALE-008), and internal mode must not soften it.
    node = build_stack(
        db_path,
        settings=make_settings(db_path, scope=Scope(allowed_hosts=("other.example.com",))),
    )
    try:
        await run_agent(node)
        rejected = node.events_of(AuditAction.SCOPE_REJECTED)
        assert rejected, node.actions()
        record = node.services.store.get_scan(scan_id)
        assert record is not None and record.status.value == "failed"
    finally:
        node.close()


def test_internal_mode_is_a_declared_configuration() -> None:
    from arachne.core.config import DistributedSettings
    from arachne.core.errors import ConfigurationError

    assert DistributedSettings(mode="internal").internal is True
    assert DistributedSettings().internal is False
    with pytest.raises(ConfigurationError, match="external"):
        DistributedSettings(mode="inside")
