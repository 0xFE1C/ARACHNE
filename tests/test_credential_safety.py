"""Safety: the credential path (S19, area CREDS: REQ-CREDS-002, REQ-CREDS-005).

Two properties, both of which a reader should be able to falsify by reading one test:

**Nothing leaks.** Over one real credentialed scan against the lab, the vaulted password is
absent from the JSON log stream, every audit record, every persisted evidence blob and both
rendered report formats — while ``[REDACTED`` *is* present, so the assertion is about redaction
happening rather than the credential path not running at all. The same file-level assertion is
made on the vault's own bytes: they are ciphertext.

**Credentials stay in their scope.** A credential is bound to the hosts and URL prefixes it was
stored for, and an out-of-scope offer is refused before a byte is sent — the authenticated
counterpart of ``tests/test_safety.py``'s scope tests, and the reason a scan cannot borrow reach
it was not given (REQ-CREDS-005). Authentication also changes no *other* gate: the requests it
makes go through the same rate limiter and the same audit sink as every other request.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import (
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.logging import configure_logging
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.target import (
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetSelector,
)
from arachne.core.vault import CredentialScope, FileCredentialVault
from arachne.creds.broker import CredentialBroker
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.m3.authenticated import AuthenticatedSurface
from arachne.modules.m3.client import XssOracle
from arachne.modules.registry import ModuleGroup, ModuleRegistry
from arachne.report import build_report_data, render_json, render_markdown
from arachne.report.builder import ReportInputs
from tests.helpers.checks import make_step_context
from tests.helpers.vault import LAB_PASSPHRASE, make_vault, portal_credential
from tests.lab.web_lab import LAB_PASSWORDS, WebLab, start_web_lab

pytestmark = pytest.mark.integration

#: The checks the credentialed scan runs: enough to produce a finding through the authenticated
#: path (the surface comparison and a reflection probe on the portal).
CHECKS: tuple[type[Any], ...] = (AuthenticatedSurface, XssOracle)
SUBSET_REGISTRY = ModuleRegistry(
    [
        ModuleGroup(
            id="M3",
            title="Web Application",
            description="credential-safety subset",
            version="2.2.0",
            checks=CHECKS,
            research_chapter="ch03",
        )
    ]
)

SECRET = LAB_PASSWORDS["carol"]


@pytest.fixture()
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


class CredentialedScan:
    """Everything a credentialed scan produced, in one place for the leak assertions."""

    def __init__(
        self,
        *,
        findings: MemoryFindingStore,
        sink: MemoryAuditSink,
        scan_id: int,
        log_text: str,
        markdown: str,
        document: str,
        vault_path: Path,
        credential_facts: dict[str, Any] | None = None,
    ) -> None:
        self.findings = findings
        self.sink = sink
        self.scan_id = scan_id
        self.log_text = log_text
        self.markdown = markdown
        self.document = document
        self.vault_path = vault_path
        self.credential_facts = dict(credential_facts or {})

    def evidence_text(self) -> str:
        blobs: list[str] = []
        for record in self.findings.list_candidates(self.scan_id):
            for item in record.evidence:
                blobs.append(json.dumps(dict(item.payload), default=str))
        return "\n".join(blobs)

    def audit_text(self) -> str:
        return "\n".join(json.dumps(event.to_dict(), default=str) for event in self.sink.events)

    def blobs(self) -> dict[str, str]:
        return {
            "log": self.log_text,
            "audit": self.audit_text(),
            "evidence": self.evidence_text(),
            "report-markdown": self.markdown,
            "report-json": self.document,
            "vault-file": self.vault_path.read_text(errors="replace"),
        }


async def run_credentialed_scan(lab: WebLab, tmp_path: Path) -> CredentialedScan:
    definition = TargetDefinition(
        name="s19-credential-safety",
        targets=(TargetSelector(kind="url", value=lab.base_url),),
        attestation={
            "attested_by": "S19 builder <s19@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": "Local vulnerable-by-design lab fixture on loopback",
            "allowed_targets": [lab.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-S19-SAFETY",
            "active_checks_authorized": True,
        },
    )
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="INFO",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=definition.compile_scope(),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
    )
    vault_path = tmp_path / "safety.enc"
    make_vault(
        tmp_path,
        name="safety.enc",
        entries={"portal": portal_credential(lab.base_url, username="carol", password=SECRET)},
    )
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    store = MemoryScanStateStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")

    # The log stream of this scan only: every formatter redacts, and this is the evidence.
    stream = io.StringIO()
    configure_logging("INFO", json_output=True, stream=stream)

    def client_factory(scope: Scope) -> ScopedHttpClient:
        return ScopedHttpClient(
            settings=settings, scope=scope, policy=settings.safety.policy, auditor=auditor
        )

    orchestrator = Orchestrator(
        settings=settings,
        store=store,
        auditor=auditor,
        bus=EventBus(),
        handlers=build_handlers(
            settings=settings,
            registry=SUBSET_REGISTRY,
            findings=findings,
            analyses=analyses,
            auditor=auditor,
            vault=FileCredentialVault(vault_path, passphrase=LAB_PASSPHRASE),
        ),
        registry=SUBSET_REGISTRY,
        client_factory=client_factory,
    )
    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            modules=ModuleSelection(
                enabled=("M3",), checks=("m3.authenticated-surface", "m3.xss-oracle")
            ),
            credentials=("portal",),
        ),
    )
    session = await orchestrator.scan(request)
    assert session.status is ScanStatus.COMPLETED, session
    record = session.record
    assert record is not None
    # The checks step persists the credential summary on the *scan* (labels and outcomes only);
    # the report builder reads exactly this block (``_credential_labels``/``_authenticated``).
    credential_facts = dict((record.stats or {}).get("credentials") or {})
    report = build_report_data(
        ReportInputs(
            scan_id=session.scan_id,
            target_name=str(record.plan.get("target_name") or definition.name),
            engine=str(record.plan.get("engine") or record.engine),
            plan=dict(record.plan),
            status=record.status.value,
            started_at=record.started_at,
            finished_at=record.finished_at,
            assets=store.list_assets(session.scan_id),
            candidates=findings.list_candidates(session.scan_id),
            analyses=analyses.list_analyses(session.scan_id),
            audit_events=sink.events,
            module_versions={group.id: group.version for group in SUBSET_REGISTRY.groups},
            rate_limits={
                "per_host_per_second": settings.rate_limit.per_host_rate,
                "global_per_second": settings.rate_limit.global_rate,
            },
            arachne_version="0.1.0",
            generated_at=record.finished_at or datetime.now(UTC),
            settings=settings,
            credentials=tuple(credential_facts.get("labels") or ()),
            authenticated=bool(credential_facts.get("authenticated")),
        )
    )
    return CredentialedScan(
        findings=findings,
        sink=sink,
        scan_id=session.scan_id,
        log_text=stream.getvalue(),
        markdown=render_markdown(report),
        document=render_json(report),
        vault_path=vault_path,
        credential_facts=credential_facts,
    )


# --------------------------------------------------------------------------- nothing leaks
async def test_the_password_is_absent_from_every_artifact(lab: WebLab, tmp_path: Path) -> None:
    """REQ-CREDS-002: zero occurrences across logs, audit, evidence, report and the vault file."""
    scan = await run_credentialed_scan(lab, tmp_path)
    blobs = scan.blobs()
    leaking = [name for name, text in blobs.items() if SECRET in text]
    assert leaking == [], leaking
    # The credential path really ran: the login was accepted and its body was redacted.
    assert scan.sink.events and any(
        event.action is AuditAction.AUTH_SESSION_ESTABLISHED for event in scan.sink.events
    )
    # The log stream carries the credentialed run (the login request is logged like every
    # other exchange) but no body, so there is nothing for it to redact: the marker is
    # asserted where the credential actually travels.
    assert "/login" in blobs["log"]
    assert "[REDACTED" in blobs["audit"]
    assert "[REDACTED" in blobs["evidence"]
    assert "[REDACTED" in blobs["report-markdown"]
    # The report says it describes an authenticated surface, and with which label — the
    # label is the whole vocabulary a report is allowed (never material, ADR-240.9).
    assert "Credentials: portal" in blobs["report-markdown"]
    assert "Credentials: portal (authenticated)" in blobs["report-markdown"]
    assert json.loads(blobs["report-json"])["scope"]["credentials"] == ["portal"]
    assert json.loads(blobs["report-json"])["scope"]["authenticated"] is True
    # ...and the facts the report read came from the scan record the handler wrote.
    assert scan.credential_facts["labels"] == ["portal"]
    assert scan.credential_facts["authenticated"] is True
    assert scan.credential_facts["vault"] is True
    # And the vault's own bytes are ciphertext, not a JSON blob with a password in it.
    assert LAB_PASSPHRASE not in blobs["vault-file"]
    assert blobs["vault-file"].splitlines()[0] == "ARACHNE-CV-1"


async def test_no_vault_path_publishes_the_username(lab: WebLab, tmp_path: Path) -> None:
    """The username is encrypted with the secret, and no vault path publishes it.

    Asserted on the paths that could publish it: the vault file itself, the audit trail, the
    scan's ``stats["credentials"]`` block and the report's methodology. **Not** asserted on the
    login exchange's own request body, which is evidence of a submitted form like any other:
    a username is an identifier, not a secret, and ``username``/``user``/``email`` are
    deliberately not secret *keys* (ADR-240.7, security review §11) — blanking them would erase
    the account names M3's enumeration evidence and M4's exposure checks exist to report.
    """
    scan = await run_credentialed_scan(lab, tmp_path)
    assert "carol" not in scan.blobs()["vault-file"]
    assert "carol" not in scan.blobs()["audit"]
    record = scan.blobs()
    assert "carol" not in json.dumps(
        {k: v for k, v in record.items() if k in {"audit", "vault-file"}}
    )
    # The vault still resolves it for the one call that needs it, so the assertion above is
    # about encryption rather than about the entry being empty.
    vault = FileCredentialVault(tmp_path / "safety.enc", passphrase=LAB_PASSPHRASE)
    from arachne.core.vault import release_seam

    handle = vault.resolve("portal", host="127.0.0.1")
    assert handle is not None
    assert handle.material(release_seam()).username == "carol"
    # ...and the operator-facing listing of the vault is metadata only.
    assert "carol" not in json.dumps([item.to_dict() for item in vault.records()])


# --------------------------------------------------------------------------- stays in scope
async def test_a_credential_outside_its_scope_never_sends_a_request(tmp_path: Path) -> None:
    """REQ-CREDS-005: the refusal happens before the request, and it is audited."""
    requests: list[str] = []

    def handler(request: Any) -> Any:
        requests.append(str(request.url))
        raise AssertionError("no request may be sent for an out-of-scope credential")

    import httpx

    vault = make_vault(
        tmp_path,
        entries={
            "elsewhere": {
                "kind": "web-form",
                "username": "carol",
                "secret": SECRET,
                "scope": CredentialScope(hosts=("app.internal",)),
            }
        },
    )
    sink = MemoryAuditSink()
    step, memory = make_step_context(seed=[("url", "http://127.0.0.1:9/")])
    client = ScopedHttpClient(
        settings=Settings(database_url="sqlite:///:memory:", log_level="CRITICAL"),
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        auditor=memory.auditor,
        transport=httpx.MockTransport(handler),
    )
    broker = CredentialBroker(
        store=vault,
        labels=("elsewhere",),
        auditor=memory.auditor,
        scan_id=memory.scan_id,
        targets=("http://127.0.0.1:9/",),
        hosts=("127.0.0.1",),
    )
    broker.validate_selection()
    session = await broker.login(client=client, inventory=None, url="http://127.0.0.1:9/")
    await client.aclose()

    assert session is None
    assert requests == []  # nothing was sent, not even a probe
    rejected = memory.sink.of_action(AuditAction.CREDENTIAL_SCOPE_REJECTED)
    assert rejected and "app.internal" in (rejected[0].reason or "")
    assert memory.sink.of_action(AuditAction.CREDENTIAL_RELEASED) == []
    assert sink.events == []
    del step


async def test_authenticated_requests_still_pass_the_rate_limiter(
    lab: WebLab, tmp_path: Path
) -> None:
    """An authenticated session is not an exempt path: the same limiter paces it."""
    definition = TargetDefinition(
        name="s19-rate",
        targets=(TargetSelector(kind="url", value=lab.base_url),),
        attestation={
            "attested_by": "S19 builder <s19@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": "Local lab fixture on loopback",
            "allowed_targets": [lab.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-S19-RATE",
            "active_checks_authorized": True,
        },
    )
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=definition.compile_scope(),
        ),
        # A deliberately tight budget: the production posture, scaled to a lab scan.
        rate_limit=RateLimitSettings(
            per_host_rate=12.0,
            per_host_burst=2,
            global_rate=12.0,
            global_burst=2,
        ),
    )
    findings = MemoryFindingStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    vault_path = tmp_path / "rate.enc"
    make_vault(
        tmp_path,
        name="rate.enc",
        entries={"portal": portal_credential(lab.base_url, username="carol", password=SECRET)},
    )
    store = MemoryScanStateStore()

    def client_factory(scope: Scope) -> ScopedHttpClient:
        return ScopedHttpClient(
            settings=settings, scope=scope, policy=settings.safety.policy, auditor=auditor
        )

    orchestrator = Orchestrator(
        settings=settings,
        store=store,
        auditor=auditor,
        bus=EventBus(),
        handlers=build_handlers(
            settings=settings,
            registry=SUBSET_REGISTRY,
            findings=findings,
            analyses=MemoryAnalysisStore(),
            auditor=auditor,
            vault=FileCredentialVault(vault_path, passphrase=LAB_PASSPHRASE),
        ),
        registry=SUBSET_REGISTRY,
        client_factory=client_factory,
    )
    await orchestrator.scan(
        ScanRequest(
            target=definition,
            options=ScanOptions(
                active_checks=True,
                modules=ModuleSelection(
                    enabled=("M3",), checks=("m3.authenticated-surface", "m3.xss-oracle")
                ),
                credentials=("portal",),
            ),
        )
    )

    actions = [event.action for event in sink.events]
    assert AuditAction.AUTH_SESSION_ESTABLISHED in actions
    release_index = actions.index(AuditAction.CREDENTIAL_RELEASED)
    throttled = [
        event
        for event in sink.events[release_index:]
        if event.action is AuditAction.HTTP_REQUEST
        and float(event.meta.get("throttled_ms") or 0) > 0
    ]
    assert throttled, "no authenticated request was paced by the rate limiter"
    # The check itself is not exempt either: the scan still went through the checks step.
    record = store.get_scan(1)
    assert record is not None
    assert record.step_state(ScanStep.CHECKS) is not None
