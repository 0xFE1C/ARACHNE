"""Acceptance: credentialed web scanning reaches what an anonymous scan cannot (S19).

REQ-CREDS-001's accept criterion is a comparison, so these tests run **two live scans against
the same lab**: one anonymous, one with a credential from the vault. The lab's authenticated
area (``/portal``, ``/portal/admin``, ``/portal/api/notes``) redirects anonymous clients to
``/login``, so the anonymous scan sees a 302 where the credentialed scan sees content.

What is asserted, in the order the requirement states it:

* the credentialed scan's findings are a strict superset of the anonymous scan's, and the extra
  ones come from the authenticated area (``m3.authenticated-surface`` naming ``/portal/admin``,
  the logout finding on ``/logout-soft``);
* the session survives being expired mid-scan, because the scanner re-authenticates instead of
  silently degrading to an anonymous scan (session keep-alive);
* a credential whose scope does not cover the target is refused — audited, never sent — and the
  scan proceeds anonymously rather than borrowing reach it was not given.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.vault import LAB_PASSPHRASE, make_vault, portal_credential
from tests.lab.web_lab import LAB_PASSWORDS, WebLab, start_web_lab

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings, WebSettings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.target import (
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetSelector,
)
from arachne.core.vault import FileCredentialVault
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.m3.authenticated import AuthenticatedSurface, SessionLogout
from arachne.modules.m3.client import XssOracle
from arachne.modules.m3.exposure import SecurityHeaders
from arachne.modules.m3.identity import AuthSessionAudit
from arachne.modules.registry import ModuleGroup, ModuleRegistry

pytestmark = pytest.mark.integration

#: The checks these tests select: the two credentialed checks plus the three that show the
#: authenticated surface changing what an existing check can reach. A *subset registry* is used
#: rather than the shipped one because ``ModuleSelection.checks`` is an opt-in list, not an
#: allowlist (F-02-09) — naming the opt-in checks there still runs every default M3 check, and
#: the full M3 measurement belongs to ``test_m3_scan.py``. Each test scans twice.
CHECKS: tuple[type[Any], ...] = (
    SecurityHeaders,
    XssOracle,
    AuthSessionAudit,
    AuthenticatedSurface,
    SessionLogout,
)

#: Markers that prove a finding came from the authenticated area.
PORTAL_MARKERS: tuple[str, ...] = (
    "/portal/admin",
    "/portal/api/notes",
    "/logout-soft",
    "portal-notes",
    "user-directory-export",
)


@dataclass
class ScanResult:
    findings: MemoryFindingStore
    analyses: MemoryAnalysisStore
    sink: MemoryAuditSink
    scan_id: int
    stats: dict[str, Any]

    def candidate_blobs(self) -> list[str]:
        blobs: list[str] = []
        for record in self.findings.list_candidates(self.scan_id):
            blobs.append(
                " ".join(
                    f"{key}={value}"
                    for item in record.evidence
                    for key, value in item.payload.items()
                )
            )
        return blobs

    def candidate_checks(self) -> set[str]:
        return {
            (record.check_key or "").split("/")[-1].split("@")[0]
            for record in self.findings.list_candidates(self.scan_id)
        }

    def portal_candidates(self) -> list[str]:
        return [blob for blob in self.candidate_blobs() if any(m in blob for m in PORTAL_MARKERS)]

    def finding_keys(self) -> set[tuple[str, str]]:
        """The lab's planted ``(check, marker)`` pairs this scan actually found.

        Compared instead of raw evidence text because two runs of one check legitimately cite
        different exchanges (timings, the login page's post-authentication response); the
        finding is the pair, and that is what "a superset of findings" means.
        """
        from tests.lab.web_lab import GROUND_TRUTH

        found: set[tuple[str, str]] = set()
        for record in self.findings.list_candidates(self.scan_id):
            name = (record.check_key or "").split("/")[-1].split("@")[0]
            check = f"{record.module.lower()}.{name}"
            blob = " ".join(
                f"{key}={value}" for item in record.evidence for key, value in item.payload.items()
            )
            for planted_check, marker in GROUND_TRUTH:
                if planted_check == check and marker in blob:
                    found.add((planted_check, marker))
        return found

    def actions(self) -> list[str]:
        return [event.action.value for event in self.sink.events]

    def of_action(self, action: AuditAction) -> list[Any]:
        return [event for event in self.sink.events if event.action is action]


@pytest.fixture()
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def build_definition(lab: WebLab) -> TargetDefinition:
    return TargetDefinition(
        name="s19-web-lab",
        targets=(TargetSelector(kind="url", value=lab.base_url),),
        attestation={
            "attested_by": "S19 builder <s19@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": "Local vulnerable-by-design lab fixture on loopback",
            "allowed_targets": [lab.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-S19",
            "active_checks_authorized": True,
            "state_changes_authorized": False,
        },
    )


def build_settings(definition: TargetDefinition) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
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
        # The lab serves ~25 pages and the authenticated area is linked late from the index:
        # the shipped cap (20 pages) would stop both crawls before reaching it, which would
        # make the comparison measure the cap rather than the session.
        web=WebSettings(max_pages=60),
    )


async def run_scan(
    lab: WebLab,
    *,
    vault: FileCredentialVault | None = None,
    credentials: tuple[str, ...] = (),
    checks: tuple[str, ...] = (
        "m3.authenticated-surface",
        "m3.session-logout",
    ),
) -> ScanResult:
    definition = build_definition(lab)
    settings = build_settings(definition)
    registry = ModuleRegistry(
        [
            ModuleGroup(
                id="M3",
                title="Web Application",
                description="S19 credentialed-scanning acceptance subset",
                version="2.2.0",
                checks=CHECKS,
                research_chapter="ch03",
            )
        ]
    )
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")

    def client_factory(scope: Scope) -> ScopedHttpClient:
        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=settings.safety.policy,
            auditor=auditor,
        )

    store = MemoryScanStateStore()
    from arachne.core.orchestrator import Orchestrator

    orchestrator = Orchestrator(
        settings=settings,
        store=store,
        auditor=auditor,
        bus=EventBus(),
        handlers=build_handlers(
            settings=settings,
            registry=registry,
            findings=findings,
            analyses=analyses,
            auditor=auditor,
            vault=vault,
        ),
        registry=registry,
        client_factory=client_factory,
    )
    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            modules=ModuleSelection(enabled=("M3",), checks=tuple(checks)),
            credentials=credentials,
        ),
    )
    session = await orchestrator.scan(request)
    record = store.get_scan(session.scan_id)
    stats = dict(record.stats) if record is not None else {}
    # The checks step's own stats carry the credential state (session, refusals).
    checks_state = record.step_state(ScanStep.CHECKS) if record is not None else None
    if checks_state is not None:
        stats.update(checks_state.stats or {})
    return ScanResult(
        findings=findings,
        analyses=analyses,
        sink=sink,
        scan_id=session.scan_id,
        stats=stats,
    )


# --------------------------------------------------------------------------- acceptance
async def test_a_credentialed_scan_is_a_strict_superset(lab: WebLab, tmp_path: Path) -> None:
    """The comparison the requirement asks for, with the same lab and the same checks."""
    anonymous = await run_scan(lab)

    vault = make_vault(
        tmp_path,
        entries={
            "portal": portal_credential(
                lab.base_url,
                username="carol",
                password=LAB_PASSWORDS["carol"],
            )
        },
    )
    credentialed = await run_scan(lab, vault=vault, credentials=("portal",))

    anonymous_keys = anonymous.finding_keys()
    credentialed_keys = credentialed.finding_keys()

    # The authenticated area is only reachable with the session.
    assert anonymous.portal_candidates() == []
    assert credentialed.portal_candidates(), credentialed.candidate_blobs()
    # The credentialed scan's findings are a strict superset: every anonymous finding is
    # still found, plus the ones only a session reaches.
    assert anonymous_keys <= credentialed_keys, (
        credentialed_keys,
        anonymous_keys - credentialed_keys,
    )
    added = credentialed_keys - anonymous_keys
    assert added, "the credentialed scan found nothing the anonymous scan could not"
    assert {check for check, _marker in added} >= {
        "m3.authenticated-surface",
        "m3.session-logout",
    }

    checks = credentialed.candidate_checks()
    assert "authenticated-surface" in checks
    assert "session-logout" in checks

    session_state = credentialed.stats.get("credentials", {}).get("session")
    assert session_state is not None and session_state["authenticated"] is True
    assert str(lab.base_url.rstrip("/")) in session_state["origin"]
    # The login was real: the audit trail says a session was established for this label.
    established = credentialed.of_action(AuditAction.AUTH_SESSION_ESTABLISHED)
    assert established and established[0].meta["label"] == "portal"


async def test_the_login_is_detected_from_the_crawl_when_none_is_declared(
    lab: WebLab, tmp_path: Path
) -> None:
    """A credential with no declared flow authenticates against the crawled login form."""
    vault = make_vault(
        tmp_path,
        entries={
            "detected": portal_credential(
                lab.base_url,
                username="alice",
                password=LAB_PASSWORDS["alice"],
                login={},  # no declaration: detection is the path under test
            )
        },
    )
    result = await run_scan(
        lab,
        vault=vault,
        credentials=("detected",),
        checks=("m3.authenticated-surface",),
    )
    session_state = result.stats.get("credentials", {}).get("session")
    assert session_state is not None and session_state["authenticated"] is True
    assert session_state["login"]["detected"] is True
    # alice is not an admin, so /portal/admin is forbidden — the portal itself is still extra.
    assert any("/portal" in blob for blob in result.portal_candidates())


async def test_a_json_login_flow_is_supported(lab: WebLab, tmp_path: Path) -> None:
    """REQ-CREDS-001 names form **and** JSON logins: the lab serves both, and both work."""
    vault = make_vault(
        tmp_path,
        entries={
            "portal-json": portal_credential(
                lab.base_url,
                username="carol",
                password=LAB_PASSWORDS["carol"],
                kind="web-json",
                login={
                    "url": f"{lab.base_url.rstrip('/')}/api/login",
                    "format": "json",
                    "username_field": "username",
                    "password_field": "password",
                    "protected_url": f"{lab.base_url.rstrip('/')}/portal/keep-alive",
                    "success_statuses": [200],
                },
            )
        },
    )
    result = await run_scan(lab, vault=vault, credentials=("portal-json",))
    session_state = result.stats["credentials"]["session"]
    assert session_state["authenticated"] is True
    assert session_state["login"]["format"] == "json"
    assert any("/portal" in blob for blob in result.portal_candidates())
    # The JSON body carried the secret and was redacted under its key.
    assert LAB_PASSWORDS["carol"] not in " ".join(result.candidate_blobs())


async def test_the_session_is_re_established_when_it_expires_mid_scan(
    lab: WebLab, tmp_path: Path
) -> None:
    """Session keep-alive: an expiry mid-scan re-authenticates instead of going anonymous."""
    lab.expire_after = 2
    vault = make_vault(
        tmp_path,
        entries={
            "portal": portal_credential(
                lab.base_url,
                username="carol",
                password=LAB_PASSWORDS["carol"],
            )
        },
    )
    result = await run_scan(lab, vault=vault, credentials=("portal",))
    session_state = result.stats["credentials"]["session"]
    assert session_state["expired_once"] is True
    assert session_state["reauths"] >= 1
    assert session_state["authenticated"] is True
    assert result.of_action(AuditAction.AUTH_SESSION_EXPIRED)


async def test_a_credential_outside_the_target_scope_is_refused_and_nothing_is_sent(
    lab: WebLab, tmp_path: Path
) -> None:
    """REQ-CREDS-005: the credential is scoped to another host, so it is never spent here."""
    vault = make_vault(
        tmp_path,
        entries={
            "elsewhere": portal_credential(
                lab.base_url,
                username="carol",
                password=LAB_PASSWORDS["carol"],
                scope_hosts=("other.example.com",),
            )
        },
    )
    before = len(lab.requests)
    result = await run_scan(lab, vault=vault, credentials=("elsewhere",))

    refusals = result.of_action(AuditAction.CREDENTIAL_SCOPE_REJECTED)
    assert refusals, result.actions()
    assert "other.example.com" in (refusals[0].reason or "")
    # No credential was released and no session was ever created on the target. (The lab does
    # see POSTs to /login: m3.auth-session-audit posts one dummy password per name for its
    # enumeration differential — that is not this credential.)
    assert result.of_action(AuditAction.CREDENTIAL_RELEASED) == []
    assert result.of_action(AuditAction.AUTH_SESSION_ESTABLISHED) == []
    assert lab.sessions == {}
    assert result.portal_candidates() == []
    assert before <= len(lab.requests)


async def test_a_label_this_node_does_not_hold_runs_the_scan_unauthenticated(
    lab: WebLab, tmp_path: Path
) -> None:
    """The internal-agent contract: an unheld label is refused, never borrowed (REQ-CREDS-003)."""
    vault = make_vault(tmp_path)  # an empty vault
    result = await run_scan(lab, vault=vault, credentials=("portal",))
    unresolved = result.of_action(AuditAction.CREDENTIAL_UNRESOLVED)
    assert unresolved and "does not hold" in (unresolved[0].reason or "")
    assert result.portal_candidates() == []
    assert result.candidate_blobs()  # the scan still ran, anonymously


async def test_the_vault_passphrase_is_needed_to_use_a_stored_credential(
    lab: WebLab, tmp_path: Path
) -> None:
    """A vault read with the wrong key refuses rather than leaking or ignoring the entry."""
    make_vault(
        tmp_path,
        entries={
            "portal": portal_credential(
                lab.base_url, username="carol", password=LAB_PASSWORDS["carol"]
            )
        },
    )
    wrong = FileCredentialVault(tmp_path / "credentials.enc", passphrase="not the passphrase")
    from arachne.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError, match="could not be authenticated"):
        wrong.labels()
    # The real passphrase still works, which is what makes the assertion above meaningful.
    right = FileCredentialVault(tmp_path / "credentials.enc", passphrase=LAB_PASSPHRASE)
    assert right.labels() == ("portal",)
