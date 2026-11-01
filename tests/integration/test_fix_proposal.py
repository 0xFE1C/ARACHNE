"""End to end: a real repository, a real finding, a real branch (S27, area FIX).

This module is the acceptance evidence for the phase-7 gate's first four items:

1. a lab repository with a planted vulnerability produces a **scoped, test-passing PR on a
   dedicated branch with no merge** (REQ-FIX-002/003), and the operator's own checkout and
   default branch are provably untouched;
2. an IaC fix proposal **passes ARACHNE's own scanner** (REQ-FIX-004) and the
   propose → apply → targeted re-scan → **auto-close** loop runs end to end (REQ-FIX-005);
3. a proposal that **fails the repository's own tests is flagged, not submitted** — the
   risk-R-18 case, with a repository whose suite genuinely requires privileged mode;
4. the prohibitions hold on the artifact (no secrets, no deletions, no dependency edits) and
   nothing outside ARACHNE happens without a named human approval (REQ-FIX-001).

Everything runs offline: the finding comes from a scan of a local ``repo:`` tree, the branch
is created in that same tree, and every process the engine starts is a git verb or the
repository's declared test command.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.api import make_api_harness
from tests.helpers.fixlab import (
    LabRepo,
    build_lab_repo,
    grant_document,
    runner_on_path,
    write_grants,
)

from arachne.core.audit import AuditAction
from arachne.core.config import (
    AnalysisSettings,
    ApiSettings,
    FixSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.safety import UrlSafetyPolicy
from arachne.core.target import ModuleSelection, ScanOptions, ScanRequest, TargetDefinition
from arachne.data.services import build_orchestrator
from arachne.fix.grants import load_fix_grants
from arachne.fix.plans import load_fix_plan_catalog
from arachne.fix.proposal import FixProposalEngine, FixProposalError

pytestmark = pytest.mark.integration

#: The M5 review that reports IaC/Kubernetes misconfigurations in a local tree.
IAC_CHECKS = ("m5.tfstate-exposure",)


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """A local repository scan and a local branch must open no socket at all."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("the fix workflow attempted real network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == [], f"unexpected socket use: {attempts}"


@pytest.fixture(autouse=True)
def _runner_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    runner_on_path(monkeypatch)


def _settings(tmp_path: Path, **fix: Any) -> Settings:
    fix_kwargs: dict[str, Any] = {"artifacts_dir": str(tmp_path / "fix-artifacts"), **fix}
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'fix.db'}",
        actor="pytest",
        api=ApiSettings(
            keys=("admin:admin:rootsecret",),
            require_tls=False,
            rate_limit_per_minute=100_000,
            rate_limit_burst=100_000,
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
        safety=SafetySettings(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)),
        fix=FixSettings(**fix_kwargs),  # type: ignore[arg-type]
        # One finding per artifact rule rather than one primary finding per asset: the fix
        # workflow selects a plan by the *rule* a finding reported, so a deployment that
        # correlates same-asset findings (the default) proposes against the primary one and
        # the rest stay visible as its related evidence. The operator guide's repo-mode
        # section records this choice; here it is what makes each rule addressable.
        analysis=AnalysisSettings(correlation_enabled=False),
    )


def _repo_request(asset_value: str, name: str = "lab-repo") -> ScanRequest:
    """The offline review of a local repository, exactly as the IaC gate declares it."""
    definition = TargetDefinition.model_validate(
        {
            "name": name,
            "targets": [{"kind": "cloud", "value": asset_value}],
            "attestation": {
                "attested_by": "S27 integration test (local repository review)",
                "attested_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                "authorization_ref": "test-s27",
                "scope_statement": "the lab repository; a local tree, read only",
                "allowed_targets": [asset_value],
                "active_checks_authorized": False,
            },
        }
    )
    return ScanRequest(
        target=definition,
        options=ScanOptions(
            engine="heuristic",
            active_checks=False,
            modules=ModuleSelection(enabled=("M5",), checks=IAC_CHECKS),
        ),
    )


def _confirmed(services: Any, scan_id: int) -> list[Any]:
    return [
        candidate
        for candidate in services.findings.list_candidates(scan_id)
        if candidate.status not in {"fp", "merged"} and candidate.severity is not None
    ]


async def _scan_and_find(harness: Any, asset_value: str, rule: str) -> tuple[int, int]:
    """Scan the repository and return ``(scan_id, finding_id)`` for one artifact rule."""
    orchestrator = build_orchestrator(harness.services)
    session = await orchestrator.scan(_repo_request(asset_value))
    assert session.scan_id is not None
    finding_id: int | None = None
    for candidate in _confirmed(harness.services, session.scan_id):
        artifacts = [
            item.payload for item in candidate.evidence if getattr(item, "kind", None) == "artifact"
        ]
        if any(artifact.get("rule") == rule for artifact in artifacts):
            finding_id = int(candidate.id)
            break
    assert finding_id is not None, f"the lab repository must report {rule}"
    return int(session.scan_id), finding_id


def _engine(
    harness: Any, tmp_path: Path, repo: LabRepo, **grant_overrides: Any
) -> FixProposalEngine:
    grants_file = write_grants(tmp_path / "grants.yaml", grant_document(repo, **grant_overrides))
    return FixProposalEngine(
        harness.services,
        plans=load_fix_plan_catalog(),
        grants=load_fix_grants(str(grants_file)),
    )


def _apply_fix(repo: LabRepo, relative: str, *, old: str, new: str) -> None:
    """The human's edit: the fix lands in the working tree (a merge would land the same bytes).

    No process is involved: the fix is what the branch already contains, and what the targeted
    re-scan reads is the tree on disk.
    """
    text = repo.read(relative)
    assert old in text, f"{relative} no longer contains {old!r}"
    (repo.root / relative).write_text(text.replace(old, new), encoding="utf-8")


# ------------------------------------------------------------------ 1. the PR
@pytest.mark.asyncio
async def test_a_planted_vulnerability_produces_a_scoped_test_passing_branch(
    tmp_path: Path,
) -> None:
    """REQ-FIX-001/002/003: propose → approve → tests → branch, and nothing merged."""
    repo = build_lab_repo(tmp_path)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        engine = _engine(harness, tmp_path, repo)

        # --- propose: an artifact, recorded, with no effect outside ARACHNE
        proposal = await engine.propose(finding_id, actor="pytest")
        assert proposal.status == "proposed", proposal.flagged_reason
        assert proposal.plan_id == "k8s-privileged-container"
        assert proposal.kind == "iac"
        assert proposal.author == "template"
        assert proposal.targets == ("deploy/api.yaml",)
        assert proposal.diff_text and "privileged: false" in proposal.diff_text
        assert proposal.safety_json["clean"] is True
        assert proposal.self_scan_json["required"] is True
        assert proposal.self_scan_json["clean"] is True
        assert proposal.self_scan_json["introduced"] == []
        assert repo.head() == repo.base_commit, "a proposal must not touch the repository"
        assert repo.branches() == (repo.default_branch,)

        # --- the human gate: submission without an approval is refused (REQ-FIX-001)
        with pytest.raises(FixProposalError, match="needs an approval"):
            engine.submit(proposal.id or 0)
        assert repo.branches() == (repo.default_branch,)

        approved = engine.approve(proposal.id or 0, actor="jane.operator@example.com")
        assert approved.status == "approved"
        assert approved.approved_by == "jane.operator@example.com"

        # --- submit: the repository's own suite first, then the dedicated branch
        submitted = engine.submit(proposal.id or 0)
        assert submitted.status == "submitted", submitted.flagged_reason
        assert submitted.test_outcome == "passed"
        assert submitted.branch and submitted.branch.startswith("arachne-fix-")
        assert submitted.commit and submitted.base_commit == repo.base_commit

        # The branch exists, carries exactly the scoped change, and the default branch has
        # not moved: nothing was merged, and the operator's checkout is untouched.
        assert submitted.branch in repo.branches()
        assert repo.branch_commit(repo.default_branch) == repo.base_commit
        assert repo.head() == repo.base_commit
        assert repo.working_tree_clean()
        assert repo.commit_files(submitted.commit) == ("deploy/api.yaml",)
        branch_diff = repo.commit_diff(submitted.commit)
        # The artifact is *provably* scoped: one line out, one line in, nothing else — the
        # tree meanwhile keeps every other line the finding's own evidence never named.
        added = [
            line
            for line in branch_diff.splitlines()
            if line.startswith("+") and not line.startswith("+++")
        ]
        removed = [
            line
            for line in branch_diff.splitlines()
            if line.startswith("-") and not line.startswith("---")
        ]
        assert added == ["+            privileged: false"]
        assert removed == ["-            privileged: true"]
        unchanged = repo.read("deploy/api.yaml")
        assert "privileged: true" in unchanged, "the branch must not touch the working tree"
        assert "readOnlyRootFilesystem: true" in unchanged
        assert submitted.meta_json["default_branch_unchanged"] is True

        # --- the reviewable PR artifact, and the audit trail from finding to proposal
        artifact = Path(submitted.pr_artifact or "")
        assert artifact.is_dir()
        assert "privileged: false" in (artifact / "patch.diff").read_text(encoding="utf-8")
        body = (artifact / "PR.md").read_text(encoding="utf-8")
        assert "did **not** merge it" in body
        assert "no secrets in the diff" in body
        for action in (
            AuditAction.FIX_PROPOSAL_CREATED,
            AuditAction.FIX_SELF_SCAN,
            AuditAction.FIX_PROPOSAL_APPROVED,
            AuditAction.FIX_BRANCH_CREATED,
            AuditAction.FIX_PR_OPENED,
        ):
            assert len(harness.sink.of_action(action)) == 1, action
        events = harness.sink.of_action(AuditAction.FIX_BRANCH_CREATED)
        assert events[0].meta["finding_id"] == finding_id
    finally:
        harness.close()


# ------------------------------------------------------------------ 2. the loop
@pytest.mark.asyncio
async def test_propose_apply_then_the_loop_auto_closes_the_finding(tmp_path: Path) -> None:
    """REQ-FIX-005: the proposal ends in the S23 verification loop's own verdict.

    The repository plants **one** misconfiguration, and the reviewer sees one asset (the
    repository the operator granted). That is what makes the loop's closure meaningful: the
    S23 loop verifies an *asset* is clean of the check that raised the finding, so the demo
    asks the honest question — after the fix, does ARACHNE's own review of that repository
    still report anything? It does not, and the finding closes on the re-scan's evidence.
    """
    repo = build_lab_repo(tmp_path, plant=("database",))
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "public-database")
        engine = _engine(harness, tmp_path, repo)

        proposal = await engine.propose(finding_id, actor="pytest")
        assert proposal.status == "proposed", proposal.flagged_reason
        assert proposal.plan_id == "iac-public-database"
        assert proposal.targets == ("infra/main.tf",)
        engine.approve(proposal.id or 0, actor="jane.operator@example.com")
        submitted = engine.submit(proposal.id or 0)
        assert submitted.status == "submitted", submitted.flagged_reason

        # The human applies the fix (they merged the branch ARACHNE opened).
        _apply_fix(repo, "infra/main.tf", old="publicly_accessible = true",
                   new="publicly_accessible = false")
        engine.mark_applied(proposal.id or 0, actor="jane.operator@example.com")

        verified = await engine.verify(proposal.id or 0, actor="jane.operator@example.com")
        assert verified.status == "verified", verified.flagged_reason
        assert verified.verification_outcome == "verified"
        assert verified.verification_scan_id is not None
        assert verified.verification_id is not None

        # The original finding is closed, by a scan, with evidence linked to it.
        stored = harness.services.posture.finding(finding_id)
        assert stored is not None and stored["status"] == "closed"
        verifications = harness.services.posture.verifications_for(finding_id)
        assert [item.outcome for item in verifications] == ["verified"]
        assert len(harness.sink.of_action(AuditAction.FIX_VERIFIED)) == 1
        assert len(harness.sink.of_action(AuditAction.POSTURE_FIX_VERIFIED)) == 1
    finally:
        harness.close()


# ------------------------------------------------------------------ 3. risk R-18
@pytest.mark.asyncio
async def test_a_patch_that_fails_the_repositorys_own_tests_is_flagged_not_submitted(
    tmp_path: Path,
) -> None:
    """The hard rule: a proposal the repository's suite rejects never becomes a branch."""
    repo = build_lab_repo(tmp_path, strict=True)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        engine = _engine(harness, tmp_path, repo)
        proposal = await engine.propose(finding_id, actor="pytest")
        engine.approve(proposal.id or 0, actor="jane.operator@example.com")

        submitted = engine.submit(proposal.id or 0)
        assert submitted.status == "tests-failed"
        assert "own suite" in (submitted.flagged_reason or "")
        assert submitted.branch is None and submitted.commit is None
        assert repo.branches() == (repo.default_branch,), "nothing may be created"
        assert repo.head() == repo.base_commit
        assert len(harness.sink.of_action(AuditAction.FIX_TESTS_FAILED)) == 1
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_a_repository_whose_suite_already_fails_is_never_claimed_as_fixed(
    tmp_path: Path,
) -> None:
    """The baseline run: a pre-broken suite is not evidence that a fix works."""
    repo = build_lab_repo(tmp_path, plant=("bucket",), broken_baseline=True)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "public-bucket-acl")
        engine = _engine(harness, tmp_path, repo)
        proposal = await engine.propose(finding_id, actor="pytest")
        engine.approve(proposal.id or 0, actor="jane.operator@example.com")
        submitted = engine.submit(proposal.id or 0)
        assert submitted.status == "baseline-failing"
        assert "already fails" in (submitted.flagged_reason or "")
        assert repo.branches() == (repo.default_branch,)
    finally:
        harness.close()


# ------------------------------------------------------------------ 4. the refusal paths
@pytest.mark.asyncio
async def test_a_repository_no_grant_covers_gets_guidance_never_a_diff(tmp_path: Path) -> None:
    """REQ-FIX-001: the operator's grant is what makes a repository fixable at all."""
    repo = build_lab_repo(tmp_path)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        bare = FixProposalEngine(harness.services, plans=load_fix_plan_catalog())
        proposal = await bare.propose(finding_id, actor="pytest")
        assert proposal.status == "refused"
        assert proposal.diff_text is None
        assert "grant" in (proposal.flagged_reason or "")
        assert len(harness.sink.of_action(AuditAction.FIX_GRANT_REFUSED)) == 1
        assert repo.branches() == (repo.default_branch,)
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_a_class_no_plan_covers_is_flagged_unsupported_with_the_catalog_steps(
    tmp_path: Path,
) -> None:
    """REQ-FIX-001's honest edge: no plan means guidance, and a *recorded* refusal."""
    repo = build_lab_repo(tmp_path, plant=("host-network",))
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-host-namespace")
        # A catalog holding only the privileged plan: the host-namespace class is uncovered.
        catalog = load_fix_plan_catalog()
        narrowed = catalog.model_copy(
            update={"plans": tuple(p for p in catalog.plans if p.id == "k8s-privileged-container")}
        )
        engine = FixProposalEngine(
            harness.services,
            plans=narrowed,
            grants=load_fix_grants(
                str(write_grants(tmp_path / "grants.yaml", grant_document(repo)))
            ),
        )
        proposal = await engine.propose(finding_id, actor="pytest")
        assert proposal.status == "unsupported"
        assert proposal.diff_text is None
        assert "no shipped fix plan covers this class" in (proposal.flagged_reason or "")
        assert proposal.meta_json["remediation"]["steps"], (
            "an unsupported class still gets the remediation catalog's steps"
        )
        assert len(harness.sink.of_action(AuditAction.FIX_PROPOSAL_REFUSED)) == 1
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_an_untestable_repository_is_flagged_and_only_proceeds_when_opted_in(
    tmp_path: Path,
) -> None:
    """REQ-FIX-002: "untestable proposals flagged as such" — with an explicit opt-in."""
    repo = build_lab_repo(tmp_path, testable=False)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        engine = _engine(harness, tmp_path, repo)
        proposal = await engine.propose(finding_id, actor="pytest")
        assert proposal.status == "proposed", proposal.flagged_reason
        engine.approve(proposal.id or 0, actor="jane.operator@example.com")

        flagged = engine.submit(proposal.id or 0)
        assert flagged.status == "untestable"
        assert "no test command" in (flagged.flagged_reason or "")
        assert repo.branches() == (repo.default_branch,)
        assert len(harness.sink.of_action(AuditAction.FIX_TESTS_FAILED)) == 1

        # The operator accepts the risk in the grant; the branch is then created and the
        # record still says the artifact was never proven by the repository's suite.
        permissive = _engine(harness, tmp_path, repo, allow_untestable=True)
        accepted = permissive.submit(proposal.id or 0)
        assert accepted.status == "submitted", accepted.flagged_reason
        assert accepted.test_outcome == "untestable"
        assert accepted.branch and accepted.branch in repo.branches()
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_a_stale_proposal_is_refused_rather_than_committed(tmp_path: Path) -> None:
    """The artifact a human approved is the artifact submitted, or nothing is."""
    repo = build_lab_repo(tmp_path)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        engine = _engine(harness, tmp_path, repo)
        proposal = await engine.propose(finding_id, actor="pytest")
        engine.approve(proposal.id or 0, actor="jane.operator@example.com")

        # Someone edits the file the plan touches between approval and submission, so the
        # approved bytes are no longer what the tree would produce.
        _apply_fix(
            repo,
            "deploy/api.yaml",
            old="            readOnlyRootFilesystem: true",
            new="            readOnlyRootFilesystem: false",
        )
        with pytest.raises(FixProposalError, match="no longer the artifact on disk"):
            engine.submit(proposal.id or 0)
        assert repo.branches() == (repo.default_branch,)
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_a_plan_that_would_introduce_an_iac_finding_is_refused(tmp_path: Path) -> None:
    """REQ-FIX-004: a fix may not bring a finding of its own — proven by the self-scan."""
    repo = build_lab_repo(tmp_path, plant=("database",))
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "public-database")
        catalog = load_fix_plan_catalog()
        plan = catalog.by_id("iac-public-database")
        assert plan is not None
        # A hostile catalog: close the public database *and* switch storage encryption off,
        # which is itself a finding — the delta the self-scan exists to catch.
        hostile = plan.model_copy(
            update={
                "edits": (
                    *plan.edits,
                    plan.edits[0].model_copy(
                        update={
                            "pattern": r"(?m)^(?P<lead>\s*storage_encrypted\s*=\s*)true"
                            r"(?P<tail>\s*(?:#.*)?)$",
                            "replacement": r"\g<lead>false\g<tail>",
                        }
                    ),
                ),
                "already_fixed": None,
            }
        )
        engine = FixProposalEngine(
            harness.services,
            plans=catalog.model_copy(update={"plans": (hostile,)}),
            grants=load_fix_grants(
                str(write_grants(tmp_path / "grants.yaml", grant_document(repo)))
            ),
        )
        proposal = await engine.propose(finding_id, actor="pytest")
        assert proposal.status == "refused", proposal.flagged_reason
        assert "self-scan" in (proposal.flagged_reason or "")
        assert proposal.diff_text is None, "an artifact that introduces a finding is never stored"
        assert proposal.meta_json["self_scan"]["introduced"], "the delta is the evidence"
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_a_pre_existing_finding_in_the_same_file_does_not_block_the_fix(
    tmp_path: Path,
) -> None:
    """The delta reading: a second, untouched misconfiguration is not the fix's fault."""
    repo = build_lab_repo(tmp_path, plant=("privileged", "host-network"))
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        # the generated fixture manifest carries *two* policy findings (privileged and host
        # networking); the proposal repairs one and must not be blamed for the other.
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        engine = _engine(harness, tmp_path, repo)
        proposal = await engine.propose(finding_id, actor="pytest")
        assert proposal.status == "proposed", proposal.flagged_reason
        kinds = {item["rule"] for item in proposal.self_scan_json["findings"]}
        assert "k8s-host-namespace" in kinds, "the pre-existing finding is still reported"
        assert proposal.self_scan_json["introduced"] == []
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_a_finding_can_only_be_proposed_while_it_is_open(tmp_path: Path) -> None:
    """A proposal against a closed finding is refused: the loop owns that state."""
    repo = build_lab_repo(tmp_path)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        engine = _engine(harness, tmp_path, repo)
        first = await engine.propose(finding_id, actor="pytest")
        assert first.status == "proposed"
        harness.services.posture.set_finding_status(finding_id, "closed")
        with pytest.raises(FixProposalError, match="applies to an open finding"):
            await engine.propose(finding_id, actor="pytest")
    finally:
        harness.close()


@pytest.mark.asyncio
async def test_the_summary_counts_every_outcome(tmp_path: Path) -> None:
    repo = build_lab_repo(tmp_path)
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    try:
        _scan_id, finding_id = await _scan_and_find(harness, repo.asset_value, "k8s-privileged")
        engine = _engine(harness, tmp_path, repo)
        await engine.propose(finding_id, actor="pytest")
        summary = engine.summary()
        assert summary.counts.get("proposed") == 1
        assert summary.total == 1
        listed = engine.proposals(status="proposed")
        assert listed and listed[0].finding_id == finding_id
    finally:
        harness.close()
