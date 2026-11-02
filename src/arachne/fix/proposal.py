"""The fix-proposal engine: propose → human approves → tests → branch → verify (S27).

The whole of area FIX in one state machine, and the shape of it is the argument
``03-delivery-plan.md`` §9 makes: *ARACHNE proposes, a human decides, ARACHNE verifies.*

``propose``
    Reads one finding, resolves the remediation catalog entry (S8) and the fix plan (S27),
    resolves the **operator's grant** for the finding's repository, applies the plan to the
    files the finding's own evidence names, judges the resulting diff against the REQ-FIX-003
    prohibitions, self-scans an IaC artifact with ARACHNE's own scanner (REQ-FIX-004) and
    records the proposal. **No effect outside ARACHNE happens here**: the artifact is a diff
    in a row. Refusals are recorded, not dropped — an ambiguity, an ungranted repository, an
    uncovered class, a diff that would add a secret, a plan that does not apply: each is a
    status with a reason, because "why is there no proposal?" is a question the operator will
    ask.

``approve`` / ``reject``
    The human gate (REQ-FIX-001). A proposal cannot be submitted without an approval naming
    its approver, and the approval is a separate audited act — which is what makes
    "no effect without human approval" checkable in the data rather than a promise.

``submit``
    Repository mode (REQ-FIX-002): re-applies the plan, refuses a **stale** proposal (the
    artifact a human approved is the artifact submitted, or nothing), runs the repository's
    **own test suite** in a throwaway worktree — a failing or baseline-failing suite is
    *flagged, never submitted* (risk R-18) — and only then creates the dedicated
    ``arachne-fix-*`` branch at the tested commit, plus a reviewable PR artifact. Never
    merged, never pushed to the default branch, and the default branch's ref is asserted
    unchanged (see :mod:`arachne.fix.gitops`).

``mark_applied`` then ``verify``
    REQ-FIX-005: a human says the fix landed (they merged the PR, or applied the patch), and
    the S23 fix-verification loop runs its targeted re-scan. The finding auto-closes on
    verified absence; the act is linked onto this row, so the proposal's record ends with the
    scan that confirmed it.

Auto-merge and auto-apply are absent by construction: there is no code path here that
changes a target's state, and the only process this engine starts is the repository's own
test command, inside a scratch worktree, after an approval named a human.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from arachne.analyzer.model import Candidate, Remediation
from arachne.analyzer.remediation import load_remediation_catalog
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import ArachneError
from arachne.data.fix_store import FixProposalRecord, FixProposalStore
from arachne.data.services import ScanServices
from arachne.fix import gitops
from arachne.fix.authoring import (
    AI_PARITY_DIVERGENCE,
    AuthorOutcome,
    AuthorRequest,
    PatchAuthor,
    TemplateAuthor,
    resolve_draft,
)
from arachne.fix.grants import FixGrantSet, RepoAuthorization, load_fix_grants
from arachne.fix.patch import PlanApplication, apply_plan, resolve_targets
from arachne.fix.plans import (
    FindingProfile,
    FixPlan,
    FixPlanCatalog,
    load_fix_plan_catalog,
)
from arachne.fix.safety import DiffVerdict, analyze_diff
from arachne.fix.selfscan import SelfScanResult, artifact_locations, self_scan_tree

__all__ = [
    "PROPOSAL_STATUSES",
    "FixProposalEngine",
    "FixProposalError",
    "proposal_branch_name",
    "render_pr_body",
]

#: The proposal vocabulary, in the order a reader meets it.
PROPOSAL_STATUSES = (
    "proposed",
    "approved",
    "rejected",
    "submitted",
    "tests-failed",
    "baseline-failing",
    "untestable",
    "applied",
    "verified",
    "still-open",
    "unsupported",
    "ambiguous",
    "already-fixed",
    "refused",
    "failed",
)

#: Statuses a proposal can be approved from.
APPROVABLE = ("proposed",)
#: Statuses a submission can start from. ``untestable`` is a *flagged* state rather than a
#: terminal one: the operator's answer to it is a grant change (``allow_untestable``), and the
#: approval they already gave still stands.
SUBMITTABLE = ("approved", "untestable")
#: Statuses a verification can start from (a human has said the fix landed).
VERIFIABLE = ("applied", "submitted")


class FixProposalError(ArachneError):
    """A proposal act was refused: wrong state, no grant, an unsafe diff, a stale artifact."""


def proposal_branch_name(finding_id: int | None, plan_id: str | None) -> str:
    """``arachne-fix-<finding>-<plan>`` — the branch REQ-FIX-002 asks for."""
    slug = (plan_id or "proposal").split("/")[-1]
    return gitops.patch_branch_name(int(finding_id or 0), slug)


def render_pr_body(
    record: FixProposalRecord,
    *,
    verdict: DiffVerdict | None,
    self_scan: SelfScanResult | None,
    test_command: Sequence[str],
    test_outcome: str,
    reviewer_note: str = "",
) -> str:
    """The reviewable PR body: what changed, why, what was proven, and who decides."""
    lines = [
        f"# ARACHNE fix proposal #{record.id}",
        "",
        f"**Finding** #{record.finding_id} — `{record.check_key or 'unknown check'}` on "
        f"`{record.asset_value or 'unknown asset'}`",
        f"**Plan** `{record.plan_id or 'none'}` ({record.kind}), author `{record.author}`",
        "",
        record.summary.strip(),
        "",
    ]
    if record.targets:
        lines += ["**Files changed**", ""]
        lines += [f"- `{item}`" for item in record.targets]
        lines.append("")
    if reviewer_note:
        lines += [reviewer_note.strip(), ""]
    lines += ["**Scope analysis (REQ-FIX-003)**", ""]
    if verdict is None:
        lines.append("- no diff-scope verdict was recorded")
    else:
        lines.append(f"- no secrets in the diff, no deletions, no mode changes: {verdict.clean}")
        lines.append(
            f"- {verdict.added_lines} added / {verdict.removed_lines} removed line(s), "
            f"{len(verdict.files)} file(s); byte-applicable: {verdict.verbatim}"
        )
    lines.append("")
    lines += ["**ARACHNE's own IaC self-scan (REQ-FIX-004)**", ""]
    if self_scan is None or not self_scan.required:
        lines.append("- not required for this artifact kind")
    else:
        lines.append(f"- {self_scan.detail}")
    lines.append("")
    lines += ["**The repository's own test suite (REQ-FIX-002)**", ""]
    lines.append(f"- `{' '.join(test_command) or '<none declared>'}` → {test_outcome}")
    lines += [
        "",
        "---",
        "",
        "ARACHNE opened this branch and wrote this artifact. It did **not** merge it, apply it",
        "or push to the default branch: a human reviews, and a human decides.",
        "",
    ]
    return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class ProposalSummary:
    """A count of the proposals by status (the CLI's one-screen view)."""

    counts: Mapping[str, int]

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def to_dict(self) -> dict[str, Any]:
        return {"total": self.total, "by_status": dict(self.counts)}


class FixProposalEngine:
    """The area-FIX workflow over one deployment's services."""

    def __init__(
        self,
        services: ScanServices,
        *,
        plans: FixPlanCatalog | None = None,
        grants: FixGrantSet | None = None,
        author: PatchAuthor | None = None,
        ai_author: PatchAuthor | None = None,
        auditor: Auditor | None = None,
    ) -> None:
        self.services = services
        self.settings = services.settings
        self.auditor = auditor or services.auditor
        self.plans = plans if plans is not None else load_fix_plan_catalog(self.settings.fix.plans)
        self.grants = grants if grants is not None else load_fix_grants(self.settings.fix.grants)
        self.author: PatchAuthor = author or TemplateAuthor()
        self.ai_author = ai_author
        self.store: FixProposalStore | None = services.fix_proposals

    # ------------------------------------------------------------------ helpers
    @property
    def artifacts_dir(self) -> Path | None:
        raw = self.settings.fix.artifacts_dir
        return Path(raw).expanduser() if raw else None

    def _require_store(self) -> FixProposalStore:
        if self.store is None:
            msg = "this deployment has no fix-proposal store wired"
            raise FixProposalError(msg)
        return self.store

    def _remediation_for(self, check_key: str | None, cwe: str | None) -> Remediation:
        catalog = load_remediation_catalog(self.settings.analysis.remediation_catalog)
        module, _, remainder = (check_key or "").partition("/")
        name = remainder.split("@", 1)[0]
        candidate = Candidate(
            scan_id=0,
            title="proposal",
            check_id=f"{module.lower()}.{name}" if name else None,
            cwe=cwe,
        )
        return catalog.resolve(candidate)

    def _finding_record(self, finding_id: int) -> tuple[dict[str, Any], Any]:
        """The stored finding plus its candidate row (evidence included)."""
        posture = self.services.posture
        if posture is None:
            msg = "no posture store is wired, so a finding cannot be read by id"
            raise FixProposalError(msg)
        finding = posture.finding(finding_id)
        if finding is None:
            msg = f"finding {finding_id} does not exist"
            raise FixProposalError(msg)
        scan_id = int(finding["scan_id"])
        candidate = next(
            (
                item
                for item in self.services.findings.list_candidates(scan_id)
                if item.id == finding_id
            ),
            None,
        )
        if candidate is None:
            msg = f"finding {finding_id} carries no stored candidate row"
            raise FixProposalError(msg)
        return finding, candidate

    def _profile(
        self, candidate: Any
    ) -> tuple[FindingProfile, tuple[dict[str, Any], ...], tuple[str, ...]]:
        """The plan-selection profile, the finding's artifact payloads and its file paths.

        The three travel together because they all come from the same evidence rows, and the
        plan engine must select on exactly what the check reported — never on anything this
        module inferred.
        """
        self_scan_locations, _ = artifact_locations(candidate.evidence)
        artifacts: list[dict[str, Any]] = []
        locations: list[str] = list(self_scan_locations)
        rule: str | None = None
        signal: str | None = None
        cwe: str | None = None
        for item in candidate.evidence:
            if getattr(item, "kind", None) != "artifact":
                continue
            payload = getattr(item, "payload", None)
            if not isinstance(payload, dict) or not payload:
                continue
            artifacts.append(dict(payload))
            rule = rule or _as_str(payload.get("rule"))
            signal = signal or _as_str(payload.get("signal"))
            cwe = cwe or _as_str(payload.get("cwe"))
        remediation = self._remediation_for(candidate.check_key, cwe)
        profile = FindingProfile(
            check_key=candidate.check_key,
            cwe=cwe,
            remediation_id=remediation.id,
            rule=rule,
            signal=signal,
        )
        return profile, tuple(artifacts), tuple(dict.fromkeys(locations))

    # ------------------------------------------------------------------ propose
    async def propose(
        self, finding_id: int, *, actor: str = "operator", now: datetime | None = None
    ) -> FixProposalRecord:
        """Build and record a proposal for one finding (no effect outside ARACHNE)."""
        store = self._require_store()
        finding, candidate = self._finding_record(finding_id)
        if str(finding["status"]) in {"closed", "fp", "merged"}:
            msg = (
                f"finding {finding_id} is {finding['status']!r}; a fix proposal applies to an "
                "open finding"
            )
            raise FixProposalError(msg)
        profile, artifacts, locations = self._profile(candidate)
        remediation = self._remediation_for(profile.check_key, profile.cwe)
        selection = self.plans.select(profile)
        common: dict[str, Any] = {
            "finding_id": finding_id,
            "scan_id": int(finding["scan_id"]),
            "check_key": profile.check_key,
            "asset_value": candidate.asset_value,
            "requested_by": actor,
            "summary": remediation.summary,
            "rationale": " ".join(remediation.steps),
            # The remediation catalog's own answer travels with every outcome — a refused
            # proposal still tells the operator what to do (that is what area POSTURE's loop
            # then verifies), it just does not claim to have done it.
            "meta_json": {
                "remediation": {
                    "id": remediation.id,
                    "summary": remediation.summary,
                    "steps": list(remediation.steps),
                    "verification": list(remediation.verification),
                    "source": remediation.source,
                }
            },
        }

        if selection.ambiguous:
            return self._record_refusal(
                common,
                status="ambiguous",
                reason=(
                    "more than one fix plan fits this finding equally well: "
                    + ", ".join(plan.id for plan in selection.candidates)
                    + " — the catalog must be narrowed before ARACHNE proposes"
                ),
                extra={"candidates": [plan.to_dict() for plan in selection.candidates]},
                now=now,
            )
        if selection.unsupported:
            return self._record_refusal(
                common,
                status="unsupported",
                reason=(
                    "no shipped fix plan covers this class (check "
                    f"{profile.check_key or 'unknown'}"
                    + (f", rule {profile.rule}" if profile.rule else "")
                    + "); the remediation catalog's steps are the artifact this class gets"
                ),
                now=now,
            )

        plan = selection.plan
        assert plan is not None  # narrowed by the branches above
        authorization = self.grants.resolve(candidate.asset_value or "")
        if authorization is None:
            return self._record_refusal(
                common,
                status="refused",
                reason=(
                    f"no fix-repo grant covers {candidate.asset_value!r}; ARACHNE proposes "
                    "against an operator-granted repository only (ARACHNE_FIX_GRANTS)"
                ),
                extra={"plan": plan.to_dict()},
                audit=AuditAction.FIX_GRANT_REFUSED,
                now=now,
            )
        if not gitops.is_git_repo(authorization.root):
            return self._record_refusal(
                common,
                status="refused",
                reason=f"{authorization.root} is not a git work tree",
                extra={"plan": plan.to_dict()},
                now=now,
            )

        root = authorization.root
        targets, skipped = resolve_targets(
            root, locations, globs=plan.globs, max_files=authorization.grant.max_files
        )
        application = apply_plan(plan, root, targets, max_files=authorization.grant.max_files)
        if application.already_fixed:
            return self._record_refusal(
                common,
                status="already-fixed",
                reason=f"the fix for {plan.id} is already present in this tree",
                extra={"plan": plan.to_dict(), "skipped": list(application.skipped)},
                now=now,
            )
        if not application.applied:
            return self._record_refusal(
                common,
                status="refused",
                reason=f"the plan does not apply to this tree: {application.reason}",
                extra={
                    "plan": plan.to_dict(),
                    "targets": list(targets),
                    "skipped": list(application.skipped),
                },
                now=now,
            )

        diff = application.diff()
        verdict = analyze_diff(
            diff,
            allowed_paths=application.changed_paths,
            budgets=authorization.budgets,
            mask_removals=plan.mask_removals,
        )
        if not verdict.clean:
            return self._record_refusal(
                common,
                status="refused",
                reason=(
                    "the artifact violates a scope prohibition: " + "; ".join(verdict.violations)
                ),
                extra={
                    "plan": plan.to_dict(),
                    "targets": list(targets),
                    "skipped": list(skipped),
                    "safety": verdict.summary(),
                },
                now=now,
            )

        parity, parity_detail, flags = self._parity(
            plan, application, profile, artifacts, remediation
        )
        self_scan = await self._self_scan(plan, application)
        if self_scan is not None and self_scan.required and not self_scan.clean:
            return self._record_refusal(
                common,
                status="refused",
                reason="ARACHNE's own IaC self-scan still reports a finding on the changed files",
                extra={
                    "plan": plan.to_dict(),
                    "targets": list(targets),
                    "self_scan": self_scan.summary(),
                    "safety": verdict.summary(),
                },
                now=now,
            )

        rationale = str(common.get("rationale") or "")
        if parity_detail:
            rationale = f"{rationale} | {parity_detail}"
        record = store.add(
            **{
                key: value for key, value in common.items() if key not in {"rationale", "meta_json"}
            },
            kind=plan.kind,
            status="proposed",
            plan_id=plan.id,
            author=self.author.name,
            parity=parity,
            rationale=rationale,
            targets_json={"files": list(application.changed_paths), "skipped": list(skipped)},
            diff_text=verdict.diff,
            verbatim=verdict.verbatim,
            manual_apply_required=plan.manual_apply_required or not verdict.verbatim,
            safety_json=verdict.summary(),
            self_scan_json=(self_scan.summary() if self_scan is not None else {"required": False}),
            meta_json={
                **dict(common.get("meta_json") or {}),
                "flags": list(flags),
                "skipped": list(skipped),
            },
            repo_name=authorization.name,
            repo_path=str(authorization.root),
            default_branch=authorization.grant.default_branch,
        )
        if self_scan is not None and self_scan.required:
            self._audit(
                AuditAction.FIX_SELF_SCAN,
                record=record,
                reason=self_scan.detail,
                meta={"clean": self_scan.clean, "scan_id": self_scan.scan_id},
            )
        if parity in {"ok", "failed"}:
            self._audit(
                AuditAction.FIX_AI_PARITY,
                record=record,
                reason=parity_detail,
                meta={"parity": parity, "flags": list(flags)},
            )
        self._audit(
            AuditAction.FIX_PROPOSAL_CREATED,
            record=record,
            reason=(
                f"{plan.id} against {authorization.name}: "
                f"{len(application.changed_paths)} file(s), {verdict.added_lines} added line(s)"
            ),
            meta={
                "plan": plan.id,
                "files": list(application.changed_paths),
                "manual_apply_required": record.manual_apply_required,
            },
        )
        return record

    def _parity(
        self,
        plan: FixPlan,
        application: PlanApplication,
        profile: FindingProfile,
        artifacts: tuple[dict[str, Any], ...],
        remediation: Remediation,
    ) -> tuple[str, str, tuple[str, ...]]:
        """The dual-engine parity outcome for a covered class (REQ-FIX-006).

        With no second engine configured this is ``n/a`` and nothing is claimed. With one,
        the template artifact stays the artifact — the second engine's job is to *agree*, and
        a divergence is recorded and flagged rather than substituted.
        """
        if self.ai_author is None:
            return "n/a", "", ()
        request = AuthorRequest(
            profile=profile,
            plan=plan,
            root=application.root,
            targets=application.targets,
            evidence=artifacts,
            remediation_summary=remediation.summary,
            remediation_steps=tuple(remediation.steps),
            mask_removals=plan.mask_removals,
        )
        outcome: AuthorOutcome = resolve_draft(
            request,
            template=self.author,
            ai=self.ai_author,
            allow_beyond_templates=False,
        )
        if outcome.draft is None:
            return "n/a", "", ()
        if outcome.parity == "ok":
            return "ok", outcome.parity_detail, ()
        if outcome.parity == "failed":
            return "failed", outcome.parity_detail, outcome.flags or (AI_PARITY_DIVERGENCE,)
        return outcome.parity, outcome.parity_detail, ()

    async def _self_scan(
        self, plan: FixPlan, application: PlanApplication
    ) -> SelfScanResult | None:
        """REQ-FIX-004: review the patched files with ARACHNE's own IaC scanner.

        Two temporary trees hold exactly the files the fix changes — one as the finding found
        them, one as the fix would leave them — because the question the requirement asks is
        "does this fix introduce a finding *of its own*", and only a before/after comparison
        answers it: the same file may already carry a second, unrelated misconfiguration that
        the fix neither caused nor claims to repair (see :mod:`arachne.fix.selfscan`).
        """
        if not plan.targets_iac or not application.applied:
            return None
        with tempfile.TemporaryDirectory(prefix="arachne-fix-selfscan-") as directory:
            base = Path(directory)
            before = base / "before"
            after = base / "after"
            for edit in application.files:
                for side, content in ((before, edit.before), (after, edit.after)):
                    target = side / edit.relative
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text(content, encoding="utf-8")
            return await self_scan_tree(
                self.services,
                after,
                changed_files=application.changed_paths,
                baseline_root=before,
            )

    def _record_refusal(
        self,
        common: Mapping[str, Any],
        *,
        status: str,
        reason: str,
        extra: Mapping[str, Any] | None = None,
        audit: AuditAction = AuditAction.FIX_PROPOSAL_REFUSED,
        now: datetime | None = None,
    ) -> FixProposalRecord:
        """Record a refusal as a first-class row (never a silently dropped proposal)."""
        store = self._require_store()
        payload = dict(common)
        meta = dict(payload.pop("meta_json", {}) or {})
        meta["refusal"] = reason
        if extra:
            meta.update(extra)
            if "plan" in extra:
                payload["plan_id"] = str(extra["plan"].get("id"))
                payload["kind"] = str(extra["plan"].get("kind"))
        payload["meta_json"] = meta
        payload["flagged_reason"] = reason
        record = store.add(**payload, status=status)
        self._audit(
            audit,
            record=record,
            outcome=AuditOutcome.BLOCKED,
            reason=reason,
            meta={"status": status},
        )
        return record

    # ------------------------------------------------------------------ the gate
    def approve(
        self, proposal_id: int, *, actor: str, now: datetime | None = None
    ) -> FixProposalRecord:
        """The human gate: without this, a proposal is never submitted (REQ-FIX-001)."""
        record = self._require(proposal_id)
        if record.status not in APPROVABLE:
            msg = (
                f"proposal {proposal_id} is {record.status!r}; only a proposed one can be approved"
            )
            raise FixProposalError(msg)
        if not record.has_artifact:
            msg = f"proposal {proposal_id} carries no artifact to approve"
            raise FixProposalError(msg)
        if not actor or not actor.strip():
            msg = "an approval must name the human approving it"
            raise FixProposalError(msg)
        updated = self._update(
            proposal_id,
            status="approved",
            approved_by=actor.strip(),
            approved_at=now or datetime.now(UTC),
        )
        self._audit(
            AuditAction.FIX_PROPOSAL_APPROVED,
            record=updated,
            reason=f"approved by {actor}",
            meta={"plan": record.plan_id, "files": list(record.targets)},
        )
        return updated

    def reject(self, proposal_id: int, *, actor: str, reason: str = "") -> FixProposalRecord:
        record = self._require(proposal_id)
        updated = self._update(
            proposal_id,
            status="rejected",
            rejected_by=actor.strip() or "operator",
            flagged_reason=reason or "rejected by the operator",
        )
        self._audit(
            AuditAction.FIX_PROPOSAL_REJECTED,
            record=updated,
            outcome=AuditOutcome.BLOCKED,
            reason=reason or "rejected by the operator",
            meta={"previous": record.status},
        )
        return updated

    def mark_applied(
        self, proposal_id: int, *, actor: str, now: datetime | None = None
    ) -> FixProposalRecord:
        """A human states the fix has landed — the precondition for the loop's re-scan."""
        record = self._require(proposal_id)
        if record.status not in (*SUBMITTABLE, "submitted"):
            msg = (
                f"proposal {proposal_id} is {record.status!r}; a fix can be marked applied "
                "only after it was approved (or submitted)"
            )
            raise FixProposalError(msg)
        if not actor or not actor.strip():
            msg = "marking a fix applied must name the human who applied it"
            raise FixProposalError(msg)
        updated = self._update(
            proposal_id,
            status="applied",
            applied_by=actor.strip(),
            applied_at=now or datetime.now(UTC),
        )
        self._audit(
            AuditAction.FIX_APPLIED,
            record=updated,
            reason=f"the fix was applied by {actor}",
            meta={"branch": record.branch, "plan": record.plan_id},
        )
        return updated

    # ------------------------------------------------------------------ repo mode
    def submit(
        self,
        proposal_id: int,
        *,
        actor: str = "operator",
        now: datetime | None = None,
    ) -> FixProposalRecord:
        """Tests first, then the dedicated branch and its PR artifact (REQ-FIX-002)."""
        del now
        record = self._require(proposal_id)
        if record.status not in SUBMITTABLE:
            msg = (
                f"proposal {proposal_id} is {record.status!r}; a submission needs an "
                "approval first (arachne fix approve)"
            )
            raise FixProposalError(msg)
        if record.manual_apply_required or not record.verbatim:
            msg = (
                f"proposal {proposal_id} is for manual application "
                f"({record.flagged_reason or 'a masked removal'}); ARACHNE will not commit it"
            )
            raise FixProposalError(msg)
        if record.plan_id is None:
            msg = f"proposal {proposal_id} carries no plan to apply"
            raise FixProposalError(msg)
        plan = self.plans.by_id(record.plan_id)
        if plan is None:
            msg = f"plan {record.plan_id!r} is no longer in the catalog"
            raise FixProposalError(msg)
        authorization = self.grants.resolve(record.asset_value or "")
        if authorization is None:
            msg = f"no fix-repo grant covers {record.asset_value!r} any more"
            raise FixProposalError(msg)
        root = authorization.root
        if not gitops.is_git_repo(root):
            msg = f"{root} is not a git work tree"
            raise FixProposalError(msg)

        application = apply_plan(
            plan, root, record.targets, max_files=authorization.grant.max_files
        )
        if not application.applied:
            msg = (
                f"the plan no longer applies to {root}: {application.reason}; "
                "a stale proposal is never submitted"
            )
            raise FixProposalError(msg)
        if application.diff() != (record.diff_text or ""):
            msg = (
                "the tree changed since this proposal was written, so the artifact a human "
                "approved is no longer the artifact on disk; re-propose instead"
            )
            raise FixProposalError(msg)

        base = gitops.head_commit(root)
        if base is None:
            msg = f"{root} has no commit to branch from"
            raise FixProposalError(msg)
        default_branch = authorization.grant.default_branch or gitops.current_branch(root)
        branch = proposal_branch_name(record.finding_id, record.plan_id)
        changes = {edit.relative: edit.after for edit in application.files}

        run = self._run_suite(root, authorization, base, changes)
        if run["outcome"] == "untestable" and not authorization.grant.allow_untestable:
            return self._flag(
                proposal_id,
                argv=authorization.grant.test_command,
                status="untestable",
                reason=(
                    "this repository declares no test command, so the patch cannot be proven "
                    "by its own suite; set test_command (and allow_untestable to accept the "
                    "risk) in the grant to proceed"
                ),
                request=run,
            )
        if run["outcome"] in {"tests-failed", "baseline-failing"}:
            return self._flag(
                proposal_id,
                argv=authorization.grant.test_command,
                status=str(run["outcome"]),
                reason=str(run["detail"]),
                request=run,
            )

        result = gitops.create_patch_branch(
            root,
            branch=branch,
            base=base,
            changes=changes,
            message=(
                f"fix: {plan.summary}\n\n"
                f"ARACHNE proposal #{proposal_id} for finding #{record.finding_id} "
                f"({record.check_key or 'unknown check'}).\n"
                "A human approved this artifact; ARACHNE never merges or applies it.\n"
            ),
            default_branch=default_branch,
            grant_name=authorization.name,
        )
        artifact = self._write_artifacts(
            record, application, run, test_command=authorization.grant.test_command
        )
        updated = self._update(
            proposal_id,
            status="submitted",
            branch=result.branch,
            commit=result.commit,
            base_commit=base,
            default_branch=default_branch,
            pr_artifact=artifact,
            test_command_json={
                "argv": list(authorization.grant.test_command),
                "baseline": run.get("baseline"),
                "patched": run.get("patched"),
            },
            test_outcome=str(run["outcome"]),
            test_output=str(run.get("output") or ""),
            meta_json={
                **dict(record.meta_json),
                "default_branch_unchanged": result.default_branch_unchanged,
                "head_unchanged": result.head_unchanged,
            },
        )
        self._audit(
            AuditAction.FIX_BRANCH_CREATED,
            record=updated,
            reason=f"created {result.branch} at {result.commit[:12]} in {authorization.name}",
            meta={
                "branch": result.branch,
                "commit": result.commit,
                "files": list(result.files),
                "default_branch": default_branch,
                "default_branch_unchanged": result.default_branch_unchanged,
            },
        )
        if artifact:
            self._audit(
                AuditAction.FIX_PR_OPENED,
                record=updated,
                reason=f"wrote the reviewable PR artifact to {artifact}",
                meta={"pr_artifact": artifact, "branch": result.branch},
            )
        del actor
        return updated

    def _run_suite(
        self,
        root: Path,
        authorization: RepoAuthorization,
        base: str,
        changes: Mapping[str, str],
    ) -> dict[str, Any]:
        """Run the repository's own suite on the base commit and then on the patch."""
        grant = authorization.grant
        if not grant.testable:
            return {"outcome": "untestable", "detail": "no test command is declared"}
        timeout = grant.test_timeout_seconds
        baseline: dict[str, Any] | None = None
        if grant.baseline_test_run:
            with gitops.WorktreeSession(repo=root, base=base) as scratch:
                run = gitops.run_declared_test(
                    grant.test_command[0], grant.test_command[1:], cwd=scratch, timeout=timeout
                )
            baseline = run.summary()
            if not run.passed:
                return {
                    "outcome": "baseline-failing",
                    "detail": (
                        "the repository's own suite already fails at "
                        f"{base[:12]} before the patch ({' '.join(grant.test_command)} → exit "
                        f"{run.exit_code}); ARACHNE will not claim a fix its tests cannot judge"
                    ),
                    "baseline": baseline,
                    "output": run.output_tail(),
                }
        with gitops.WorktreeSession(repo=root, base=base) as scratch:
            for relative, text in sorted(changes.items()):
                target = (scratch / relative).resolve()
                if scratch.resolve() not in target.parents:
                    return {
                        "outcome": "failed",
                        "detail": f"refusing to write {relative!r} outside the worktree",
                        "baseline": baseline,
                    }
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            run = gitops.run_declared_test(
                grant.test_command[0], grant.test_command[1:], cwd=scratch, timeout=timeout
            )
        if not run.passed:
            return {
                "outcome": "tests-failed",
                "detail": (
                    "the patch fails the repository's own suite "
                    f"({' '.join(grant.test_command)} → exit {run.exit_code}"
                    + (", timed out" if run.timed_out else "")
                    + "); flagged, not submitted (risk R-18)"
                ),
                "baseline": baseline,
                "patched": run.summary(),
                "output": run.output_tail(),
            }
        return {
            "outcome": "passed",
            "detail": "the patch passes the repository's own suite",
            "baseline": baseline,
            "patched": run.summary(),
            "output": run.output_tail(),
        }

    def _write_artifacts(
        self,
        record: FixProposalRecord,
        application: PlanApplication,
        run: Mapping[str, Any],
        *,
        test_command: tuple[str, ...],
    ) -> str | None:
        directory = self.artifacts_dir
        if directory is None:
            return None
        target = directory / f"proposal-{record.id}"
        target.mkdir(parents=True, exist_ok=True)
        patch = target / "patch.diff"
        patch.write_text(record.diff_text or application.diff(), encoding="utf-8")
        body = render_pr_body(
            record,
            verdict=_verdict_of(record),
            self_scan=_self_scan_of(record),
            test_command=test_command,
            test_outcome=str(run["outcome"]),
            reviewer_note=(
                "Apply with `git apply patch.diff` on the branch above, or review the branch "
                "directly. The patch passed the repository's own suite before this branch "
                "existed."
            ),
        )
        (target / "PR.md").write_text(body, encoding="utf-8")
        return str(target)

    def _flag(
        self,
        proposal_id: int,
        *,
        status: str,
        reason: str,
        request: Mapping[str, Any],
        argv: tuple[str, ...] = (),
    ) -> FixProposalRecord:
        updated = self._update(
            proposal_id,
            status=status,
            flagged_reason=reason,
            test_outcome=str(request.get("outcome") or status),
            test_command_json={
                "argv": list(argv),
                "baseline": request.get("baseline"),
                "patched": request.get("patched"),
            },
            test_output=str(request.get("output") or ""),
        )
        self._audit(
            AuditAction.FIX_TESTS_FAILED,
            record=updated,
            outcome=AuditOutcome.BLOCKED,
            reason=reason,
            meta={"status": status},
        )
        return updated

    # ------------------------------------------------------------------ the loop
    async def verify(
        self, proposal_id: int, *, actor: str = "operator", now: datetime | None = None
    ) -> FixProposalRecord:
        """REQ-FIX-005: the targeted re-scan that closes the finding the fix addressed."""
        from arachne.posture.verify import FixVerificationService

        record = self._require(proposal_id)
        if record.status not in VERIFIABLE:
            msg = (
                f"proposal {proposal_id} is {record.status!r}; the loop verifies a fix a human "
                "has marked applied (arachne fix applied)"
            )
            raise FixProposalError(msg)
        if record.finding_id is None:
            msg = f"proposal {proposal_id} is no longer linked to a finding"
            raise FixProposalError(msg)
        result = await FixVerificationService(self.services).verify(
            record.finding_id, actor=actor, now=now
        )
        verification_id = result.record.id if result.record is not None else None
        updated = self._update(
            proposal_id,
            status="verified" if result.closed else "still-open",
            verification_id=verification_id,
            verification_outcome=result.outcome,
            verification_scan_id=result.verification_scan_id,
        )
        self._audit(
            AuditAction.FIX_VERIFIED if result.closed else AuditAction.FIX_STILL_OPEN,
            record=updated,
            reason=result.detail,
            meta={
                "finding_id": record.finding_id,
                "verification_scan_id": result.verification_scan_id,
                "outcome": result.outcome,
            },
        )
        return updated

    # ------------------------------------------------------------------ reads
    def proposals(
        self,
        *,
        finding_id: int | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> tuple[FixProposalRecord, ...]:
        return self._require_store().proposals(finding_id=finding_id, status=status, limit=limit)

    def proposal(self, proposal_id: int) -> FixProposalRecord:
        return self._require(proposal_id)

    def summary(self) -> ProposalSummary:
        return ProposalSummary(counts=dict(self._require_store().counts()))

    def _require(self, proposal_id: int) -> FixProposalRecord:
        record = self._require_store().proposal(proposal_id)
        if record is None:
            msg = f"proposal {proposal_id} does not exist"
            raise FixProposalError(msg)
        return record

    def _update(self, proposal_id: int, **changes: Any) -> FixProposalRecord:
        updated = self._require_store().update(proposal_id, **changes)
        if updated is None:  # pragma: no cover - _require checked existence
            msg = f"proposal {proposal_id} disappeared during the update"
            raise FixProposalError(msg)
        return updated

    def _audit(
        self,
        action: AuditAction,
        *,
        record: FixProposalRecord,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        reason: str = "",
        meta: Mapping[str, Any] | None = None,
    ) -> None:
        self.auditor.record(
            action,
            outcome=outcome,
            scan_id=record.scan_id,
            target=f"proposal:{record.id}",
            reason=reason,
            meta={
                "finding_id": record.finding_id,
                "plan": record.plan_id,
                **dict(meta or {}),
            },
        )


def _as_str(value: Any) -> str | None:
    return str(value) if isinstance(value, (str, int, float)) else None


def _verdict_of(record: FixProposalRecord) -> DiffVerdict | None:
    payload = record.safety_json
    if not payload:
        return None
    return DiffVerdict(
        diff=record.diff_text or "",
        violations=tuple(str(item) for item in payload.get("violations") or ()),
        files=tuple(str(item) for item in payload.get("files") or ()),
        added_lines=int(payload.get("added_lines") or 0),
        removed_lines=int(payload.get("removed_lines") or 0),
        masked_lines=int(payload.get("masked_lines") or 0),
        verbatim=bool(payload.get("verbatim", True)),
    )


def _self_scan_of(record: FixProposalRecord) -> SelfScanResult | None:
    payload = record.self_scan_json
    if not payload:
        return None
    return SelfScanResult(
        required=bool(payload.get("required", False)),
        clean=bool(payload.get("clean", True)),
        scan_id=payload.get("scan_id") if isinstance(payload.get("scan_id"), int) else None,
        detail=str(payload.get("detail") or ""),
    )


def proposal_json(record: FixProposalRecord) -> str:
    """The CLI's machine-readable view of one proposal."""
    payload = record.to_dict()
    payload["diff"] = record.diff_text or ""
    payload["skipped"] = list(record.skipped)
    payload["test_output"] = record.test_output
    return json.dumps(payload, indent=2, default=str)


def propose_sync(
    services: ScanServices, finding_id: int, *, actor: str = "operator", **kwargs: Any
) -> FixProposalRecord:
    """Synchronous entry point for the CLI (the self-scan makes a proposal async)."""
    return asyncio.run(FixProposalEngine(services, **kwargs).propose(finding_id, actor=actor))


def verify_sync(
    services: ScanServices, proposal_id: int, *, actor: str = "operator", **kwargs: Any
) -> FixProposalRecord:
    return asyncio.run(FixProposalEngine(services, **kwargs).verify(proposal_id, actor=actor))
