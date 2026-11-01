"""Remediation as code (S27, area FIX).

ARACHNE proposes; a human decides; ARACHNE verifies. This package turns the remediation
catalog's *prose* (S8's ``analyzer/remediation.py``) into a reviewable **artifact** — a code
patch, an IaC/cloud config change — and drives it through a gate that ends where the fix
does: in the S23 fix-verification loop, where a targeted re-scan closes the finding.

The modules, and why each is separate:

==============================  ======================================================
``fix.plans``                   the fix-plan catalog: which class of finding maps to
                                which concrete edits, as data (never code)
``fix.patch``                   the pure patch engine: evidence → target files → a
                                unified diff, with every path check in one place
``fix.safety``                  the REQ-FIX-003 prohibitions, checked on the artifact
                                itself (secrets, deletions, mode changes, dependency
                                manifests, destructive lines, budgets)
``fix.grants``                  the operator's authorization, deny-by-default: no
                                grant file means no repository is fixable
``fix.gitops``                  the one module that touches git, on a throwaway
                                worktree, with a closed subcommand vocabulary
``fix.authoring``               the author seam and the dual-engine parity gate
                                (REQ-FIX-006)
``fix.selfscan``                ARACHNE's own IaC scanner, run over the patched files
                                (REQ-FIX-004)
``fix.proposal``                the engine: propose → approve → tests → branch →
                                verify, with the whole state machine in one file
==============================  ======================================================

Two invariants the package is built around, and neither is negotiable:

* **no effect outside ARACHNE without a named human approval** — a proposal is a database
  row and a diff until an approval names someone, and even then the only outside effect is a
  branch in an operator-granted repository;
* **no merging, no applying, no pushing to a default branch, ever** — there is no code path
  in this package that can do any of the three, and the process module's subcommand
  vocabulary makes them unrepresentable rather than merely unused.
"""

from __future__ import annotations

from arachne.fix.authoring import (
    AI_PARITY_DIVERGENCE,
    AiPatchAuthor,
    AuthorDraft,
    AuthorOutcome,
    AuthorRequest,
    ParityReport,
    PatchAuthor,
    TemplateAuthor,
    parity_report,
    resolve_draft,
)
from arachne.fix.grants import FixGrantSet, FixRepoGrant, RepoAuthorization, load_fix_grants
from arachne.fix.patch import FileEdit, PlanApplication, apply_plan, repo_root_of, resolve_targets
from arachne.fix.plans import (
    EditOp,
    FindingProfile,
    FixPlan,
    FixPlanCatalog,
    PlanSelection,
    PlanTargeting,
    load_fix_plan_catalog,
)
from arachne.fix.proposal import (
    PROPOSAL_STATUSES,
    FixProposalEngine,
    FixProposalError,
    propose_sync,
    render_pr_body,
    verify_sync,
)
from arachne.fix.safety import DEPENDENCY_MANIFESTS, DiffBudgets, DiffVerdict, analyze_diff
from arachne.fix.selfscan import SelfScanFinding, SelfScanResult, self_scan_tree

__all__ = [
    "AI_PARITY_DIVERGENCE",
    "DEPENDENCY_MANIFESTS",
    "PROPOSAL_STATUSES",
    "AiPatchAuthor",
    "AuthorDraft",
    "AuthorOutcome",
    "AuthorRequest",
    "DiffBudgets",
    "DiffVerdict",
    "EditOp",
    "FileEdit",
    "FindingProfile",
    "FixGrantSet",
    "FixPlan",
    "FixPlanCatalog",
    "FixProposalEngine",
    "FixProposalError",
    "FixRepoGrant",
    "ParityReport",
    "PatchAuthor",
    "PlanApplication",
    "PlanSelection",
    "PlanTargeting",
    "RepoAuthorization",
    "SelfScanFinding",
    "SelfScanResult",
    "TemplateAuthor",
    "analyze_diff",
    "apply_plan",
    "load_fix_grants",
    "load_fix_plan_catalog",
    "parity_report",
    "propose_sync",
    "render_pr_body",
    "repo_root_of",
    "resolve_draft",
    "resolve_targets",
    "self_scan_tree",
    "verify_sync",
]
