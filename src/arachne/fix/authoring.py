"""Patch authorship and the dual-engine parity gate (S27, REQ-FIX-006).

The template engine is the default author: a :class:`~arachne.fix.plans.FixPlan` from the
catalog plus the finding's own evidence produce the artifact deterministically. AI-assisted
authoring may *extend* that, under one rule that this module makes structural:

**a template-covered class is never authored by a model alone.** When a plan covers the
class, the artifact used is the plan's, and a configured AI author is run as a *second
engine* whose draft must be parity-equivalent — the same files changed, the same lines added
and removed. Agreement is recorded; divergence is recorded, flagged, and never silently
substituted. A class no plan covers may be authored by the model (if the deployment opted
in), and its draft then faces exactly the same gates as a template's: the diff-scope
analysis, the repository's own test suite, and ARACHNE's IaC self-scan.

The engine is injected (`PatchAuthor`), so the parity gate is testable with no provider
configured — which is also why `build_patch_author` returns ``None`` in a default
deployment: no prompt stage is shipped for patch authoring, so the template engine authors
every proposal and ``parity`` reads ``n/a``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from arachne.fix.patch import PlanApplication, apply_plan
from arachne.fix.plans import FindingProfile, FixPlan

__all__ = [
    "AI_PARITY_DIVERGENCE",
    "AiPatchAuthor",
    "AuthorDraft",
    "AuthorOutcome",
    "AuthorRequest",
    "ParityReport",
    "PatchAuthor",
    "TemplateAuthor",
    "change_set",
    "parity_report",
    "resolve_draft",
]

#: The flag raised when a second engine disagrees with the template for a covered class.
AI_PARITY_DIVERGENCE = "ai-parity-divergence"


@dataclass(frozen=True, slots=True)
class AuthorRequest:
    """Everything an author may see about one finding (and nothing else)."""

    profile: FindingProfile
    plan: FixPlan | None
    root: Path | None
    targets: tuple[str, ...]
    evidence: tuple[Mapping[str, object], ...] = ()
    remediation_summary: str = ""
    remediation_steps: tuple[str, ...] = ()
    mask_removals: bool = False


@dataclass(frozen=True, slots=True)
class AuthorDraft:
    """One engine's proposed artifact."""

    author: str
    diff: str
    plan_id: str | None = None
    rationale: str = ""
    application: PlanApplication | None = None


@runtime_checkable
class PatchAuthor(Protocol):
    """The author seam: a template engine, or a model behind it."""

    @property
    def name(self) -> str: ...

    def draft(self, request: AuthorRequest) -> AuthorDraft | None: ...


@dataclass(frozen=True, slots=True)
class TemplateAuthor:
    """The deterministic engine: a catalog plan applied to the finding's own target files."""

    name: str = "template"

    def draft(self, request: AuthorRequest) -> AuthorDraft | None:
        if request.plan is None or request.root is None:
            return None
        application = apply_plan(request.plan, request.root, request.targets)
        if not application.applied:
            return None
        return AuthorDraft(
            author=self.name,
            diff=application.diff(),
            plan_id=request.plan.id,
            rationale=request.plan.summary,
            application=application,
        )


@dataclass(frozen=True, slots=True)
class AiPatchAuthor:
    """A model-backed engine behind an injected callable.

    The callable receives the request and returns a unified diff (or ``None`` when the model
    declined or no provider is configured). Nothing here talks to a network: the seam is the
    callable, so a deployment wires its own transport and this module stays testable.
    """

    complete: Callable[[AuthorRequest], str | None]
    name: str = "ai"
    rationale: str = ""

    def draft(self, request: AuthorRequest) -> AuthorDraft | None:
        diff = self.complete(request)
        if not diff or not diff.strip():
            return None
        return AuthorDraft(
            author=self.name,
            diff=diff,
            plan_id=request.plan.id if request.plan else None,
            rationale=self.rationale or "AI-authored draft (dual-engine parity required)",
        )


@dataclass(frozen=True, slots=True)
class ParityReport:
    """Whether two engines produced the same change set, and where they did not."""

    equivalent: bool
    differences: tuple[str, ...] = ()
    files: tuple[str, ...] = ()

    def summary(self) -> dict[str, object]:
        return {
            "equivalent": self.equivalent,
            "differences": list(self.differences),
            "files": list(self.files),
        }


def change_set(diff: str) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """A diff as ``path → (added lines, removed lines)``, whitespace-normalized.

    Line order *within* a file is preserved (it is a change set, not a hunk set), and only
    the trailing whitespace is normalized — a reformatting is a real difference, an editor's
    trailing space is not.
    """
    current: str | None = None
    added: dict[str, list[str]] = {}
    removed: dict[str, list[str]] = {}
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            current = path[2:] if path.startswith("b/") else path
            added.setdefault(current, [])
            removed.setdefault(current, [])
            continue
        if current is None or line.startswith(("--- ", "@@", "diff ", "index ")):
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added[current].append(line[1:].rstrip())
        elif line.startswith("-") and not line.startswith("---"):
            removed[current].append(line[1:].rstrip())
    return {
        path: (tuple(added.get(path, ())), tuple(removed.get(path, ())))
        for path in sorted(set(added) | set(removed))
    }


def parity_report(template_diff: str, ai_diff: str) -> ParityReport:
    """Compare two engines' artifacts by change set (see :func:`change_set`)."""
    left = change_set(template_diff)
    right = change_set(ai_diff)
    differences: list[str] = []
    for path in sorted(set(left) | set(right)):
        if path not in left:
            differences.append(f"{path}: only the second engine changed this file")
            continue
        if path not in right:
            differences.append(f"{path}: only the template engine changed this file")
            continue
        left_added, left_removed = left[path]
        right_added, right_removed = right[path]
        if sorted(left_added) != sorted(right_added):
            differences.append(f"{path}: the two engines add different lines")
        if sorted(left_removed) != sorted(right_removed):
            differences.append(f"{path}: the two engines remove different lines")
    return ParityReport(
        equivalent=not differences,
        differences=tuple(differences),
        files=tuple(sorted(set(left) | set(right))),
    )


@dataclass(frozen=True, slots=True)
class AuthorOutcome:
    """What the engine resolved to, and what the second engine had to say about it."""

    draft: AuthorDraft | None
    engine: str = "template"
    #: ``n/a`` (one engine), ``ok``, ``failed``, or ``not-covered`` (no plan exists).
    parity: str = "n/a"
    parity_detail: str = ""
    flags: tuple[str, ...] = field(default=())


def resolve_draft(
    request: AuthorRequest,
    *,
    template: PatchAuthor | None = None,
    ai: PatchAuthor | None = None,
    allow_beyond_templates: bool = False,
) -> AuthorOutcome:
    """Pick the artifact for one finding, applying the parity rule (see the module docstring)."""
    template_author = template if template is not None else TemplateAuthor()
    template_draft = template_author.draft(request)
    covers = request.plan is not None

    if covers:
        if ai is None:
            return AuthorOutcome(draft=template_draft, engine="template", parity="n/a")
        ai_draft = ai.draft(request)
        if ai_draft is None or template_draft is None:
            return AuthorOutcome(
                draft=template_draft,
                engine="template",
                parity="n/a",
                parity_detail="the second engine produced no draft to compare",
            )
        report = parity_report(template_draft.diff, ai_draft.diff)
        if report.equivalent:
            return AuthorOutcome(
                draft=template_draft,
                engine="template",
                parity="ok",
                parity_detail=(
                    f"{ai.name} agreed with the template on change set "
                    f"({len(report.files)} file(s))"
                ),
            )
        return AuthorOutcome(
            draft=template_draft,
            engine="template",
            parity="failed",
            parity_detail=f"{ai.name}: " + "; ".join(report.differences),
            flags=(AI_PARITY_DIVERGENCE,),
        )

    # No plan covers this class: only an opted-in deployment lets a model author it.
    if ai is None or not allow_beyond_templates:
        return AuthorOutcome(draft=None, engine="none", parity="not-covered")
    ai_draft = ai.draft(request)
    return AuthorOutcome(draft=ai_draft, engine=ai.name, parity="not-covered")


def build_patch_author(
    *, enabled: bool, complete: Callable[[AuthorRequest], str | None] | None = None
) -> PatchAuthor | None:
    """The configured AI author, or ``None``.

    ``None`` is the default and the honest state of this deployment: no prompt stage is
    shipped for patch authoring, so nothing calls a model. An operator's own integration
    passes its callable in (the seam above), which is what the parity tests exercise.
    """
    if not enabled or complete is None:
        return None
    return AiPatchAuthor(complete=complete)
