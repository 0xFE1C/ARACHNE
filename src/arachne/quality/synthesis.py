"""Feed-driven check synthesis: proposals, never deployments (REQ-AGENT-004).

The requirement's verbs are precise, and each one is a design decision here:

**Feed-driven.** A synthesis run starts from *threat-intel data* — a KEV entry, an NVD record —
not from a model's imagination. The :class:`FeedHint` carries the CVE, the product and the
description; that is the whole input, and it is data an operator can see and check.

**Reviewable.** A :class:`CheckProposal` is a directory of artefacts: a catalogue row (the YAML
the planner loads), a *test scaffold* (the pytest module a developer fills in, with the
ground-truth marker the check must match), and a review checklist. A human reads it or it does
not ship.

**Tested.** A proposal is not approvable without a parity report: :func:`approve` refuses one
that has not been through the harness, because "every change MUST pass parity" is the
requirement's own condition on this loop.

**Versioned.** Every proposal names the version it supersedes and the version it proposes
(a MINOR bump: new detection capability, same check identity), and the manifest records the
catalogue version it was generated against.

**Never auto-deployed.** This is structural, not a promise. The synthesizer can only *write
files*; there is no code path from here into ``ModuleRegistry``. :func:`write_artifacts`
additionally refuses to write into the package's own template directory — the one place a
file would be picked up as a live check — so an operator has to move an approved artefact into
place deliberately. The registry's own tests then reject a check whose metadata the catalogue
does not describe, which is the second lock on the same door.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from arachne.core.errors import ConfigurationError

__all__ = [
    "SYNTHESIS_VERSION",
    "CheckProposal",
    "CheckSynthesizer",
    "FeedHint",
    "ParityEvidence",
    "approve",
    "write_artifacts",
]

#: Bumped when the manifest or the artefact layout changes.
SYNTHESIS_VERSION: Final = "1.0"

_MODEL = ConfigDict(frozen=True, extra="forbid")

#: The catalogue's own file, relative to the package — the one path synthesis must not write.
_LIVE_CATALOGUE_HINT: Final = "templates/plan/check_catalog.yaml"

_CVE_RE: Final = re.compile(r"^CVE-\d{4}-\d{4,}$")
_NAME_RE: Final = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class FeedHint(BaseModel):
    """One threat-intel record a proposal can be based on (KEV, NVD, an advisory)."""

    model_config = _MODEL

    cve: str
    product: str = Field(default="", max_length=200)
    summary: str = Field(default="", max_length=2000)
    source: str = Field(default="feed", max_length=64)
    known_exploited: bool = False
    cvss: float | None = None

    def model_post_init(self, __context: Any) -> None:
        if not _CVE_RE.match(self.cve):
            msg = f"{self.cve!r} is not a CVE id (CVE-YYYY-NNNN)"
            raise ValueError(msg)


class ParityEvidence(BaseModel):
    """The benchmark/parity result a proposal must carry before it can be approved."""

    model_config = _MODEL

    ok: bool
    suite: str = ""
    detail: str = Field(default="", max_length=1000)
    measured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class CheckProposal(BaseModel):
    """A reviewable suggestion to add or bump one check."""

    model_config = _MODEL

    id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    based_on: FeedHint
    module: str = "M2"
    name: str
    #: ``None`` for a brand-new check; the live version when this bumps an existing one.
    previous_version: str | None = None
    proposed_version: str
    title: str = Field(max_length=512)
    description: str = Field(max_length=2000)
    research_ref: str = "ch02#1"
    cwe: str | None = "CWE-1395"
    target_kinds: tuple[str, ...] = ("host",)
    estimated_requests: int = 2
    requires_active_checks: bool = False
    proof: str = "L1"
    rationale: str = Field(default="", max_length=2000)
    #: ``proposed`` → ``approved`` (parity recorded) → shipped by a human (outside this module).
    status: Literal["proposed", "approved"] = "proposed"
    parity: ParityEvidence | None = None
    approved_by: str | None = None
    catalogue_version: str = ""

    @property
    def check_id(self) -> str:
        return f"{self.module.lower()}.{self.name}"

    @property
    def bumped(self) -> bool:
        """True when this proposal supersedes a live check (a version bump, not an addition)."""
        return self.previous_version is not None

    def catalogue_row(self) -> dict[str, Any]:
        """The catalogue row an operator would merge (the planner's own format)."""
        return {
            "module": self.module,
            "name": self.name,
            "version": self.proposed_version,
            "title": self.title,
            "description": self.description,
            "research_ref": self.research_ref,
            "cwe": self.cwe,
            "target_kinds": list(self.target_kinds),
            "estimated_requests": self.estimated_requests,
            "requires_active_checks": self.requires_active_checks,
            "proof": self.proof,
        }

    def to_dict(self) -> dict[str, Any]:
        """The proposal document written to disk, with its derived views for the reviewer."""
        document = self.model_dump(mode="json")
        document["check_id"] = self.check_id
        document["catalogue_row"] = self.catalogue_row()
        return document

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> CheckProposal:
        """Rebuild from a written document, ignoring the derived views it carries."""
        payload = {
            key: value
            for key, value in dict(document).items()
            if key not in {"check_id", "catalogue_row"}
        }
        return cls.model_validate(payload)


class CheckSynthesizer:
    """Turns feed records into proposals. It cannot touch the registry, by construction."""

    def __init__(self, *, catalogue_version: str = "", module: str = "M2") -> None:
        self.catalogue_version = catalogue_version
        self.module = module

    def propose(
        self,
        hints: Iterable[FeedHint],
        *,
        existing_versions: dict[str, str] | None = None,
    ) -> tuple[CheckProposal, ...]:
        """One proposal per feed record whose product can be fingerprinted."""
        versions = dict(existing_versions or {})
        out: list[CheckProposal] = []
        seen: set[str] = set()
        for hint in sorted(hints, key=lambda item: item.cve):
            name = _check_name_for(hint)
            if not _NAME_RE.match(name) or name in seen:
                continue
            seen.add(name)
            previous = versions.get(f"{self.module.lower()}.{name}")
            out.append(
                CheckProposal(
                    id=f"proposal-{self.module.lower()}-{name}",
                    based_on=hint,
                    module=self.module,
                    name=name,
                    previous_version=previous,
                    proposed_version=_bump(previous),
                    title=f"{hint.product or hint.cve} affected by {hint.cve}",
                    description=(
                        (hint.summary or f"{hint.cve} affects {hint.product or 'the product'}.")
                        + f" Detected by fingerprinting the product and comparing its version "
                        f"against {hint.cve}."
                    )[:2000],
                    rationale=(
                        f"derived from {hint.source} "
                        f"({'known exploited' if hint.known_exploited else 'advisory'})"
                    ),
                    catalogue_version=self.catalogue_version,
                )
            )
        return tuple(out)

    # ------------------------------------------------------------------ artefacts
    def write(self, proposals: Sequence[CheckProposal], directory: str | Path) -> Path:
        return write_artifacts(proposals, directory)


def _check_name_for(hint: FeedHint) -> str:
    """``CVE-2021-44228`` on ``Apache Log4j`` → ``cve-2021-44228-apache-log4j``."""
    parts = hint.cve.split("-")
    year, number = parts[1], parts[2]
    product_slug = re.sub(r"[^a-z0-9]+", "-", hint.product.lower()).strip("-") or "product"
    return f"cve-{year}-{number}-{product_slug}"[:120]


def _bump(previous: str | None) -> str:
    """MINOR bump for an existing check ('1.2' → '1.3'), '0.1.0' for a new one."""
    if previous is None:
        return "0.1.0"
    parts = previous.split(".")
    try:
        numbers = [int(part) for part in parts]
    except ValueError as exc:  # pragma: no cover - a malformed live version is a build defect
        raise ConfigurationError(f"cannot bump a malformed check version {previous!r}") from exc
    while len(numbers) < 3:
        numbers.append(0)
    return f"{numbers[0]}.{numbers[1] + 1}.0"


def approve(
    proposal: CheckProposal, *, parity: ParityEvidence, reviewer: str
) -> CheckProposal:
    """Record a review: parity must have passed, and the approver is named (REQ-AGENT-004)."""
    if not parity.ok:
        raise ConfigurationError(
            "this proposal has not passed parity; a synthesized check is never approved "
            "without it (REQ-AGENT-004)"
        )
    if not reviewer.strip():
        raise ConfigurationError("an approval needs a named reviewer")
    return proposal.model_copy(
        update={"status": "approved", "parity": parity, "approved_by": reviewer.strip()}
    )


# --------------------------------------------------------------------------- artefacts


def write_artifacts(proposals: Sequence[CheckProposal], directory: str | Path) -> Path:
    """Write the reviewable artefacts and a manifest; return the manifest path.

    Refuses to write into the shipped catalogue directory (see the module docstring): the one
    path that would make a proposal live is the one path this function will not accept.
    """
    target = Path(directory).expanduser()
    resolved = target.resolve()
    if resolved.name == "plan" and resolved.parent.name == "templates":
        raise ConfigurationError(
            "refusing to write synthesized checks into the shipped catalogue directory: a "
            "proposal is reviewed and moved into place by a human, never deployed by a script"
        )
    if _LIVE_CATALOGUE_HINT in str(resolved):
        raise ConfigurationError(
            "refusing to write a synthesized check into the live catalogue path"
        )
    target.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, Any]] = []
    for proposal in proposals:
        folder = target / proposal.check_id
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "check.yaml").write_text(
            yaml.safe_dump(proposal.catalogue_row(), sort_keys=False), encoding="utf-8"
        )
        (folder / "test_proposed_check.py").write_text(
            _test_scaffold(proposal), encoding="utf-8"
        )
        (folder / "REVIEW.md").write_text(_review_notes(proposal), encoding="utf-8")
        (folder / "proposal.json").write_text(
            json.dumps(proposal.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        entries.append(
            {
                "check_id": proposal.check_id,
                "proposed_version": proposal.proposed_version,
                "previous_version": proposal.previous_version,
                "status": proposal.status,
                "cve": proposal.based_on.cve,
            }
        )
    manifest = {
        "version": SYNTHESIS_VERSION,
        "catalogue_version": proposals[0].catalogue_version if proposals else "",
        "generated_at": datetime.now(UTC).isoformat(),
        "proposals": entries,
        "deployed": False,
        "note": (
            "Synthesized checks are proposals. Review, run parity, then move the approved row "
            "into templates/plan/check_catalog.yaml and implement the check yourself."
        ),
    }
    path = target / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _test_scaffold(proposal: CheckProposal) -> str:
    """The pytest module a developer fills in: the marker the check must match, and its absence."""
    return (
        '"""Scaffold generated by `arachne synthesize` (S21, REQ-AGENT-004).\n\n'
        f"Proposed check: {proposal.check_id} {proposal.proposed_version}\n"
        f"Based on: {proposal.based_on.cve} ({proposal.based_on.source})\n\n"
        "Fill in the fixtures: the vulnerable response must raise the candidate, and the\n"
        'hardened counterpart must not. Until then this module fails, by design.\n'
        '"""\n\n'
        "from __future__ import annotations\n\n"
        "import pytest\n\n"
        f"CHECK_ID = {proposal.check_id!r}\n"
        f"VULNERABLE_MARKER = {proposal.based_on.cve!r}\n\n\n"
        "def test_the_vulnerable_fixture_is_reported(lab) -> None:\n"
        f'    """The {proposal.based_on.cve} fixture must produce a candidate."""\n'
        '    pytest.fail("implement: run the check against the vulnerable fixture")\n\n\n'
        "def test_the_hardened_fixture_is_not_reported(lab) -> None:\n"
        '    """The patched product must not be reported (false-positive guard)."""\n'
        '    pytest.fail("implement: run the check against the hardened fixture")\n\n\n'
        "def test_the_check_declares_the_proposed_version() -> None:\n"
        f'    """The version must be {proposal.proposed_version} — a synthesis always bumps."""\n'
        "    pytest.fail('implement: assert the registered metadata version')\n"
    )


def _review_notes(proposal: CheckProposal) -> str:
    """The checklist a reviewer works through before the row goes anywhere near the catalogue."""
    return (
        f"# Review — {proposal.check_id} {proposal.proposed_version}\n\n"
        f"- Source: {proposal.based_on.source}, {proposal.based_on.cve}"
        + (" (known exploited)" if proposal.based_on.known_exploited else "")
        + "\n"
        f"- Supersedes: {proposal.previous_version or 'nothing (a new check)'}\n"
        f"- Proposed version: {proposal.proposed_version}\n"
        f"- Proof level: {proposal.proof}\n"
        f"- Catalogue version generated against: {proposal.catalogue_version or 'unknown'}\n\n"
        "Checklist (REQ-AGENT-004):\n\n"
        "1. The detection is testable offline from a recorded fixture — no live vendor needed.\n"
        "2. The hardened counterpart is a false-positive test, and it passes.\n"
        "3. The check is passive (L0/L1) unless the proof ladder justifies more.\n"
        "4. The version was bumped, and parity was run (`python -m arachne.tools.benchmark\n"
        "   --lab --gate`) with the result recorded.\n"
        "5. The catalogue row was merged by a human, and the check was implemented — this\n"
        "   artefact is a proposal, not an implementation.\n"
    )
