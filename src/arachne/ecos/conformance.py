"""The conformance kit: what a candidate check has to prove before it can be merged (REQ-ECOS-007).

``.spec/05-detection-program.md`` §2.2 lists seven properties every check must have and says
each is "asserted by the conformance kit". This module is that kit. It reads a candidate's
conformance manifest (:mod:`arachne.ecos.sdk`), loads the check, and returns a report of
blocking and advisory defects — the four classes the requirement names, each with a message
that says what to do:

``mapping``
    No framework mapping. A check the ledger cannot see is invisible to every buyer and to the
    coverage gate (REQ-DET-002), and a mapping id outside the pinned snapshot claims a test
    that does not exist.
``proof``
    L2+ declared without the opt-in it requires, or L3/L4 without the state-change attestation
    (REQ-PROOF-001, INV-5). The proof ladder is the capability boundary; a check that reaches
    past its declared level is the defect the ladder exists to catch.
``decoy``
    No assigned false-positive trap, or a decoy the check fires on. §7 of the detection
    programme refuses a check whose oracle the decoy can fool, so "no decoy" and "dirty decoy"
    are refusal reasons, not warnings.
``evidence``
    A finding with no verification-relevant evidence. Spec §7's *Evidence* row asks "could a
    human confirm this manually?" and rejects status-code-only evidence; a check whose finding
    cannot be confirmed by hand is a rumour with a severity.

Three further defects the kit reports are not in the required four but are free once the check
is loaded, and each is a refusal reason in §7 or in the registry itself: a candidate that
collides with a built-in check id (**collision** — a pack may add checks, never replace one), a
fixture that does not record what the check requests (**fixture gap** — a verdict about a
fabricated 501), and a non-deterministic verdict (**determinism** — §2.2 rule 3: two runs
against the same fixture must agree). A capability defect (**capability**) is a check whose
source uses a construct a plugin is not granted: a process, a raw socket, dynamic code, FFI or
unpickling. That scan is the one :mod:`arachne.plugins.review` performs on a content pack —
reused rather than re-written, so there is exactly one policy table in the tree.

**The kit imports the candidate, so it scans it first.** ``load_check`` executes module-level
code; the capability scan runs on the source *before* the import and a candidate that fails it
is not imported at all. That ordering is the whole reason the policy gate is first and why the
report can say "refused without running it".
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal

import yaml

from arachne.core.errors import ConfigurationError
from arachne.core.proof import ProofLevel, metadata_proof_problems
from arachne.core.results import Evidence
from arachne.ecos.sdk import (
    ConformanceManifest,
    FixtureGapError,
    FixtureRun,
    load_check,
    load_manifest,
    replay_fixture,
    run_fixture,
)
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.framework_map import validate_items
from arachne.modules.registry import ModuleRegistry

__all__ = [
    "DEFECT_CLASSES",
    "REPORT_FORMAT",
    "VERIFICATION_EVIDENCE_KINDS",
    "ConformanceDefect",
    "ConformanceGate",
    "ConformanceReport",
    "conform",
    "conform_json",
    "metadata_proof_defects",
    "verification_relevant",
]

#: Tag for a conformance report; bump when its meaning changes.
REPORT_FORMAT: Final = "arachne-check-conformance-report/1"

Severity = Literal["block", "warn"]

#: Evidence kinds a reviewer can use to confirm a claim by hand. A ``note`` is deliberately
#: absent: an observation the check made about itself is not something a human can check
#: against the target, which is what spec §7's *Evidence* row asks for.
VERIFICATION_EVIDENCE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "http_request",
        "http_response",
        "banner",
        "file_path",
        "artifact",
        "tls_certificate",
        "proof",
    }
)

#: Payload keys that carry no verification content on their own. A finding whose whole evidence
#: is ``{"status_code": 200}`` says "something answered" — the rejection example in spec §7.
_NON_SUBSTANTIVE_KEYS: Final[frozenset[str]] = frozenset(
    {"status", "status_code", "truncated", "binary", "elapsed_ms", "captured_at", "attempts"}
)

DEFECT_MAPPING: Final = "conformance.mapping_missing"
DEFECT_PROOF: Final = "conformance.proof_not_optin"
DEFECT_DECOY: Final = "conformance.decoy_missing"
DEFECT_EVIDENCE: Final = "conformance.evidence_missing"

#: Every defect code, and the defect *class* it belongs to. The four required classes are
#: ``mapping``, ``proof``, ``decoy`` and ``evidence``; the rest are reported because the kit
#: has the check loaded and each one is a refusal reason in its own right.
DEFECT_CLASSES: Final[dict[str, str]] = {
    "conformance.mapping_missing": "mapping",
    "conformance.mapping_invalid": "mapping",
    "conformance.mapping_drift": "mapping",
    "conformance.proof_not_optin": "proof",
    "conformance.decoy_missing": "decoy",
    "conformance.decoy_dirty": "decoy",
    "conformance.evidence_missing": "evidence",
    "conformance.evidence_thin": "evidence",
    "conformance.registry_collision": "collision",
    "conformance.fixture_gap": "fixture",
    "conformance.nondeterministic": "determinism",
    "conformance.capability": "capability",
    "conformance.check_unloadable": "loadable",
}

#: The four classes REQ-ECOS-007 requires the kit to reject.
REQUIRED_CLASSES: Final[tuple[str, ...]] = ("mapping", "proof", "decoy", "evidence")


def verification_relevant(evidence: Evidence) -> bool:
    """True when ``evidence`` is something a reviewer could use to confirm the claim.

    Two conditions, both necessary: the *kind* must be one a human can follow (a captured
    exchange, a certificate, an artifact — not a note), and the payload must carry something
    beyond "something answered" — a body, headers, a banner, a path, a digest. A status code
    alone fails the second condition, which is exactly the rejection example in
    ``.spec/05-detection-program.md`` §7.
    """
    if evidence.kind not in VERIFICATION_EVIDENCE_KINDS:
        return False
    substantive = {
        key: value for key, value in evidence.payload.items() if key not in _NON_SUBSTANTIVE_KEYS
    }
    return any(_has_content(value) for value in substantive.values())


def _has_content(value: Any) -> bool:
    """True when ``value`` carries information (a non-empty string, a non-empty container)."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, Mapping):
        return any(_has_content(item) for item in value.values())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(_has_content(item) for item in value)
    # A bool is a flag about something else, never information a reviewer can check.
    return not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class ConformanceDefect:
    """One thing the candidate must fix, the class it belongs to and where it was seen."""

    code: str
    severity: Severity
    message: str
    path: str = ""
    line: int = 0

    @property
    def defect_class(self) -> str:
        return DEFECT_CLASSES.get(self.code, "other")

    @property
    def actionable(self) -> bool:
        """True when the message tells the author what to change (every kit message does)."""
        return bool(self.message.strip()) and len(self.message.strip().split()) >= 5

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "class": self.defect_class,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "line": self.line,
        }


@dataclass(frozen=True, slots=True)
class ConformanceGate:
    """One part of the kit's verdict, with everything it has to say about it."""

    gate: str
    passed: bool
    detail: str = ""
    defects: tuple[ConformanceDefect, ...] = ()

    @property
    def blockers(self) -> tuple[ConformanceDefect, ...]:
        return tuple(item for item in self.defects if item.severity == "block")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "gate": self.gate,
            "passed": self.passed,
            "detail": self.detail,
        }
        if self.defects:
            payload["defects"] = [item.to_dict() for item in self.defects]
        return payload


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    """The kit's verdict on one candidate check."""

    check: str
    source: str
    gates: tuple[ConformanceGate, ...] = ()
    format: str = REPORT_FORMAT

    @property
    def conformant(self) -> bool:
        """True only when every gate passed — there is no partial conformance."""
        return all(gate.passed for gate in self.gates)

    @property
    def blockers(self) -> tuple[ConformanceDefect, ...]:
        return tuple(item for gate in self.gates for item in gate.blockers)

    @property
    def defect_classes(self) -> tuple[str, ...]:
        """The distinct defect classes present, sorted (what the gate reports)."""
        return tuple(sorted({item.defect_class for item in self.blockers}))

    @property
    def actionable(self) -> bool:
        """True when every blocking defect explains what to change."""
        return all(item.actionable for item in self.blockers)

    def gate(self, name: str) -> ConformanceGate | None:
        for item in self.gates:
            if item.gate == name:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "check": self.check,
            "source": self.source,
            "conformant": self.conformant,
            "defect_classes": list(self.defect_classes),
            "gates": [gate.to_dict() for gate in self.gates],
        }


# --------------------------------------------------------------------------- entry point
def conform(manifest: ConformanceManifest | str | Path) -> ConformanceReport:
    """Run every gate over the candidate the manifest describes.

    The gates run in this order for a reason: the capability scan reads the *source*, so a
    candidate that uses a primitive a plugin is not granted is refused without being imported
    at all. Everything after it may therefore import the check and reason about real metadata
    and real verdicts rather than guesses from the text.
    """
    loaded = manifest if isinstance(manifest, ConformanceManifest) else load_manifest(manifest)
    source = loaded.module_file
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        defect = ConformanceDefect(
            code="conformance.check_unloadable",
            severity="block",
            message=(
                f"cannot read {source}: {exc}. The manifest's module_file must point at the "
                "Python file that defines the check"
            ),
            path=str(source),
        )
        return ConformanceReport(
            check=loaded.check,
            source=loaded.source,
            gates=(ConformanceGate("capability", False, str(exc), (defect,)),),
        )
    policy = _capability_gate(text, source)
    if not policy.passed:
        # Refused without importing: the candidate's module-level code never runs.
        return ConformanceReport(check=loaded.check, source=loaded.source, gates=(policy,))
    try:
        check = load_check(loaded)
    except Exception as exc:  # a candidate that raises on import is a defect, not a crash
        defect = ConformanceDefect(
            code="conformance.check_unloadable",
            severity="block",
            message=(
                f"the check could not be imported: {exc.__class__.__name__}: {exc}. A candidate "
                "whose module body raises cannot be reviewed; fix the import error and run the "
                "kit again"
            ),
            path=str(source),
        )
        return ConformanceReport(
            check=loaded.check,
            source=loaded.source,
            gates=(policy, ConformanceGate("metadata", False, str(exc), (defect,))),
        )
    metadata = check.metadata
    declarations = _mapping_gate(loaded, metadata)
    behaviour = _behaviour_gate(loaded, check)
    return ConformanceReport(
        check=metadata.id,
        source=loaded.source,
        gates=(policy, declarations, behaviour),
    )


def conform_json(report: ConformanceReport) -> str:
    """Deterministic JSON for a conformance report (the CLI's ``--json`` form)."""
    return json.dumps(report.to_dict(), indent=2, sort_keys=False, default=str) + "\n"


# --------------------------------------------------------------------------- gates
def _capability_gate(text: str, source: Path) -> ConformanceGate:
    """Scan the candidate's source before importing it (the plugin capability policy)."""
    from arachne.plugins.review import scan_python_source

    findings = scan_python_source(text, path=str(source))
    defects = tuple(
        ConformanceDefect(
            code="conformance.capability",
            severity="block",
            message=(
                f"{item.message}. A check reaches the network through ctx.http (the shared "
                "scoped client) and is not granted processes, raw sockets, dynamic code, FFI "
                "or unpickling; the candidate was refused without being imported"
            ),
            path=item.path or str(source),
            line=item.line,
        )
        for item in findings
        if item.severity == "block"
    )
    return ConformanceGate(
        gate="capability",
        passed=not defects,
        detail=(f"{len(defects)} blocking capability finding(s)" if defects else "source scanned"),
        defects=defects,
    )


def metadata_proof_defects(metadata: CheckMetadata) -> tuple[ConformanceDefect, ...]:
    """Proof-ladder contradictions read from the metadata object as it stands.

    :class:`CheckMetadata` refuses a contradiction at construction, and
    :class:`~arachne.modules.registry.ModuleGroup` re-checks every declaration when a group is
    built — so on an ordinarily loaded candidate this is empty. It is asked anyway, and it is
    public so it is testable in isolation: the kit's input is a *candidate*, and a metadata
    object mutated after construction (or one whose module defines no group at all, so the
    registry's re-check never ran) must be refused by the kit rather than trusted because the
    constructor usually runs.
    """
    problems = metadata_proof_problems(
        metadata.proof,
        enabled_by_default=metadata.enabled_by_default,
        requires_state_attestation=metadata.requires_state_attestation,
    )
    return tuple(
        ConformanceDefect(
            code=DEFECT_PROOF,
            severity="block",
            message=(
                f"{problem}. An L2+ check is opt-in by definition (enabled_by_default = False) "
                "and an L3/L4 check additionally requires the state-change attestation; declare "
                "the level that matches what the check actually does"
            ),
        )
        for problem in problems
    )


def _mapping_gate(manifest: ConformanceManifest, metadata: CheckMetadata) -> ConformanceGate:
    """The metadata, proof and mapping-entry rules (REQ-DET-002, REQ-PROOF-001)."""
    defects: list[ConformanceDefect] = []
    if not metadata.framework:
        defects.append(
            ConformanceDefect(
                code=DEFECT_MAPPING,
                severity="block",
                message=(
                    f"check {metadata.id!r} declares no framework mapping. Name at least one "
                    "WSTG, API, CWE, ATT&CK, LLM or ASI item in `framework = (...)` and in the "
                    "mapping entry: the registry refuses an unmapped check, and no coverage "
                    "report can see one"
                ),
            )
        )
    else:
        for problem in validate_items(metadata.framework):
            defects.append(
                ConformanceDefect(
                    code="conformance.mapping_invalid",
                    severity="block",
                    message=(
                        f"{problem}. Take the id from the pinned snapshot the message names, or "
                        "drop it: a mapping may only claim a test that exists"
                    ),
                )
            )
    proof_problems = metadata_proof_defects(metadata)
    defects.extend(proof_problems)
    defects.extend(_mapping_entry_defects(manifest, metadata))
    defects.extend(_registry_defects(metadata))
    return ConformanceGate(
        gate="metadata",
        passed=not any(item.severity == "block" for item in defects),
        detail=f"{len(metadata.framework)} framework item(s), proof {metadata.proof.value}",
        defects=tuple(defects),
    )


def _registry_defects(metadata: CheckMetadata) -> list[ConformanceDefect]:
    """A candidate may add a check, never replace one (the registry's own rule).

    ``ModuleRegistry.add`` refuses a duplicate id, which is the enforcement; asking here means
    the author is told *before* they install the package, and by the kit rather than by a
    traceback at import time.
    """
    if metadata.id not in ModuleRegistry.builtin().check_ids():
        return []
    return [
        ConformanceDefect(
            code="conformance.registry_collision",
            severity="block",
            message=(
                f"check id {metadata.id!r} already exists in the built-in catalogue. A plugin "
                "adds checks, it never replaces one; choose a free id"
            ),
        )
    ]


def _mapping_entry_defects(
    manifest: ConformanceManifest, metadata: CheckMetadata
) -> list[ConformanceDefect]:
    """The mapping entry is present, valid, and agrees with the metadata it was generated from."""
    if manifest.mapping is None:
        return [
            ConformanceDefect(
                code=DEFECT_MAPPING,
                severity="block",
                message=(
                    "the conformance manifest declares no mapping entry. Add "
                    "`mapping: mappings/<name>.yaml` and the file it names: the mapping entry "
                    "is the check's declaration of what it covers, and the kit reads it to "
                    "detect drift from the metadata"
                ),
            )
        ]
    path = manifest.mapping
    if not path.is_file():
        return [
            ConformanceDefect(
                code=DEFECT_MAPPING,
                severity="block",
                message=(
                    f"the manifest declares mapping {path}, which does not exist. Write it "
                    "(regenerate it from the metadata) or drop the declaration"
                ),
                path=str(path),
            )
        ]
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return [
            ConformanceDefect(
                code=DEFECT_MAPPING,
                severity="block",
                message=f"the mapping entry {path} is not valid YAML: {exc}.",
                path=str(path),
            )
        ]
    if not isinstance(document, Mapping):
        return [
            ConformanceDefect(
                code=DEFECT_MAPPING,
                severity="block",
                message=f"the mapping entry {path} must be a mapping with a `framework` list.",
                path=str(path),
            )
        ]
    declared = _declared_items(document)
    if not declared:
        return [
            ConformanceDefect(
                code=DEFECT_MAPPING,
                severity="block",
                message=(
                    f"the mapping entry {path} declares an empty `framework` list. Its "
                    "`framework:` must list every item the check's metadata declares"
                ),
                path=str(path),
            )
        ]
    defects: list[ConformanceDefect] = []
    for problem in validate_items(declared):
        defects.append(
            ConformanceDefect(
                code="conformance.mapping_invalid",
                severity="block",
                message=(
                    f"{problem} (in {path}). Take the id from the pinned snapshot the message "
                    "names, or drop it: a mapping may only claim a test that exists"
                ),
                path=str(path),
            )
        )
    if set(declared) != set(metadata.framework):
        defects.append(
            ConformanceDefect(
                code="conformance.mapping_drift",
                severity="block",
                message=(
                    f"the mapping entry lists {sorted(declared)} but the metadata declares "
                    f"{sorted(metadata.framework)}. The entry is the check's declaration of "
                    "what it covers; regenerate it from the metadata so the two agree."
                ),
                path=str(path),
            )
        )
    defects.extend(_mapping_proof_defects(document, path, metadata))
    return defects


def _mapping_proof_defects(
    document: Mapping[str, Any], path: Path, metadata: CheckMetadata
) -> list[ConformanceDefect]:
    """The proof declaration in the mapping entry, checked against the opt-in rules.

    This is where an "L2 without opt-in" defect is *writable*: the metadata constructor refuses
    the pair, so a candidate declares it here, and the kit reads it back.
    """
    level = str(document.get("proof") or "").strip().upper()
    if not level:
        return []
    if level not in {"L0", "L1", "L2", "L3", "L4"}:
        return [
            ConformanceDefect(
                code=DEFECT_PROOF,
                severity="block",
                message=(
                    f"the mapping entry declares proof {level!r}, which is not a proof level; "
                    "use one of L0, L1, L2, L3, L4"
                ),
                path=str(path),
            )
        ]
    opt_in = document.get("enabled_by_default")
    attestation = document.get("requires_state_attestation")
    enabled = metadata.enabled_by_default if opt_in is None else bool(opt_in)
    requires = metadata.requires_state_attestation if attestation is None else bool(attestation)
    problems = metadata_proof_problems(
        ProofLevel(level), enabled_by_default=enabled, requires_state_attestation=requires
    )
    return [
        ConformanceDefect(
            code=DEFECT_PROOF,
            severity="block",
            message=(
                f"the mapping entry declares proof {level} with enabled_by_default={enabled} "
                f"and requires_state_attestation={requires}: {problem}. An L2+ check is opt-in "
                "by definition and an L3/L4 check additionally requires the state-change "
                "attestation"
            ),
            path=str(path),
        )
        for problem in problems
    ]


def _declared_items(document: Mapping[str, Any]) -> tuple[str, ...]:
    raw = document.get("framework")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    return tuple(str(item).strip() for item in raw if str(item).strip())


def _behaviour_gate(manifest: ConformanceManifest, check: type[Module]) -> ConformanceGate:
    """Run the check against its own fixtures: the decoy, the evidence and determinism."""
    defects: list[ConformanceDefect] = []
    defects.extend(_fixture_declared(manifest, "positive", manifest.positive))
    defects.extend(_fixture_declared(manifest, "decoy", manifest.decoy))
    if any(item.severity == "block" for item in defects):
        return ConformanceGate(
            gate="behaviour",
            passed=False,
            detail="the candidate's fixtures are not declared",
            defects=tuple(defects),
        )
    assert manifest.positive is not None  # narrowed by _fixture_declared
    assert manifest.decoy is not None
    positive, positive_gap = _replay(check, manifest.positive)
    if positive_gap is not None:
        defects.append(positive_gap)
    decoy, decoy_gap = _replay(check, manifest.decoy)
    if decoy_gap is not None:
        defects.append(decoy_gap)

    if positive is not None:
        findings = positive.findings
        if not findings:
            defects.append(
                ConformanceDefect(
                    code=DEFECT_EVIDENCE,
                    severity="block",
                    message=(
                        "the check produced no finding against its positive fixture. Either the "
                        "fixture does not contain what the check detects, or the check's claim "
                        "does not hold; a check that cannot establish its own claim on a "
                        "recorded example cannot be merged"
                    ),
                    path=str(manifest.positive),
                )
            )
        else:
            for finding in findings:
                relevant = [item for item in finding.evidence if verification_relevant(item)]
                if not relevant:
                    defects.append(
                        ConformanceDefect(
                            code="conformance.evidence_thin",
                            severity="block",
                            message=(
                                f"the finding {finding.title!r} carries no "
                                "verification-relevant evidence: a reviewer has nothing to "
                                "confirm by hand. Attach the captured exchange (or the banner, "
                                "certificate or artifact) the claim rests on — a status code "
                                "alone is not evidence"
                            ),
                            path=str(manifest.positive),
                        )
                    )
    if decoy is not None and decoy.findings:
        titles = ", ".join(repr(item.title) for item in decoy.findings)
        defects.append(
            ConformanceDefect(
                code="conformance.decoy_dirty",
                severity="block",
                message=(
                    f"the check fired on its decoy ({titles}). An oracle the false-positive "
                    "trap can fool is a refusal reason, not a refinement: tighten the match "
                    "(an exact token, not a word; the payload you sent back, not the status "
                    "code) or declare a decoy that is a fair trap"
                ),
                path=str(manifest.decoy),
            )
        )
    if positive is not None:
        defects.extend(_determinism_defects(check, manifest.positive, positive))
    return ConformanceGate(
        gate="behaviour",
        passed=not any(item.severity == "block" for item in defects),
        detail=(
            f"positive: {len(positive.findings) if positive else 0} finding(s), "
            f"decoy: {len(decoy.findings) if decoy else 0} finding(s)"
        ),
        defects=tuple(defects),
    )


def _fixture_declared(
    manifest: ConformanceManifest, role: str, path: Path | None
) -> list[ConformanceDefect]:
    if path is None:
        if role == "decoy":
            return [
                ConformanceDefect(
                    code=DEFECT_DECOY,
                    severity="block",
                    message=(
                        "the conformance manifest declares no decoy fixture. Every check is "
                        "assigned a false-positive trap it must stay silent on (detection "
                        "programme §2.2 rule 7); add `decoy: fixtures/<name>/decoy.json` and "
                        "the recorded response that traps this claim."
                    ),
                )
            ]
        return [
            ConformanceDefect(
                code=DEFECT_EVIDENCE,
                severity="block",
                message=(
                    "the conformance manifest declares no positive fixture, so the check's "
                    "evidence rule cannot be tested. Add `positive: fixtures/<name>/"
                    "positive.json` with the recorded response that made you write the check."
                ),
            )
        ]
    if not path.is_file():
        code = DEFECT_DECOY if role == "decoy" else DEFECT_EVIDENCE
        return [
            ConformanceDefect(
                code=code,
                severity="block",
                message=(
                    f"the manifest declares {role} fixture {path}, which does not exist. Record "
                    f"the response there or drop the declaration."
                ),
                path=str(path),
            )
        ]
    return []


def _replay(
    check: type[Module], fixture: Path
) -> tuple[FixtureRun | None, ConformanceDefect | None]:
    """Replay one fixture, turning a fixture gap into a defect rather than a crash.

    ``replay_fixture`` deliberately *reports* a gap rather than raising (the strict
    ``run_fixture`` is what raises), so this is where a gap becomes a defect: a verdict computed
    from the transport's fabricated ``501`` is not a verdict, and the kit must say so instead of
    calling a candidate clean because it asked for something nobody recorded.
    """
    try:
        run = asyncio.run(replay_fixture(check, fixture))
    except ConfigurationError as exc:
        return None, ConformanceDefect(
            code="conformance.check_unloadable",
            severity="block",
            message=f"the check could not be run against {fixture}: {exc}",
            path=str(fixture),
        )
    if not run.complete:
        listed = ", ".join(run.unrecorded)
        return None, ConformanceDefect(
            code="conformance.fixture_gap",
            severity="block",
            message=(
                f"the fixture records no response for {listed}, so the check's verdict would be "
                "about a fabricated 501. Record the response the check asks for, or point the "
                "check at a recorded path"
            ),
            path=str(fixture),
        )
    return run, None


def _determinism_defects(
    check: type[Module], fixture: Path, first: FixtureRun
) -> list[ConformanceDefect]:
    """Run the fixture again and compare the deterministic part of the verdicts.

    Evidence timestamps are *not* compared — a captured-at clock is allowed to move. What must
    not move is the verdict: the same input has to produce the same status, title and detail
    (``.spec/05-detection-program.md`` §2.2 rule 3: non-determinism is a defect, not "AI").
    """
    try:
        again = run_fixture(check, fixture)
    except (FixtureGapError, ConfigurationError) as exc:  # pragma: no cover - the first run passed
        return [
            ConformanceDefect(
                code="conformance.nondeterministic",
                severity="block",
                message=f"the second run over {fixture} failed: {exc}",
                path=str(fixture),
            )
        ]
    before = [(item.status, item.title, item.detail) for item in first.results]
    after = [(item.status, item.title, item.detail) for item in again]
    if before == after:
        return []
    return [
        ConformanceDefect(
            code="conformance.nondeterministic",
            severity="block",
            message=(
                f"two runs over {fixture} disagree ({before!r} then {after!r}). A check must "
                "produce the same verdict for the same input; remove the clock, the random "
                "choice or the ordering that moved"
            ),
            path=str(fixture),
        )
    ]
