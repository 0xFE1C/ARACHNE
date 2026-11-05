"""The check authoring SDK: the paved road from a blank file to a green check (REQ-ECOS-007).

Before this module the only authoring path was the 730-line developer guide: an author had to
read the registry, the handler dispatch, the metadata constraints, the proof model and the
golden-file report scheme before writing one line of detection logic. That is a day of reading
per check, and the content-velocity target (REQ-ECOS-007: ≥10 checks per week) is unreachable
on it. Three things remove the reading:

:class:`AuthorCheck`
    A base class with sensible defaults. A subclass declares *what the check establishes* —
    ``check_id``, ``title``, ``description``, ``framework`` — and the base fills in the rest
    (module, name, version, proof level, target kinds, request estimate) and builds a
    validated :class:`~arachne.modules.base.CheckMetadata`. Nothing is hidden: the metadata it
    builds is the ordinary one, and a bad id or a contradictory proof declaration is refused
    at class-definition time exactly as it is for a built-in check.
:func:`scaffold_check`
    The generator behind ``arachne plugin new-check``: a check, its test, its
    framework-mapping entry, a positive fixture, a decoy fixture and a docs stub. The output
    is designed to pass the repository's own gates — lint, format, types and its own test — with
    **zero edits**, because a scaffold whose output needs fixing teaches the wrong lesson.
:func:`run_fixture`
    One call that runs a check against a recorded fixture and returns its results. The
    alternative — building a :class:`~arachne.core.lifecycle.StepContext`, a scope, a scoped
    HTTP client and an auditor by hand — is the part of the guide an author should not have to
    read at all.

The fixtures are **recorded responses**, never a live target: a check's test is deterministic
(the determinism rule) and runs offline, so the whole SDK works in an
air-gapped checkout. The conventions a plugin must obey are the runtime's, not this module's:
a check reaches the network only through ``ctx.http`` (the shared scoped client, ADR-05), so
:func:`run_fixture` builds a real :class:`~arachne.core.http.ScopedHttpClient` over a recorded
transport rather than handing the check a looser object. The scope gate still applies, so a
check that reaches outside its asset fails here the same way it would in a scan.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import re
import textwrap
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Final
from urllib.parse import urlsplit

import yaml

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.errors import ConfigurationError
from arachne.core.events import EventBus
from arachne.core.http import RecordedResponse, ScopedHttpClient, fixture_transport
from arachne.core.lifecycle import MemoryScanStateStore, StepContext
from arachne.core.planner import ScanStep
from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.core.steps import seed_asset
from arachne.core.target import ScanOptions, TargetDefinition, TargetKind, TargetSelector
from arachne.modules.base import Asset, CheckMetadata, CheckType, Module, SeverityHint
from arachne.modules.context import CheckContext, ModuleConfig

__all__ = [
    "CHECK_FIXTURE_FORMAT",
    "CONFORMANCE_MANIFEST_FORMAT",
    "DEFAULT_CHECK_VERSION",
    "SCAFFOLD_FORMAT",
    "AuthorCheck",
    "CheckFixture",
    "CheckId",
    "ConformanceManifest",
    "FixtureGapError",
    "FixtureRun",
    "ScaffoldResult",
    "author_metadata",
    "check_class_in",
    "load_check",
    "load_fixture",
    "load_manifest",
    "module_checks",
    "replay_fixture",
    "run_fixture",
    "run_fixture_async",
    "scaffold_check",
]

#: Tag for a recorded check fixture; bump when its meaning changes.
CHECK_FIXTURE_FORMAT: Final = "arachne-check-fixture/1"

#: Tag stamped into the scaffold's manifest, so a later generator can recognise its output.
SCAFFOLD_FORMAT: Final = "arachne-check-scaffold/1"

#: The conformance manifest's format tag (the file ``arachne plugin conform`` reads).
CONFORMANCE_MANIFEST_FORMAT: Final = "arachne-check-conformance/1"

#: The version a newly authored check starts at.
DEFAULT_CHECK_VERSION: Final = "1.0"

#: ``m4.kebab-name`` — the module-qualified check identity (``CheckMetadata`` re-validates it).
_CHECK_ID = re.compile(r"^(?P<module>[mM][1-6])\.(?P<name>[a-z0-9]+(?:-[a-z0-9]+)*)$")

#: The address a scaffolded check's recorded fixtures answer on. ``.test`` is reserved by
#: RFC 2606, so a fixture can never name something real — and it is never resolved anyway
#: (``StaticResolver`` pins the recorded address, and the transport replays the recording).
_FIXTURE_HOST: Final = "demo.example.test"
_FIXTURE_ADDRESS: Final = "93.184.216.34"

#: The marker a scaffolded check looks for. A *token*, not a word, so the decoy can carry the
#: near-miss a sloppy oracle would match (``markers``, ``demo marker``) and stay clean.
_SCAFFOLD_MARKER: Final = "demo-marker-exposed"

#: Generated lines are wrapped to this width; the repository's limit is 100, and leaving room
#: means a generated file stays clean even after an author renames the check (a longer id).
_WRAP = 80


@dataclass(frozen=True, slots=True)
class CheckId:
    """A parsed, validated check identity (``m4.header-missing``)."""

    module: str
    name: str

    @classmethod
    def parse(cls, raw: str) -> CheckId:
        """Parse ``raw`` or refuse it with a message saying what is wrong and what to write.

        The message is the point: an author who types ``M4.Header`` should be told the accepted
        shape, not handed a regex.
        """
        value = raw.strip()
        match = _CHECK_ID.match(value)
        if match is None:
            msg = (
                f"{raw!r} is not a check id; write '<module>.<kebab-subject>' with a module of "
                "M1..M6, for example 'm4.header-missing'"
            )
            raise ConfigurationError(msg)
        return cls(module=match.group("module").upper(), name=match.group("name"))

    @property
    def id(self) -> str:
        return f"{self.module.lower()}.{self.name}"

    @property
    def module_number(self) -> str:
        return self.module[1:]

    @property
    def class_name(self) -> str:
        """A PascalCase class name derived from the subject (``header-missing`` → same)."""
        return "".join(part.capitalize() for part in self.name.split("-")) + "Check"

    @property
    def distribution(self) -> str:
        """The distribution name the scaffold writes (``arachne-check-<subject>``)."""
        return f"arachne-check-{self.name}"

    @property
    def module_package(self) -> str:
        """The import package name (``arachne_check_<subject>``)."""
        return f"arachne_check_{self.name.replace('-', '_')}"

    @property
    def research_ref(self) -> str:
        """The corpus reference's default: chapter ``ch0N`` (the module), method ``#1``."""
        return f"ch0{self.module_number}#1"


def author_metadata(
    check_id: str,
    *,
    title: str,
    description: str,
    framework: Sequence[str],
    cwe: str | None = None,
    research_ref: str | None = None,
    version: str = DEFAULT_CHECK_VERSION,
    proof: str = "L1",
    severity_hint: SeverityHint = "low",
    check_type: CheckType = "hybrid",
    target_kinds: Sequence[TargetKind] = (TargetKind.URL,),
    estimated_requests: int = 1,
    rate_cost: float = 1.0,
    requires_credentials: Sequence[str] = (),
) -> CheckMetadata:
    """Build a validated :class:`CheckMetadata` from the fields an author actually knows.

    ``check_id`` is parsed into ``module``/``name``/``id`` so the three can never disagree
    (``CheckMetadata`` refuses an id that is not ``module.name``); ``research_ref`` defaults to
    the module's chapter. Everything is then validated by ``CheckMetadata`` itself, so a
    contradiction — an unmapped framework id, a CWE missing from ``framework``, an empty
    description — is refused here with the same messages a built-in check gets.

    The defaults are the *cheapest honest* ones: L1, a GET-only (``hybrid``) read, a URL
    target, one request. The proof level drives the two flags it must agree with
    (REQ-PROOF-001): L2+ is opt-in by definition, and L3/L4 requires the state-change
    attestation. Deriving them from the level means an author cannot forget the pairing, while
    a check that declares ``enabled_by_default`` itself through ``CheckMetadata`` still is
    refused if it contradicts its level.
    """
    parsed = CheckId.parse(check_id)
    wanted = proof.strip().upper()
    try:
        level = ProofLevel(wanted)
    except ValueError as exc:
        msg = (
            f"{proof!r} is not a proof level; declare one of "
            f"{', '.join(item.value for item in ProofLevel)}"
        )
        raise ConfigurationError(msg) from exc
    return CheckMetadata(
        id=parsed.id,
        module=parsed.module,
        name=parsed.name,
        version=version,
        title=title,
        description=description,
        research_ref=research_ref or parsed.research_ref,
        framework=tuple(framework),
        cwe=cwe,
        target_kinds=tuple(target_kinds),
        severity_hint=severity_hint,
        type=check_type,
        safe=True,
        verifiable=True,
        enabled_by_default=level is ProofLevel.L1,
        proof=level,
        requires_state_attestation=level in {ProofLevel.L3, ProofLevel.L4},
        estimated_requests=estimated_requests,
        rate_cost=rate_cost,
        requires_credentials=tuple(requires_credentials),
    )


class AuthorCheck(Module):
    """The base class a third-party check extends (REQ-ECOS-007).

    Declare the claim; the base builds the metadata::

        class MissingHeaderCheck(AuthorCheck):
            check_id = "m4.missing-header"
            check_title = "Missing security header"
            check_description = "Reports a response that omits the configured header."
            check_framework = ("WSTG-CONF-07", "CWE-693")

            async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
                ...

    :func:`author_metadata` does the construction and validation, so an id that is not
    ``module.name``, a framework id outside the pinned snapshot or a proof level that
    contradicts the opt-in rule fails at class-definition time — the author sees it on the
    first import, not mid-scan.

    The declarations are all prefixed ``check_`` because :class:`Module` already defines
    ``name``, ``version``, ``description`` and ``research_ref`` as properties derived from the
    metadata. A plain ``description = ...`` here would shadow that property and quietly detach
    ``check.description`` from the metadata it is supposed to mirror; the prefix makes the
    declaration and the derived value impossible to confuse.

    The placeholder metadata below exists only because
    :meth:`~arachne.modules.base.Module.__init_subclass__` refuses a class without metadata at
    class-definition time. No module group registers ``AuthorCheck``, so it never reaches a
    plan, a report or the coverage ledger; every real subclass replaces it.
    """

    #: ``m<N>.<kebab-subject>`` — required.
    check_id: ClassVar[str] = "m1.author-check"
    #: What the check establishes, one line — required.
    check_title: ClassVar[str] = "Authoring base class"
    #: How it establishes that — required.
    check_description: ClassVar[str] = (
        "Placeholder metadata for the authoring base class; a subclass replaces it at "
        "class-definition time."
    )
    #: The framework items this check's evidence bears on — required (REQ-DET-002).
    check_framework: ClassVar[tuple[str, ...]] = ("CWE-693",)
    #: The primary weakness class, which must also appear in ``check_framework``.
    check_cwe: ClassVar[str | None] = None
    #: The corpus reference; defaults to the module's chapter.
    check_research_ref: ClassVar[str | None] = None
    check_version: ClassVar[str] = DEFAULT_CHECK_VERSION
    #: ``L0``..``L4``. L2+ makes the check opt-in and L3/L4 demands the state attestation.
    check_proof: ClassVar[str] = "L1"
    check_severity_hint: ClassVar[SeverityHint] = "low"
    check_type: ClassVar[CheckType] = "hybrid"
    check_target_kinds: ClassVar[tuple[TargetKind, ...]] = (TargetKind.URL,)
    check_estimated_requests: ClassVar[int] = 1
    check_rate_cost: ClassVar[float] = 1.0
    check_credentials: ClassVar[tuple[str, ...]] = ()

    metadata = author_metadata(
        check_id,
        title=check_title,
        description=check_description,
        framework=check_framework,
        research_ref="ch01#1",
    )

    def __init_subclass__(cls, **kwargs: Any) -> None:
        cls.metadata = author_metadata(
            cls.check_id,
            title=cls.check_title,
            description=cls.check_description,
            framework=cls.check_framework,
            cwe=cls.check_cwe,
            research_ref=cls.check_research_ref,
            version=cls.check_version,
            proof=cls.check_proof,
            severity_hint=cls.check_severity_hint,
            check_type=cls.check_type,
            target_kinds=cls.check_target_kinds,
            estimated_requests=cls.check_estimated_requests,
            rate_cost=cls.check_rate_cost,
            requires_credentials=cls.check_credentials,
        )
        super().__init_subclass__(**kwargs)


# --------------------------------------------------------------------------- fixtures
class FixtureGapError(ConfigurationError):
    """The check asked for a URL its fixture does not record.

    A distinct type because the conformance kit reports it as a *defect* rather than failing:
    "your fixture does not cover what your check requests" is an authoring problem the kit has
    to say out loud, and it is the reason a verdict from an incomplete fixture is worthless.
    """

    def __init__(self, message: str, *, requests: tuple[str, ...] = ()) -> None:
        super().__init__(message)
        self.requests = requests


@dataclass(frozen=True, slots=True)
class CheckFixture:
    """A recorded run: one declared target, and the responses its requests are answered with."""

    check: str
    asset_kind: str
    asset_value: str
    responses: tuple[RecordedResponse, ...] = ()
    source: str = ""
    format: str = CHECK_FIXTURE_FORMAT

    @property
    def host(self) -> str:
        """The host the recorded responses must share (the scope is compiled from the asset)."""
        if self.asset_kind == TargetKind.URL.value:
            return urlsplit(self.asset_value).hostname or ""
        if self.asset_kind in {TargetKind.DOMAIN.value, TargetKind.DOMAIN_PATTERN.value}:
            return self.asset_value.lstrip("*.")
        if self.asset_kind == TargetKind.IP.value:
            return self.asset_value
        if self.asset_kind == TargetKind.GIT.value:
            return urlsplit(self.asset_value).hostname or ""
        return ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "check": self.check,
            "asset": {"kind": self.asset_kind, "value": self.asset_value},
            "responses": [item.to_dict() for item in self.responses],
        }


def load_fixture(path: str | Path) -> CheckFixture:
    """Read and validate a recorded fixture, naming the file and the field on any problem.

    A whole-line ``#`` comment is allowed and stripped: a fixture is a file an author is
    expected to *edit*, and "why this response made you write the check" belongs in the file
    rather than in a wiki page nobody opens. Only whole-line comments are stripped — JSON has
    no multi-line strings, so a line whose first non-space character is ``#`` cannot be part of
    a value.
    """
    resolved = Path(path).expanduser()
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read the check fixture {resolved}: {exc}"
        raise ConfigurationError(msg) from exc
    document_text = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    try:
        document = json.loads(document_text)
    except json.JSONDecodeError as exc:
        msg = f"{resolved}: the fixture is not valid JSON: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(document, Mapping):
        msg = f"{resolved}: expected a JSON object at the top level"
        raise ConfigurationError(msg)
    asset = document.get("asset")
    if not isinstance(asset, Mapping) or not str(asset.get("kind") or "").strip():
        msg = f'{resolved}: "asset" must be an object with a "kind" (e.g. "url") and a "value"'
        raise ConfigurationError(msg)
    kind = str(asset["kind"]).strip()
    valid_kinds = ", ".join(item.value for item in TargetKind)
    if kind not in {item.value for item in TargetKind}:
        msg = f"{resolved}: asset kind {kind!r} is not a target kind ({valid_kinds})"
        raise ConfigurationError(msg)
    value = str(asset.get("value") or "")
    if not value:
        msg = f'{resolved}: "asset.value" is required'
        raise ConfigurationError(msg)
    raw_responses = document.get("responses")
    if raw_responses is None:
        raw_responses = []
    if not isinstance(raw_responses, Sequence) or isinstance(raw_responses, (str, bytes)):
        msg = f'{resolved}: "responses" must be a list'
        raise ConfigurationError(msg)
    responses: list[RecordedResponse] = []
    for index, item in enumerate(raw_responses):
        if not isinstance(item, Mapping):
            msg = f"{resolved}: responses[{index}] must be an object"
            raise ConfigurationError(msg)
        try:
            responses.append(RecordedResponse.from_dict(item))
        except (KeyError, TypeError, ValueError) as exc:
            msg = (
                f"{resolved}: responses[{index}] is malformed (method and url are required): {exc}"
            )
            raise ConfigurationError(msg) from exc
    return CheckFixture(
        check=str(document.get("check") or ""),
        asset_kind=kind,
        asset_value=value,
        responses=tuple(responses),
        source=str(resolved),
    )


@dataclass(frozen=True, slots=True)
class FixtureRun:
    """One replay: what the check yielded, and which requests the recording covered."""

    check: str
    results: tuple[CheckResult, ...] = ()
    recorded: tuple[str, ...] = ()
    unrecorded: tuple[str, ...] = ()

    @property
    def findings(self) -> tuple[CheckResult, ...]:
        return tuple(item for item in self.results if item.status == "vulnerable")

    @property
    def complete(self) -> bool:
        """True when every request the check made was answered from the recording."""
        return not self.unrecorded

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "recorded": list(self.recorded),
            "unrecorded": list(self.unrecorded),
            "results": [item.to_dict() for item in self.results],
        }


async def replay_fixture(check: type[Module], fixture: CheckFixture | str | Path) -> FixtureRun:
    """Run ``check`` once against a recorded fixture and report *what actually happened*.

    The check receives a real :class:`~arachne.core.http.ScopedHttpClient` over a recorded
    transport: no socket is opened, and the scope gate still applies. The transport answers an
    unrecorded request with a fabricated ``501``, which is the right behaviour for the client
    and the wrong input for a verdict — a check that asked its fixture for something the fixture
    does not record has produced a result about a number nobody recorded. So the replay reads
    the client's own audit trail and reports those requests separately, and
    :func:`run_fixture` refuses to return at all when there are any.
    """
    loaded = fixture if isinstance(fixture, CheckFixture) else load_fixture(fixture)
    selector = TargetSelector(kind=TargetKind(loaded.asset_kind), value=loaded.asset_value)
    definition = TargetDefinition(
        name=f"fixture:{loaded.check or check.metadata.id}", targets=(selector,)
    )
    scope: Scope = definition.compile_scope()
    if scope.is_empty:
        msg = (
            f"{loaded.source or 'fixture'}: the declared asset does not compile to a scope the "
            "client can enforce; check asset.kind and asset.value"
        )
        raise ConfigurationError(msg)
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="check-sdk")
    client = ScopedHttpClient(
        scope=scope,
        policy=UrlSafetyPolicy(allow_private_ips=True),
        resolver=StaticResolver((_FIXTURE_ADDRESS,)),
        auditor=auditor,
        transport=fixture_transport(loaded.responses),
    )
    step = StepContext(
        scan_id=1,
        step=ScanStep.CHECKS,
        definition=definition,
        options=ScanOptions(),
        scope=scope,
        store=MemoryScanStateStore(),
        bus=EventBus(),
        auditor=auditor,
        http=client,
    )
    kind, value, meta = seed_asset(selector)
    context = CheckContext(
        step=step,
        module=check(),
        asset=Asset.from_meta(kind, value, meta),
        config=ModuleConfig(),
    )
    results: list[CheckResult] = []
    try:
        async for result in context.module.run(context):
            results.append(result)
    finally:
        await client.aclose()
    recorded, unrecorded = _replay_coverage(loaded, sink)
    return FixtureRun(
        check=loaded.check or check.metadata.id,
        results=tuple(results),
        recorded=recorded,
        unrecorded=unrecorded,
    )


def _replay_coverage(
    fixture: CheckFixture, sink: MemoryAuditSink
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """``(recorded, unrecorded)`` request keys, from the client's own audit trail.

    The match mirrors ``fixture_transport``: an exact ``METHOD url`` first, then
    ``METHOD host+path`` when exactly one recording has it. Doing it here rather than guessing
    from status codes means a *recorded* ``501`` is not mistaken for a gap and a fabricated one
    is never mistaken for a response.
    """
    exact = {f"{item.method.upper()} {item.url}" for item in fixture.responses}
    by_path: dict[str, int] = {}
    for item in fixture.responses:
        parts = urlsplit(item.url)
        key = f"{item.method.upper()} {parts.netloc}{parts.path}"
        by_path[key] = by_path.get(key, 0) + 1
    recorded: list[str] = []
    unrecorded: list[str] = []
    seen: set[str] = set()
    for event in sink.of_action(AuditAction.HTTP_REQUEST):
        target = str(event.target or "")
        method = str((event.meta or {}).get("method") or "GET").upper()
        key = f"{method} {target}"
        if key in seen:
            continue
        seen.add(key)
        parts = urlsplit(target)
        path_key = f"{method} {parts.netloc}{parts.path}"
        if key in exact or by_path.get(path_key) == 1:
            recorded.append(key)
        else:
            unrecorded.append(key)
    return tuple(recorded), tuple(unrecorded)


def run_fixture(check: type[Module], fixture: CheckFixture | str | Path) -> list[CheckResult]:
    """Blocking, strict form of :func:`replay_fixture`: refuse to answer around a fixture gap.

    Used by the generated test and by any author-facing code. A gap is an authoring error — the
    check asked for something the recording does not contain — and returning a verdict computed
    from a fabricated ``501`` would be worse than raising.
    """
    run = asyncio.run(replay_fixture(check, fixture))
    if not run.complete:
        listed = ", ".join(run.unrecorded)
        msg = (
            f"the fixture records no response for {listed}: the check asked for a URL the "
            "fixture does not cover, so any verdict would be about a fabricated 501. Record "
            "the response, or point the check at a recorded path"
        )
        raise FixtureGapError(msg, requests=run.unrecorded)
    return list(run.results)


async def run_fixture_async(
    check: type[Module], fixture: CheckFixture | str | Path
) -> list[CheckResult]:
    """Awaitable form of :func:`run_fixture`."""
    run = await replay_fixture(check, fixture)
    if not run.complete:
        listed = ", ".join(run.unrecorded)
        msg = (
            f"the fixture records no response for {listed}: the check asked for a URL the "
            "fixture does not cover, so any verdict would be about a fabricated 501"
        )
        raise FixtureGapError(msg, requests=run.unrecorded)
    return list(run.results)


# --------------------------------------------------------------------------- the manifest
@dataclass(frozen=True, slots=True)
class ConformanceManifest:
    """What a candidate check declares about itself, and where its fixtures are.

    The manifest is the kit's input and the author's checklist in one file: the check id, the
    module that defines it, the mapping entry, and the two fixtures. Generated by
    :func:`scaffold_check` and read by ``arachne plugin conform``; the decoy is not optional
    because a check with no assigned false-positive trap cannot be merged
    (the check contract's decoy rule).
    """

    check: str
    module_file: Path
    root: Path
    source: str = ""
    mapping: Path | None = None
    positive: Path | None = None
    decoy: Path | None = None
    format: str = CONFORMANCE_MANIFEST_FORMAT

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "check": self.check,
            "module_file": str(self.module_file),
            "mapping": _optional_str(self.mapping),
            "positive": _optional_str(self.positive),
            "decoy": _optional_str(self.decoy),
            "source": self.source,
        }


def _optional_str(value: Path | None) -> str | None:
    return None if value is None else str(value)


def load_manifest(path: str | Path) -> ConformanceManifest:
    """Read a conformance manifest, naming the file and the field on any problem.

    Every path in the manifest is relative to the manifest's own directory, so a candidate
    tree can be moved or vendored whole. An absolute path or a ``..`` hop is refused: the
    manifest describes a package, and a package that reaches outside its own tree is not one
    the kit can speak about.
    """
    resolved = Path(path).expanduser()
    if resolved.is_dir():
        resolved = resolved / "conformance.yaml"
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        msg = (
            f"cannot read the conformance manifest {resolved}: {exc}. Pass the path to a "
            "candidate's conformance.yaml (or its directory)"
        )
        raise ConfigurationError(msg) from exc
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{resolved}: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(document, Mapping):
        msg = f"{resolved}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    declared = str(document.get("format") or "").strip()
    if declared and declared != CONFORMANCE_MANIFEST_FORMAT:
        msg = (
            f"{resolved}: format {declared!r} is not {CONFORMANCE_MANIFEST_FORMAT!r}; the kit "
            "reads only the format it writes"
        )
        raise ConfigurationError(msg)
    check_id = str(document.get("check") or "").strip()
    if not check_id:
        msg = f'{resolved}: "check" is required (the id the manifest is about)'
        raise ConfigurationError(msg)
    root = resolved.parent.resolve()
    module_file = _manifest_path(document, "module_file", root=root, source=resolved)
    if module_file is None:
        msg = f'{resolved}: "module_file" is required (the Python file defining the check)'
        raise ConfigurationError(msg)
    return ConformanceManifest(
        check=CheckId.parse(check_id).id,
        module_file=module_file,
        root=root,
        source=str(resolved),
        mapping=_manifest_path(document, "mapping", root=root, source=resolved),
        positive=_manifest_path(document, "positive", root=root, source=resolved),
        decoy=_manifest_path(document, "decoy", root=root, source=resolved),
    )


def _manifest_path(
    document: Mapping[str, Any], key: str, *, root: Path, source: Path
) -> Path | None:
    raw = document.get(key)
    if raw is None or not str(raw).strip():
        return None
    text = str(raw).strip()
    relative = Path(text)
    if relative.is_absolute():
        msg = f"{source}: {key} must be relative to the manifest, not {text!r}"
        raise ConfigurationError(msg)
    target = (root / relative).resolve()
    if root not in target.parents and target != root:
        msg = f"{source}: {key} {text!r} escapes the candidate tree; keep it inside {root}"
        raise ConfigurationError(msg)
    return target


def load_check(manifest: ConformanceManifest | str | Path) -> type[Module]:
    """Import the candidate and return the one check it defines.

    Importing a candidate executes its module-level code, so the caller must have run the
    policy scan first — :func:`arachne.ecos.conformance.conform` does, and refuses to import a
    candidate whose source uses a capability a plugin is not granted (a process, a raw socket,
    dynamic code). A manifest that names a check the file does not define is refused rather
    than guessed at.
    """
    loaded = manifest if isinstance(manifest, ConformanceManifest) else load_manifest(manifest)
    path = loaded.module_file
    if not path.is_file():
        msg = (
            f"{loaded.source}: module_file {path} does not exist; point it at the Python file "
            "that defines the check"
        )
        raise ConfigurationError(msg)
    parsed = CheckId.parse(loaded.check)
    spec = importlib.util.spec_from_file_location(f"_arachne_candidate_{parsed.name}", path)
    if spec is None or spec.loader is None:  # pragma: no cover - a loader always exists for .py
        msg = f"{loaded.source}: cannot load {path} as a Python module"
        raise ConfigurationError(msg)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return check_class_in(module, loaded.check)


# --------------------------------------------------------------------------- generation
def _literal(text: str, *, indent: str) -> str:
    """A Python string literal for ``text``, wrapped so no generated line breaks the limit.

    ``json.dumps`` does the quoting (JSON string escapes are valid Python escapes for the
    characters a check description can contain) and always emits double quotes, which is the
    form ``ruff format`` would leave in place — so the output needs no reformatting. A trailing
    space is kept on every line but the last, so the implicit concatenation reproduces ``text``
    exactly. ``indent`` is the indentation of the line the literal is assigned on; a wrapped
    literal closes at that indent.
    """
    lines = textwrap.wrap(text, width=_WRAP, break_long_words=False, break_on_hyphens=False)
    if not lines:
        return '""'
    if len(lines) == 1:
        return json.dumps(lines[0])
    body_indent = indent + " " * 4
    pieces = [
        f"{body_indent}{json.dumps(line + (' ' if index < len(lines) - 1 else ''))}"
        for index, line in enumerate(lines)
    ]
    return "(\n" + "\n".join(pieces) + f"\n{indent})"


def _tuple_literal(items: Sequence[str]) -> str:
    """A double-quoted tuple literal (the form ``ruff format`` keeps)."""
    if not items:
        return "()"
    if len(items) == 1:
        return f"({json.dumps(items[0])},)"
    return "(" + ", ".join(json.dumps(item) for item in items) + ")"


def _python_value(value: str | None) -> str:
    """A Python literal for a nullable string (``None`` rather than JSON's ``null``)."""
    return "None" if value is None else json.dumps(value)


def _docstring(text: str, *, indent: str) -> str:
    """``text`` as a docstring body, wrapped to the generated line width.

    Paragraphs are separated by a blank line and every paragraph is wrapped, so a long
    description still produces a file the repository's line-length rule accepts.
    """
    lines: list[str] = []
    for paragraph in text.split("\n\n"):
        lines.extend(textwrap.wrap(paragraph, width=_WRAP, break_long_words=False) or [""])
        lines.append("")
    while lines and not lines[-1]:
        lines.pop()
    return "\n".join(f"{indent}{line}".rstrip() for line in lines)


@dataclass(frozen=True, slots=True)
class ScaffoldResult:
    """What :func:`scaffold_check` wrote, and the one command that proves it is green."""

    check_id: str
    root: Path
    files: tuple[Path, ...] = field(default_factory=tuple)
    written: bool = True

    @property
    def test_path(self) -> Path:
        parsed = CheckId.parse(self.check_id)
        return self.root / "tests" / f"test_{parsed.name.replace('-', '_')}.py"

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": SCAFFOLD_FORMAT,
            "check": self.check_id,
            "root": str(self.root),
            "written": self.written,
            "files": sorted(str(path.relative_to(self.root)) for path in self.files),
            "verify": f"cd {self.root} && python -m pytest tests -q",
        }


def scaffold_check(
    check_id: str,
    *,
    root: str | Path,
    title: str | None = None,
    description: str | None = None,
    framework: Sequence[str] = ("WSTG-CONF-07", "CWE-693"),
    cwe: str | None = None,
    force: bool = False,
) -> ScaffoldResult:
    """Write a complete, tested check under ``root``; return what was written.

    The output is a plugin package in the shape ``examples/plugins/`` uses: the check, its
    test, its framework-mapping entry, a positive fixture, a decoy fixture, a docs stub, the
    conformance manifest and the ``pyproject.toml`` that registers it under
    ``arachne.modules``. Every file is derived from ``check_id`` and the declared fields alone
    — no clock, no randomness, no environment — so scaffolding the same id twice produces
    byte-identical output, which is what makes "passes the suite with zero edits" a testable
    claim rather than an aspiration.

    A contradictory declaration fails here, before anything is written: the metadata is built
    through :func:`author_metadata`, the same path the generated code uses, so the scaffold
    cannot emit files that refuse to import.
    """
    parsed = CheckId.parse(check_id)
    metadata = author_metadata(
        parsed.id,
        title=title or f"{parsed.name.replace('-', ' ').capitalize()} is exposed",
        description=description
        or (
            f"Requests /{parsed.name} and reports a response that exposes the authoring marker "
            f"{_SCAFFOLD_MARKER}. Read-only: GET only, no payload submitted."
        ),
        framework=framework,
        cwe=cwe,
    )
    base = Path(root).expanduser()
    files = _scaffold_files(parsed, metadata)
    existing = [base / relative for relative in files if (base / relative).exists()]
    if existing and not force:
        msg = (
            f"refusing to overwrite {existing[0]}: the scaffold already ran here. Delete the "
            "tree, choose another --out directory, or pass --force to overwrite it"
        )
        raise ConfigurationError(msg)
    written: list[Path] = []
    for relative, text in files.items():
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        written.append(target)
    return ScaffoldResult(check_id=parsed.id, root=base, files=tuple(written))


def _scaffold_files(parsed: CheckId, metadata: CheckMetadata) -> dict[Path, str]:
    """Every file the scaffold writes, keyed by its path relative to the out directory."""
    package = parsed.module_package
    stem = parsed.name.replace("-", "_")
    return {
        Path("pyproject.toml"): _pyproject(parsed, package),
        Path("src") / package / "__init__.py": _check_source(parsed, metadata),
        Path("tests") / f"test_{stem}.py": _test_source(parsed, package),
        Path("fixtures") / parsed.name / "positive.json": _fixture_text(
            parsed,
            body=json.dumps({"check": parsed.id, "detail": _SCAFFOLD_MARKER}, indent=2),
            marker_present=True,
        ),
        Path("fixtures") / parsed.name / "decoy.json": _fixture_text(
            parsed,
            body=json.dumps(
                {
                    "markers": {"demo": "absent"},
                    "note": "this page names the concept and carries no marker",
                    "path": f"/{parsed.name}/",
                },
                indent=2,
            ),
            marker_present=False,
        ),
        Path("mappings") / f"{parsed.name}.yaml": _mapping_source(parsed, metadata),
        Path("docs") / f"{parsed.name}.md": _docs_source(parsed, metadata, package),
        Path("conformance.yaml"): _conformance_manifest(parsed, package),
    }


def _fixture_text(parsed: CheckId, *, body: str, marker_present: bool) -> str:
    """A recorded fixture: one URL asset and one recorded 200 for the check's path.

    The decoy is the false-positive trap REQ-ECOS-007 requires: a 200 that echoes the request
    path, names the concept and carries no marker. An oracle that matched on the status code,
    on the request path or on the bare word ``demo`` fires against it; the shipped one does
    not. Both fixtures are one request deep, so the recorded transport cannot have a gap.
    """
    note = (
        "The response that made you write this check belongs here.\n"
        if marker_present
        else (
            "The decoy: a 200 that echoes the request path and carries no marker.\n"
            "It must produce zero findings.\n"
        )
    )
    document = {
        "format": CHECK_FIXTURE_FORMAT,
        "check": parsed.id,
        "asset": {"kind": "url", "value": f"https://{_FIXTURE_HOST}/"},
        "responses": [
            {
                "method": "GET",
                "url": f"https://{_FIXTURE_HOST}/{parsed.name}",
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": body,
            }
        ],
    }
    # The fixture is JSON, so the note travels as a leading comment block outside the document:
    # it is the one file in the tree an author is expected to edit by hand.
    return (
        "# "
        + note.replace("\n", "\n# ").rstrip("# ").rstrip()
        + "\n"
        + json.dumps(document, indent=2)
        + "\n"
    )


def _pyproject(parsed: CheckId, package: str) -> str:
    return f"""# The plugin package `arachne plugin new-check {parsed.id}` generated.
#
# The one ARACHNE-specific line is the entry-point group: `arachne.modules` is the group
# `ModuleRegistry.discover()` reads (F-09-01), so installing this package adds the check to
# {parsed.module} with no change to ARACHNE itself.
#
# `pythonpath = ["src"]` is what makes `python -m pytest tests` work in the checkout before
# anything is installed: the paved road should not need an install step to be green.
[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "{parsed.distribution}"
version = "0.1.0"
description = "ARACHNE check plugin: {parsed.id}"
requires-python = ">=3.11"
dependencies = ["arachne>=0.1"]

[project.entry-points."arachne.modules"]
{parsed.name} = "{package}:PLUGIN_GROUP"

[tool.hatch.build.targets.wheel]
packages = ["src/{package}"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
"""


def _check_source(parsed: CheckId, metadata: CheckMetadata) -> str:
    title_literal = _literal(metadata.title, indent="    ")
    description_literal = _literal(metadata.description, indent="    ")
    module_docstring = _docstring(_module_docstring_text(parsed), indent="")
    class_docstring = _docstring(
        f"`{parsed.id}` — {metadata.title}.\n\n{metadata.description}", indent="    "
    ).lstrip()
    return f'''"""{module_docstring}
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from arachne.core.results import CheckResult
from arachne.ecos.sdk import AuthorCheck
from arachne.modules.context import CheckContext
from arachne.modules.registry import ModuleGroup

__all__ = ["MARKERS", "PATH", "PLUGIN_GROUP", "{parsed.class_name}"]

#: What this check looks for in the response body. A real check keeps its token
#: list in managed data (`src/arachne/templates/`) so a vendor can be added
#: without a code change; a first check can keep it here.
MARKERS: tuple[str, ...] = {_tuple_literal((_SCAFFOLD_MARKER,))}
#: The path this check reads, relative to the asset's origin. GET only.
PATH = "/{parsed.name}"


class {parsed.class_name}(AuthorCheck):
    """{class_docstring}
    """

    check_id = "{parsed.id}"
    check_title = {title_literal}
    check_description = {description_literal}
    check_framework = {_tuple_literal(metadata.framework)}
    check_cwe = {_python_value(metadata.cwe)}
    check_research_ref = "{metadata.research_ref}"
    check_severity_hint = {json.dumps(metadata.severity_hint)}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client = ctx.http
        if client is None:
            # Dry-run mode: no client exists because nothing may be sent.
            yield ctx.skipped("no HTTP client (dry-run mode)")
            return

        exchange = await client.get(ctx.asset.value.rstrip("/") + PATH)
        if exchange.status_code >= 400:
            return
        marker = next((item for item in MARKERS if item in exchange.body), None)
        if marker is None:
            return
        body = exchange.to_dict()
        evidence = ctx.evidence("http_response", body, source=ctx.asset.key)
        yield ctx.candidate(
            {json.dumps(metadata.title)},
            detail=f"HTTP {{exchange.status_code}} at {{PATH}} carries {{marker!r}}",
            confidence=0.5,
            evidence=[evidence],
        )


#: The group the entry point exports. Its id ({parsed.module}) matches the check
#: metadata module, so discovery *merges* it into the built-in module.
PLUGIN_GROUP = ModuleGroup(
    id="{parsed.module}",
    title="{parsed.module} ({parsed.distribution})",
    description="{parsed.distribution} supplies {parsed.id}.",
    version="0.1",
    checks=({parsed.class_name},),
    research_chapter="{metadata.research_ref.split("#", 1)[0]}",
    origin="{parsed.distribution}",
)
'''


def _module_docstring_text(parsed: CheckId) -> str:
    return (
        f"{parsed.distribution} — the {parsed.id} check plugin.\n\n"
        f"Generated by `arachne plugin new-check {parsed.id}`. The metadata, the fixtures and "
        "the test are wired; replace the marker lookup in `run` with the claim this check "
        "actually establishes, then run `arachne plugin conform conformance.yaml` before "
        "opening a pull request."
    )


def _test_source(parsed: CheckId, package: str) -> str:
    del package  # the test is manifest-driven, so it does not import the package by name
    return f'''"""Tests for {parsed.id}: the recorded positive fires, the decoy stays clean.

Run with `python -m pytest tests -q` from this directory. The check is loaded from
`conformance.yaml`, so these tests need no install, no entry point and no network:
an authoring test has to be green on any checkout, which is what makes it a gate
rather than a ritual.
"""

from __future__ import annotations

from pathlib import Path

from arachne.core.results import CheckResult
from arachne.ecos.sdk import load_check, load_manifest, run_fixture

HERE = Path(__file__).resolve().parent
MANIFEST = load_manifest(HERE.parent / "conformance.yaml")
CHECK = load_check(MANIFEST)


def results(fixture: Path | None) -> list[CheckResult]:
    """Every result the check produces for one recorded fixture."""
    assert fixture is not None, "the manifest declares no such fixture"
    return run_fixture(CHECK, fixture)


def findings(fixture: Path | None) -> list[CheckResult]:
    """The candidate findings in that run."""
    return [item for item in results(fixture) if item.status == "vulnerable"]


def verdicts(fixture: Path | None) -> list[tuple[str, str, str | None]]:
    """(status, title, detail) per result: the deterministic part of a run."""
    return [(item.status, item.title, item.detail) for item in results(fixture)]


def test_the_positive_fixture_is_reported() -> None:
    reported = findings(MANIFEST.positive)
    assert reported, "the positive fixture produced no finding"
    assert reported[0].evidence, "a finding must carry evidence"


def test_the_decoy_fixture_is_clean() -> None:
    dirty = findings(MANIFEST.decoy)
    assert not dirty, f"the decoy produced findings: {{[item.title for item in dirty]}}"


def test_the_verdict_is_deterministic() -> None:
    assert verdicts(MANIFEST.positive) == verdicts(MANIFEST.positive)
'''


def _mapping_source(parsed: CheckId, metadata: CheckMetadata) -> str:
    """The framework-mapping entry: what this check's evidence bears on, and at what level.

    It restates ``CheckMetadata.framework`` and the proof declaration on purpose, and is
    generated from them, so the file cannot drift at authoring time. The conformance kit reads
    it back and refuses a check whose metadata no longer agrees — that is how "no framework
    mapping" and "L2 without opt-in" stay *detected* defects rather than conventions.
    """
    items = "\n".join(f"  - {item}" for item in metadata.framework)
    level = metadata.proof.value if isinstance(metadata.proof, ProofLevel) else str(metadata.proof)
    return f"""# The mapping entry for {parsed.id} (REQ-DET-002, REQ-PROOF-001).
#
# Generated from the check's metadata; edit the metadata and regenerate rather than editing
# this file alone. The framework ids must come from the pinned snapshots in
# `src/arachne/data/frameworks/`: a WSTG id that does not exist, or a CWE outside the pinned
# range, is refused at registration.
check: {parsed.id}
module: {parsed.module}
framework:
{items}
cwe: {metadata.cwe if metadata.cwe else "null"}
proof: {level}
enabled_by_default: {str(metadata.enabled_by_default).lower()}
requires_state_attestation: {str(metadata.requires_state_attestation).lower()}
"""


def _conformance_manifest(parsed: CheckId, package: str) -> str:
    """What the conformance kit reads: the check, its module file and its two fixtures."""
    return f"""# The conformance manifest for {parsed.id} (REQ-ECOS-007).
#
# `arachne plugin conform conformance.yaml` runs the kit over the check this file names. The
# decoy entry is not optional: a check with no assigned false-positive trap cannot be merged,
# so its absence is one of the four defects the kit reports.
format: {CONFORMANCE_MANIFEST_FORMAT}
check: {parsed.id}
module_file: src/{package}/__init__.py
mapping: mappings/{parsed.name}.yaml
positive: fixtures/{parsed.name}/positive.json
decoy: fixtures/{parsed.name}/decoy.json
"""


def _docs_source(parsed: CheckId, metadata: CheckMetadata, package: str) -> str:
    items = ", ".join(metadata.framework)
    level = metadata.proof.value if isinstance(metadata.proof, ProofLevel) else str(metadata.proof)
    kinds = ", ".join(kind.value for kind in metadata.target_kinds)
    return f"""# {metadata.title}

| | |
|---|---|
| Check id | `{parsed.id}` |
| Module | {parsed.module} |
| Proof level | {level} |
| Framework mapping | {items} |
| Target kinds | {kinds} |
| Estimated requests | {metadata.estimated_requests} per applicable asset |

## What is established

{metadata.description}

## How

One GET to `PATH` below the asset's origin, and a search of the response body for the tokens
in `MARKERS`. The response is a candidate finding when it carries a token. The decoy fixture
(`fixtures/{parsed.name}/decoy.json`) is a 200 that names the concept and carries no token; the
check must stay silent on it.

## Evidence a reviewer can check by hand

The recorded `http_response` (status, headers and the body) travels with the finding, so the
claim can be confirmed with one `curl` against the same path.

## Before merging

1. Replace the marker list with the real claim (or move it to managed data).
2. Record the response that made you write the check as `fixtures/{parsed.name}/positive.json`.
3. Run `arachne plugin conform conformance.yaml` and fix everything it reports.
4. Add a release-note line; the mapping entry (`mappings/{parsed.name}.yaml`) already states
   what this check covers.

*Generated by `arachne plugin new-check {parsed.id}`; package `{package}`.*
"""


def module_checks(module: Any) -> tuple[type[Module], ...]:
    """The :class:`Module` subclasses ``module`` *defines* (not the ones it imported).

    A candidate file is imported by the conformance kit, and an import brings names with it;
    only a class whose ``__module__`` is the candidate's own can be the check under test.
    """
    found: list[type[Module]] = []
    for value in vars(module).values():
        if not isinstance(value, type) or not issubclass(value, Module):
            continue
        if value.__module__ == getattr(module, "__name__", None):
            found.append(value)
    return tuple(found)


def check_class_in(module: Any, check_id: str | None = None) -> type[Module]:
    """The one :class:`Module` a candidate file defines, or a message naming the problem.

    ``check_id`` selects among several; without it a file must define exactly one, because
    guessing which of two checks a manifest means would produce a verdict about the wrong one.
    """
    found = module_checks(module)
    if check_id:
        matching = [item for item in found if item.metadata.id == check_id]
        if not matching:
            identifiers = ", ".join(sorted(item.metadata.id for item in found)) or "none"
            msg = f"the candidate defines no check with id {check_id!r} (found: {identifiers})"
            raise ConfigurationError(msg)
        return matching[0]
    if not found:
        msg = "the candidate defines no Module subclass"
        raise ConfigurationError(msg)
    if len(found) > 1:
        identifiers = ", ".join(sorted(item.metadata.id for item in found))
        msg = (
            f"the candidate defines {len(found)} checks ({identifiers}); name the one to "
            "conform with `check:` in the conformance manifest"
        )
        raise ConfigurationError(msg)
    return found[0]
