"""The plugin contract (docs/spec/02- §5, F-02-01, F-09-01).

One :class:`Module` is one **check**: a thin, typed, async unit that inspects one asset and
yields :class:`~arachne.core.results.CheckResult` objects. It declares its metadata up
front (the common check metadata of docs/spec/05-) and never decides severity or writes
prose — analysis is the Analyzer's job (ADR-02).

The names in this module follow docs/spec/02- §5 verbatim: the base class is ``Module``,
it carries ``name`` / ``version`` / ``description`` / ``research_ref``, and it exposes
``supports(asset)`` and ``run(ctx)``. The M1..M6 grouping from docs/spec/02- §2.2 is a
separate, thinner concept (:class:`~arachne.modules.registry.ModuleGroup`), because one
class cannot be both "a check" (single ``research_ref``, ``supports(one asset)``) and "a
package of thirteen checks".

Two invariants this module protects:

* **Metadata is validated at class-definition time.** A bad ``id``, a ``research_ref`` that
  is not ``chNN#M``, or a check that claims to be active but not to require an opt-in is a
  programming error, and it must fail at import rather than produce a plan nobody can trust.
  The same is true of the proof ladder (S15, REQ-PROOF-001): an L2+ check that is not opt-in,
  or an L3/L4 check that does not declare the state-change attestation requirement, cannot be
  constructed at all.
* **Findings carry evidence.** ``run`` yields results; a ``vulnerable`` result without
  evidence is unrepresentable only by convention — :meth:`CheckResult` keeps it possible,
  so the checks step (``modules.handlers``) records every candidate with whatever evidence
  it has and the report engine decides how to present it.
"""

from __future__ import annotations

import ipaddress
import re
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, ClassVar, Literal
from urllib.parse import urlsplit

from arachne.core.errors import ConfigurationError
from arachne.core.proof import ProofLevel, metadata_proof_problems
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind

if TYPE_CHECKING:  # a type-only cycle: context.py imports this module for Asset/Module
    from arachne.modules.context import CheckContext

__all__ = [
    "ASSET_KINDS",
    "Asset",
    "CheckMetadata",
    "CheckType",
    "Module",
    "ProofLevel",
    "SeverityHint",
]

#: ``passive`` never touches the target (third-party indexes only); ``active`` talks to the
#: target; ``hybrid`` does both (docs/spec/05- "Common check metadata").
CheckType = Literal["passive", "active", "hybrid"]

#: A *hint* for the analyzer's default scoring, never a severity decision (ADR-02).
SeverityHint = Literal["info", "low", "medium", "high", "critical"]

#: The asset vocabulary (``assets.kind``, docs/spec/02- §2.4 plus the S2 seed mapping in
#: ``core.steps.seed_asset``): a declared domain, a host name or address, a URL, a network,
#: a Git reference, a cloud resource.
ASSET_KINDS: frozenset[str] = frozenset(
    {"domain", "domain_pattern", "host", "url", "network", "git", "cloud", "bucket", "artifact"}
)

_MODULE_ID = re.compile(r"^M[1-6]$")
_CHECK_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_RESEARCH_REF = re.compile(r"^ch0[1-6]#\d{1,2}(?:-\d{1,2})?$")
_CWE = re.compile(r"^CWE-\d{1,5}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


@dataclass(frozen=True, slots=True)
class CheckMetadata:
    """The common check metadata of docs/spec/05-, validated on construction.

    ``id`` is the module-qualified identity (``m1.ct-lookup``) used in plans, reports and
    the coverage matrix; ``(module, name, version)`` is the tuple the ``checks`` table and
    the planner catalogue key on, so the same check cannot be described two different ways.
    """

    id: str
    module: str
    name: str
    version: str
    title: str
    description: str
    research_ref: str
    target_kinds: tuple[TargetKind, ...] = ()
    cwe: str | None = None
    cve: str | None = None
    severity_hint: SeverityHint = "info"
    type: CheckType = "passive"
    safe: bool = True
    verifiable: bool = False
    enabled_by_default: bool = True
    #: How far this check may go to prove a finding (REQ-PROOF-001): L0 passive,
    #: L1 active read-only (the default), L2 out-of-band, L3 one-shot command,
    #: L4 minimal reversible state change. L2+ is opt-in by definition and L3/L4
    #: additionally demand :attr:`requires_state_attestation`; a contradictory
    #: declaration is refused here, at construction (unrepresentable-invalid).
    proof: ProofLevel = ProofLevel.L1
    #: True only for L3/L4 checks: they change (or prove execution on) the target and
    #: therefore require an attestation that authorizes state changes (REQ-PROOF-001).
    requires_state_attestation: bool = False
    rate_cost: float = 1.0
    estimated_requests: int = 0
    requires_active_checks: bool = False
    #: Environment-only credentials the check needs (F-08-01); empty means "none".
    requires_credentials: tuple[str, ...] = ()
    #: True when the check only runs against assets the *target definition* declared. A
    #: check that would feed on its own discoveries (and so multiply its own request count)
    #: must opt in explicitly, which keeps the dry-run estimate honest.
    runs_on_discovered: bool = False

    def __post_init__(self) -> None:
        problems: list[str] = []
        if not _MODULE_ID.match(self.module):
            problems.append(f"module {self.module!r} is not a module id (expected M1..M6)")
        if not _CHECK_NAME.match(self.name):
            problems.append(f"name {self.name!r} is not kebab-case")
        expected_id = f"{self.module.lower()}.{self.name}"
        if self.id != expected_id:
            problems.append(f"id {self.id!r} must equal {expected_id!r} (module.name)")
        if not _RESEARCH_REF.match(self.research_ref):
            problems.append(
                f"research_ref {self.research_ref!r} is not a corpus reference (expected chNN#M)"
            )
        if self.cwe is not None and not _CWE.match(self.cwe):
            problems.append(f"cwe {self.cwe!r} is not CWE-NNN")
        if self.cve is not None and not _CVE.match(self.cve):
            problems.append(f"cve {self.cve!r} is not CVE-YYYY-NNNN")
        if not self.target_kinds:
            problems.append("target_kinds is empty: the check could never run")
        unknown = sorted({kind.value for kind in self.target_kinds} - {k.value for k in TargetKind})
        if unknown:
            problems.append(f"unknown target kind(s) {unknown}")
        if self.estimated_requests < 0:
            problems.append("estimated_requests must be >= 0")
        if self.rate_cost < 0:
            problems.append("rate_cost must be >= 0")
        if self.type == "active" and not self.requires_active_checks:
            # An active check that does not demand an opt-in would bypass the safety gate
            # of F-01-09; the two flags exist together or not at all.
            problems.append("an active check must set requires_active_checks=True")
        if self.requires_active_checks and not self.safe:
            # "safe" means "read-only, no state change". An unsafe active check has no
            # place in a scanner that detects rather than exploits (docs/spec/07- §8).
            problems.append("requires_active_checks=True with safe=False is not supported")
        try:
            # One coercion point: check authors may write proof="L1", and every consumer
            # (plans, reports, the proof gate) then sees a ProofLevel. An invalid value
            # becomes a metadata problem below rather than a crash with no context.
            object.__setattr__(self, "proof", ProofLevel(self.proof))
        except ValueError:
            problems.append(f"proof {self.proof!r} is not a ProofLevel (L0..L4)")
        if isinstance(self.proof, ProofLevel):
            # REQ-PROOF-001: L2+ without the opt-in flag, or L3/L4 without the state-change
            # attestation requirement (and the inverse of each), is unrepresentable.
            problems.extend(
                metadata_proof_problems(
                    self.proof,
                    enabled_by_default=self.enabled_by_default,
                    requires_state_attestation=self.requires_state_attestation,
                )
            )
        if not self.title or not self.description:
            problems.append("title and description are required")
        if problems:
            raise ConfigurationError(
                f"invalid check metadata for {self.id!r}: " + "; ".join(problems)
            )

    @property
    def key(self) -> str:
        """``module/name@version`` — the identity plans, reports and the store key on."""
        return f"{self.module}/{self.name}@{self.version}"

    @property
    def is_opt_in(self) -> bool:
        """True when the check is not part of the default set (F-02-09)."""
        return not self.enabled_by_default

    def supports_kind(self, kind: TargetKind) -> bool:
        return kind in self.target_kinds


@dataclass(frozen=True, slots=True)
class Asset:
    """The thing a check inspects (docs/spec/02- §5 ``supports(asset)``).

    ``kind`` uses the asset vocabulary (``host``, ``network``, ...) while check metadata
    declares applicability in *target* kinds (``ip``, ``cidr``, ...); :meth:`selector_kind`
    is the single translation between them, so a declared IP target and an ``ip``-scoped
    check always agree.
    """

    kind: str
    value: str
    meta: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.kind not in ASSET_KINDS:
            msg = f"unknown asset kind {self.kind!r}; expected one of {sorted(ASSET_KINDS)}"
            raise ConfigurationError(msg)
        if not self.value:
            msg = "asset value must not be empty"
            raise ConfigurationError(msg)

    # ------------------------------------------------------------------ derivation
    @property
    def declared(self) -> bool:
        """True when the target definition named this asset (rather than a check finding it)."""
        return bool(self.meta.get("declared"))

    @property
    def host(self) -> str | None:
        """The host this asset refers to, when it has one."""
        if self.kind == "url":
            return urlsplit(self.value).hostname
        if self.kind in {"domain", "domain_pattern", "host"}:
            return self.value
        return None

    @property
    def query_name(self) -> str | None:
        """The name a passive source is queried with (no wildcard label, no scheme)."""
        host = self.host
        if host is None:
            return None
        return host[2:] if host.startswith("*.") else host

    def selector_kind(self) -> TargetKind | None:
        """The target kind this asset corresponds to (``None`` for Git/cloud references)."""
        if self.kind == "url":
            return TargetKind.URL
        if self.kind == "domain":
            return TargetKind.DOMAIN
        if self.kind == "domain_pattern":
            return TargetKind.DOMAIN_PATTERN
        if self.kind == "network":
            return TargetKind.CIDR
        if self.kind == "git":
            return TargetKind.GIT
        if self.kind == "cloud":
            return TargetKind.CLOUD
        if self.kind == "artifact":
            # A local artifact (S29, REQ-DEPTH-005): an offline input, never a network one.
            return TargetKind.ARTIFACT
        if self.kind == "host":
            # A seeded IP target becomes a ``host`` asset (core.steps.seed_asset); a
            # discovered name is also a ``host``. The value decides which one it is.
            return TargetKind.IP if _is_ip_literal(self.value) else TargetKind.DOMAIN
        return None

    @classmethod
    def from_meta(cls, kind: str, value: str, meta: dict[str, object] | None = None) -> Asset:
        return cls(kind=kind, value=value, meta=dict(meta or {}))

    @property
    def key(self) -> str:
        """``kind:value`` — a stable label for logs, events and step statistics."""
        return f"{self.kind}:{self.value}"

    def to_dict(self) -> dict[str, object]:
        return {"kind": self.kind, "value": self.value, "meta": dict(self.meta)}


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


class Module(ABC):
    """A detection check (docs/spec/02- §5, F-02-01).

    Subclasses set :attr:`metadata` and implement :meth:`run`. Everything else — name,
    version, description, research reference, applicability — is derived from the metadata
    so the two can never disagree.
    """

    #: Every subclass must set this. It is a ``ClassVar`` so the registry can read metadata
    #: without instantiating the check (planning must not import side effects).
    metadata: ClassVar[CheckMetadata]

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        if getattr(cls, "metadata", None) is None:
            msg = f"{cls.__name__} does not declare check metadata"
            raise ConfigurationError(msg)

    # ------------------------------------------------------------------ §5 attributes
    @property
    def name(self) -> str:
        return self.metadata.name

    @property
    def version(self) -> str:
        return self.metadata.version

    @property
    def description(self) -> str:
        return self.metadata.description

    @property
    def research_ref(self) -> str:
        return self.metadata.research_ref

    # ------------------------------------------------------------------ contract
    def supports(self, asset: Asset) -> bool:
        """True when this check applies to ``asset``.

        The default is metadata-driven — the asset's target kind is one of the declared
        ``target_kinds`` — and a check that needs more (a URL that actually serves
        JavaScript, a network with more than one address) overrides it.
        """
        if asset.kind == "bucket":
            return TargetKind.CLOUD in self.metadata.target_kinds
        kind = asset.selector_kind()
        if kind is None:
            return False
        return self.metadata.supports_kind(kind)

    @abstractmethod
    def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        """Inspect ``ctx.asset`` and yield candidate results (F-02-08).

        A generator, not a coroutine returning a list: results stream, so a check that
        finds something early reports it without waiting for its budget to run out.
        """
        raise NotImplementedError
