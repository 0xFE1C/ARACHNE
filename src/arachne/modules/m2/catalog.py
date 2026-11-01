"""M2's managed data: the port catalogue and the offline CVE index (F-09-03, ADR-04).

Both files live under ``templates/m2/`` and are loaded through ``importlib.resources``, so
they ship inside the wheel exactly like the planning catalogue does. Loading is strict
(unknown fields fail), because a typo in the CVE index would silently disable a whole
correlation and "no findings" is indistinguishable from "no matching version" in a report.

The version-matching engine (:func:`version_matches`) is deliberately tiny and total: M2
compares the version strings banners actually produce (``9.8p1``, ``1.18.0``, ``5.5.62``,
``2.4.49``) against written constraints, and a version it cannot parse is reported as
*unmatched*, never as a match. A false CVE is worse than a missing one.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.core.errors import ConfigurationError

__all__ = [
    "CVE_BASELINE_RESOURCE",
    "CVE_INDEX_RESOURCE",
    "PORT_CATALOG_RESOURCE",
    "CveEntry",
    "CveIndex",
    "PortCatalog",
    "PortEntry",
    "VersionConstraint",
    "load_cve_index",
    "load_port_catalog",
    "merge_cve_indexes",
    "normalize_product",
    "parse_version",
    "version_matches",
]

#: Locations of the bundled data files, relative to the ``arachne.templates`` package.
PORT_CATALOG_RESOURCE: Final = ("m2", "ports.yaml")
#: S18: the index is a **generated baseline** plus this **curated overlay**. The overlay is the
#: hand-written file this stage inherited (impact/remediation prose, priority calls and the
#: signal-triggered entries no CPE can express); the baseline is regenerated from the synced
#: NVD corpus by ``arachne intel build-index`` (REQ-INTEL-001, ADR-230.4).
CVE_INDEX_RESOURCE: Final = ("m2", "cve-index.yaml")
CVE_BASELINE_RESOURCE: Final = ("m2", "cve-index-baseline.yaml")

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: A probe family the fingerprinter knows how to speak (see ``m2/fingerprint.py``).
ProbeName = Literal[
    "unknown",
    "ssh",
    "http",
    "tls",
    "ftp",
    "telnet",
    "smtp",
    "pop3",
    "imap",
    "dns",
    "ntp",
    "ssdp",
    "smb",
    "rpcbind",
    "ldap",
    "kerberos",
    "vnc",
    "rdp",
    "mysql",
    "postgres",
    "mssql",
    "oracle",
    "redis",
    "memcached",
    "mongodb",
    "elasticsearch",
    "couchdb",
    "snmp",
    "modbus",
    "bacnet",
    # S29 depth expansion (REQ-DEPTH-003/006): the gRPC/HTTP-2 posture family and the
    # read-only OT protocols. A catalogue entry with one of these names is the documented
    # way to say where the service lives on a non-standard port (F-09-04).
    "grpc",
    "s7",
    "dnp3",
]

#: Operators the version matcher understands (``all`` is a whole-table wildcard).
_OPERATORS: Final[frozenset[str]] = frozenset({"<", "<=", ">", ">=", "==", "=", "all"})


class PortEntry(BaseModel):
    """One port in the catalogue: its number, neutral service name and probe hint."""

    model_config = _MODEL_CONFIG

    port: int = Field(ge=1, le=65535)
    service: str = Field(min_length=1, max_length=64)
    probe: ProbeName = "unknown"


class PortCatalog(BaseModel):
    """The shipped port catalogue (order *is* the frequency rank)."""

    model_config = _MODEL_CONFIG

    catalog_version: str = Field(min_length=1, max_length=32)
    source: str = ""
    tcp: tuple[PortEntry, ...] = ()
    udp: tuple[PortEntry, ...] = ()

    @property
    def tcp_ports(self) -> tuple[PortEntry, ...]:
        return self.tcp

    @property
    def udp_ports(self) -> tuple[PortEntry, ...]:
        return self.udp

    def top_tcp(self, count: int) -> tuple[int, ...]:
        """The first ``count`` TCP ports, i.e. the "top-ports" policy of research ch02#7."""
        return tuple(entry.port for entry in self.tcp[: max(0, count)])

    def hint(self, port: int, *, protocol: str = "tcp") -> PortEntry | None:
        """The catalogue's entry for ``port`` (a hint only — never a conclusion)."""
        table = self.udp if protocol == "udp" else self.tcp
        for entry in table:
            if entry.port == port:
                return entry
        return None

    def hint_service(self, port: int, *, protocol: str = "tcp") -> str | None:
        entry = self.hint(port, protocol=protocol)
        return entry.service if entry else None

    def ports_for_probe(self, probe: str, *, protocol: str = "tcp") -> tuple[int, ...]:
        table = self.udp if protocol == "udp" else self.tcp
        return tuple(entry.port for entry in table if entry.probe == probe)


@dataclass(frozen=True, slots=True)
class VersionConstraint:
    """One constraint of an ``affected`` clause."""

    op: str = "all"
    version: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"op": self.op, "version": self.version}


class CveEntry(BaseModel):
    """One row of the offline index: a product/version range and the CVE it implies."""

    model_config = _MODEL_CONFIG

    product: str = Field(min_length=1, max_length=128)
    aliases: tuple[str, ...] = ()
    vendor: str | None = None
    #: ``[{op: "<", version: "9.8"}]``, or the shorthand ``[all]`` for "every version".
    affected: tuple[Mapping[str, Any] | str, ...] = ()
    cve: str = Field(pattern=r"^CVE-\d{4}-\d{4,7}$")
    #: S18: the generated baseline marks a row CISA has confirmed as exploited in the wild. The
    #: curated overlay may set it too; the correlation check reports it in the finding.
    kev: bool = False
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    epss: float | None = Field(default=None, ge=0.0, le=1.0)
    cwe: str | None = None
    title: str = Field(min_length=1, max_length=512)
    impact: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()
    #: A non-version signal that triggers the entry (``sslv3-supported``, ``3des-cipher``).
    match: str | None = None

    @property
    def constraints(self) -> tuple[VersionConstraint, ...]:
        parsed: list[VersionConstraint] = []
        for item in self.affected:
            if isinstance(item, str):
                # ``affected: [all]`` — the shorthand for "every version of this product".
                parsed.append(VersionConstraint(op="all" if item.strip() == "all" else item))
                continue
            op = str(item.get("op", "")).strip()
            version = str(item.get("version", "")).strip()
            if op == "all" or (not op and not version):
                parsed.append(VersionConstraint(op="all"))
                continue
            if op not in _OPERATORS:
                continue
            if op == "=":
                op = "=="
            parsed.append(VersionConstraint(op=op, version=version))
        return tuple(parsed)

    def product_names(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys([self.product, *self.aliases]))

    def all_versions_affected(self) -> bool:
        constraints = self.constraints
        return bool(constraints) and all(item.op == "all" for item in constraints)


class CveIndex(BaseModel):
    """The shipped offline CVE/EPSS snapshot."""

    model_config = _MODEL_CONFIG

    index_version: str = Field(min_length=1, max_length=32)
    generated_at: str = ""
    #: Provenance of a generated layer (the feed version it was built from); the overlay leaves
    #: it unset and the merged index keeps the overlay's ``generated_at``.
    source: str | None = None
    entries: tuple[CveEntry, ...] = ()

    def by_product(self) -> Mapping[str, tuple[CveEntry, ...]]:
        """``{normalized product name: entries}``, aliases included."""
        table: dict[str, list[CveEntry]] = {}
        for entry in self.entries:
            for name in entry.product_names():
                table.setdefault(normalize_product(name), []).append(entry)
        return {key: tuple(value) for key, value in table.items()}

    def for_signal(self, signal: str) -> tuple[CveEntry, ...]:
        """Entries triggered by a non-version signal (TLS posture, SMBv1, ...)."""
        return tuple(entry for entry in self.entries if entry.match == signal)


def _resource_text(resource: tuple[str, ...]) -> str:
    node = files("arachne.templates")
    for part in resource:
        node = node.joinpath(part)
    try:
        return node.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled data file is missing ({'/'.join(resource)}): {exc}"
        raise ConfigurationError(msg) from exc


def _load_yaml(path: str | Path | None, resource: tuple[str, ...]) -> Any:
    if path is None:
        text = _resource_text(resource)
        source = f"bundled {resource[-1]}"
    else:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"data file {resolved} does not exist or is not a file"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"cannot read data file {resolved}: {exc}"
            raise ConfigurationError(msg) from exc
        source = str(resolved)
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only, never yaml.load
    except yaml.YAMLError as exc:
        msg = f"{source}: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    return data


def _validation_error(source: str, exc: ValidationError) -> ConfigurationError:
    parts: list[str] = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error["loc"]) or "<root>"
        parts.append(f"{location}: {error['msg']}")
    return ConfigurationError(f"{source}: invalid data: {'; '.join(parts)}")


def load_port_catalog(path: str | Path | None = None) -> PortCatalog:
    """Load the port catalogue from ``path``, or the bundled default."""
    data = _load_yaml(path, PORT_CATALOG_RESOURCE)
    source = str(path) if path is not None else "bundled port catalogue"
    try:
        catalog = PortCatalog.model_validate(data)
    except ValidationError as exc:
        raise _validation_error(source, exc) from exc
    if not catalog.tcp:
        msg = f"{source}: no TCP ports defined"
        raise ConfigurationError(msg)
    return catalog


def load_cve_index(
    path: str | Path | None = None, *, baseline: str | Path | None = None
) -> CveIndex:
    """Load the offline CVE index: the generated baseline merged with the curated overlay.

    ``path`` is the overlay (``None`` = the bundled one, ``ARACHNE_CVE_INDEX``), which always
    wins on a repeated ``(product, cve)`` pair. ``baseline`` is the generated layer:
    ``None`` loads the bundled baseline, a path loads that file, and the literal ``"off"``
    (or ``"none"``) disables the layer — which is what a deployment that wants only its
    hand-curated table sets, and what an air-gapped box with no baseline file gets anyway.
    """
    overlay = _load_cve_document(path, CVE_INDEX_RESOURCE, label="CVE index")
    if overlay is None:  # pragma: no cover - only the baseline layer may be absent
        msg = "the curated CVE-index overlay could not be loaded"
        raise ConfigurationError(msg)
    if baseline is not None and str(baseline).strip().lower() in {"off", "none", ""}:
        return overlay
    generated = _load_cve_document(
        baseline, CVE_BASELINE_RESOURCE, label="CVE-index baseline", missing_ok=baseline is None
    )
    if generated is None:
        return overlay
    return merge_cve_indexes(baseline=generated, overlay=overlay)


def _load_cve_document(
    path: str | Path | None,
    resource: tuple[str, ...],
    *,
    label: str,
    missing_ok: bool = False,
) -> CveIndex | None:
    """Load one CVE-index layer; ``missing_ok`` turns a missing *bundled* file into ``None``."""
    if path is None and missing_ok:
        node = files("arachne.templates")
        for part in resource:
            node = node.joinpath(part)
        if not node.is_file():
            return None
    data = _load_yaml(path, resource)
    source = str(path) if path is not None else f"bundled {label.lower()}"
    try:
        return CveIndex.model_validate(data)
    except ValidationError as exc:
        raise _validation_error(source, exc) from exc


def merge_cve_indexes(*, baseline: CveIndex, overlay: CveIndex) -> CveIndex:
    """Merge the generated baseline with the curated overlay; the overlay wins.

    Identity is ``(normalized product, cve)`` — the same pair ``by_product()`` looks entries up
    by — so an operator can correct a generated row's prose, cvss or affected range by writing
    one entry with the same product and CVE, and the rest of the baseline still applies. The
    merged index reports both versions, so a report can say which data produced a match.
    """
    merged: dict[tuple[str, str], CveEntry] = {}
    for entry in baseline.entries:
        merged[(normalize_product(entry.product), entry.cve)] = entry
    for entry in overlay.entries:
        merged[(normalize_product(entry.product), entry.cve)] = entry
    ordered = sorted(merged.values(), key=lambda item: (item.product, item.cve))
    return CveIndex(
        index_version=f"{baseline.index_version}+{overlay.index_version}"[:32],
        generated_at=overlay.generated_at or baseline.generated_at,
        entries=tuple(ordered),
    )


# --------------------------------------------------------------------------- matching
_VERSION_TOKEN = re.compile(r"\d+")


def normalize_product(value: str) -> str:
    """Normalize a product name for matching: lower case, single spaces, no punctuation."""
    text = value.strip().lower()
    text = re.sub(r"[/_]+", " ", text)
    text = re.sub(r"[^a-z0-9. +\-]+", "", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_version(value: str) -> tuple[int, ...] | None:
    """Turn a banner version string into comparable integers.

    ``9.8p1`` → ``(9, 8, 1)``; ``1.18.0`` → ``(1, 18, 0)``; ``2.4.49`` → ``(2, 4, 49)``;
    ``5.5.62-log`` → ``(5, 5, 62)``. Returns ``None`` when the string holds no digits at
    all, which is what makes an unparseable version *unmatched* rather than guessed.
    """
    parts = _VERSION_TOKEN.findall(value or "")
    if not parts:
        return None
    return tuple(int(part) for part in parts[:6])


def _compare(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    """Tuple comparison, zero-padded so ``1.18`` and ``1.18.0`` compare equal."""
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return (padded_left > padded_right) - (padded_left < padded_right)


def _constraint_holds(constraint: VersionConstraint, version: tuple[int, ...]) -> bool | None:
    """``True``/``False``/``None`` (unknown: the constraint or version is unusable)."""
    if constraint.op == "all":
        return True
    other = parse_version(constraint.version)
    if other is None:
        return None
    order = _compare(version, other)
    if constraint.op == "<":
        return order < 0
    if constraint.op == "<=":
        return order <= 0
    if constraint.op == ">":
        return order > 0
    if constraint.op == ">=":
        return order >= 0
    if constraint.op == "==":
        return order == 0
    return None


def version_matches(
    version: str,
    constraints: Iterable[VersionConstraint],
    *,
    accept_all: bool = True,
) -> bool:
    """True when ``version`` satisfies every constraint.

    An empty constraint tuple matches only when ``accept_all`` is set (the caller decides
    whether "no range written" means "any version" — for a product-level CVE it does).
    A version that cannot be parsed never matches, and a constraint that cannot be parsed
    makes the whole entry unmatched: the failure mode is a missing finding, not a wrong one.
    """
    items = tuple(constraints)
    if not items:
        return accept_all
    parsed = parse_version(version)
    if parsed is None:
        return False
    for constraint in items:
        holds = _constraint_holds(constraint, parsed)
        if holds is None or not holds:
            return False
    return True


@dataclass(frozen=True, slots=True)
class MatchResult:
    """One ``(service, entry)`` match, with the constraints that produced it."""

    entry: CveEntry
    version: str
    constraints: tuple[VersionConstraint, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.entry.cve,
            "title": self.entry.title,
            "product": self.entry.product,
            "version": self.version,
            "cvss": self.entry.cvss,
            "epss": self.entry.epss,
            "cwe": self.entry.cwe,
            "constraints": [item.to_dict() for item in self.constraints],
        }
