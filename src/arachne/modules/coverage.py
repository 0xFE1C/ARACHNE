"""Coverage matrix: which research methods are mapped to checks (G-01).

Goal G-01 asks for "≥ 90% of research methods mapped to checks", tracked in a generated
``coverage_matrix.md``. The tool works the way `` §9.5 describes: it **greps
``research_ref:`` values** out of the source tree and reports them against the method
universe parsed from ``docs/research/``.

Two deliberate properties:

* **It greps rather than importing.** The matrix must be computable for code that does not
  import cleanly (a half-migrated tree, a plugin under development) and must never be able to
  run a check as a side effect. Only the two parsing steps are I/O: reading ``.py``/``.yaml``
  text, and reading the research chapters.
* **It counts the corpus, not the catalogue.** Coverage is measured against the numbered
  methods in the research chapters (30 + 30 + 35 + 30 + 25 + 25 = 175), because that is what
  G-01 means. Default roots are the *implemented* module sources, so a row in the planning
  catalogue that no check implements does not inflate the number; ``include_templates`` adds
  the data files when a caller wants the "planned" view as well.

The second half of this module is the **framework coverage ledger** (REQ-DET-001): one record
per registered check — its identity, proof level, target kinds, framework mapping and the date
it was last verified — plus the WSTG per-id states (REQ-DET-003) and the API Top 10 tally
(REQ-DET-005). Unlike the matrix it does *not* grep: it reads ``ModuleRegistry``, because the
mapping is now a validated metadata field and the registry is the whole truth.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from arachne.core.errors import ConfigurationError
from arachne.modules import lifecycle_policy
from arachne.modules.framework_map import (
    api_top10_coverage,
    asi_top10_coverage,
    cwe_top25_coverage,
    cwe_top25_framework,
    framework_versions,
    llm_top10_coverage,
    sorted_items,
    wstg_coverage,
)

if TYPE_CHECKING:  # a registry is imported lazily: this module must stay importable alone
    from arachne.modules.registry import ModuleRegistry

__all__ = [
    "LEDGER_VERSION",
    "ChapterCoverage",
    "CoverageLedger",
    "CoverageReport",
    "LedgerRecord",
    "MethodCoverage",
    "RefHit",
    "ResearchMethod",
    "build_coverage",
    "build_ledger",
    "check_ledger",
    "default_ledger_paths",
    "default_research_dir",
    "default_source_roots",
    "expand_ref",
    "hits_by_check",
    "parse_research_methods",
    "render_coverage_markdown",
    "render_coverage_text",
    "render_ledger_json",
    "render_ledger_markdown",
    "scan_sources_for_refs",
    "write_coverage_markdown",
]

#: ``ch04#1``, ``ch01#12-13`` — the traceability reference a check declares.
_REF_RE = re.compile(r"\bresearch_ref\s*[:=]\s*[\"']?(ch0[1-6]#\d{1,2}(?:-\d{1,2})?)[\"']?")
#: ``id="m4.env-file-probe"`` / ``id: m4.env-file-probe`` / ``name: env-file-probe`` — the
#: check identity a reference belongs to. Tracked per file so a hit can name its check.
_ID_RE = re.compile(r"\b(?:id|name)\s*[:=]\s*[\"']?([A-Za-z0-9][A-Za-z0-9._\-]{0,80})[\"']?")
#: ``### 14. Wayback Machine and Web Archives`` — a method heading in a research chapter.
_METHOD_RE = re.compile(r"^###\s+(\d{1,2})\.\s+(.+?)\s*$")
#: ``03-web-application-vulnerability-testing.md`` / ``01-reconnaissance-and-osint.md`` —
#: the chapter number comes from the file name, because the chapter titles are not uniform
#: (``# Chapter 1 — ...`` in some files, ``# Web Application ...`` in others).
_CHAPTER_FILE_RE = re.compile(r"^(\d{1,2})[-_](.+)$")
#: ``# Chapter 1 — Passive Reconnaissance & OSINT``; used for the title, not the number.
_CHAPTER_RE = re.compile(r"^#\s+(?:Chapter\s+(\d{1,2})\b[^\w]*)?(.+?)\s*$")


@dataclass(frozen=True, slots=True)
class ResearchMethod:
    """One numbered method in a research chapter."""

    chapter: str
    number: int
    title: str
    chapter_title: str = ""

    @property
    def ref(self) -> str:
        return f"{self.chapter}#{self.number}"


@dataclass(frozen=True, slots=True)
class RefHit:
    """One ``research_ref`` occurrence in the source tree."""

    ref: str
    path: str
    line: int
    check_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"ref": self.ref, "path": self.path, "line": self.line, "check": self.check_id}


@dataclass(frozen=True, slots=True)
class MethodCoverage:
    """Whether one research method is mapped, and by which checks."""

    method: ResearchMethod
    checks: tuple[str, ...] = ()
    locations: tuple[str, ...] = ()

    @property
    def mapped(self) -> bool:
        return bool(self.checks or self.locations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref": self.method.ref,
            "chapter": self.method.chapter,
            "number": self.method.number,
            "title": self.method.title,
            "mapped": self.mapped,
            "checks": list(self.checks),
            "locations": list(self.locations),
        }


@dataclass(frozen=True, slots=True)
class ChapterCoverage:
    """Coverage for one research chapter."""

    chapter: str
    title: str
    methods: tuple[MethodCoverage, ...]

    @property
    def total(self) -> int:
        return len(self.methods)

    @property
    def mapped(self) -> int:
        return sum(1 for item in self.methods if item.mapped)

    @property
    def percent(self) -> float:
        return round(100.0 * self.mapped / self.total, 1) if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "chapter": self.chapter,
            "title": self.title,
            "total": self.total,
            "mapped": self.mapped,
            "percent": self.percent,
            "methods": [item.to_dict() for item in self.methods],
        }


@dataclass(frozen=True, slots=True)
class CoverageReport:
    """The whole matrix (G-01)."""

    chapters: tuple[ChapterCoverage, ...]
    hits: tuple[RefHit, ...] = ()
    research_dir: str | None = None
    source_roots: tuple[str, ...] = ()
    unmapped: tuple[str, ...] = field(default=())

    @property
    def total(self) -> int:
        return sum(chapter.total for chapter in self.chapters)

    @property
    def mapped(self) -> int:
        return sum(chapter.mapped for chapter in self.chapters)

    @property
    def percent(self) -> float:
        return round(100.0 * self.mapped / self.total, 1) if self.total else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "research_dir": self.research_dir,
            "source_roots": list(self.source_roots),
            "total": self.total,
            "mapped": self.mapped,
            "percent": self.percent,
            "unmapped": list(self.unmapped),
            "chapters": [chapter.to_dict() for chapter in self.chapters],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# --------------------------------------------------------------------------- parsing
def parse_research_methods(research_dir: str | Path) -> tuple[ResearchMethod, ...]:
    """Parse the numbered methods out of every research chapter (``docs/research/*.md``)."""
    directory = Path(research_dir).expanduser()
    if not directory.is_dir():
        msg = f"research directory {directory} does not exist"
        raise ConfigurationError(msg)
    methods: list[ResearchMethod] = []
    for chapter_file in sorted(directory.glob("*.md")):
        if chapter_file.name.lower() == "readme.md":
            continue
        methods.extend(_methods_in_file(chapter_file))
    if not methods:
        msg = f"no numbered methods found under {directory}"
        raise ConfigurationError(msg)
    return tuple(methods)


def _methods_in_file(path: Path) -> list[ResearchMethod]:
    """Parse one chapter: the number from the file name, the methods from ``### N.``."""
    match = _CHAPTER_FILE_RE.match(path.stem)
    if match is None:
        return []
    chapter = f"ch{int(match.group(1)):02d}"
    chapter_title = ""
    methods: list[ResearchMethod] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# ") and not chapter_title:
            title_match = _CHAPTER_RE.match(line)
            if title_match:
                chapter_title = title_match.group(2).strip()
            continue
        method_match = _METHOD_RE.match(line)
        if method_match:
            methods.append(
                ResearchMethod(
                    chapter=chapter,
                    number=int(method_match.group(1)),
                    title=method_match.group(2).strip(),
                    chapter_title=chapter_title,
                )
            )
    return methods


def scan_sources_for_refs(roots: Iterable[str | Path]) -> tuple[RefHit, ...]:
    """Grep ``research_ref`` occurrences out of ``.py``/``.yaml``/``.yml``/``.json`` files.

    A hit is associated with the nearest preceding ``id``/``name`` assignment in the same
    file, which is how the check metadata in this codebase is written (and how the data files
    spell it), so the matrix can say *which* check maps a method without parsing Python.
    """
    hits: list[RefHit] = []
    for root in roots:
        path = Path(root).expanduser()
        if path.is_file():
            hits.extend(_hits_in_file(path))
            continue
        if not path.is_dir():
            continue
        for candidate in sorted(path.rglob("*")):
            if candidate.suffix.lower() not in {".py", ".yaml", ".yml", ".json", ".md"}:
                continue
            hits.extend(_hits_in_file(candidate))
    return tuple(hits)


def _hits_in_file(path: Path) -> list[RefHit]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    hits: list[RefHit] = []
    current_id: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        id_match = _ID_RE.search(line)
        if id_match:
            current_id = id_match.group(1)
        ref_match = _REF_RE.search(line)
        if ref_match:
            hits.append(
                RefHit(ref=ref_match.group(1), path=str(path), line=number, check_id=current_id)
            )
    return hits


def expand_ref(ref: str) -> tuple[str, ...]:
    """``ch01#12-13`` → ``("ch01#12", "ch01#13")``; ``ch04#1`` → ``("ch04#1",)``."""
    chapter, _, numbers = ref.partition("#")
    if "-" not in numbers:
        return (f"{chapter}#{numbers}",)
    start, _, end = numbers.partition("-")
    try:
        first, last = int(start), int(end)
    except ValueError:
        return (ref,)
    if last < first:
        first, last = last, first
    return tuple(f"{chapter}#{number}" for number in range(first, last + 1))


def default_source_roots() -> tuple[Path, ...]:
    """The implemented module sources (see the module docstring for why not the catalogue)."""
    package = Path(__file__).resolve().parents[1]  # .../src/arachne
    return (package / "modules",)


def default_research_dir() -> Path | None:
    """Locate ``docs/research`` from a source checkout (``None`` when not present)."""
    here = Path(__file__).resolve()
    for candidate in (here.parents[3].parent, *here.parents):
        research = candidate / "docs" / "research"
        if research.is_dir():
            return research
    return None


def build_coverage(
    research_dir: str | Path | None = None,
    *,
    source_roots: Sequence[str | Path] | None = None,
    include_templates: bool = False,
) -> CoverageReport:
    """Compute the coverage matrix over ``source_roots`` (G-01)."""
    roots = tuple(source_roots) if source_roots is not None else default_source_roots()
    if include_templates:
        template_root = Path(__file__).resolve().parents[1] / "templates"
        roots = (*roots, template_root)
    hits = scan_sources_for_refs(roots)

    resolved_research = research_dir if research_dir is not None else default_research_dir()
    if resolved_research is None:
        # Without the corpus we can still report what is mapped, just not what is missing.
        return CoverageReport(
            chapters=(), hits=hits, research_dir=None, source_roots=tuple(str(r) for r in roots)
        )
    methods = parse_research_methods(resolved_research)

    by_ref: dict[str, list[RefHit]] = {}
    for hit in hits:
        for expanded in expand_ref(hit.ref):
            by_ref.setdefault(expanded, []).append(hit)

    chapters: dict[str, list[MethodCoverage]] = {}
    titles: dict[str, str] = {}
    for method in methods:
        found = by_ref.get(method.ref, [])
        chapters.setdefault(method.chapter, []).append(
            MethodCoverage(
                method=method,
                checks=tuple(sorted({hit.check_id for hit in found if hit.check_id})),
                locations=tuple(sorted({hit.path for hit in found})),
            )
        )
        titles.setdefault(method.chapter, method.chapter_title)

    chapter_rows = tuple(
        ChapterCoverage(chapter=chapter, title=titles.get(chapter, ""), methods=tuple(items))
        for chapter, items in chapters.items()
    )
    unmapped = tuple(
        item.method.ref for chapter in chapter_rows for item in chapter.methods if not item.mapped
    )
    return CoverageReport(
        chapters=chapter_rows,
        hits=hits,
        research_dir=str(resolved_research),
        source_roots=tuple(str(root) for root in roots),
        unmapped=unmapped,
    )


# --------------------------------------------------------------------------- rendering
def render_coverage_text(report: CoverageReport) -> str:
    """Human-readable matrix for the CLI."""
    lines: list[str] = ["ARACHNE coverage matrix (G-01): research methods mapped to checks"]
    if report.research_dir is None:
        lines.append(
            "  note: the research corpus (docs/research/) was not found, so only the mapped "
            "references can be reported"
        )
    lines.append(f"  source roots: {', '.join(report.source_roots) or '(none)'}")
    lines.append(f"  references found: {len(report.hits)}")
    if report.chapters:
        lines.append("")
        lines.append(f"  {'chapter':9}{'mapped/total':16}percent  title")
        for chapter in report.chapters:
            lines.append(
                f"  {chapter.chapter:9}{f'{chapter.mapped}/{chapter.total}':16}"
                f"{chapter.percent:6.1f}%  {chapter.title}"
            )
        lines.append("")
        lines.append(f"  total: {report.mapped}/{report.total} ({report.percent}%)")
        for chapter in report.chapters:
            lines.append("")
            lines.append(f"  {chapter.chapter} — {chapter.title}")
            for item in chapter.methods:
                mark = "x" if item.mapped else " "
                checks = ", ".join(item.checks) or "-"
                lines.append(
                    f"    [{mark}] {item.method.ref:9} {item.method.title[:58]:58} {checks}"
                )
    return "\n".join(lines)


def render_coverage_markdown(report: CoverageReport) -> str:
    """The ``coverage_matrix.md`` document ."""
    # Paths are rendered relative to the repository root: the matrix is committed, and a file
    # that changes with every developer's home directory is not a useful artefact.
    corpus = _relative(report.research_dir) if report.research_dir else "(not found)"
    roots = ", ".join(f"`{_relative(root)}`" for root in report.source_roots) or "(none)"
    lines = [
        "# ARACHNE coverage matrix (G-01)",
        "",
        "Generated by `arachne coverage --write coverage_matrix.md`. Do not edit by hand:",
        "the tool greps `research_ref` values out of the source tree and compares them with",
        "the numbered methods in `docs/research/`.",
        "",
        f"- research corpus: `{corpus}`",
        f"- source roots: {roots}",
        f"- references found: **{len(report.hits)}**",
    ]
    if report.chapters:
        lines += [
            f"- coverage: **{report.mapped}/{report.total} ({report.percent}%)**",
            "",
            "## Summary",
            "",
            "| Chapter | Mapped | Total | Percent | Title |",
            "|---|---|---|---|---|",
        ]
        for chapter in report.chapters:
            lines.append(
                f"| {chapter.chapter} | {chapter.mapped} | {chapter.total} | "
                f"{chapter.percent}% | {chapter.title} |"
            )
        lines += [
            f"| **total** | **{report.mapped}** | **{report.total}** | **{report.percent}%** | |",
            "",
            "## Methods",
        ]
        for chapter in report.chapters:
            lines += ["", f"### {chapter.chapter} — {chapter.title}", ""]
            lines.append("| # | Method | Mapped | Checks |")
            lines.append("|---|---|---|---|")
            for item in chapter.methods:
                lines.append(
                    f"| {item.method.number} | {item.method.title} | "
                    f"{'yes' if item.mapped else 'no'} | "
                    f"{', '.join(f'`{check}`' for check in item.checks) or '—'} |"
                )
        if report.unmapped:
            lines += ["", "## Unmapped methods", ""]
            lines += [f"- `{ref}`" for ref in report.unmapped]
    else:
        lines += [
            "",
            "The research corpus was not available, so the method universe is unknown; only "
            "the mapped references are listed below.",
            "",
            "## Mapped references",
            "",
            "| Reference | Check | Location |",
            "|---|---|---|",
        ]
        for hit in report.hits:
            lines.append(f"| `{hit.ref}` | {hit.check_id or '—'} | `{_relative(hit.path)}` |")
    lines.append("")
    return "\n".join(lines)


def _relative(path: str) -> str:
    """Path relative to the repository root when it is inside one (prettier in a report)."""
    resolved = Path(path).resolve()
    for parent in resolved.parents:
        if (parent / "docs" / "spec").is_dir() or (parent / "pyproject.toml").is_file():
            return resolved.relative_to(parent).as_posix()
    return path


def write_coverage_markdown(report: CoverageReport, path: str | Path) -> Path:
    """Write the markdown matrix to ``path`` (creating parents)."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(render_coverage_markdown(report), encoding="utf-8")
    return target


def hits_by_check(hits: Sequence[RefHit]) -> Mapping[str, tuple[str, ...]]:
    """``{check id: refs}`` — the inverse view, useful in a report appendix."""
    out: dict[str, list[str]] = {}
    for hit in hits:
        if hit.check_id:
            out.setdefault(hit.check_id, []).append(hit.ref)
    return {key: tuple(sorted(set(value))) for key, value in out.items()}


# =========================================================================== coverage ledger
#: The ledger's own schema version. Bump it when a record's shape changes.
LEDGER_VERSION = "1.0"

#: The registry catalogue version the ledger was generated from (`ModuleRegistry.catalog`).
REGISTRY_VERSION = "registry-1.0"

#: Committed artefacts, relative to the repository root, beside the generated coverage matrix a
#: reviewer reads them with. Repository evidence rather than package data: CI regenerates them
#: and compares byte for byte (REQ-DET-001), so they live in the tree a reviewer reads, not in
#: the wheel a user installs.
LEDGER_JSON = "coverage-ledger.json"
LEDGER_MARKDOWN = "coverage-ledger.md"

_LAST_VERIFIED_NOTE = (
    "last_verified is the date the corpus was last exercised by the test suite: the ledger is "
    "regenerated after a full suite run, and every registered check is run by it. A per-check "
    "date arrives with the verification-record store (REQ-PROOF-*). It is committed content, "
    "not a wall-clock read, so --check is byte-stable."
)


@dataclass(frozen=True, slots=True)
class LedgerRecord:
    """One registered check, as the ledger states it (REQ-DET-001)."""

    id: str
    module: str
    title: str
    proof: str
    target_kinds: tuple[str, ...]
    framework: tuple[str, ...]
    last_verified: str
    cwe: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "module": self.module,
            "title": self.title,
            "proof": self.proof,
            "target_kinds": list(self.target_kinds),
            "framework": list(self.framework),
            "last_verified": self.last_verified,
            "cwe": self.cwe,
        }


@dataclass(frozen=True, slots=True)
class CoverageLedger:
    """The whole ledger: header, per-check records and the framework tallies."""

    generated_at: str
    records: tuple[LedgerRecord, ...]
    wstg_items: tuple[dict[str, Any], ...]
    api_items: tuple[dict[str, Any], ...]
    registry_digest: str
    framework_versions: Mapping[str, str] = field(default_factory=dict)
    cwe_items: tuple[dict[str, Any], ...] = ()
    cwe_version: str = ""
    #: The Agentic Top 10 per-item states (REQ-DET-013). Empty only for a ledger built by hand.
    asi_items: tuple[dict[str, Any], ...] = ()
    #: The LLM Top 10 per-item states (REQ-DET-027): each item either ``mapped`` or a ``gap``
    #: named individually, beside the ASI tally. Empty only for a ledger built by hand.
    llm_items: tuple[dict[str, Any], ...] = ()
    #: The cloud-provider coverage rows (REQ-DET-017): every provider is either
    #: ``supported`` with its checks or ``not_supported`` with a reason. Empty only for a
    #: ledger built by hand.
    cloud_provider_items: tuple[dict[str, Any], ...] = ()
    cloud_provider_version: str = ""
    registry_version: str = REGISTRY_VERSION
    ledger_version: str = LEDGER_VERSION

    # ------------------------------------------------------------------ tallies
    @property
    def check_count(self) -> int:
        return len(self.records)

    @property
    def cwe_only(self) -> tuple[str, ...]:
        """Checks whose whole mapping is a CWE — the REQ-DET-002 burn-down metric."""
        return tuple(
            record.id
            for record in self.records
            if record.framework and all(item.startswith("CWE-") for item in record.framework)
        )

    def wstg_counts(self) -> dict[str, int]:
        states = [str(item["state"]) for item in self.wstg_items]
        return {
            "mapped": states.count("mapped"),
            "out_of_scope": states.count("out_of_scope"),
            "gap": states.count("gap"),
            "total": len(states),
            "in_scope": states.count("mapped") + states.count("gap"),
        }

    def api_counts(self) -> dict[str, int]:
        return {
            "mapped": sum(1 for item in self.api_items if item["state"] == "mapped"),
            "total": len(self.api_items),
        }

    def asi_counts(self) -> dict[str, Any]:
        """The REQ-DET-013 tally: ``mapped / 10`` with every unmapped item named as a gap."""
        return {
            "mapped": sum(1 for item in self.asi_items if item["state"] == "mapped"),
            "total": len(self.asi_items),
            "gap": [str(item["id"]) for item in self.asi_items if item["state"] == "gap"],
        }

    def llm_counts(self) -> dict[str, Any]:
        """The REQ-DET-027 tally: ``mapped / 10`` with every unmapped item named as a gap."""
        return {
            "mapped": sum(1 for item in self.llm_items if item["state"] == "mapped"),
            "total": len(self.llm_items),
            "gap": [str(item["id"]) for item in self.llm_items if item["state"] == "gap"],
        }

    def cloud_provider_counts(self) -> dict[str, Any]:
        """The REQ-DET-017 tally: supported providers and the explicit gaps."""
        supported = [
            str(item["provider"])
            for item in self.cloud_provider_items
            if item["state"] == "supported"
        ]
        unsupported = [
            str(item["provider"])
            for item in self.cloud_provider_items
            if item["state"] == "not_supported"
        ]
        return {
            "supported": supported,
            "not_supported": unsupported,
            "supported_count": len(supported),
            "not_supported_count": len(unsupported),
            "total": len(self.cloud_provider_items),
        }

    def cwe_counts(self) -> dict[str, dict[str, Any]]:
        """The REQ-DET-004 tally: in-scope coverage first, the full 25 beside it."""

        def tally(items: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
            covered = sum(1 for item in items if item["covered"])
            total = len(items)
            return {
                "covered": covered,
                "total": total,
                "percent": round(100.0 * covered / total, 1) if total else 0.0,
            }

        in_scope = [item for item in self.cwe_items if item["in_scope"]]
        return {"in_scope": tally(in_scope), "all": tally(self.cwe_items)}

    # ------------------------------------------------------------------ rendering
    def to_dict(self) -> dict[str, Any]:
        return {
            "ledger_version": self.ledger_version,
            "generated_at": self.generated_at,
            "registry_version": self.registry_version,
            "registry_digest": self.registry_digest,
            "framework_versions": dict(self.framework_versions),
            "last_verified_note": _LAST_VERIFIED_NOTE,
            "totals": {
                "checks": self.check_count,
                "cwe_only_checks": len(self.cwe_only),
            },
            "wstg": self.wstg_counts(),
            "api_top10": self.api_counts(),
            "asi_top10": {**self.asi_counts(), "items": [dict(item) for item in self.asi_items]},
            "llm_top10": {**self.llm_counts(), "items": [dict(item) for item in self.llm_items]},
            "cwe_top25": {
                "version": self.cwe_version,
                **self.cwe_counts(),
                "items": [dict(item) for item in self.cwe_items],
            },
            "checks": [record.to_dict() for record in self.records],
            "wstg_items": [dict(item) for item in self.wstg_items],
            # REQ-DET-017: the provider rows, including the explicit not_supported gaps.
            "cloud_providers": {
                "version": self.cloud_provider_version,
                **self.cloud_provider_counts(),
                "items": [dict(item) for item in self.cloud_provider_items],
            },
            # REQ-DET-008: deprecated checks, their successor and their removal horizon.
            "deprecations": lifecycle_policy.ledger_section(),
        }

    def to_json(self) -> str:
        return render_ledger_json(self)


def registry_digest(registry: ModuleRegistry) -> str:
    """A stable digest of the registry's content: ``id@version`` for every check."""
    joined = "\n".join(
        sorted(f"{metadata.id}@{metadata.version}" for metadata in registry.metadata())
    )
    return "sha256:" + hashlib.sha256(joined.encode("utf-8")).hexdigest()


def build_ledger(
    registry: ModuleRegistry | None = None,
    *,
    generated_at: str | None = None,
) -> CoverageLedger:
    """Generate the ledger from the registry (REQ-DET-001).

    The only non-derived input is ``generated_at``, which is also the per-check
    ``last_verified`` date. ``--check`` supplies the committed value, so the generated bytes
    are a pure function of the registry plus that one date and a byte comparison is a real
    gate rather than a "usually stable" one.
    """
    if registry is None:
        from arachne.modules.registry import ModuleRegistry

        registry = ModuleRegistry.discover()
    date = generated_at if generated_at is not None else datetime.now(UTC).date().isoformat()

    by_item: dict[str, list[str]] = {}
    by_cwe: dict[str, list[str]] = {}
    records: list[LedgerRecord] = []
    for metadata in registry.metadata():
        items = sorted_items(metadata.framework)
        for item in items:
            by_item.setdefault(item, []).append(metadata.id)
        if metadata.cwe is not None:
            by_cwe.setdefault(metadata.cwe, []).append(metadata.id)
        records.append(
            LedgerRecord(
                id=metadata.id,
                module=metadata.module,
                title=metadata.title,
                proof=metadata.proof.value,
                target_kinds=tuple(kind.value for kind in metadata.target_kinds),
                framework=items,
                last_verified=date,
                cwe=metadata.cwe,
            )
        )

    wstg_items = tuple(
        {
            "id": state.id,
            "state": state.state,
            "title": state.item.title,
            "checks": list(state.checks),
            **({"reason": state.item.reason} if state.item.reason else {}),
        }
        for state in wstg_coverage(by_item)
    )
    api_items = tuple(
        {
            "id": state.id,
            "state": state.state,
            "title": state.item.title,
            "checks": list(state.checks),
        }
        for state in api_top10_coverage(by_item)
    )
    cwe_items = tuple(
        {
            "id": state.id,
            "title": state.item.title,
            "in_scope": state.in_scope,
            "covered": state.covered,
            "checks": list(state.checks),
            **({"reason": state.item.reason} if state.item.reason else {}),
        }
        for state in cwe_top25_coverage(by_cwe)
    )
    asi_items = tuple(
        {
            "id": state.id,
            "state": state.state,
            "title": state.item.title,
            "checks": list(state.checks),
        }
        for state in asi_top10_coverage(by_item)
    )
    llm_items = tuple(
        {
            "id": state.id,
            "state": state.state,
            "title": state.item.title,
            "checks": list(state.checks),
        }
        for state in llm_top10_coverage(by_item)
    )
    from arachne.modules.cloud_providers import (
        CLOUD_PROVIDER_MATRIX,
        PROVIDER_LEDGER_VERSION,
    )

    cloud_provider_items = tuple(entry.to_dict() for entry in CLOUD_PROVIDER_MATRIX)
    return CoverageLedger(
        generated_at=date,
        records=tuple(records),
        wstg_items=wstg_items,
        api_items=api_items,
        cwe_items=cwe_items,
        asi_items=asi_items,
        llm_items=llm_items,
        cloud_provider_items=cloud_provider_items,
        cloud_provider_version=PROVIDER_LEDGER_VERSION,
        cwe_version=cwe_top25_framework().version,
        registry_digest=registry_digest(registry),
        framework_versions=framework_versions(),
    )


def render_ledger_json(ledger: CoverageLedger) -> str:
    """The committed JSON ledger (sorted, two-space indented, trailing newline)."""
    return json.dumps(ledger.to_dict(), indent=2, sort_keys=False) + "\n"


def render_ledger_markdown(ledger: CoverageLedger) -> str:
    """The committed Markdown ledger: the same data, readable in a diff."""
    wstg = ledger.wstg_counts()
    api = ledger.api_counts()
    asi = ledger.asi_counts()
    llm = ledger.llm_counts()
    cwe = ledger.cwe_counts()
    versions = ", ".join(f"{name} {version}" for name, version in ledger.framework_versions.items())
    lines = [
        "# ARACHNE coverage ledger (REQ-DET-001)",
        "",
        "Generated by `arachne coverage ledger --write`. Do not edit by hand: CI runs",
        "`python -m arachne.tools.ledger --check` and fails when this file drifts from",
        "`ModuleRegistry`.",
        "",
        f"- ledger version: **{ledger.ledger_version}**",
        f"- generated: **{ledger.generated_at}**",
        f"- registry: `{ledger.registry_version}` (`{ledger.registry_digest}`)",
        f"- framework versions: {versions}",
        f"- checks: **{ledger.check_count}**; checks mapped only to a CWE: "
        f"**{len(ledger.cwe_only)}**",
        f"- WSTG v4.2: **{wstg['mapped']}/{wstg['total']} mapped**, "
        f"{wstg['in_scope']} in scope, {wstg['out_of_scope']} out of scope, {wstg['gap']} gap",
        f"- OWASP API Top 10 (2023): **{api['mapped']}/{api['total']} mapped**",
        f"- OWASP LLM Top 10 (2025): **{llm['mapped']}/{llm['total']} mapped**; gap: "
        + (", ".join(f"`{item}`" for item in llm["gap"]) if llm["gap"] else "none"),
        f"- OWASP Agentic Top 10 (2026): **{asi['mapped']}/{asi['total']} mapped**; gap: "
        + (", ".join(f"`{item}`" for item in asi["gap"]) if asi["gap"] else "none"),
        f"- CWE Top 25 (2025), in scope: **{cwe['in_scope']['covered']}/"
        f"{cwe['in_scope']['total']} covered**; all 25: "
        f"{cwe['all']['covered']}/{cwe['all']['total']}",
        "",
        "## Checks",
        "",
        "| Check | Module | Proof | Targets | Framework items | Last verified |",
        "|---|---|---|---|---|---|",
    ]
    for record in ledger.records:
        lines.append(
            f"| `{record.id}` | {record.module} | {record.proof} | "
            f"{', '.join(record.target_kinds)} | {', '.join(record.framework)} | "
            f"{record.last_verified} |"
        )
    lines += [
        "",
        "## WSTG v4.2 — all 97 test IDs",
        "",
        "Every id is in exactly one state: `mapped` (a check names it), `out_of_scope` (with a",
        "reason) or `gap` (a work item).",
        "",
        "| WSTG id | State | Checks | Test |",
        "|---|---|---|---|",
    ]
    for item in ledger.wstg_items:
        checks = ", ".join(f"`{check}`" for check in item["checks"]) or "—"
        reason = f" — {item['reason']}" if item.get("reason") else ""
        lines.append(f"| `{item['id']}` | {item['state']} | {checks} | {item['title']}{reason} |")
    lines += [
        "",
        "## OWASP API Security Top 10 (2023)",
        "",
        "| API id | State | Checks | Item |",
        "|---|---|---|---|",
    ]
    for item in ledger.api_items:
        checks = ", ".join(f"`{check}`" for check in item["checks"]) or "—"
        lines.append(f"| `{item['id']}` | {item['state']} | {checks} | {item['title']} |")
    lines += [
        "",
        f"## OWASP LLM Top 10 (2025) — {llm['mapped']}/{llm['total']} mapped (REQ-DET-027)",
        "",
        "An item is `mapped` when at least one registered check names it in its framework",
        "mapping (`CheckMetadata.framework`) and `gap` when none does. The unmapped items are",
        "named individually: they are the requirement's remaining coverage debt, not a silent",
        "shortfall. `LLM05` (improper output handling) and `LLM09` (misinformation) are the",
        "honest gaps — both describe what an application does with model *output*, which a",
        "read-only scan cannot establish without sending a prompt, and sending one is out of",
        "scope permanently.",
        "",
        "| LLM id | State | Checks | Item |",
        "|---|---|---|---|",
    ]
    for item in ledger.llm_items:
        checks = ", ".join(f"`{check}`" for check in item["checks"]) or "—"
        lines.append(f"| `{item['id']}` | {item['state']} | {checks} | {item['title']} |")
    lines += [
        "",
        f"## OWASP Agentic Top 10 (2026) — {asi['mapped']}/{asi['total']} mapped (REQ-DET-013)",
        "",
        "An item is `mapped` when at least one registered check names it in its framework",
        "mapping (`CheckMetadata.framework`) and `gap` when none does. The unmapped items are",
        "named individually: they are the requirement's remaining coverage debt, not a silent",
        "shortfall.",
        "",
        "| ASI id | State | Checks | Item |",
        "|---|---|---|---|",
    ]
    for item in ledger.asi_items:
        checks = ", ".join(f"`{check}`" for check in item["checks"]) or "—"
        lines.append(f"| `{item['id']}` | {item['state']} | {checks} | {item['title']} |")
    lines += [
        "",
        f"## CWE Top 25 ({ledger.cwe_version}) — {cwe['in_scope']['covered']}/"
        f"{cwe['in_scope']['total']} in-scope ids covered",
        "",
        "An id is `covered` when at least one registered check classifies its findings as that",
        "CWE (`CheckMetadata.cwe`). The seven memory-safety classes are in the denominator and",
        "marked `out_of_scope` with a reason, so the 18/18 claim is visible against 25.",
        "",
        "| CWE id | State | Checks | Weakness |",
        "|---|---|---|---|",
    ]
    for item in ledger.cwe_items:
        checks = ", ".join(f"`{check}`" for check in item["checks"]) or "—"
        if item["covered"]:
            state = "covered"
        elif item["in_scope"]:
            state = "gap"
        else:
            state = "out_of_scope"
        reason = f" — {item['reason']}" if item.get("reason") else ""
        lines.append(f"| `{item['id']}` | {state} | {checks} | {item['title']}{reason} |")
    provider = ledger.cloud_provider_counts()
    lines += [
        "",
        f"## Cloud providers (REQ-DET-017) — {provider['supported_count']} supported, "
        f"{provider['not_supported_count']} not supported",
        "",
        "A provider is either `supported` with the read-only checks that cover it, or",
        "`not_supported` with the reason. The second state is a stated gap, never silence.",
        "",
        "| Provider | State | Checks | Read operations | Reason |",
        "|---|---|---|---|---|",
    ]
    for item in ledger.cloud_provider_items:
        checks = ", ".join(f"`{check}`" for check in item["checks"]) or "—"
        operations = ", ".join(f"`{op['method']} {op['path']}`" for op in item["operations"]) or "—"
        lines.append(
            f"| `{item['provider']}` | {item['state']} | {checks} | {operations} | "
            f"{item['reason']} |"
        )
    deprecations = lifecycle_policy.ledger_section()
    horizon = deprecations["removal_horizon_minors"]
    lines += [
        "",
        f"## Deprecated checks (REQ-DET-008) — removal horizon {horizon} minor releases",
        "",
        "A deprecated check still runs (compatibility) and keeps its framework mapping; it is",
        "listed here with the check that replaces it and the release it must be removed by.",
        "The ledger's `--check` mode fails once that release is reached.",
        "",
        "| Check | Successor | Deprecated in | Remove by | Reason |",
        "|---|---|---|---|---|",
    ]
    for entry in deprecations["deprecated"]:
        lines.append(
            f"| `{entry['check_id']}` | `{entry['successor']}` | {entry['deprecated_in']} "
            f"| {entry['removal_horizon']} | {entry['reason']} |"
        )
    if not deprecations["deprecated"]:
        lines.append("| — | — | — | — | no shipped check is deprecated |")
    lines.append("")
    return "\n".join(lines)


def default_ledger_paths(root: str | Path | None = None) -> tuple[Path, Path]:
    """The committed ledger paths: ``(json, markdown)`` under the repository root."""
    base = Path(root).expanduser() if root is not None else _repo_root()
    return base / LEDGER_JSON, base / LEDGER_MARKDOWN


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file():
            return parent
    return here.parents[1]


def check_ledger(
    json_path: str | Path | None = None,
    markdown_path: str | Path | None = None,
    *,
    registry: ModuleRegistry | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Compare the committed ledger with generated output (REQ-DET-001's CI gate).

    Returns ``(ok, differences)``. The committed ``generated_at`` is fed back into the
    generator, so the bytes are comparable; every difference names the check id it concerns,
    which is what makes "you added a check and forgot to regenerate" a readable failure.
    """
    default_json, default_markdown = default_ledger_paths()
    json_target = Path(json_path) if json_path is not None else default_json
    markdown_target = Path(markdown_path) if markdown_path is not None else default_markdown

    if not json_target.is_file():
        return False, (f"the committed ledger {json_target} does not exist",)
    committed = json.loads(json_target.read_text(encoding="utf-8"))
    generated_at = str(committed.get("generated_at", "")) or None
    ledger = build_ledger(registry, generated_at=generated_at)

    differences: list[str] = []
    generated = ledger.to_dict()
    if committed != generated:
        differences.extend(_record_differences(committed.get("checks"), generated["checks"]))
        for key in sorted(set(committed) | set(generated)):
            if key == "checks":
                continue
            if committed.get(key) != generated.get(key):
                differences.append(f"ledger field {key!r} differs from the registry")
    if markdown_target.is_file():
        if markdown_target.read_text(encoding="utf-8") != render_ledger_markdown(ledger):
            differences.append(f"the committed markdown ledger {markdown_target.name} differs")
    else:
        differences.append(f"the committed markdown ledger {markdown_target} does not exist")
    # REQ-DET-008: a deprecation that has outlived its two-minor horizon fails this gate, which
    # is the CI step that already runs. The message names the check and the release to remove
    # it by, so the failure is actionable rather than a red job.
    differences.extend(
        f"lifecycle: {problem}"
        for problem in lifecycle_policy.problems(
            registry_check_ids=set((registry or _discover_registry()).check_ids())
        )
    )
    return (not differences), tuple(differences)


def _discover_registry() -> ModuleRegistry:
    """The built-in registry, imported here so the module stays importable without it."""
    from arachne.modules.registry import ModuleRegistry

    return ModuleRegistry.discover()


def _record_differences(committed: Any, generated: list[dict[str, Any]]) -> list[str]:
    """Name each check that is missing, extra or changed between two record sets."""
    old = {str(record["id"]): record for record in committed or () if isinstance(record, Mapping)}
    new = {record["id"]: record for record in generated}
    differences: list[str] = []
    for check_id in sorted(set(old) - set(new)):
        differences.append(f"check {check_id!r} is in the committed ledger but not registered")
    for check_id in sorted(set(new) - set(old)):
        differences.append(f"check {check_id!r} is registered but missing from the ledger")
    for check_id in sorted(set(old) & set(new)):
        if old[check_id] != new[check_id]:
            differences.append(f"check {check_id!r} changed since the ledger was generated")
    return differences
