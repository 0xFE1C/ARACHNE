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
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arachne.core.errors import ConfigurationError

__all__ = [
    "ChapterCoverage",
    "CoverageReport",
    "MethodCoverage",
    "RefHit",
    "ResearchMethod",
    "build_coverage",
    "default_research_dir",
    "default_source_roots",
    "expand_ref",
    "hits_by_check",
    "parse_research_methods",
    "render_coverage_markdown",
    "render_coverage_text",
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
