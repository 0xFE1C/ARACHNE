"""PDF renderer — the formal-delivery format (F-06-02, docs/spec/06- §4).

The contract is docs/spec/06- §4: *"generated from the HTML render via headless renderer;
page numbers, cover"*. This module honours the first half literally — the input is exactly
what :func:`arachne.report.html_render.render_html` produced, parsed back into blocks — and
offers two kinds of headless renderer for the second:

**The built-in renderer** (default) is a small, deterministic, dependency-free paginator. It
lays the report's blocks out on A4, gives it a cover page, wraps long lines and table cells,
and prints "page N of M" on every sheet. It needs no browser, no system library and no
network, which is what makes the PDF path work on an air-gapped host and in CI — and what
makes a golden-file test possible at all.

**External backends** (``ARACHNE_PDF_BACKEND=auto``) hand the same HTML to a real headless
engine — WeasyPrint, headless Chromium/Chrome, or headless Firefox — when a deployment wants
CSS-exact output. They are selected by presence and never required; ``auto`` falls back to the
built-in renderer and says so in the returned :class:`PdfResult`.

Both paths consume the *same* rendered HTML, so the two formats cannot drift: a fact that is
in the HTML is in the PDF, and a value that is escaped in one is escaped in the other. No
external process is ever started with a shell, and the HTML is passed by file, never by argv.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from html import unescape
from html.parser import HTMLParser
from typing import Final

from arachne.core.errors import ReportError
from arachne.report.html_render import render_html
from arachne.report.model import ReportData
from arachne.report.pdf_backend import (
    BACKENDS,
    available_backends,
    render_external,
    select_backend,
)

__all__ = [
    "BACKENDS",
    "BuiltinBackend",
    "ExternalBackend",
    "PdfResult",
    "available_backends",
    "render_pdf",
    "select_backend",
]

# --------------------------------------------------------------------------- page geometry

#: A4 in PostScript points and the margins the built-in paginator uses.
PAGE_WIDTH: Final = 595.28
PAGE_HEIGHT: Final = 841.89
MARGIN_LEFT: Final = 56.7
MARGIN_RIGHT: Final = 56.7
MARGIN_TOP: Final = 56.7
MARGIN_BOTTOM: Final = 70.0
FOOTER_BASELINE: Final = 40.0

#: Base-14 font metrics (widths in 1/1000 em) for the two text faces the paginator uses.
#: Taken from the Adobe AFM metrics shipped with every PostScript interpreter; only the
#: printable ASCII range is needed because anything else is transliterated to '?'.
_HELVETICA: Final[tuple[int, ...]] = (
    278,
    278,
    355,
    556,
    556,
    889,
    667,
    191,
    333,
    333,
    389,
    584,
    278,
    333,
    278,
    278,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    278,
    278,
    584,
    584,
    584,
    556,
    1015,
    667,
    667,
    722,
    722,
    667,
    611,
    778,
    722,
    278,
    500,
    667,
    556,
    833,
    722,
    778,
    667,
    778,
    722,
    667,
    611,
    722,
    667,
    944,
    667,
    667,
    611,
    278,
    278,
    278,
    469,
    556,
    333,
    556,
    556,
    500,
    556,
    556,
    278,
    556,
    556,
    222,
    222,
    500,
    222,
    833,
    556,
    556,
    556,
    556,
    333,
    500,
    278,
    556,
    500,
    722,
    500,
    500,
    500,
    334,
    260,
    334,
    584,
)
_HELVETICA_BOLD: Final[tuple[int, ...]] = (
    278,
    333,
    474,
    556,
    556,
    889,
    722,
    238,
    333,
    333,
    389,
    584,
    278,
    333,
    278,
    278,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    556,
    333,
    333,
    584,
    584,
    584,
    611,
    975,
    722,
    722,
    722,
    722,
    667,
    611,
    778,
    722,
    278,
    556,
    722,
    611,
    833,
    722,
    778,
    667,
    778,
    722,
    667,
    611,
    722,
    667,
    944,
    667,
    667,
    611,
    333,
    278,
    333,
    584,
    556,
    333,
    556,
    611,
    556,
    611,
    556,
    333,
    611,
    611,
    278,
    278,
    556,
    278,
    889,
    611,
    611,
    611,
    611,
    389,
    556,
    333,
    611,
    556,
    778,
    556,
    556,
    500,
    389,
    280,
    389,
    584,
)


def _char_width(char: str, *, bold: bool, size: float) -> float:
    code = ord(char)
    if 32 <= code <= 126:
        table = _HELVETICA_BOLD if bold else _HELVETICA
        return table[code - 32] * size / 1000.0
    if char in "\u2014\u2013":
        return 1000 * size / 1000.0
    return (556 if not bold else 611) * size / 1000.0


def _text_width(text: str, *, bold: bool, size: float) -> float:
    return sum(_char_width(char, bold=bold, size=size) for char in text)


def _wrap(text: str, *, bold: bool, size: float, width: float) -> list[str]:
    """Greedy word wrap. Words longer than the line are hard-split so nothing overflows."""
    if width <= 0:
        return [text]
    lines: list[str] = []
    for paragraph in text.split("\n"):
        words = paragraph.split()
        if not words:
            lines.append("")
            continue
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if _text_width(candidate, bold=bold, size=size) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
            while _text_width(word, bold=bold, size=size) > width and len(word) > 1:
                cut = 1
                while (
                    cut < len(word) and _text_width(word[: cut + 1], bold=bold, size=size) <= width
                ):
                    cut += 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines


# --------------------------------------------------------------------------- HTML → blocks


@dataclass(slots=True)
class _Block:
    """One laid-out unit: a heading, a paragraph, a list, a table, or a code block."""

    kind: str  # heading | paragraph | bullets | table | code
    text: str = ""
    level: int = 0
    bullets: list[str] = field(default_factory=list)
    ordered: bool = False
    rows: list[list[str]] = field(default_factory=list)
    cover: bool = False


class _BlockParser(HTMLParser):
    """Parse *our* HTML subset into blocks.

    Deliberately small: the input is the document :mod:`arachne.report.html_render` emits, not
    the web at large. Anything it does not recognise contributes its text to the enclosing
    block instead of being dropped, so a future section cannot vanish from the PDF silently.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.blocks: list[_Block] = []
        self.title = ""
        self._stack: list[str] = []
        self._buffer: list[str] = []
        self._blocks_kind = ""
        self._list_bullets: list[str] = []
        self._list_ordered = False
        self._table_rows: list[list[str]] = []
        self._row: list[str] = []
        self._cell: list[str] = []
        self._in_pre = False
        self._cover = False
        self._heading_level = 0
        self._in_title = False
        self._in_summary = False
        self._skip_depth = 0

    # -- helpers
    def _flush(self, kind: str, level: int = 0) -> None:
        text = unescape(" ".join("".join(self._buffer).split()))
        self._buffer = []
        if text:
            self.blocks.append(_Block(kind=kind, text=text, level=level, cover=self._cover))

    def _flush_list(self) -> None:
        if self._list_bullets:
            self.blocks.append(
                _Block(
                    kind="bullets",
                    bullets=[unescape(" ".join(item.split())) for item in self._list_bullets],
                    ordered=self._list_ordered,
                    cover=self._cover,
                )
            )
        self._list_bullets = []
        self._list_ordered = False

    def _flush_table(self) -> None:
        if self._table_rows:
            self.blocks.append(
                _Block(
                    kind="table", rows=[list(row) for row in self._table_rows], cover=self._cover
                )
            )
        self._table_rows = []
        self._row = []
        self._cell = []

    # -- parser hooks
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        classes = dict(attrs).get("class") or ""
        if tag in {"style", "script"}:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "title":
            self._in_title = True
            return
        if tag == "section" and "cover" in classes:
            self._cover = True
        if tag == "pre":
            self._flush("paragraph")
            self._in_pre = True
            return
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._flush("paragraph")
            self._heading_level = int(tag[1])
            self._stack.append("heading")
            return
        if tag in {"p", "dt", "dd", "td", "th"}:
            if tag in {"td", "th"}:
                self._cell = []
                self._stack.append("cell")
                return
            self._flush("paragraph")
            self._stack.append("paragraph")
            return
        if tag == "li":
            self._flush("paragraph")
            self._list_bullets.append("")
            self._stack.append("li")
            return
        if tag in {"ul", "ol"}:
            self._flush("paragraph")
            self._in_ordered_context = tag == "ol"
            if not self._list_bullets:
                self._list_ordered = tag == "ol"
            return
        if tag == "table":
            self._flush("paragraph")
            self._table_rows = []
            return
        if tag == "tr":
            self._row = []
            return
        if tag == "summary":
            self._flush("paragraph")
            self._in_summary = True
            self._stack.append("summary")
            return
        if tag == "details":
            self._flush("paragraph")
            return
        if tag in {
            "html",
            "head",
            "body",
            "div",
            "span",
            "strong",
            "em",
            "b",
            "i",
            "code",
            "a",
            "header",
            "main",
            "br",
        }:
            return

    _in_ordered_context = False

    def handle_endtag(self, tag: str) -> None:
        if tag in {"style", "script"}:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth:
            return
        if tag == "title":
            self._in_title = False
            return
        if tag == "pre":
            self._in_pre = False
            text = "".join(self._buffer)
            self._buffer = []
            if text.strip():
                self.blocks.append(_Block(kind="code", text=text.rstrip("\n"), cover=self._cover))
            return
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._flush("heading", self._heading_level)
            self._stack.pop() if self._stack and self._stack[-1] == "heading" else None
            self._heading_level = 0
            return
        if tag in {"td", "th"}:
            text = unescape(" ".join("".join(self._cell).split()))
            self._row.append(text)
            self._cell = []
            self._stack.pop() if self._stack and self._stack[-1] == "cell" else None
            return
        if tag == "tr":
            if self._row:
                self._table_rows.append(self._row)
            self._row = []
            return
        if tag == "table":
            self._flush_table()
            return
        if tag == "li":
            item = unescape(" ".join("".join(self._buffer).split()))
            self._buffer = []
            if self._list_bullets:
                self._list_bullets[-1] = item
            self._stack.pop() if self._stack and self._stack[-1] == "li" else None
            return
        if tag in {"ul", "ol"}:
            self._flush_list()
            self._in_ordered_context = False
            return
        if tag == "p":
            self._flush("paragraph")
            self._stack.pop() if self._stack and self._stack[-1] == "paragraph" else None
            return
        if tag in {"dt", "dd"}:
            self._flush("paragraph")
            self._stack.pop() if self._stack and self._stack[-1] == "paragraph" else None
            return
        if tag == "summary":
            self._flush("heading", 3)
            self._in_summary = False
            self._stack.pop() if self._stack and self._stack[-1] == "summary" else None
            return
        if tag == "section":
            if self._cover:
                # The cover is its own sheet (docs/spec/06- §4): one explicit break, never one
                # per element, or a two-line cover would consume a page per line.
                self._flush("paragraph")
                self.blocks.append(_Block(kind="pagebreak"))
            self._cover = False

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
            return
        if self._in_pre:
            self._buffer.append(data)
            return
        if self._stack and self._stack[-1] == "cell":
            self._cell.append(data)
            return
        self._buffer.append(data)

    def close(self) -> None:
        super().close()
        self._flush("paragraph")
        self._flush_list()
        self._flush_table()


def parse_blocks(document: str) -> list[_Block]:
    """Parse a rendered HTML report into blocks (the paginator's input)."""
    parser = _BlockParser()
    parser.feed(document)
    parser.close()
    return parser.blocks


# --------------------------------------------------------------------------- PDF writer


def _pdf_string(text: str) -> str:
    """A PDF literal string, WinAnsi-escaped (everything outside Latin-1 becomes '?')."""
    out: list[str] = ["("]
    for char in text:
        code = ord(char)
        if char in "()\\":
            out.append("\\" + char)
        elif 32 <= code <= 126:
            out.append(char)
        elif code <= 255:
            out.append(f"\\{code:03o}")
        else:
            out.append("?")
    out.append(")")
    return "".join(out)


class _Page:
    def __init__(self) -> None:
        self.ops: list[str] = []

    def line(self, x: float, y: float, text: str, *, size: float, bold: bool = False) -> None:
        font = "/F2" if bold else "/F1"
        self.ops.append(
            f"BT {font} {size:.2f} Tf 1 0 0 1 {x:.2f} {y:.2f} Tm {_pdf_string(text)} Tj ET"
        )

    def rect(self, x: float, y: float, w: float, h: float, *, gray: float) -> None:
        self.ops.append(f"{gray:.3f} g {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f 0 g")

    def rule(self, x1: float, y1: float, x2: float, y2: float) -> None:
        self.ops.append(f"0.65 G 0.6 w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S 0 G")

    def content(self) -> str:
        return "\n".join(self.ops)


def _build_pdf(pages: Sequence[_Page], *, title: str) -> bytes:
    """Assemble a PDF 1.4 document from page content streams."""
    objects: list[bytes] = []
    # 1 catalog, 2 pages, 3 font F1, 4 font F2, then per page: content + page object.
    page_ids = [5 + index * 2 for index in range(len(pages))]
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("latin-1"))
    objects.append(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )
    objects.append(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    )
    for index, page in enumerate(pages):
        stream = page.content().encode("latin-1", errors="replace")
        objects.append(
            b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
        )
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH:.2f} {PAGE_HEIGHT:.2f}] "
                "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> "
                f"/Contents {5 + index * 2} 0 R >>"
            ).encode("latin-1")
        )
    info_id = 5 + len(pages) * 2
    objects.append(f"<< /Title {_pdf_string(title)} /Producer (ARACHNE) >>".encode("latin-1"))

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets: list[int] = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{number} 0 obj\n".encode("latin-1") + body + b"\nendobj\n"
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode("latin-1")
    out += b"0000000000 65535 f \n"
    for offset in offsets:
        out += f"{offset:010d} 00000 n \n".encode("latin-1")
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R /Info {info_id} 0 R >>\n"
        f"startxref\n{xref_at}\n%%EOF\n"
    ).encode("latin-1")
    return bytes(out)


# --------------------------------------------------------------------------- paginator


_HEADING_SIZES: Final[dict[int, float]] = {1: 19.0, 2: 14.0, 3: 11.5, 4: 10.0}


class _Paginator:
    def __init__(self) -> None:
        self.pages: list[_Page] = []
        self.page = _Page()
        self.pages.append(self.page)
        self.y = PAGE_HEIGHT - MARGIN_TOP
        self.width = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT
        self.total = 0  # filled in a second pass

    def new_page(self) -> None:
        self.page = _Page()
        self.pages.append(self.page)
        self.y = PAGE_HEIGHT - MARGIN_TOP

    def space(self, amount: float) -> None:
        self.y -= amount

    def ensure(self, needed: float) -> None:
        if self.y - needed < MARGIN_BOTTOM:
            self.new_page()

    def text(
        self,
        text: str,
        *,
        size: float,
        bold: bool = False,
        indent: float = 0.0,
        leading: float = 1.32,
        gap_after: float = 0.0,
    ) -> None:
        line_height = size * leading
        for line in _wrap(text, bold=bold, size=size, width=self.width - indent):
            self.ensure(line_height)
            self.y -= line_height
            self.page.line(MARGIN_LEFT + indent, self.y, line, size=size, bold=bold)
        self.space(gap_after)

    def code(self, text: str) -> None:
        size = 8.2
        line_height = size * 1.28
        lines: list[str] = []
        for raw in text.split("\n"):
            lines.extend(_wrap(raw, bold=False, size=size, width=self.width - 12) or [""])
        height = line_height * len(lines) + 8
        self.ensure(min(height, (PAGE_HEIGHT - MARGIN_TOP - MARGIN_BOTTOM)))
        for line in lines:
            if self.y - line_height < MARGIN_BOTTOM:
                self.new_page()
            self.y -= line_height
            self.page.line(MARGIN_LEFT + 8, self.y, line[:200], size=size)
        self.space(6)

    def bullets(self, items: Sequence[str], *, ordered: bool) -> None:
        size = 9.5
        for index, item in enumerate(items, start=1):
            marker = f"{index}." if ordered else "\u2022"
            indent = 16.0
            first = True
            for line in _wrap(item, bold=False, size=size, width=self.width - indent):
                self.ensure(size * 1.34)
                self.y -= size * 1.34
                prefix = marker if first else ""
                self.page.line(MARGIN_LEFT, self.y, f"{prefix} {line}".strip(), size=size)
                first = False
        self.space(4)

    def table(self, rows: Sequence[Sequence[str]]) -> None:
        if not rows:
            return
        columns = max(len(row) for row in rows)
        size = 8.6
        weights = []
        for col in range(columns):
            longest = max((len(row[col]) for row in rows if col < len(row)), default=1)
            weights.append(min(max(longest, 6), 46))
        total_weight = sum(weights) or 1
        widths = [self.width * weight / total_weight for weight in weights]
        for row_index, row in enumerate(rows):
            bold = row_index == 0
            wrapped: list[list[str]] = []
            for col in range(columns):
                value = row[col] if col < len(row) else ""
                wrapped.append(_wrap(value, bold=bold, size=size, width=widths[col] - 8))
            row_height = max(len(lines) for lines in wrapped) * size * 1.28 + 6
            if self.y - row_height < MARGIN_BOTTOM:
                self.new_page()
            top = self.y
            if bold:
                self.page.rect(MARGIN_LEFT, top - row_height, self.width, row_height, gray=0.94)
            x = MARGIN_LEFT
            for col, lines in enumerate(wrapped):
                for offset, line in enumerate(lines):
                    self.page.line(
                        x + 4,
                        top - 4 - size * 1.28 * (offset + 1) + size * 0.28,
                        line,
                        size=size,
                        bold=bold,
                    )
                x += widths[col]
            self.y = top - row_height
            self.page.rule(MARGIN_LEFT, self.y, MARGIN_LEFT + self.width, self.y)
        self.space(8)

    def render(self, blocks: Iterable[_Block], *, footer: str) -> None:
        self.total = 0
        for block in blocks:
            if block.kind == "heading":
                size = _HEADING_SIZES.get(block.level, 10.0)
                self.ensure(size * 2.6)
                self.space(10 if block.level <= 2 else 6)
                self.text(block.text, size=size, bold=True, gap_after=2)
                if block.level == 2:
                    self.page.rule(MARGIN_LEFT, self.y + 2, MARGIN_LEFT + self.width, self.y + 2)
                    self.space(4)
            elif block.kind == "paragraph":
                self.text(block.text, size=9.6, gap_after=3)
            elif block.kind == "bullets":
                self.bullets(block.bullets, ordered=block.ordered)
            elif block.kind == "table":
                self.table(block.rows)
            elif block.kind == "code":
                self.code(block.text)
            elif block.kind == "pagebreak":
                self.new_page()
        # The footer is stamped after pagination, so the total page count is known.
        self.total = len(self.pages)
        for index, page in enumerate(self.pages, start=1):
            page.line(
                PAGE_WIDTH / 2 - 90,
                FOOTER_BASELINE,
                f"{footer} · page {index} of {self.total}",
                size=8.0,
            )


# --------------------------------------------------------------------------- backends


@dataclass(slots=True)
class PdfResult:
    """A rendered PDF and how it was produced (the provenance the CLI/API can report)."""

    data: bytes
    backend: str
    fallback: str | None = None

    @property
    def bytes_len(self) -> int:
        return len(self.data)


class BuiltinBackend:
    """The dependency-free paginator (always available)."""

    name = "builtin"

    def render(self, document: str, *, title: str) -> bytes:
        parser = _BlockParser()
        parser.feed(document)
        parser.close()
        paginator = _Paginator()
        paginator.render(parser.blocks, footer="ARACHNE report")
        return _build_pdf(paginator.pages, title=title or parser.title or "ARACHNE report")


class ExternalBackend:
    """One of the optional headless engines, driven by its CLI or its Python API.

    All process handling lives in :mod:`arachne.report.pdf_backend` — this class is the
    adapter that keeps the built-in and external paths interchangeable.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def render(self, document: str, *, title: str) -> bytes:
        return render_external(self.name, document)


def render_pdf(report: ReportData, *, backend: str | None = None) -> PdfResult:
    """Render ``report`` to PDF (F-06-02, docs/spec/06- §4).

    The HTML render happens first and unconditionally: it is the input to both paths, so a
    caller can always inspect what the PDF was made from. With no external engine installed
    the built-in renderer produces the artifact — a scan must never fail because a browser
    is missing.
    """
    document = render_html(report)
    title = f"ARACHNE report — {report.target_name}"
    name, fallback = select_backend(backend)
    try:
        data = _backend_for(name).render(document, title=title)
    except ReportError:
        raise
    except Exception as exc:  # an external renderer failing must not lose the report
        if fallback is not None:
            raise
        data = BuiltinBackend().render(document, title=title)
        return PdfResult(data=data, backend="builtin", fallback=f"{name} failed: {exc}")
    return PdfResult(data=data, backend=name, fallback=fallback)


def _backend_for(name: str) -> BuiltinBackend | ExternalBackend:
    if name == "builtin":
        return BuiltinBackend()
    return ExternalBackend(name)


def pdf_text(data: bytes) -> str:
    """Extract the visible text from a *built-in-backend* PDF (used by the QA gate).

    Only the uncompressed content streams this module writes are read; an externally produced
    PDF has no extractable text here and returns an empty string rather than a wrong one.
    """
    text = data.decode("latin-1", errors="replace")
    chunks: list[str] = []
    for match in re.finditer(r"\((?:[^()\\]|\\.)*\)\s*Tj", text):
        raw = match.group(0)
        body = raw[raw.index("(") + 1 : raw.rindex(")")]
        body = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), body)
        body = body.replace("\\(", "(").replace("\\)", ")").replace("\\\\", "\\")
        chunks.append(body)
    return "\n".join(chunks)
