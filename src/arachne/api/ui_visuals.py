"""Server-rendered SVG for the product UI: attack-path graph, posture trend, coverage (S26).

REQ-ECOS-004 asks for a product-grade UI with an attack-path graph, an executive dashboard and
tenant self-service. The UI here has **no JavaScript build step and no browser** (the CSS is one
file and the only script is vendored htmx), so the visualizations are SVG the *server* writes:
pure functions from the data the API already returns to a string. Three consequences, all
deliberate:

* **Deterministic.** No timestamps, no random element ids, no iteration over unordered
  collections. The same data renders byte-identically, which is what makes the output a
  *golden file* — a screenshot in a form a diff can read, and a gate that cannot flake.
* **Testable without a browser.** ``tests/report_qa/`` renders these and compares them to
  committed ``.svg`` goldens. There is no headless Chromium in the suite, and adding one would
  trade a deterministic gate for an installation dependency.
* **Safe by construction.** Every label is ``html.escape``d: an asset value is target-controlled,
  so it reaches the document as text, never as markup.

The colours mirror the stylesheet's severity ramp so a graph and a table read as one system.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from itertools import pairwise
from typing import Any, Final

__all__ = ["SEVERITY_COLOURS", "attack_path_svg", "coverage_bars_svg", "posture_trend_svg"]

#: The severity ramp, kept in step with ``templates/web/static/app.css``.
SEVERITY_COLOURS: Final[dict[str, str]] = {
    "critical": "#e5484d",
    "high": "#e8730c",
    "medium": "#d8a700",
    "low": "#4aa3ff",
    "info": "#6b7a90",
    "unanalysed": "#4a5566",
}

_MUTED: Final = "#8a97a8"
_TEXT: Final = "#d7dee8"
_BACKGROUND: Final = "#171d26"
_BORDER: Final = "#2a3546"

#: The ATT&CK-shaped kill chain an attack-path hop is stamped with (S21, REQ-AGENT-003).
STAGE_ORDER: Final[tuple[str, ...]] = ("exposure", "credentials", "access", "execution", "impact")

#: The statuses a framework control can carry (S22, REQ-TRUST-001). "gap" is a control no
#: shipped check addresses or that did not run — the explicit hole a coverage report exists to
#: show, and the reason this chart has four bands rather than a pass percentage.
_CONTROL_ORDER: Final[tuple[tuple[str, str], ...]] = (
    ("pass", "#35c07a"),
    ("fail", "#e5484d"),
    ("gap", "#4a5566"),
)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _severity_colour(severity: str) -> str:
    return SEVERITY_COLOURS.get(severity, SEVERITY_COLOURS["unanalysed"])


# --------------------------------------------------------------------------- attack-path graph
def attack_path_svg(paths: Sequence[Mapping[str, Any]], *, row_height: int = 74) -> str:
    """A node-per-hop graph of the composed attack paths: stages left→right, one row per path.

    A path is a chain on one asset (S21 composes hops per host), so the honest picture is a
    left-to-right chain across kill-chain stages, not a free-form graph: the adding-up of
    findings is the story, and a force-directed blob would hide it. A **filled** node is a
    verified hop, a **hollow** node is a candidate with the check that would verify it named
    underneath — the distinction the report's own attack-path table makes, kept visible here.
    """
    entries = sorted(paths, key=lambda item: str(item.get("id", "")))
    width = 960
    column_x = {stage: 60 + index * 175 for index, stage in enumerate(STAGE_ORDER)}
    header_y = 26
    top = 54
    height = top + max(len(entries), 1) * row_height + 20

    parts: list[str] = [
        _svg_open(width, height, "attack paths"),
        f'<rect width="{width}" height="{height}" fill="{_BACKGROUND}"/>',
    ]
    for stage in STAGE_ORDER:
        x = column_x[stage]
        parts.append(
            f'<text x="{x}" y="{header_y}" fill="{_MUTED}" font-size="11" '
            f'text-anchor="middle">{_esc(stage)}</text>'
        )
    if not entries:
        parts.append(
            f'<text x="{width // 2}" y="{top + 20}" fill="{_MUTED}" font-size="13" '
            f'text-anchor="middle">No multi-step attack path was composed from this scan.'
            "</text>"
        )
        parts.append("</svg>")
        return "".join(parts)

    for row, path in enumerate(entries):
        centre = top + row * row_height + 18
        hops = list(path.get("hops") or ())
        positions: list[tuple[int, int, Mapping[str, Any]]] = []
        for hop in hops:
            stage = str(hop.get("stage") or "exposure")
            column = STAGE_ORDER.index(stage) if stage in STAGE_ORDER else 0
            positions.append((column_x[STAGE_ORDER[column]], centre, hop))
        # Edges first, so a node always sits on top of the line that reaches it.
        for (x1, y1, _first), (x2, y2, _second) in pairwise(positions):
            parts.append(
                f'<line x1="{x1 + 13}" y1="{y1}" x2="{x2 - 13}" y2="{y2}" '
                f'stroke="{_BORDER}" stroke-width="2"/>'
            )
        cheapest_id = str(path.get("cheapest_finding_id") or "")
        for x, y, hop in positions:
            severity = str(hop.get("severity") or "info")
            colour = _severity_colour(severity)
            verified = bool(hop.get("verified"))
            fill = colour if verified else _BACKGROUND
            stroke_width = 3 if str(hop.get("finding_id") or "") == cheapest_id else 2
            parts.append(
                f'<circle cx="{x}" cy="{y}" r="13" fill="{fill}" stroke="{colour}" '
                f'stroke-width="{stroke_width}"/>'
            )
            if not verified:
                parts.append(
                    f'<circle cx="{x}" cy="{y}" r="5" fill="none" stroke="{colour}" '
                    'stroke-width="1.5"/>'
                )
            parts.append(
                f'<text x="{x + 20}" y="{y - 4}" fill="{_TEXT}" font-size="11">'
                f"{_esc(hop.get('check_id'))}</text>"
            )
            detail = hop.get("finding_id") or hop.get("verifying_check") or ""
            parts.append(
                f'<text x="{x + 20}" y="{y + 11}" fill="{_MUTED}" font-size="10">'
                f"{_esc(detail)}</text>"
            )
        label_y = centre - 22
        business = path.get("business_severity")
        suffix = f" · tier {path['criticality']}" if path.get("criticality") is not None else ""
        if business:
            suffix += f" → {business}"
        parts.append(
            f'<text x="12" y="{label_y}" fill="{_severity_colour(str(path.get("severity")))}" '
            f'font-size="11" font-weight="700">{_esc(path.get("id"))} · '
            f"{_esc(str(path.get('severity')).upper())}{_esc(suffix)}</text>"
        )
        parts.append(
            f'<text x="12" y="{label_y + 13}" fill="{_TEXT}" font-size="11">'
            f"{_esc(path.get('asset'))} · "
            f"{'verified' if path.get('fully_verified') else 'partially verified'}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- posture trend
def posture_trend_svg(
    points: Sequence[Mapping[str, Any]], *, width: int = 720, height: int = 220
) -> str:
    """The severity trend as stacked bars, oldest scan left — the executive view of drift.

    Each bar is one scan, segmented by severity in the ramp's order, so a reader sees both the
    total (bar height) and the mix (segments) at once. A scan with no findings still gets a
    baseline tick, because "we scanned and found nothing" must not look like "we did not scan".
    """
    series = list(points)
    parts: list[str] = [_svg_open(width, height, "posture trend")]
    left, right, top, bottom = 46, 12, 16, 42
    plot_w = width - left - right
    plot_h = height - top - bottom
    parts.append(
        f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" fill="none" '
        f'stroke="{_BORDER}"/>'
    )
    if not series:
        parts.append(
            f'<text x="{width // 2}" y="{top + plot_h // 2}" fill="{_MUTED}" font-size="13" '
            f'text-anchor="middle">No scans yet.</text></svg>'
        )
        return "".join(parts)

    totals = [int(point.get("total") or 0) for point in series]
    scale = max(totals) or 1
    slot = plot_w / len(series)
    bar_w = max(6.0, min(38.0, slot * 0.6))
    for index, point in enumerate(series):
        counts = point.get("counts") or {}
        x = left + index * slot + (slot - bar_w) / 2
        cursor = float(top + plot_h)
        for severity in ("info", "low", "medium", "high", "critical"):
            value = int(counts.get(severity) or 0)
            if value <= 0:
                continue
            segment = plot_h * value / scale
            cursor -= segment
            parts.append(
                f'<rect x="{x:.2f}" y="{cursor:.2f}" width="{bar_w:.2f}" '
                f'height="{segment:.2f}" fill="{_severity_colour(severity)}"/>'
            )
        # A tick on the baseline marks a clean scan (total 0) as *scanned*, not missing.
        if int(point.get("total") or 0) == 0:
            parts.append(
                f'<rect x="{x:.2f}" y="{top + plot_h - 2:.2f}" width="{bar_w:.2f}" '
                f'height="2" fill="{_MUTED}"/>'
            )
        parts.append(
            f'<text x="{left + index * slot + slot / 2:.2f}" y="{height - 24}" '
            f'fill="{_MUTED}" font-size="10" text-anchor="middle">'
            f"{_esc(point.get('scan_id'))}</text>"
        )
    parts.append(
        f'<text x="{left - 8}" y="{top + 10}" fill="{_MUTED}" font-size="10" '
        f'text-anchor="end">{scale}</text>'
    )
    parts.append(
        f'<text x="{left - 8}" y="{top + plot_h}" fill="{_MUTED}" font-size="10" '
        f'text-anchor="end">0</text>'
    )
    parts.append(
        f'<text x="{left}" y="{height - 8}" fill="{_MUTED}" font-size="10">'
        f"scan id (oldest → newest) · tallest bar = {scale} finding(s)</text>"
    )
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------- control coverage
def coverage_bars_svg(frameworks: Sequence[Mapping[str, Any]], *, width: int = 720) -> str:
    """Per-framework control coverage as a four-band bar: pass / fail / gap / unmapped.

    ``unmapped`` is the whole point of drawing this rather than a percentage: a framework's
    controls that no shipped check addresses are *not covered*, and a chart that showed only the
    mapped controls would claim coverage the platform does not have (REQ-TRUST-001). The band is
    drawn last and hatched so it cannot be mistaken for a status.
    """
    entries = list(frameworks)
    row_height = 46
    height = 40 + max(len(entries), 1) * row_height
    parts: list[str] = [_svg_open(width, height, "control coverage")]
    if not entries:
        parts.append(
            f'<text x="{width // 2}" y="34" fill="{_MUTED}" font-size="13" text-anchor="middle">'
            "No compliance framework is configured for this deployment.</text></svg>"
        )
        return "".join(parts)
    bar_left, bar_w = 190, width - 240
    for index, framework in enumerate(entries):
        y = 14 + index * row_height
        controls = list(framework.get("controls") or ())
        total = int(framework.get("total_controls") or 0) or 1
        counts = {status: 0 for status, _ in _CONTROL_ORDER}
        for control in controls:
            status = str(control.get("status") or "gap")
            if status in counts:
                counts[status] += 1
        mapped = sum(counts.values())
        unmapped = max(0, total - min(mapped, total))
        parts.append(
            f'<text x="12" y="{y + 16}" fill="{_TEXT}" font-size="12">'
            f"{_esc(framework.get('name') or framework.get('framework'))}</text>"
        )
        parts.append(
            f'<text x="12" y="{y + 31}" fill="{_MUTED}" font-size="10">'
            f"{total} control(s) · mapped {mapped} · unmapped {unmapped}</text>"
        )
        cursor = float(bar_left)
        for status, colour in _CONTROL_ORDER:
            value = counts[status]
            if value <= 0:
                continue
            span = bar_w * value / total
            parts.append(
                f'<rect x="{cursor:.2f}" y="{y + 4}" width="{span:.2f}" height="20" '
                f'fill="{colour}"/>'
            )
            cursor += span
        if unmapped > 0:
            span = bar_w * unmapped / total
            parts.append(
                f'<rect x="{cursor:.2f}" y="{y + 4}" width="{span:.2f}" height="20" '
                f'fill="url(#unmapped)" stroke="{_BORDER}"/>'
            )
        parts.append(
            f'<text x="{bar_left + bar_w + 8}" y="{y + 19}" fill="{_MUTED}" font-size="10">'
            f"{counts['pass']} pass · {counts['fail']} fail · {counts['gap']} gap</text>"
        )
    # One shared hatch pattern for the unmapped band, declared last and referenced by id.
    parts.append(
        '<defs><pattern id="unmapped" width="6" height="6" patternUnits="userSpaceOnUse" '
        'patternTransform="rotate(45)"><rect width="6" height="6" fill="#2a3546"/>'
        '<line x1="0" y1="0" x2="0" y2="6" stroke="#4a5566" stroke-width="2"/></pattern></defs>'
    )
    parts.append("</svg>")
    return "".join(parts)


def _svg_open(width: int, height: int, label: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{_esc(label)}" '
        f'viewBox="0 0 {width} {height}" width="100%" '
        f'preserveAspectRatio="xMidYMid meet" font-family="ui-monospace, Menlo, monospace">'
    )
