"""HTML renderer — the sharing format, and the input the PDF renderer consumes (F-06-02).

The HTML report is a **single self-contained file**: no external stylesheet, no script, no
web font. That is a requirement rather than a preference — a report is a security document
that gets attached to tickets and mailed to people who will open it offline, so it must not
fetch anything to render.

It mirrors :mod:`arachne.report.markdown` section for section (and the §9
skeleton), because a reader who compares the two must not be able to find a fact in one that
is missing from the other. The differences are the ones the medium earns:

* the cover is a real title page, with the print CSS placing page numbers on every sheet;
* findings are ``<details>`` blocks, so a 200-finding report stays navigable — but they are
  rendered **open**, so print (and the PDF renderer, which parses this document) sees every
  finding rather than a list of collapsed summaries;
* evidence bodies are ``<pre>`` blocks with the same escaping the Markdown renderer applies,
  for the same reason: a target controls part of its own evidence.

Everything target-controlled is escaped with :func:`html.escape`. The Markdown renderer
neutralises fences and pipes; this one must not be a softer target, or the same evidence
would be safe in one format and not in another ("no unredacted secrets in
any format" — and no injected markup either).
"""

from __future__ import annotations

import html
import json
import re
from collections.abc import Sequence
from datetime import datetime

from arachne.i18n import DEFAULT_LOCALE, translate
from arachne.report.model import (
    ReportData,
    ReportEvidence,
    ReportFinding,
    SeverityCounts,
)

__all__ = ["HTML_CSS", "render_html"]

#: Inline stylesheet. Print rules carry the cover break and the page-number footer, so the
#: PDF path needs no extra template.
HTML_CSS = """
:root { --ink:#1b1f24; --muted:#5b6672; --line:#d8dee6; --bg:#fff; --panel:#f6f8fa; }
* { box-sizing: border-box; }
body { margin:0; color:var(--ink); background:var(--bg);
  font:15px/1.55 -apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif; }
.wrap { max-width: 960px; margin: 0 auto; padding: 28px 22px 60px; }
h1 { font-size: 1.9rem; margin: 0 0 .3rem; }
h2 { font-size: 1.35rem; margin: 2.2rem 0 .7rem; padding-bottom:.25rem; border-bottom:1px solid var(--line); }
h3 { font-size: 1.05rem; margin: 1.6rem 0 .5rem; }
h4 { font-size: .98rem; margin: 1.1rem 0 .4rem; color:var(--muted); }
p, li, td, th { font-size: .95rem; }
code, pre { font-family: "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .85rem; }
code { background: var(--panel); padding: 1px 4px; border-radius: 3px; }
pre { background: var(--panel); border:1px solid var(--line); border-radius:6px;
  padding: 10px 12px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; }
table { border-collapse: collapse; width:100%; margin:.6rem 0 1rem; }
th, td { border:1px solid var(--line); padding:5px 8px; text-align:left; vertical-align:top; }
th { background: var(--panel); }
.muted { color: var(--muted); }
.small { font-size:.85rem; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:.78rem;
  font-weight:600; color:#fff; }
.sev-critical { background:#8b0000; } .sev-high { background:#c0392b; }
.sev-medium { background:#d68910; } .sev-low { background:#2874a6; }
.sev-info { background:#5b6672; } .sev-other { background:#8e44ad; }
.cover { border:1px solid var(--line); border-radius:8px; padding:26px 24px; background:var(--panel); }
.cover .target { font-size:1.15rem; margin:.2rem 0 1rem; }
.cover dl { display:grid; grid-template-columns:max-content 1fr; gap:2px 14px; margin:0; }
.cover dt { color:var(--muted); }
.cover dd { margin:0; }
.finding { border:1px solid var(--line); border-radius:8px; margin:.7rem 0; padding:0 14px; }
.finding > summary { cursor:pointer; padding:.6rem 0; font-weight:600; }
.finding[open] > summary { border-bottom:1px solid var(--line); margin-bottom:.6rem; }
dl.meta { display:grid; grid-template-columns:max-content 1fr; gap:1px 12px; margin:.4rem 0 1rem; }
dl.meta dt { color:var(--muted); }
dl.meta dd { margin:0; }
.lc { background:#fff8e1; border:1px solid #f0d894; border-radius:6px; padding:.6rem .9rem; }
.footer { margin-top:2.4rem; color:var(--muted); font-size:.8rem; border-top:1px solid var(--line); padding-top:.6rem; }
@media print {
  .wrap { max-width:none; padding:0; }
  h2 { break-after: avoid; } h3 { break-after: avoid; }
  .finding, pre, table, .cover { break-inside: avoid; }
  .finding { break-inside: auto; }
  .cover { break-after: page; background:#fff; }
  a { color:inherit; text-decoration:none; }
  @page { size: A4; margin: 16mm 14mm 18mm;
    @bottom-center { content: "ARACHNE report · page " counter(page) " of " counter(pages);
      font-size:9px; color:#5b6672; } }
}
"""

_SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def _locale_of(report: ReportData) -> str | None:
    """The locale a report selects, or ``None`` for the deployment default (S26)."""
    return report.locale or None


def _t(key: str, report: ReportData) -> str:
    """An HTML-escaped catalogue lookup in the report's own locale (S26, REQ-ECOS-005)."""
    return html.escape(translate(key, locale=_locale_of(report)), quote=False)


def _severity_label(severity: str, report: ReportData) -> str:
    return _t(f"report.severity.{severity}", report)


def _esc(value: object | None) -> str:
    """Escape a possibly target-controlled value for HTML text/attribute context."""
    if value is None:
        return '<span class="muted">(not recorded)</span>'
    return html.escape(str(value), quote=True)


def _text(value: object | None) -> str:
    """Escape a value as plain text (for a ``<pre>`` block)."""
    return "" if value is None else html.escape(str(value), quote=False)


def _inline(value: object | None) -> str:
    """One-line escaped rendering of a multi-line value."""
    if value is None:
        return '<span class="muted">(not recorded)</span>'
    return html.escape(" ".join(str(value).split()), quote=False) or "(empty)"


def _date(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "(not recorded)"


def _iso(value: datetime | None) -> str:
    return html.escape(value.isoformat(), quote=False) if value else "(not recorded)"


def _badge(severity: str) -> str:
    known = severity if severity in _SEVERITY_ORDER else "other"
    return f'<span class="badge sev-{known}">{_esc(severity)}</span>'


def _cvss(value: float | None) -> str:
    return f"{value:.1f}" if value is not None else "n/a"


def _counts_table(counts: SeverityCounts) -> str:
    rows = "".join(
        f"<tr><td>{_esc(label)}</td><td>{count}</td></tr>" for label, count in counts.as_rows()
    )
    return f"<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>"


# --------------------------------------------------------------------------- sections


def _cover(report: ReportData) -> str:
    cover = report.cover
    brand = report.branding
    modules = ", ".join(f"{k} {v}" for k, v in sorted(cover.module_versions.items()))
    rows = [
        ("Target", cover.target),
        ("Scan id", cover.scan_id),
        ("Generated", _iso(cover.generated_at)),
        ("Scan started", _iso(cover.scan_started_at)),
        ("Scan finished", _iso(cover.scan_finished_at)),
        ("Engine", cover.engine),
        ("ARACHNE", cover.arachne_version),
        ("Modules", modules or "(none recorded)"),
        ("Schema", cover.schema_version),
    ]
    definition = "".join(f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>" for label, value in rows)
    branding = ""
    if brand.is_customised():
        if brand.logo_url:
            logo = (
                f'<img class="logo" src="{_esc(brand.logo_url)}" '
                f'alt="{_esc(brand.display_name())}">'
            )
        elif brand.logo_text:
            logo = f'<span class="logo-mark">{_esc(brand.logo_text)}</span>'
        else:
            logo = ""
        heading = " · ".join(part for part in (brand.company_name, brand.tagline) if part)
        name_html = f'<p class="brand-name">{_esc(heading)}</p>' if heading else ""
        branding = f'<div class="brand">{logo}{name_html}</div>'
    return (
        '<section class="cover">'
        f"{branding}"
        f"<h1>{_esc(cover.title)}</h1>"
        f'<p class="target">{_esc(cover.target)}</p>'
        f"<dl>{definition}</dl>"
        "</section>"
    )


def _summary(report: ReportData) -> str:
    summary = report.executive_summary
    parts = [f"<section><h2>1. {_t('report.section.executive_summary', report)}</h2>"]
    for paragraph in summary.paragraphs:
        parts.append(f"<p>{_esc(paragraph)}</p>")
    parts.append(_counts_table(summary.counts))
    parts.append(
        f'<p class="small muted">Total {summary.counts.total} confirmed finding(s) · '
        f"{summary.low_confidence_count} low-confidence observation(s) · posture "
        f"{_esc(summary.posture)}</p>"
    )
    if summary.headline_finding_ids:
        parts.append(
            '<p class="small">Highest priority: '
            + ", ".join(_esc(item) for item in summary.headline_finding_ids)
            + "</p>"
        )
    if report.diff is not None:
        counts = report.diff.counts
        parts.append(
            '<p class="small">Trend vs '
            f"{_esc(report.diff.scan_a)}: "
            + ", ".join(f"{key} {value}" for key, value in counts.items())
            + "</p>"
        )
    parts.append("</section>")
    return "".join(parts)


def _scope(report: ReportData) -> str:
    scope = report.scope
    parts = [f'<section><h2>2. {_t("report.section.scope", report)}</h2><dl class="meta">']
    rows: list[tuple[str, str]] = [
        ("Target definition", scope.target_name),
        ("Modules", ", ".join(scope.modules)),
        ("Engine mode", scope.engine_mode),
        ("Checks run", f"{scope.checks_run} run, {scope.checks_skipped} not run"),
        ("Timeframe", f"{_iso(scope.started_at)} → {_iso(scope.finished_at)}"),
        (
            "Duration",
            f"{scope.duration_seconds:.0f} seconds"
            if scope.duration_seconds is not None
            else "(not recorded)",
        ),
        ("Report schema", scope.report_schema_version),
    ]
    for label, value in rows:
        parts.append(f"<dt>{_esc(label)}</dt><dd>{_esc(value)}</dd>")
    parts.append("</dl>")
    if scope.scope:
        parts.append("<h4>Scope (compiled, deny by default)</h4><ul>")
        for key, values in sorted(scope.scope.items()):
            if values:
                parts.append(
                    f"<li>{_esc(key)}: " + ", ".join(_esc(item) for item in values) + "</li>"
                )
        parts.append("</ul>")
    if scope.exclusions:
        parts.append(
            "<h4>Exclusions</h4><ul>"
            + "".join(f"<li>{_esc(item)}</li>" for item in scope.exclusions)
            + "</ul>"
        )
    if scope.checks:
        body = "".join(
            "<tr>"
            f"<td>{_esc(check.module)}</td><td>{_esc(check.name)}</td>"
            f"<td>{_esc(check.version)}</td><td>{_esc(check.research_ref)}</td>"
            f"<td>{'ran' if check.ran else 'not run — ' + _text(check.skip_reason)}</td>"
            "</tr>"
            for check in scope.checks
        )
        parts.append(
            "<table><thead><tr><th>Module</th><th>Check</th><th>Version</th>"
            f"<th>Research</th><th>Status</th></tr></thead><tbody>{body}</tbody></table>"
        )
    parts.append("</section>")
    return "".join(parts)


def _assets(report: ReportData) -> str:
    parts = [f"<section><h2>3. {_t('report.section.assets', report)}</h2>"]
    if not report.assets:
        parts.append('<p class="muted">No assets were recorded.</p>')
    else:
        body = "".join(
            "<tr>"
            f"<td>{_esc(asset.kind)}</td><td>{_esc(asset.value)}</td>"
            f"<td>{_inline(', '.join(asset.tags)) if asset.tags else '—'}</td>"
            f"<td>{_inline(asset.source) if asset.source else '—'}</td>"
            "</tr>"
            for asset in report.assets
        )
        parts.append(
            "<table><thead><tr><th>Kind</th><th>Asset</th><th>Tags</th><th>Source</th>"
            f"</tr></thead><tbody>{body}</tbody></table>"
        )
        correlated = [asset for asset in report.assets if asset.cve_refs]
        if correlated:
            parts.append("<h4>CVE-correlated assets</h4><ul>")
            for asset in correlated:
                parts.append(f"<li>{_esc(asset.value)} — {_inline(', '.join(asset.cve_refs))}</li>")
            parts.append("</ul>")
    parts.append("</section>")
    return "".join(parts)


def _payload_block(entry: ReportEvidence) -> str:
    payload = entry.payload
    if not payload:
        return ""
    kind = entry.kind
    lines: list[str] = []
    if kind == "http_request":
        lines.append(
            f"Request: {_text(payload.get('method') or 'GET')} {_text(payload.get('url'))}"
        )
        headers = payload.get("headers")
        if isinstance(headers, dict) and headers:
            rendered = "; ".join(f"{k}: {v}" for k, v in sorted(headers.items()))
            lines.append(f"Headers: {rendered}")
    elif kind == "http_response":
        status = payload.get("status_code")
        body = payload.get("body")
        size = len(body) if isinstance(body, str) else 0
        matched = payload.get("captured_patterns")
        suffix = ""
        if isinstance(matched, Sequence) and matched and not isinstance(matched, str):
            suffix = " · matched patterns: " + ", ".join(str(item) for item in matched)
        lines.append(f"Response: {status if status is not None else '?'} · {size} bytes{suffix}")
        if isinstance(body, str) and body.strip():
            lines.append(body.strip()[:2000])
    else:
        lines.append(json.dumps(payload, indent=2, sort_keys=True, default=str)[:4000])
    return "<pre>" + _text("\n".join(lines)) + "</pre>"


def _finding_block(index: int, finding: ReportFinding, report: ReportData) -> str:
    section, _ = next(
        (
            (number, _severity_label(name, report))
            for number, name in enumerate(_SEVERITY_ORDER, start=4)
            if name == finding.severity
        ),
        (0, _severity_label("info", report)),
    )
    classification = f" · {_esc(finding.classification.cwe)}" if finding.classification.cwe else ""
    head = (
        f"{_badge(finding.severity)} <strong>{_esc(finding.id)}</strong> · "
        f"{_esc(finding.title)}{classification} · conf {finding.score.confidence}"
    )
    meta_rows: list[tuple[str, str]] = [
        ("Asset", finding.asset.value),
        ("CVSS", _cvss(finding.score.cvss_base)),
        ("Vector", finding.score.cvss_vector or "(not recorded)"),
        ("OWASP risk", finding.score.owasp_risk or "(not recorded)"),
        ("First seen", _date(finding.timestamps.first_seen)),
    ]
    if finding.check_id:
        check = finding.check_id
        if finding.check_version:
            check += f"@{finding.check_version}"
        meta_rows.append(("Check", check))
    if finding.research_ref:
        meta_rows.append(("Research", finding.research_ref))
    if finding.classification.cve:
        meta_rows.append(("CVE", finding.classification.cve))
    meta = "".join(f"<dt>{_esc(k)}</dt><dd>{_inline(v)}</dd>" for k, v in meta_rows)

    parts = [
        f'<details class="finding" open><summary>{head}</summary>',
        f"<h4>{section}.{index} {_esc(finding.id)}</h4>",
        f'<dl class="meta">{meta}</dl>',
        f"<p><strong>Description:</strong> {_inline(finding.description)}</p>",
    ]
    if finding.evidence_refs:
        parts.append("<h4>Evidence</h4><ul>")
        for ref in finding.evidence_refs:
            entry = report.evidence_by_id(ref)
            if entry is None:
                parts.append(f"<li>{_esc(ref)} (payload not found in this report)</li>")
                continue
            digest = f" · sha256 <code>{_esc(entry.sha256[:16])}…</code>" if entry.sha256 else ""
            parts.append(
                f"<li><strong>{_esc(entry.id)} · {_esc(entry.kind)}</strong> — {_inline(entry.summary)}{digest}"
            )
            parts.append(_payload_block(entry))
            parts.append("</li>")
        parts.append("</ul>")
    parts.append(f"<h4>Remediation</h4><p>{_inline(finding.remediation.summary)}</p>")
    if finding.remediation.steps:
        parts.append(
            "<ol>"
            + "".join(f"<li>{_inline(step)}</li>" for step in finding.remediation.steps)
            + "</ol>"
        )
    if finding.remediation.verification:
        parts.append("<h4>Verification of fix</h4><ol>")
        parts.append(
            "".join(f"<li>{_inline(step)}</li>" for step in finding.remediation.verification)
        )
        parts.append("</ol>")
    if finding.remediation.references:
        parts.append(
            '<p class="small">References: '
            + ", ".join(_esc(ref) for ref in finding.remediation.references)
            + "</p>"
        )
    provenance = finding.provenance
    bits = [f"engine={provenance.engine}"]
    if provenance.template_version:
        bits.append(f"template={provenance.template_version}")
    if provenance.rule_ids:
        bits.append("rules=" + ", ".join(provenance.rule_ids))
    if provenance.signatures:
        bits.append("signatures=" + ", ".join(provenance.signatures))
    bits.append(f"status={finding.status}")
    bits.append(f"remediation={finding.remediation.id}")
    parts.append(f'<p class="small muted">Provenance: {_inline(", ".join(bits))}</p>')
    parts.append("</details>")
    return "".join(parts)


def _findings(report: ReportData) -> str:
    parts: list[str] = []
    for number, severity in enumerate(_SEVERITY_ORDER, start=4):
        label = _severity_label(severity, report)
        findings = report.findings_by_severity(severity)
        section = _t('report.section.findings', report)
        parts.append(f"<section><h2>{number}. {section} — {label}</h2>")
        if not findings:
            parts.append(f'<p class="muted">No {label.lower()} findings were confirmed.</p>')
        else:
            for offset, finding in enumerate(findings, start=1):
                parts.append(_finding_block(offset, finding, report))
        parts.append("</section>")
    return "".join(parts)


def _low_confidence(report: ReportData) -> str:
    parts = [f"<section><h2>9. {_t('report.section.low_confidence', report)}</h2>"]
    if not report.low_confidence:
        parts.append('<p class="muted">No observations fell below the confidence threshold.</p>')
        parts.append("</section>")
        return "".join(parts)
    parts.append(
        '<p class="lc">These observations are <strong>not confirmed findings</strong>. They fell '
        "below the report's confidence threshold and should be triaged before they are acted "
        "on.</p>"
    )
    body = "".join(
        "<tr>"
        f"<td>{_esc(finding.id)}</td><td>{_esc(finding.title)}</td>"
        f"<td>{_esc(finding.asset.value)}</td><td>{_badge(finding.severity)}</td>"
        f"<td>{finding.score.confidence}</td>"
        f"<td>{_inline(', '.join(finding.evidence_refs) or '—')}</td>"
        "</tr>"
        for finding in report.low_confidence
    )
    parts.append(
        "<table><thead><tr><th>Id</th><th>Title</th><th>Asset</th><th>Severity</th>"
        f"<th>Confidence</th><th>Evidence</th></tr></thead><tbody>{body}</tbody></table>"
    )
    parts.append("</section>")
    return "".join(parts)


def _patch_gap(report: ReportData) -> str:
    parts = [f"<section><h2>10. {_t('report.section.patch_gap', report)}</h2>"]
    patch_gap = report.patch_gap
    if patch_gap is None:
        parts.append(
            '<p class="muted">M6 (AI-era signals) did not run in this scan, so no patch-gap '
            "section is reported. An absent section is not a clean result.</p></section>"
        )
        return "".join(parts)
    known = patch_gap.get("known_vulnerable") or []
    if known:
        rows = "".join(
            f"<tr><td>{_inline(item.get('finding_id'))}</td>"
            f"<td>{_inline(item.get('asset'))}</td><td>{_inline(item.get('cve'))}</td></tr>"
            for item in known
        )
        parts.append(
            "<h4>Known-vulnerable versions</h4><table><thead><tr><th>Finding</th>"
            f"<th>Asset</th><th>CVE</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        parts.append('<p class="muted">No CVE-correlated findings were recorded.</p>')
    epss = patch_gap.get("epss_top") or []
    if epss:
        rows = "".join(
            f"<tr><td>{_inline(item.get('finding_id'))}</td><td>{_inline(item.get('cve'))}</td>"
            f"<td>{_cvss(item.get('epss'))}</td></tr>"
            for item in epss
        )
        parts.append(
            "<h4>Top EPSS items</h4><table><thead><tr><th>Finding</th><th>CVE</th>"
            f"<th>EPSS</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    webshell = patch_gap.get("webshell_scan")
    count = webshell.get("findings") if isinstance(webshell, dict) else None
    parts.append(
        f"<p><strong>Webshell scan:</strong> {_esc(count if count is not None else 'see findings')}</p>"
    )
    parts.append("</section>")
    return "".join(parts)


def _appendix(report: ReportData) -> str:
    appendix = report.appendix
    parts = [
            f"<section><h2>11. {_t('report.section.appendix', report)}</h2>",
            f"<h3>A. {_t('report.appendix.evidence', report)}</h3>",
        ]
    if not appendix.evidence:
        parts.append('<p class="muted">No evidence was captured.</p>')
    for entry in appendix.evidence:
        digest = f" · sha256 <code>{_esc(entry.sha256)}</code>" if entry.sha256 else ""
        parts.append(f"<h4>{_esc(entry.id)} · {_esc(entry.kind)}{digest}</h4>")
        parts.append(f"<p>{_inline(entry.summary)}</p>")
        if entry.payload:
            rendered = json.dumps(entry.payload, indent=2, sort_keys=True, default=str)
            parts.append("<pre>" + _text(rendered) + "</pre>")
    parts.append("<h3>B. Audit log summary</h3>")
    audit = appendix.audit
    parts.append(
        f'<p class="small">{audit.total_events} event(s) · {audit.blocked_events} blocked · '
        f"{_iso(audit.first_event_at)} → {_iso(audit.last_event_at)}</p>"
    )
    if audit.actions:
        rows = "".join(
            f"<tr><td>{_esc(action)}</td><td>{count}</td></tr>"
            for action, count in sorted(audit.actions.items())
        )
        parts.append(
            f"<table><thead><tr><th>Action</th><th>Count</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    parts.append("<h3>C. Out-of-scope events</h3>")
    if audit.out_of_scope_events:
        parts.append(
            "<ul>"
            + "".join(f"<li>{_esc(item)}</li>" for item in audit.out_of_scope_events)
            + "</ul>"
        )
    else:
        parts.append('<p class="muted">No out-of-scope requests were attempted.</p>')
    parts.append("<h3>D. False positives</h3>")
    if appendix.false_positives:
        rows = "".join(
            f"<tr><td>{_esc(item.finding_id)}</td><td>{_esc(item.title)}</td>"
            f"<td>{_esc(item.severity)}</td><td>{_inline(item.reason)}</td></tr>"
            for item in appendix.false_positives
        )
        parts.append(
            "<table><thead><tr><th>Finding</th><th>Title</th><th>Severity</th><th>Reason</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>"
        )
    else:
        parts.append('<p class="muted">No findings were dropped or merged.</p>')
    parts.append("<h3>E. Glossary</h3>")
    if appendix.glossary:
        definition = "".join(
            f"<dt>{_esc(term)}</dt><dd>{_inline(text)}</dd>"
            for term, text in sorted(appendix.glossary.items())
        )
        parts.append(f'<dl class="meta">{definition}</dl>')
    else:
        parts.append('<p class="muted">No glossary entries.</p>')
    parts.append("</section>")
    return "".join(parts)


def _simulation(report: ReportData) -> str:
    """The what-if annex (S28, REQ-SIM-002/004).

    Its own section, visibly marked, after the appendix — the same placement the Markdown
    renderer uses, so a reader who receives either format meets the hypothetical material only
    after everything the scan established.
    """
    simulation = getattr(report, "simulation", None)
    if simulation is None:
        return ""
    parts = [
        f"<section><h2>13. {_t('report.section.simulation', report)}</h2>",
        f'<p class="classification">{_esc(simulation.disclosure)}</p>',
        f"<p><strong>Provenance:</strong> {_esc(simulation.provenance)} · "
        f"<strong>Estate model:</strong> {_esc(simulation.estate_key)} · "
        f"<strong>Exposure score:</strong> {simulation.exposure_before} → "
        f"{simulation.exposure_after}</p>",
    ]
    if simulation.hypotheses:
        rows = "".join(
            f"<tr><td>{_esc(item.id)}</td><td>{_esc(item.kind)}</td><td>{_esc(item.asset)}</td>"
            f"<td>{_badge(item.severity)}</td><td>{_inline(item.note or item.title)}</td></tr>"
            for item in simulation.hypotheses
        )
        parts.append(
            "<h3>Hypothetical states injected</h3>"
            "<table><thead><tr><th>Id</th><th>Kind</th><th>Asset</th><th>Severity</th>"
            f"<th>Change</th></tr></thead><tbody>{rows}</tbody></table>"
        )
    if simulation.refusals:
        items = "".join(f"<li>{_inline(item)}</li>" for item in simulation.refusals)
        parts.append(f"<h3>Hypotheses that could not be applied</h3><ul>{items}</ul>")
    parts.append("<h3>Resulting paths</h3>")
    if not simulation.paths:
        parts.append(
            '<p class="muted">No multi-step path follows from the estate plus these '
            "hypothetical states.</p>"
        )
    for path in simulation.paths:
        origin = "hypothetical" if path.hypothetical else "observed"
        hops = "".join(
            f"<tr><td>{_esc(hop.stage)}</td><td><code>{_esc(hop.check_id)}</code></td>"
            f"<td>{_esc(hop.asset)}</td><td>{_badge(hop.severity)}</td>"
            f"<td>{_esc(hop.origin)}</td><td>{_esc(hop.hypothesis_id or '—')}</td></tr>"
            for hop in path.hops
        )
        parts.append(
            f"<h4>{_esc(path.id)} — {_esc(path.asset)}</h4>"
            f"<p>Chain: {_esc(' → '.join(path.stages))} · "
            f"Terminal impact: {_badge(path.severity)} ({_esc(origin)})</p>"
            f"<p>{_inline(path.cheapest_break or '—')}</p>"
            "<table><thead><tr><th>Stage</th><th>Check</th><th>Asset</th><th>Severity</th>"
            f"<th>Origin</th><th>Hypothesis</th></tr></thead><tbody>{hops}</tbody></table>"
        )
    if simulation.change is not None:
        change = simulation.change
        parts.append(
            f"<h3>Proposed change: {_esc(change.name)}</h3>"
            f"<p>Exposure {change.exposure_before} → {change.exposure_after} "
            f"({change.exposure_delta:+d}), paths {change.paths_before} → "
            f"{change.paths_after}</p>"
        )
    parts.append("</section>")
    return "".join(parts)


def render_html(report: ReportData) -> str:
    """Render ``report`` as one self-contained HTML document (F-06-02)."""
    brand = report.branding
    title = f"{brand.product_name} report — {report.target_name}"
    banner = (
        f'<div class="classification">{_esc(brand.classification)}</div>'
        if brand.classification
        else ""
    )
    brand_note = ""
    if brand.is_customised():
        brand_note = " · ".join(
            part for part in (brand.company_name, brand.contact, brand.footer_text) if part
        )
    footer_bits = [
        f"Generated by {_esc(brand.product_name)} {_esc(report.cover.arachne_version)}",
        f"schema {_esc(report.schema_version)}",
        "defensive security reporting; handle as sensitive.",
    ]
    if brand_note:
        footer_bits.insert(0, _esc(brand_note))
    body = "".join(
        [
            banner,
            _cover(report),
            _summary(report),
            _scope(report),
            _assets(report),
            _findings(report),
            _low_confidence(report),
            _patch_gap(report),
            _appendix(report),
            # S28: the what-if annex, after everything the scan established (REQ-SIM-004).
            _simulation(report),
            f'<p class="footer">{" · ".join(footer_bits)}</p>',
        ]
    )
    style = HTML_CSS
    if brand.is_customised():
        # Colours are validated hex literals (Branding), so they are safe in a stylesheet.
        style += (
            f":root {{ --brand:{brand.primary_color}; --accent:{brand.accent_color}; }}"
            ".brand{display:flex;align-items:center;gap:.7rem;margin-bottom:.6rem}"
            ".logo{max-height:56px;max-width:220px}"
            ".logo-mark{display:inline-flex;align-items:center;justify-content:center;"
            "min-width:46px;height:46px;padding:0 8px;border-radius:6px;"
            "background:var(--brand);color:#fff;font-weight:700;letter-spacing:.5px}"
            ".brand-name{color:var(--muted);margin:0;font-size:.95rem}"
            ".classification{background:var(--accent);color:#fff;text-align:center;"
            "font-weight:700;letter-spacing:.12em;padding:.35rem;font-size:.78rem;"
            "border-radius:4px;margin-bottom:.8rem}"
        )
    return (
        "<!doctype html>\n"
        '<html lang="' + html.escape(report.locale or DEFAULT_LOCALE, quote=True)
        + '"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_esc(title)}</title><style>{style}</style></head>\n"
        f'<body><div class="wrap">{body}</div></body></html>\n'
    )


# Re-exported so a caller can strip markup without importing `re` itself (used by tests).
_TAG_RE = re.compile(r"<[^>]+>")


def html_to_text(document: str) -> str:
    """A crude text projection of a rendered report (for full-text search assertions)."""
    return html.unescape(_TAG_RE.sub(" ", document))
