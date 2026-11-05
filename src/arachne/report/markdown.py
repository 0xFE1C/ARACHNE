"""Markdown renderer — the default report format (/§9).

Markdown is the human/Git format, so it is the one that must read like the sample skeleton
in the report *exactly*: the same numbered sections (executive summary, scope,
inventory, findings grouped critical→info, low-confidence observations, patch-gap, appendix)
and the same per-finding block (asset · CVSS · first seen, description, evidence, remediation,
provenance).

Determinism is a hard requirement (ADR-06): every list is sorted by the DTO before it
reaches this module, every timestamp is rendered from the DTO (never ``now()``), and numbers
are formatted with a fixed precision. The only clock in a report is
``ReportData.cover.generated_at``, supplied by the builder.

Two safety properties:

* **No value is invented.** If a field is absent the renderer prints "(not recorded)" rather
  than a plausible-looking default, because a report that guesses is worse than one with a
  gap.
* **Table cells are escaped.** A finding title or asset value can contain a ``|`` or a
  newline (a target controls part of its own name); both are neutralised so one finding
  cannot break the table it sits in.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime

from arachne.i18n import translate
from arachne.report import model as m
from arachne.report.model import (
    SEVERITY_ORDER,
    ReportData,
    ReportEvidence,
    ReportFinding,
    SeverityCounts,
)

__all__ = ["render_markdown"]

_SEVERITY_SECTIONS: dict[str, int] = {
    "critical": 4,
    "high": 5,
    "medium": 6,
    "low": 7,
    "info": 8,
}


def _locale_of(report: ReportData) -> str | None:
    """The locale a report selects, or ``None`` for the deployment default (S26)."""
    return report.locale or None


def _t(key: str, report: ReportData) -> str:
    """A catalogue lookup in the report's own locale (S26, REQ-ECOS-005).

    Every label in this renderer goes through here rather than reading a locale from the
    environment, so one process can render two reports in two languages. The key is always a
    literal, which is what ``tests/unit/test_i18n.py`` scans for to keep the catalogue and the
    renderers in step.
    """
    return translate(key, locale=_locale_of(report))


def _severity_label(severity: str, report: ReportData) -> str:
    return _t(f"report.severity.{severity}", report)


#: Attack-path table columns, in render order (the keys are catalogue entries, so the
#: header is translated while the rows' identifiers never are).
_ATTACK_PATH_COLUMNS: tuple[str, ...] = (
    "report.attack_path.hop",
    "report.attack_path.stage",
    "report.attack_path.check",
    "report.attack_path.asset",
    "report.attack_path.severity",
    "report.attack_path.verified",
    "report.attack_path.evidence",
)


def _attack_path_header(report: ReportData) -> str:
    return "| " + " | ".join(_t(key, report) for key in _ATTACK_PATH_COLUMNS) + " |"


def _inline(value: object | None) -> str:
    """One-line rendering of a possibly target-controlled value."""
    if value is None:
        return "(not recorded)"
    text = " ".join(str(value).split())
    return text.replace("|", "\\|") or "(empty)"


def _date(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d") if value else "(not recorded)"


def _iso(value: datetime | str | None) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return value if value else "(not recorded)"


def _fence_for(text: str) -> str:
    """A code fence longer than any backtick run in ``text``.

    Evidence bodies are target-controlled. A body containing ```` ``` ```` would otherwise
    close the fence and let the target write Markdown into the report.
    """
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def _cvss(value: float | None) -> str:
    return f"{value:.1f}" if value is not None else "n/a"


def _counts_table(counts: SeverityCounts) -> list[str]:
    lines = ["| Severity | Count |", "|---|---|"]
    lines.extend(f"| {label} | {count} |" for label, count in counts.as_rows())
    lines.append(f"| **Total** | **{counts.total}** |")
    return lines


def _numbered(steps: Sequence[str]) -> list[str]:
    out: list[str] = []
    for index, step in enumerate(steps, start=1):
        text = step.strip()
        # Catalog steps are written "1. ..." already; renumber so a reordered/edited entry
        # cannot produce two "1." lines.
        for prefix in (f"{index}. ", f"{index}.", f"{index}) "):
            if text.startswith(prefix):
                text = text[len(prefix) :].strip()
                break
        out.append(f"{index}. {text}")
    return out


def _evidence_block(finding: ReportFinding, report: ReportData) -> list[str]:
    lines: list[str] = [f"**{_t('report.finding.evidence', report)}:**"]
    for ref in finding.evidence_refs:
        entry = report.evidence_by_id(ref)
        if entry is None:
            lines.append(f"- {ref} (payload not found in this report)")
            continue
        digest = f" · sha256 `{entry.sha256[:16]}…`" if entry.sha256 else ""
        lines.append(f"- **{entry.id} · {entry.kind}** — {_inline(entry.summary)}{digest}")
        excerpt = _payload_excerpt(entry)
        if excerpt:
            lines.extend("  " + line for line in excerpt)
    return lines


def _payload_excerpt(entry: ReportEvidence) -> list[str]:
    """A short, safe rendering of an evidence payload (request line, status, body excerpt)."""
    payload = entry.payload
    if not payload:
        return []
    lines: list[str] = []
    if entry.kind == "http_request":
        method = _inline(payload.get("method") or "GET")
        url = _inline(payload.get("url"))
        lines.append(f"Request: `{method} {url}`")
        headers = payload.get("headers")
        if isinstance(headers, dict) and headers:
            rendered = "; ".join(f"{key}: {value}" for key, value in sorted(headers.items()))
            lines.append(f"Headers: {_inline(rendered)}")
    elif entry.kind == "http_response":
        status = payload.get("status_code")
        body = payload.get("body")
        size = len(body) if isinstance(body, str) else 0
        matched = payload.get("captured_patterns")
        suffix = (
            " · matched patterns: " + ", ".join(str(item) for item in matched)
            if isinstance(matched, Sequence) and matched and not isinstance(matched, str)
            else ""
        )
        lines.append(f"Response: {status if status is not None else '?'} · {size} bytes{suffix}")
        if isinstance(body, str) and body.strip():
            excerpt = body.strip().splitlines()[:12]
            fence = _fence_for("\n".join(excerpt))
            lines.append(fence)
            lines.extend(excerpt)
            lines.append(fence)
    elif entry.kind == "artifact":
        keys = ", ".join(sorted(str(key) for key in payload))
        lines.append(f"Artifact keys: {keys}")
    elif entry.kind == "note":
        detail = payload.get("detail")
        if isinstance(detail, str) and detail.strip():
            lines.append(f"Detail: {_inline(detail)}")
    else:
        keys = ", ".join(sorted(str(key) for key in payload))
        if keys:
            lines.append(f"Payload keys: {keys}")
    return lines


def _proof_block(finding: ReportFinding) -> list[str]:
    """The finding's *Proof* section (S15, REQ-PROOF-013): level, method, cleanup."""
    proof = finding.proof
    if proof is None:
        return []
    lines = ["**Proof:**"]
    parts = [f"level {proof.level}"]
    if proof.method:
        parts.append(proof.method)
    lines.append(f"- {' · '.join(_inline(part) for part in parts)}")
    if proof.token:
        lines.append(f"- callback token: `{_inline(proof.token)}`")
    if proof.nonce and proof.nonce != proof.token:
        lines.append(f"- nonce: `{_inline(proof.nonce)}`")
    cleanup = proof.cleanup or "(not recorded)"
    lines.append(f"- cleanup: {_inline(cleanup)}")
    change = proof.detail.get("change")
    if isinstance(change, Mapping):
        restored = bool(change.get("restored"))
        verified = bool(change.get("restore_verified"))
        lines.append(
            f"- state change: {_inline(change.get('kind'))} on {_inline(change.get('locator'))}"
            f" — restored: {'yes' if restored else '**NO — repair required**'}"
            f" · re-verified: {'yes' if verified else 'no'}"
        )
    lines.append("")
    return lines


def _verification_block(finding: ReportFinding, report: ReportData) -> list[str]:
    """The finding's *Verification* section (WP-13, REQ-PROOF-015/016).

    Always rendered: the record is required by the schema, and an ``unverified`` one says
    why the finding carries no proof rather than rendering nothing.
    """
    record = finding.verification
    label = _t("report.finding.verification_record", report)
    lines = [f"**{label}:**"]
    head = [f"level {record.level}", record.status]
    if record.check_version:
        head.append(f"check {record.check_version}")
    if record.method:
        head.append(record.method)
    lines.append(f"- {' · '.join(_inline(part) for part in head)}")
    if record.reproducibility:
        # Deliberately not ``token: <value>``: a ``<sensitive-key>: <value>`` shape is
        # indistinguishable from a leaked credential to a text scanner (the repository's own
        # ``contains_secret``), and the report must not *look* like it leaked one.
        lines.append(f"- reproducibility: `{_inline(record.reproducibility)}`")
    if record.verified_at:
        lines.append(f"- verified at: {_date(record.verified_at)}")
    for item in record.observations[:12]:
        lines.append(f"- observation: {_inline(m.observation_summary(item))}")
    for entry in finding.verification_history:
        if entry.parent_record_id is None:
            continue
        lines.append(
            f"- re-verification: {_inline(entry.outcome or entry.status)} at level "
            f"{_inline(entry.level)} (parent record {entry.parent_record_id})"
        )
    lines.append("")
    return lines


def _finding_block(index: int, finding: ReportFinding, report: ReportData) -> list[str]:
    section = _SEVERITY_SECTIONS.get(finding.severity, 0)
    classification = f" ({finding.classification.cwe})" if finding.classification.cwe else ""
    lines = [
        f"### {section}.{index} {finding.id} · {_inline(finding.title)}{classification}"
        f" · conf {finding.score.confidence}",
        "",
        f"{_t('report.finding.asset', report)}: "
        f"{_inline(finding.asset.value)}"
        f" · CVSS {_cvss(finding.score.cvss_base)}"
        f" · first seen {_date(finding.timestamps.first_seen)}",
        "",
        f"**{_t('report.finding.description', report)}:** {_inline(finding.description)}",
        "",
    ]
    if finding.check_id:
        check = f"{finding.check_id}"
        if finding.check_version:
            check += f"@{finding.check_version}"
        extras = [f"check `{check}`"]
        if finding.research_ref:
            extras.append(f"research `{finding.research_ref}`")
        if finding.classification.owasp_2025:
            extras.append(finding.classification.owasp_2025)
        if finding.classification.cve:
            extras.append(finding.classification.cve)
        lines.extend(
            [
                f"{_t('report.finding.classification', report)}: "
                f"{' · '.join(_inline(item) for item in extras)}",
                "",
            ]
        )
    lines.extend(_evidence_block(finding, report))
    lines.extend(_proof_block(finding))
    lines.extend(_verification_block(finding, report))
    remediation = _t("report.finding.remediation", report)
    lines.extend(["", f"**{remediation}:** {_inline(finding.remediation.summary)}", ""])
    if finding.remediation.steps:
        lines.extend(_numbered(finding.remediation.steps))
        lines.append("")
    if finding.remediation.verification:
        lines.append(f"**{_t('report.finding.verification', report)}:**")
        lines.extend(_numbered(finding.remediation.verification))
        lines.append("")
    if finding.remediation.references:
        lines.append(
            "**References:** "
            + ", ".join(f"<{reference}>" for reference in finding.remediation.references)
        )
        lines.append("")
    provenance = finding.provenance
    parts = [f"engine={provenance.engine}"]
    if provenance.template_version:
        parts.append(f"template={provenance.template_version}")
    if provenance.rule_ids:
        parts.append("rules=" + ", ".join(provenance.rule_ids))
    if provenance.signatures:
        parts.append("signatures=" + ", ".join(provenance.signatures))
    if provenance.analysis_log_id:
        parts.append(f"analysis_log={provenance.analysis_log_id}")
    parts.append(f"status={finding.status}")
    parts.append(f"remediation={finding.remediation.id}")
    lines.extend([f"**{_t('report.finding.provenance', report)}:** {', '.join(parts)}", ""])
    return lines


def _residue_warning(report: ReportData) -> list[str]:
    """The residue warning, right under the executive summary (WP-14, REQ-PROOF-017).

    Present only when the scan recorded an attestation **and** that attestation is not
    clean. A scan with no attestation renders nothing here — the state-changes table in the
    appendix says "no state change was made" on its own evidence, and inventing a clean
    verdict for a scan that never produced one is the mistake this requirement exists to
    prevent. The signed statement is quoted verbatim: it is the artefact's own text, and
    paraphrasing a signed claim would make the report disagree with what was signed.
    """
    attestation = report.residue_attestation
    if attestation is None or attestation.clean:
        return []
    signature = _t(
        "report.residue.signed" if attestation.signed else "report.residue.unsigned", report
    )
    digest = (attestation.hash or "")[:16]
    lines = [
        "",
        f"> **{_t('report.residue.warning', report)}** — {_inline(attestation.statement)}",
        f"> {_t('report.residue.attestation', report)}: {_inline(digest)}... ({signature})",
    ]
    for instruction in attestation.repair_instructions:
        lines.append(f"> - {_inline(instruction)}")
    return lines


def _severity_section(
    number: int, severity: str, findings: Sequence[ReportFinding], report: ReportData
) -> list[str]:
    label = _severity_label(severity, report)
    section = _t("report.section.findings", report)
    lines = [f"## {number}. {section} — {label}", ""]
    if not findings:
        lines.extend([f"No {label.lower()} findings were confirmed.", ""])
        return lines
    for offset, finding in enumerate(findings, start=1):
        lines.extend(_finding_block(offset, finding, report))
    return lines


def _scope_section(report: ReportData) -> list[str]:
    scope = report.scope
    lines = [f"## 2. {_t('report.section.scope', report)}", ""]
    lines.append(f"- Target definition: {_inline(scope.target_name)}")
    if scope.requested_by:
        lines.append(f"- Requested by: {_inline(scope.requested_by)}")
    if scope.credentials:
        # Labels, not secrets: an operator reading the report must be able to tell that the
        # scan saw an authenticated surface, and which vault entry it used.
        state = "authenticated" if scope.authenticated else "no session established"
        lines.append(
            f"- Credentials: {', '.join(_inline(label) for label in scope.credentials)} ({state})"
        )
    if scope.modules:
        lines.append(f"- Modules enabled: {', '.join(scope.modules)}")
    lines.append(
        f"- Engine mode: {_inline(scope.engine_mode)}"
        + (
            f" · analysis corpus {_inline(scope.research_corpus_version)}"
            if scope.research_corpus_version
            else ""
        )
    )
    if scope.started_at or scope.finished_at:
        lines.append(
            f"- Timeframe: {_iso(scope.started_at)} → {_iso(scope.finished_at)}"
            + (
                f" ({scope.duration_seconds:.0f} seconds)"
                if scope.duration_seconds is not None
                else ""
            )
        )
    lines.append(f"- Checks run: {scope.checks_run} run, {scope.checks_skipped} not run")
    if scope.rate_limits:
        rendered = ", ".join(f"{key}={value}" for key, value in sorted(scope.rate_limits.items()))
        lines.append(f"- Rate limits: {rendered}")
    lines.append(f"- Report schema: {scope.report_schema_version}")
    lines.append("")

    if scope.scope:
        lines.extend(["**Scope (compiled, deny by default):**", ""])
        for key, values in sorted(scope.scope.items()):
            if values:
                lines.append(f"- {key}: {', '.join(_inline(item) for item in values)}")
        lines.append("")
    if scope.exclusions:
        lines.extend(
            ["**Exclusions:** " + ", ".join(_inline(item) for item in scope.exclusions), ""]
        )
    if scope.checks:
        lines.extend(
            [
                "| Module | Check | Version | Research | Status |",
                "|---|---|---|---|---|",
            ]
        )
        for check in scope.checks:
            status = "ran" if check.ran else f"not run — {_inline(check.skip_reason)}"
            lines.append(
                f"| {check.module} | {_inline(check.name)} | {_inline(check.version)} | "
                f"{_inline(check.research_ref)} | {status} |"
            )
        lines.append("")
    return lines


def _assets_section(report: ReportData) -> list[str]:
    lines = [f"## 3. {_t('report.section.assets', report)}", ""]
    if not report.assets:
        lines.extend(["No assets were recorded.", ""])
        return lines
    lines.extend(["| Kind | Asset | Tags | Source |", "|---|---|---|---|"])
    for asset in report.assets:
        lines.append(
            f"| {_inline(asset.kind)} | {_inline(asset.value)} | "
            f"{_inline(', '.join(asset.tags)) if asset.tags else '—'} | "
            f"{_inline(asset.source) if asset.source else '—'} |"
        )
    lines.append("")
    correlated = [asset for asset in report.assets if asset.cve_refs]
    if correlated:
        lines.append("**CVE-correlated assets:**")
        for asset in correlated:
            lines.append(f"- {_inline(asset.value)} — {', '.join(asset.cve_refs)}")
        lines.append("")
    return lines


def _attack_paths_section(report: ReportData) -> list[str]:
    """``## 9. Attack paths`` (S21, REQ-AGENT-003).

    One block per path: the stages it walks, the terminal impact, every hop with its evidence,
    and the cheapest way to break the chain. A hop the analyzer did not accept is rendered as a
    **candidate** hop and names the check that would verify it — a report that showed those as
    proven steps would be claiming more than the scan established.
    """
    lines = [f"## 9. {_t('report.section.attack_paths', report)}", ""]
    paths = getattr(report, "attack_paths", ())
    if not paths:
        lines.extend(
            [
                "No multi-step attack path was composed from this scan's verified findings.",
                "",
            ]
        )
        return lines
    lines.extend(
        [
            "A path is a chain of findings on one asset whose stages strictly increase "
            "(exposure → credentials → access → execution → impact). Its severity is the "
            "**terminal** hop's impact. Hops marked *candidate* were not verified by the "
            "analyzer and name the check that would verify them.",
            "",
        ]
    )
    for path in paths:
        verified = "verified" if path.fully_verified else "partially verified"
        lines.extend(
            [
                f"### {path.id} — {_inline(path.asset)}",
                "",
                f"- Chain: {' → '.join(path.stages)}",
                f"- Terminal impact: **{path.severity}** ({verified})",
            ]
        )
        if path.criticality is not None and path.business_severity:
            lines.append(
                f"- Business impact: tier {path.criticality} "
                f"(ranks as **{path.business_severity}**; from the CMDB import)"
            )
        lines.extend(
            [
                f"- {_t('report.attack_path.cheapest', report)}: "
                f"{_inline(path.cheapest_break or '—')}",
                "",
                _attack_path_header(report),
                "|---|---|---|---|---|---|---|",
            ]
        )
        for hop in path.hops:
            if hop.verified:
                state = "yes"
            else:
                state = f"candidate — verify with {_inline(hop.verifying_check or 'a fresh scan')}"
            lines.append(
                f"| {hop.finding_id or '—'} | {hop.stage} | {_inline(hop.check_id)} | "
                f"{_inline(hop.asset)} | {hop.severity} | {state} | "
                f"{', '.join(hop.evidence_refs) or '—'} |"
            )
        lines.append("")
    return lines


def _simulation_section(report: ReportData) -> list[str]:
    """``## 13. Simulated scenarios (what-if)`` (S28, REQ-SIM-002/004).

    Rendered **only** when a simulation was attached, and placed after the evidence appendix
    deliberately: the verified body is numbered 1-12 and does not move for a deployment that
    never simulates, and a reader meets the hypothetical section *after* everything the scan
    actually established. Every hop states its origin, a hypothetical one names the hypothesis
    that introduced it, and the disclosure says in plain words that nothing here was observed
    on a target.
    """
    simulation = getattr(report, "simulation", None)
    if simulation is None:
        return []
    lines = [f"## 13. {_t('report.section.simulation', report)}", ""]
    lines.extend(
        [
            f"> **{_t('report.simulation.disclosure', report)}**",
            "",
            _inline(simulation.disclosure),
            "",
            f"- Provenance: **{simulation.provenance}**",
            f"- Estate model: {_inline(simulation.estate_key)}",
        ]
    )
    if simulation.built_from_scans:
        scans = ", ".join(str(item) for item in simulation.built_from_scans)
        lines.append(f"- Built from scan(s): {scans}")
    if simulation.model:
        summary = " · ".join(f"{key}={simulation.model[key]}" for key in sorted(simulation.model))
        lines.append(f"- Model: {summary}")
    lines.append(f"- Exposure score: {simulation.exposure_before} → {simulation.exposure_after}")
    lines.append("")
    if simulation.hypotheses:
        lines.extend([f"### {_t('report.simulation.hypotheses', report)}", ""])
        lines.extend(
            ["| Id | Kind | Asset | Severity | Hypothetical change |", "|---|---|---|---|---|"]
        )
        for item in simulation.hypotheses:
            lines.append(
                f"| {_inline(item.id)} | {_inline(item.kind)} | {_inline(item.asset)} | "
                f"{item.severity} | {_inline(item.note or item.title)} |"
            )
        lines.append("")
    if simulation.refusals:
        lines.extend([f"### {_t('report.simulation.refusals', report)}", ""])
        lines.extend(
            ["These hypotheses were **not applied** — the model could not support them:", ""]
        )
        lines.extend(f"- {_inline(item)}" for item in simulation.refusals)
        lines.append("")
    lines.extend([f"### {_t('report.simulation.paths', report)}", ""])
    if not simulation.paths:
        lines.extend(
            ["No multi-step path follows from the estate plus these hypothetical states.", ""]
        )
    else:
        lines.extend(
            [
                "Each hop is marked *observed* (a scan established it) or *hypothetical* "
                "(a hypothesis introduced it, naming which). These paths are **not** findings "
                "and are excluded from every gate verdict.",
                "",
            ]
        )
        for path in simulation.paths:
            origin = "hypothetical" if path.hypothetical else "observed"
            lines.extend(
                [
                    f"#### {path.id} — {_inline(path.asset)}",
                    "",
                    f"- Chain: {' → '.join(path.stages)}",
                    f"- Terminal impact: **{path.severity}** ({origin})",
                ]
            )
            if path.hypotheses:
                lines.append(f"- Introduced by: {', '.join(path.hypotheses)}")
            if path.business_severity and path.criticality is not None:
                lines.append(
                    f"- Business impact: tier {path.criticality} "
                    f"(ranks as **{path.business_severity}**; from the CMDB import)"
                )
            lines.append(f"- Cheapest break: {_inline(path.cheapest_break or '—')}")
            lines.append("")
            lines.extend(
                [
                    "| Stage | Check | Asset | Severity | Origin | Hypothesis |",
                    "|---|---|---|---|---|---|",
                ]
            )
            for hop in path.hops:
                lines.append(
                    f"| {hop.stage} | {_inline(hop.check_id)} | {_inline(hop.asset)} | "
                    f"{hop.severity} | {hop.origin} | "
                    f"{_inline(hop.hypothesis_id) if hop.hypothesis_id else '—'} |"
                )
            lines.append("")
    if simulation.change is not None:
        change = simulation.change
        direction = "worse" if change.exposure_delta > 0 else "better"
        if change.exposure_delta == 0:
            direction = "unchanged"
        lines.extend([f"### {_t('report.simulation.change', report)}: {_inline(change.name)}", ""])
        if change.description:
            lines.extend([_inline(change.description), ""])
        lines.extend(
            [
                f"- Exposure before: {change.exposure_before} ({change.paths_before} path(s))",
                f"- Exposure after: {change.exposure_after} ({change.paths_after} path(s))",
                f"- Delta: **{change.exposure_delta:+d}** ({direction})",
            ]
        )
        if change.introduced:
            lines.append(
                f"- Paths introduced: {', '.join(_inline(item) for item in change.introduced)}"
            )
        if change.removed:
            lines.append(f"- Paths removed: {', '.join(_inline(item) for item in change.removed)}")
        lines.append("")
    return lines


def _low_confidence_section(report: ReportData) -> list[str]:
    lines = [f"## 10. {_t('report.section.low_confidence', report)}", ""]
    if not report.low_confidence:
        lines.extend(["No observations fell below the confidence threshold.", ""])
        return lines
    lines.extend(
        [
            "These observations are **not confirmed findings**. They fell below the report's "
            "confidence threshold and should be triaged before they are acted on.",
            "",
            "| Id | Title | Asset | Severity | Confidence | Evidence |",
            "|---|---|---|---|---|---|",
        ]
    )
    for finding in report.low_confidence:
        lines.append(
            f"| {finding.id} | {_inline(finding.title)} | {_inline(finding.asset.value)} | "
            f"{finding.severity} | {finding.score.confidence} | "
            f"{', '.join(finding.evidence_refs) or '—'} |"
        )
    lines.append("")
    return lines


def _patch_gap_section(report: ReportData) -> list[str]:
    lines = [f"## 11. {_t('report.section.patch_gap', report)}", ""]
    patch_gap = report.patch_gap
    if patch_gap is None:
        lines.extend(
            [
                "M6 (AI-era signals) did not run in this scan, so no patch-gap section is "
                "reported. An absent section is not a clean result.",
                "",
            ]
        )
        return lines
    known = patch_gap.get("known_vulnerable") or []
    if known:
        lines.extend(["**Known-vulnerable versions:**", ""])
        lines.extend(["| Finding | Asset | CVE |", "|---|---|---|"])
        for item in known:
            lines.append(
                f"| {item.get('finding_id')} | {_inline(item.get('asset'))} | "
                f"{_inline(item.get('cve'))} |"
            )
        lines.append("")
    else:
        lines.extend(["No CVE-correlated findings were recorded.", ""])
    epss = patch_gap.get("epss_top") or []
    if epss:
        lines.extend(["**Top EPSS items:**", ""])
        lines.extend(["| Finding | CVE | EPSS |", "|---|---|---|"])
        for item in epss:
            lines.append(
                f"| {item.get('finding_id')} | {_inline(item.get('cve'))} | "
                f"{_cvss(item.get('epss'))} |"
            )
        lines.append("")
    lines.extend(
        [
            "**Webshell scan:** " + _webshell_line(patch_gap.get("webshell_scan")),
            "",
        ]
    )
    return lines


def _webshell_line(value: object) -> str:
    if value is None:
        return "not run"
    if isinstance(value, dict):
        count = value.get("findings")
        if count is None:
            return "see findings"
        return f"{count} finding(s)"
    return "see findings"


def _appendix(report: ReportData) -> list[str]:
    appendix = report.appendix
    lines = [f"## 12. {_t('report.section.appendix', report)}", ""]
    lines.extend([f"### A. {_t('report.appendix.evidence', report)}", ""])
    if not appendix.evidence:
        lines.extend(["No evidence was captured.", ""])
    for entry in appendix.evidence:
        digest = f" · sha256 `{entry.sha256}`" if entry.sha256 else ""
        lines.append(f"#### {entry.id} · {entry.kind}{digest}")
        lines.append("")
        lines.append(_inline(entry.summary))
        lines.append("")
        if entry.payload:
            rendered_json = "\n".join(_json_lines(entry.payload))
            fence = _fence_for(rendered_json)
            lines.append(f"{fence}json")
            lines.extend(rendered_json.splitlines())
            lines.append(fence)
            lines.append("")
    lines.extend([f"### B. {_t('report.appendix.audit', report)}", ""])
    audit = appendix.audit
    lines.append(
        f"{audit.total_events} event(s) · {audit.blocked_events} blocked · "
        f"{_iso(audit.first_event_at)} → {_iso(audit.last_event_at)}"
    )
    lines.append("")
    if audit.actions:
        lines.extend(["| Action | Count |", "|---|---|"])
        for action, count in sorted(audit.actions.items()):
            lines.append(f"| {action} | {count} |")
        lines.append("")
    lines.extend([f"### C. {_t('report.appendix.out_of_scope', report)}", ""])
    if audit.out_of_scope_events:
        lines.extend(f"- {_inline(event)}" for event in audit.out_of_scope_events)
    else:
        lines.append("No request was refused or discarded for scope reasons.")
    lines.append("")
    lines.extend([f"### D. {_t('report.appendix.false_positives', report)}", ""])
    if appendix.false_positives:
        lines.extend(["| Finding | Title | Status | Reason |", "|---|---|---|---|"])
        for fp_entry in appendix.false_positives:
            lines.append(
                f"| {fp_entry.finding_id} | {_inline(fp_entry.title)} | {fp_entry.status} | "
                f"{_inline(fp_entry.reason)} |"
            )
        lines.append("")
    else:
        lines.extend(["No findings were dropped or merged.", ""])
    lines.extend([f"### F. {_t('report.appendix.state_changes', report)}", ""])
    lines.extend(_state_changes_section(report))
    lines.extend(_intel_section(report))
    lines.extend(_compliance_section(report))
    lines.extend(_detection_validation_section(report))
    lines.extend([f"### E. {_t('report.appendix.glossary', report)}", ""])
    for term, definition in sorted(appendix.glossary.items()):
        lines.append(f"- **{term}**: {_inline(definition)}")
    lines.append("")
    return lines


def _state_changes_section(report: ReportData) -> list[str]:
    """The report-level *state changes* table (S15, REQ-PROOF-013).

    What/where/before/after/restored for every L4 write. A `restored=no` row means the
    target is NOT in its prior state: the row is a repair instruction, and the audit
    trail carries the matching `proof.repair_required` event (REQ-PROOF-010).
    """
    if not report.state_changes:
        return ["No state change was made on any target.", ""]
    lines = [
        "| Change | Kind | Check | Where | Before | After | Restored |",
        "|---|---|---|---|---|---|---|",
    ]
    for change in report.state_changes:
        if change.restored and change.restore_verified:
            restored = "yes (verified)"
        elif change.restored:
            restored = "yes"
        else:
            restored = "**NO — repair required**"
        lines.append(
            f"| {_inline(change.change_id)} | {_inline(change.kind)} | {_inline(change.check)} | "
            f"{_inline(change.where)} | {_inline(change.before) if change.before else '—'} | "
            f"{_inline(change.after) or '—'} | {restored} |"
        )
    lines.append("")
    unrestored = [change for change in report.state_changes if not change.restored]
    if unrestored:
        lines.append(
            f"**{len(unrestored)} change(s) were not restored.** Treat each row above as a "
            "repair instruction: restore the recorded before-value manually, then verify. "
            "The audit trail carries the matching `proof.repair_required` event."
        )
        lines.append("")
    return lines


def _intel_section(report: ReportData) -> list[str]:
    """Threat-intel freshness: the data this report's conclusions rest on (S18).

    "No KEV match" means something different against a catalogue from yesterday and one from
    last quarter, so the freshness of every feed travels with the report rather than being
    something a reader has to go and look up (REQ-INTEL-001). A feed that was never ingested is
    rendered as *not ingested* — not as fresh and not as stale — because the three states call
    for different operator action.
    """
    intel = report.intel
    if intel is None:
        return []
    lines: list[str] = [f"### G. {_t('report.appendix.intel', report)}", ""]
    lines.append(
        f"Snapshot taken {_iso(intel.generated_at)}"
        + (" — **an ingested feed is past its freshness TTL**." if intel.stale else ".")
    )
    if intel.warnings:
        # WP-21 (REQ-INTEL-006): a stale severity-contributing feed is a **warning**, not
        # an error. The report is valid and the scan completed; what a reader must not do is
        # trust the severity ordering without knowing the data behind it is old.
        lines.append("")
        lines.append("> **Warning — feed freshness SLA.**")
        for warning in intel.warnings:
            lines.append(f"> {_inline(warning)}.")
        lines.append("")
    if intel.severity_feeds:
        lines.append(
            "Severity-contributing feeds: "
            + ", ".join(f"`{_inline(kind)}`" for kind in intel.severity_feeds)
            + "."
        )
    if intel.missing:
        lines.append(
            "Not ingested (a match against data nobody loaded is not a clean result): "
            + ", ".join(f"`{kind}`" for kind in intel.missing)
            + "."
        )
    lines.append("")
    if intel.feeds:
        lines.extend(
            [
                "| Feed | Source | Version | Ingested | Age | TTL | State | Integrity | Rows |",
                "|---|---|---|---|---|---|---|---|---|",
            ]
        )
        for feed in intel.feeds:
            if not feed.imported_at:
                state = "not ingested"
            elif feed.stale:
                state = "**stale**"
            else:
                state = "fresh"
            age = f"{feed.age_hours:.1f} h" if feed.age_hours is not None else "—"
            ttl = f"{feed.ttl_hours:.0f} h" if feed.ttl_hours else "—"
            integrity = (
                f"verified ({_inline(feed.verification)})"
                if feed.verified and feed.verification
                else ("verified" if feed.verified else "not verified")
            )
            lines.append(
                f"| `{_inline(feed.kind)}` | {_inline(feed.source) if feed.source else '—'} | "
                f"{_inline(feed.version) if feed.version else '—'} | "
                f"{_iso(feed.imported_at)} | {age} | {ttl} | {state} | {integrity} | "
                f"{feed.record_count} |"
            )
        lines.append("")
    if intel.providers:
        opted_in = ", ".join(f"`{name}`" for name in intel.opted_in_providers) or "none"
        lines.append(
            "Third-party providers enabled for this deployment: "
            + ", ".join(f"`{name}`" for name in intel.providers)
            + f". Strictly opt-in providers in use: {opted_in}."
        )
        lines.append("")
    return lines


def _detection_validation_section(report: ReportData) -> list[str]:
    """Appendix I: the purple-team detection test this scan performed (S24).

    Two things a reader must be able to check without trust: the **nonce** every emitted
    payload carried (so an artifact in their SIEM can be matched to this run), and the
    **Sigma verdict** per action — whether a shipped hunt rule matches the telemetry the
    test produces. A rule-miss is stated as what it is: a gap in the rule set, not a clean
    result (REQ-VALID-003/004).
    """
    block = report.detection_validation
    if block is None:
        return []
    lines: list[str] = [f"### I. {_t('report.appendix.validation', report)}", ""]
    lines.append(
        f"Campaign `{_inline(block.campaign)}` ran as a detection test — **designed to be "
        f"seen**, emitted verbatim under the ordinary rate limit, inside the coordinated "
        f"window below. Run nonce `{_inline(block.nonce)}` is carried by every payload and "
        "every artifact this run produced."
    )
    lines.append("")
    if block.window:
        lines.append(
            f"- Detection window: {_inline(str(block.window.get('starts_at', '—')))} .. "
            f"{_inline(str(block.window.get('ends_at', '—')))} "
            f"(coordinated with {_inline(str(block.window.get('coordinator', '—')))})"
        )
    else:
        lines.append("- Detection window: _none recorded_")
    if block.stopped_at:
        lines.append(
            f"- Auto-stopped at {_iso(block.stopped_at)}: the window closed and the "
            "remaining actions were skipped rather than fired outside it."
        )
    lines.append("")
    if block.actions:
        lines.extend(
            [
                "| Action | Technique | Tactic | Severity | Sigma | Matching rules | Nonce |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for action in block.actions:
            rules = ", ".join(_inline(rule) for rule in action.sigma_rules) or "—"
            verdict = action.sigma_verdict or "not aligned"
            lines.append(
                f"| `{_inline(action.action)}` | {_inline(action.technique)} | "
                f"{_inline(action.tactic_label or action.tactic)} | {_inline(action.severity)} | "
                f"{_inline(verdict)} | {rules} | `{_inline(action.nonce)}` |"
            )
        lines.append("")
    if block.rule_misses:
        lines.append(
            f"Rule-miss: the shipped hunt library has no rule matching the telemetry of "
            f"{', '.join(_inline(item) for item in block.rule_misses)} "
            f"({block.rules_evaluated} rule(s) evaluated). A rule-miss is a gap in the rule "
            "set, not a failure of the test."
        )
        lines.append("")
    return lines


def _compliance_section(report: ReportData) -> list[str]:
    """``### H. Compliance framework coverage`` (S22, REQ-TRUST-001).

    One block per configured framework. A control is ``fail`` (a mapped check found
    something), ``pass`` (mapped checks ran and found nothing) or ``gap`` (its checks
    did not run — never a clean result). The framework's own control count is stated
    beside the assessed one, so the unmapped remainder is an explicit gap in the report
    rather than something a reader has to know the framework to notice.
    """
    if not report.compliance:
        return []
    lines: list[str] = [f"### H. {_t('report.appendix.compliance', report)}", ""]
    lines.extend(
        [
            "A control is **fail** (a mapped check found something), **pass** (mapped checks "
            "ran and found nothing) or **gap** (its checks did not run in this scan — not a "
            "clean result). Technical findings are evidence about a control's operation; "
            "they are not, by themselves, proof of conformity with a management-system "
            "standard.",
            "",
        ]
    )
    for framework in report.compliance:
        lines.extend(
            [
                f"#### {framework.name} ({framework.edition}) — map v{framework.map_version}",
                "",
                f"- Mapped: {framework.mapped} of {framework.total_controls} "
                f"{framework.kind}s the framework defines — **{framework.unmapped} "
                f"{framework.kind}(s) are outside ARACHNE's check catalogue** and cannot be "
                "assessed by any scan.",
                f"- This scan: {framework.count('fail')} fail · {framework.count('pass')} pass · "
                f"{framework.count('gap')} gap (mapped checks that did not run).",
                "",
                "| Control | Title | Status | Findings | Checks not run |",
                "|---|---|---|---|---|",
            ]
        )
        for row in framework.controls:
            if row.status == "fail":
                status = "**fail**"
            elif row.status == "gap":
                status = "gap"
            else:
                status = "pass"
            not_run = ", ".join(row.checks_not_run) or "—"
            lines.append(
                f"| {row.control} | {_inline(row.title)} | {status} | "
                f"{', '.join(row.findings) or '—'} | {_inline(not_run)} |"
            )
        gaps = [row for row in framework.controls if row.status == "gap"]
        if gaps:
            lines.append("")
            lines.append(
                "**Explicit gaps.** The following "
                f"{len(gaps)} control(s) have mapped checks that did not run in this scan; "
                "no conclusion about them can be drawn from this report:"
            )
            for row in gaps:
                lines.append(
                    f"- {row.control} {_inline(row.title)} — not run: "
                    f"{', '.join(f'`{check}`' for check in row.checks_not_run) or 'all checks'}"
                )
        lines.append("")
    return lines


def _json_lines(payload: object) -> list[str]:
    import json

    return json.dumps(payload, indent=2, sort_keys=True, default=str).splitlines()


def _diff_section(report: ReportData) -> list[str]:
    diff = report.diff
    if diff is None:
        return []
    counts = diff.counts
    lines = [
        f"### Change since scan {_inline(diff.scan_a)}",
        "",
        f"{counts['new']} new · {counts['fixed']} fixed · "
        f"{counts['regressed']} regressed · {counts['recurring']} recurring · "
        f"{counts.get('suppressed', 0)} suppressed",
        "",
    ]
    for label, keys in (
        ("New", diff.new),
        ("Fixed", diff.fixed),
        ("Regressed", diff.regressed),
        ("Suppressed by rule", diff.suppressed),
    ):
        if keys:
            lines.append(f"- **{label}:** " + ", ".join(_inline(key) for key in keys))
    if diff.suppressed or diff.suppression_version:
        # REQ-QUAL-002: a suppression is never silent. Even a zero count is stated when rules
        # are in force, so "nothing disappeared" is something the report says rather than
        # something a reader has to infer.
        lines.append(
            f"- {len(diff.suppressed)} finding(s) silenced by suppressions "
            f"v{diff.suppression_version}; they are excluded from *new*, never from the record."
        )
    if lines[-1] != "":
        lines.append("")
    lines.extend(_severity_trend(diff.severity_trend))
    return lines


def _severity_trend(trend: dict[str, dict[str, int]]) -> list[str]:
    """The F-06-05 trend table: severity counts over the compared scans ."""
    if len(trend) < 2:
        return []
    labels = list(trend)
    lines = [
        "| Severity | " + " | ".join(_inline(label) for label in labels) + " |",
        "|---|" + "---|" * len(labels),
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(
            f"| {severity} | "
            + " | ".join(str(trend[label].get(severity, 0)) for label in labels)
            + " |"
        )
    lines.extend(["", f"Showing {len(labels)} consecutive scan(s) of this target.", ""])
    return lines


def render_markdown(report: ReportData) -> str:
    """Render ``report`` as the Markdown skeleton."""
    cover = report.cover
    brand = report.branding
    lines: list[str] = []
    if brand.classification:
        lines.extend([f"**{_inline(brand.classification)}**", ""])
    lines.extend([f"# {_inline(cover.title)}", ""])
    if brand.company_name or brand.tagline:
        vendor = " · ".join(part for part in (brand.company_name, brand.tagline) if part)
        lines.extend([f"*{_inline(vendor)}*", ""])
    lines.extend(
        [
            f"{_t('report.label.scan', report)}: {cover.scan_id} · {_date(cover.generated_at)} · "
            f"{_inline(brand.product_name)} {cover.arachne_version or '(version unknown)'} "
            f"(modules {', '.join(cover.module_versions) or '(none)'}) · engine: {cover.engine}",
        ]
    )
    authorization = cover.authorization
    if authorization:
        attested_by = authorization.get("attested_by") or "(unknown)"
        scope_text = (
            ", ".join(str(item) for item in authorization.get("allowed_targets") or ())
            or "(scope not recorded)"
        )
        expires = authorization.get("expires_at") or "no expiry"
        lines.append(
            f"{_t('report.label.authorization', report)}: attested by {_inline(attested_by)} "
            f"(scope: {_inline(scope_text)}; expires {_inline(expires)})"
        )
    else:
        lines.append("Authorization: no attestation recorded for this scan")
    lines.extend(["", f"## 1. {_t('report.section.executive_summary', report)}", ""])
    lines.extend(_residue_warning(report))
    summary = report.executive_summary
    for paragraph in summary.paragraphs:
        lines.extend([_inline(paragraph), ""])
    lines.extend(_counts_table(summary.counts))
    lines.append("")
    lines.append(
        f"Low-confidence observations (reported separately, not confirmed): "
        f"{summary.low_confidence_count}"
    )
    lines.append("")
    lines.extend(_diff_section(report))
    lines.extend(_scope_section(report))
    lines.extend(_assets_section(report))
    for number in range(4, 9):
        severity = SEVERITY_ORDER[number - 4]
        lines.extend(
            _severity_section(number, severity, report.findings_by_severity(severity), report)
        )
    lines.extend(_attack_paths_section(report))
    lines.extend(_low_confidence_section(report))
    lines.extend(_patch_gap_section(report))
    lines.extend(_appendix(report))
    # S28: the what-if annex, after everything the scan established (REQ-SIM-004). Absent
    # unless an operator asked for a simulation, so an ordinary report is unchanged.
    lines.extend(_simulation_section(report))
    lines.extend(_branding_footer(report))
    return "\n".join(lines).rstrip() + "\n"


def _branding_footer(report: ReportData) -> list[str]:
    """The white-label footer (S14); empty for the neutral default presentation."""
    brand = report.branding
    if not brand.is_customised():
        return []
    lines = ["", "---", ""]
    if brand.footer_text:
        lines.extend([_inline(brand.footer_text), ""])
    attribution = " · ".join(part for part in (brand.contact, brand.classification) if part)
    if attribution:
        lines.extend([f"*{_inline(attribution)}*", ""])
    if brand.show_arachne_branding:
        lines.append(f"*Report produced with {_inline(brand.product_name)}.*")
    elif brand.company_name:
        lines.append(f"*{_inline(brand.company_name)}.*")
    return lines
