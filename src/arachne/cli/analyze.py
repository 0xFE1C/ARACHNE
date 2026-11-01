"""``arachne analyze`` — inspect (or re-run) the analysis of a stored scan (F-05-*, F-07-01).

Two uses, one command:

``arachne analyze --scan ID``
    Re-run the analyzer over the scan's stored candidates and print what it decides —
    severity, confidence, CWE, score, narrative, remediation and the rule trace. It writes
    **nothing**: it is the operator's "what would the current rule corpus say about this
    scan?" query, and it is deliberately separate from the scan's own ``analysis`` step so a
    rule change can be evaluated without touching the stored findings.

``arachne analyze --scan ID --show``
    Print the analyses the scan already stored, without re-running anything.

``--engine ai`` (or ``hybrid`` with a provider configured) re-runs with the AI engine, which
anchors on the heuristic verdict and annotates it (docs/spec/03- §4). It performs provider
calls, so it is explicit: without a configured provider it fails rather than silently falling
back (F-03-03).

Both read-only modes are deterministic for the heuristic engine (a pure function of the stored
evidence and the data files), which is what makes the output safe to diff between rule
revisions. AI mode is not deterministic; its provenance says so.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

import typer

from arachne.analyzer.engine import Analyzer, severity_histogram, summarize
from arachne.analyzer.handlers import (
    CandidateMetadata,
    candidates_from_store,
    create_heuristic_engine,
    metadata_map,
)
from arachne.analyzer.model import Analysis, ScanContext
from arachne.core.config import get_settings
from arachne.core.errors import ConfigurationError
from arachne.data.analysis_store import SqlAnalysisStore, analysis_from_log
from arachne.data.finding_store import SqlFindingStore
from arachne.data.services import build_services

__all__ = ["analyze_command", "render_analyses", "render_analysis"]


def analyze_command(
    scan: Annotated[int, typer.Option("--scan", "-s", help="Scan id to analyse.")],
    stored: Annotated[
        bool,
        typer.Option("--show", help="Show the analyses the scan stored instead of re-running."),
    ] = False,
    engine_name: Annotated[
        str | None,
        typer.Option(
            "--engine",
            help=(
                "Engine for the preview: heuristic (default), ai, or hybrid. 'ai' performs "
                "provider calls and needs a configured provider."
            ),
        ),
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Analyse a stored scan's candidates with the current corpus."""
    services = build_services(get_settings())
    try:
        analyses_store = SqlAnalysisStore(services.session_factory)
        if stored:
            rows = analyses_store.list_analyses(scan)
            if not rows:
                typer.echo(f"scan {scan}: no stored analyses (did its analysis step run?)")
                raise typer.Exit(code=1)
            if json_output:
                typer.echo(_json([row.to_dict() for row in rows]))
                return
            _emit_stored(rows)
            return

        findings = SqlFindingStore(services.session_factory)
        metadata: dict[str, CandidateMetadata] = metadata_map(services.registry)
        candidates = candidates_from_store(findings, scan, metadata, only_candidates=False)
        if not candidates:
            typer.echo(f"scan {scan}: no candidate findings to analyse")
            raise typer.Exit(code=1)
        engine = _resolve_engine(services.settings, engine_name)
        config = services.settings.analysis
        context = ScanContext(
            scan_id=scan,
            engine=engine.name,
            asset_criticality=config.criticality_map(),
            fp=analyses_store.feedback_stats(),
            can_verify=False,
        )
        results = _run_engine(engine, candidates, context)
        summary = summarize(results, candidates, context, minimum_confidence=config.min_confidence)
        if json_output:
            typer.echo(
                _json(
                    {
                        "scan_id": scan,
                        "engine": engine.name,
                        "summary": summary.to_stats(),
                        "analyses": [analysis.to_dict() for analysis in results],
                    }
                )
            )
            return
        typer.echo(
            f"scan {scan}: {summary.analyzed} finding(s), {summary.dropped} dropped, "
            f"severities {dict(summary.severities)} on engine {engine.name} "
            "(read-only preview — nothing was written)"
        )
        typer.echo(render_analyses(results))
    finally:
        services.close()


def _resolve_engine(settings: Any, engine_name: str | None) -> Analyzer:
    """The preview's engine: heuristic by default, AI when configured and asked for."""
    from arachne.ai.engine import build_ai_engine

    requested = (engine_name or "heuristic").lower()
    if requested == "heuristic":
        return create_heuristic_engine(settings)
    ai = build_ai_engine(settings, heuristic=create_heuristic_engine(settings))
    if requested == "ai" and ai is None:
        raise ConfigurationError(
            "no AI provider is configured; set ARACHNE_AI_CONFIG or ARACHNE_AI_BASE_URL/"
            "ARACHNE_AI_MODEL, or use --engine heuristic"
        )
    if requested in {"ai", "hybrid"} and ai is not None:
        return ai
    if requested == "hybrid":
        return create_heuristic_engine(settings)
    raise ConfigurationError(f"unknown engine {requested!r}; expected heuristic, ai or hybrid")


def _run_engine(engine: Analyzer, candidates: Any, context: ScanContext) -> tuple[Analysis, ...]:
    """Run the engine, driving the AI engine's async form when it has one."""
    analyze_async = getattr(engine, "analyze_async", None)
    if callable(analyze_async):
        return tuple(asyncio.run(analyze_async(candidates, context)))
    return tuple(engine.analyze(candidates, context))


def _emit_stored(rows: Any) -> None:
    analyses = [analysis_from_log(row) for row in rows]
    rendered = [item for item in analyses if item is not None]
    typer.echo(f"{len(rendered)} stored analysis(ies); severities {severity_histogram(rendered)}")
    typer.echo(render_analyses(rendered))


def render_analyses(analyses: Any) -> str:
    """One block per analysis, in input order."""
    blocks = [render_analysis(analysis) for analysis in analyses]
    return "\n\n".join(blocks)


def render_analysis(analysis: Analysis) -> str:
    """The human-readable form of one analysis (severity, score, narrative, remediation)."""
    score = analysis.score
    lines = [
        f"[{analysis.severity.upper():8}] {analysis.title}",
        f"  asset:      {analysis.asset or '(unknown)'}"
        + (f"   check: {analysis.check_id}" if analysis.check_id else ""),
        f"  confidence: {analysis.confidence}/100"
        + (f"   cwe: {analysis.cwe}" if analysis.cwe else "")
        + (f"   cve: {analysis.cve}" if analysis.cve else "")
        + (f"   status: {analysis.status}" if analysis.verdict != "analyzed" else ""),
        f"  score:      cvss {score.cvss_base:.1f}"
        + (f" ({score.cvss_vector})" if score.cvss_vector else "")
        + f"   owasp: {score.owasp_risk}"
        + (f"   epss: {score.epss}" if score.epss is not None else ""),
        f"  rules:      {', '.join(analysis.provenance.rule_ids) or '(none)'}"
        + (f"   signatures: {', '.join(analysis.signatures)}" if analysis.signatures else ""),
        f"  engine:     {analysis.provenance.engine}"
        + (
            f" (provider {analysis.provenance.provider}, model {analysis.provenance.model})"
            if analysis.provenance.provider
            else ""
        )
        + (
            f"   prompt: {analysis.provenance.prompt_template or '(none)'}"
            if analysis.provenance.engine == "ai"
            else ""
        ),
        f"  narrative:  {analysis.narrative}",
        f"  remediate:  {analysis.remediation.id} — {analysis.remediation.summary}",
    ]
    if analysis.provenance.fallback:
        lines.append(f"  fallback:   {analysis.provenance.fallback}")
    if analysis.risk_notes:
        lines.append(f"  notes:      {analysis.risk_notes}")
    if analysis.verdict != "analyzed":
        lines.append(f"  verdict:    {analysis.verdict} ({analysis.drop_reason or 'no reason'})")
    return "\n".join(lines)


def _json(payload: Any) -> str:
    import json

    return json.dumps(payload, indent=2, default=str)
