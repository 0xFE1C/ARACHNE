"""The Analyzer: one interface, two engines (docs/spec/02- §2.3, docs/spec/04-).

``analyze(candidates, context) -> list[Analysis]`` is the contract both engines implement.
:class:`~arachne.analyzer.engine.HeuristicEngine` is the default engine in this build — the
whole non-AI stack of ``docs/spec/04-``: rules, signature templates, correlation, scoring,
confidence and explanation synthesis. The AI engine lands in S9 and plugs into the same
interface and the same ``Analysis`` schema (F-03-01..05, G-05).

The package boundary matters: the analyzer imports ``arachne.core`` and ``arachne.data``'s
DTOs, and **never** the module layer or the ORM. `analyzer.handlers` is the single adapter
that turns stored candidate rows into the engine's input, which is what keeps the engine
pure, deterministic and testable without a scan (ADR-090.1/7).

Typical use::

    from arachne.analyzer import HeuristicEngine, ScanContext, analyze_scan

    engine = HeuristicEngine()
    analyses = engine.analyze(candidates, ScanContext(scan_id=1))
"""

from __future__ import annotations

from typing import Any

from arachne.analyzer.conditions import FactSpace, build_facts, parse_expression
from arachne.analyzer.correlation import CorrelationEngine, load_correlation_rules
from arachne.analyzer.engine import (
    AnalysisPolicies,
    AnalysisSummary,
    Analyzer,
    HeuristicEngine,
    select_engine,
    summarize,
)
from arachne.analyzer.fp import FpTuner, HttpVerifier, NullVerifier, classify, load_fp_filters
from arachne.analyzer.model import (
    SEVERITY_ORDER,
    Analysis,
    Candidate,
    EvidenceFact,
    Provenance,
    Remediation,
    RuleTraceEntry,
    ScanContext,
    ScoreBreakdown,
    VerificationOutcome,
    severity_rank,
)
from arachne.analyzer.narrative import NarrativeSynthesizer, load_narrative_templates
from arachne.analyzer.remediation import load_remediation_catalog
from arachne.analyzer.rules import RuleEngine, load_rule_set
from arachne.analyzer.scoring import ScoringModel, load_vector_table
from arachne.analyzer.signatures import SignatureLibrary

#: The adapter layer's public names, resolved lazily (PEP 562).
#:
#: ``analyzer.handlers`` imports ``arachne.data.analysis_store``, which imports
#: ``arachne.analyzer.model`` — so an eager ``from arachne.analyzer.handlers import ...`` here
#: makes ``import arachne.data.analysis_store`` fail with a partially-initialised-module error
#: depending on which side of the cycle Python entered first (a user or plugin importing the
#: store before the analyzer hits it). Resolving these five names on first attribute access
#: keeps the documented surface — ``from arachne.analyzer import build_analysis_handlers``
#: still works — without making the package root a cycle member.
_LAZY_HANDLER_EXPORTS: frozenset[str] = frozenset(
    {
        "build_analysis_handlers",
        "candidate_from_record",
        "create_correlation_engine",
        "create_heuristic_engine",
        "make_analysis_handler",
        "make_correlation_handler",
    }
)


def __getattr__(name: str) -> Any:
    """Resolve the adapter-layer names on first use (see ``_LAZY_HANDLER_EXPORTS``)."""
    if name in _LAZY_HANDLER_EXPORTS:
        from arachne.analyzer import handlers as _handlers

        return getattr(_handlers, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "SEVERITY_ORDER",
    "Analysis",
    "AnalysisPolicies",
    "AnalysisSummary",
    "Analyzer",
    "Candidate",
    "CorrelationEngine",
    "EvidenceFact",
    "FactSpace",
    "FpTuner",
    "HeuristicEngine",
    "HttpVerifier",
    "NarrativeSynthesizer",
    "NullVerifier",
    "Provenance",
    "Remediation",
    "RuleEngine",
    "RuleTraceEntry",
    "ScanContext",
    "ScoreBreakdown",
    "ScoringModel",
    "SignatureLibrary",
    "VerificationOutcome",
    "build_analysis_handlers",
    "build_facts",
    "candidate_from_record",
    "classify",
    "create_correlation_engine",
    "create_heuristic_engine",
    "load_correlation_rules",
    "load_fp_filters",
    "load_narrative_templates",
    "load_remediation_catalog",
    "load_rule_set",
    "load_vector_table",
    "make_analysis_handler",
    "make_correlation_handler",
    "parse_expression",
    "select_engine",
    "severity_rank",
    "summarize",
]
