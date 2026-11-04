"""Service-level objectives as code: definitions, the metric contract, and the burn alerts.

The problem this module solves is narrow and specific. ARACHNE already exposes metrics
(REQ-OPS-003); what it did not have was a *number an operator can be held to*, and a rule
that fires before the number is missed. REQ-OPS-007 asks for three things — definitions with
a target, a window and a measurement query; fast and slow error-budget burn alerts; and a
contract test proving the definitions name metrics the endpoint really exposes.

Why the artefacts live in the repository, not in a dashboard:

* **A dashboard is not a decision.** A target, a window and the query that measures them can
  be reviewed, diffed and tested. A panel in someone's Grafana cannot.
* **The alert rules are generated, not typed.** :func:`render_alert_rules` derives both burn
  alerts from the definition's own query, so an SLO whose denominator changed cannot leave
  its alert measuring the old one. ``--check`` fails when the committed rules file and the
  definitions disagree, exactly as the coverage ledger and the generated clients do.
* **The metric contract is machine-checked.** :func:`validate_slos` parses the PromQL the
  definitions contain and resolves every metric name and every label against
  :data:`arachne.core.metrics.METRIC_FAMILIES` — the declaration the endpoint renders from. A
  definition naming a metric nobody exposes is a green dashboard over nothing, and this is
  the test that refuses it.

Two design notes an operator should know:

* **The threshold bucket is a real bucket.** An SLO expressed as "requests under 500 ms" is
  measured from the histogram's own ``le="0.5"`` series, so the number on the dashboard and
  the number the budget is spent against are the same number.
* **Burn rate is expressed against the objective window.** A fast burn (14.4x, one hour) spends
  2 % of a 30-day budget; a slow burn (6x, six hours) spends 5 %. Those are the multi-window
  rates the SRE workbook recommends, and they are constants here so a definition cannot pick
  a threshold that quietly never fires.

Usage::

    python -m arachne.ops.slo --check        # the contract test + the generated-rules check
    python -m arachne.ops.slo --render       # rewrite the alert rules from the definitions
    python -m arachne.ops.slo --json         # the definitions and their budget arithmetic
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import typer
import yaml

from arachne.core.metrics import (
    METRIC_FAMILIES,
    MetricFamily,
    status_class,
)

__all__ = [
    "DEFAULT_ALERT_RULES",
    "DEFAULT_SLO_DIR",
    "FAST_BURN",
    "SLO",
    "SLOW_BURN",
    "BurnPolicy",
    "Finding",
    "MetricReference",
    "load_slos",
    "metric_references",
    "render_alert_rules",
    "validate_slos",
]

#: Repository-relative locations of the artefacts this module owns.
DEFAULT_SLO_DIR: Final = Path("deploy/observability/slos")
DEFAULT_ALERT_RULES: Final = Path("deploy/observability/alerts/arachne-slo-burn.yaml")
DEFAULT_DASHBOARD: Final = Path("deploy/observability/dashboards/arachne-slo.json")

#: Burn-rate thresholds and their evaluation windows, as (rate, lookback, for, severity).
#: 14.4x over 1 h spends 2 % of a 30-day budget; 6x over 6 h spends 5 %.
FAST_BURN: Final = (14.4, "1h", "2m", "page")
SLOW_BURN: Final = (6.0, "6h", "15m", "ticket")

_WINDOW_PLACEHOLDER: Final = "{{window}}"

#: A PromQL identifier (metric or label name).
_IDENTIFIER: Final = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
#: A label-matcher block, keeping its content for the label check.
_MATCHER_BLOCK: Final = re.compile(r"\{([^{}]*)\}")
#: A range selector, e.g. ``[5m]``.
_RANGE_SELECTOR: Final = re.compile(r"\[[^\[\]]*\]")
#: An aggregation grouping clause, e.g. ``by (method)``.
_GROUPING_CLAUSE: Final = re.compile(
    r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^()]*\)"
)
#: One label matcher: ``name``, operator, quoted value.
_LABEL_MATCHER: Final = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(!=|=~|!~|=)\s*"((?:[^"\\]|\\.)*)"')
#: PromQL words that are not metric names.
_KEYWORDS: Final = frozenset(
    {
        "and",
        "at",
        "bool",
        "by",
        "end",
        "group_left",
        "group_right",
        "ignoring",
        "inf",
        "Inf",
        "NaN",
        "nan",
        "offset",
        "on",
        "or",
        "start",
        "unless",
        "without",
    }
)

#: Histogram series suffixes; the family they belong to is the name without the suffix.
_HISTOGRAM_SUFFIXES: Final = ("_bucket", "_count", "_sum")

#: The statuses ``core/lifecycle.py`` counts a *finished* scan under, and therefore the
#: vocabulary the scan-completion indicator may select on. This is asserted against the
#: call sites in ``core/lifecycle.py`` by ``tests/unit/test_slo_contract.py``: the pair is a
#: claim about another module, so the test reads that module rather than trusting this set.
SCAN_OUTCOMES: Final = frozenset({"completed", "failed"})


def _bucket_label(value: float) -> str:
    """Format a histogram bound the way the exposition format prints ``le``."""
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(float(value))


def _number(value: float) -> str:
    """A short, stable rendering for a threshold in a rule expression."""
    return f"{value:.6g}"


def _status_classes() -> frozenset[str]:
    """The status labels the API middleware can emit, derived from the classifier itself."""
    return frozenset(status_class(code) for code in range(100, 600))


#: Label vocabularies where a *closed* set is knowable from code, so a definition selecting a
#: value the deployment never emits is a contract failure rather than a typo nobody notices.
#: ``None`` means "this label takes an open set of values" (a method name, a project id) and
#: only the label's existence is checked.
def _label_vocabulary(family: MetricFamily, label: str) -> frozenset[str] | None:
    if label == "le":
        if not family.buckets:
            return None
        return frozenset(_bucket_label(bound) for bound in family.buckets)
    if family.name == "arachne_api_requests_total" and label == "status":
        return _status_classes()
    if family.name == "arachne_scans_total" and label == "status":
        return SCAN_OUTCOMES
    return None


@dataclass(frozen=True, slots=True)
class MetricReference:
    """One metric a definition names: the series, and the matchers applied to it."""

    name: str
    labels: Mapping[str, str] = field(default_factory=dict)

    @property
    def family_name(self) -> str:
        """The declared family this reference resolves to (``_bucket``/``_count``/``_sum``)."""
        for suffix in _HISTOGRAM_SUFFIXES:
            if self.name.endswith(suffix):
                return self.name[: -len(suffix)]
        return self.name

    @property
    def is_bucket(self) -> bool:
        return self.name.endswith("_bucket")

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "labels": dict(self.labels)}


@dataclass(frozen=True, slots=True)
class Finding:
    """One way a definition fails the contract."""

    code: str
    slo: str
    detail: str

    def __str__(self) -> str:
        return f"{self.slo}: {self.code}: {self.detail}"


@dataclass(frozen=True, slots=True)
class BurnPolicy:
    """A burn-rate alert derived from an objective."""

    severity: str
    threshold: float
    lookback: str
    for_duration: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "threshold": self.threshold,
            "lookback": self.lookback,
            "for": self.for_duration,
        }


@dataclass(frozen=True, slots=True)
class SLO:
    """One service-level objective, as defined on disk."""

    id: str
    title: str
    service: str
    owner: str
    description: str
    target: float
    window: str
    sli_query: str
    runbook_doc: str
    runbook_section: str
    extra: Mapping[str, str] = field(default_factory=dict)

    @property
    def error_budget_ratio(self) -> float:
        """The fraction of events the objective allows to be bad."""
        return 1.0 - self.target

    @property
    def burn_policies(self) -> tuple[BurnPolicy, ...]:
        return tuple(
            BurnPolicy(
                severity=severity, threshold=threshold, lookback=lookback, for_duration=for_d
            )
            for threshold, lookback, for_d, severity in (FAST_BURN, SLOW_BURN)
        )

    @property
    def runbook_anchor(self) -> str:
        """The runbook URL an alert annotation carries (a heading anchor, GitHub's slug rule)."""
        slug = re.sub(r"[^a-z0-9 -]", "", self.runbook_section.lower())
        return f"{self.runbook_doc}#{slug.replace(' ', '-')}"

    def query(self, window: str | None = None) -> str:
        """The measurement query with its window substituted."""
        return self.sli_query.replace(_WINDOW_PLACEHOLDER, window or self.window)

    def sli_recording_name(self, lookback: str) -> str:
        return f"arachne:slo_{_rule_slug(self.id)}:sli_{lookback}"

    def burn_recording_name(self, lookback: str) -> str:
        return f"arachne:slo_{_rule_slug(self.id)}:burn_rate_{lookback}"

    def burn_expression(self, policy: BurnPolicy) -> str:
        """``(1 - sli) / error_budget`` — the multiple of the budget the service is spending."""
        return (
            f"(1 - {self.sli_recording_name(policy.lookback)}) / {_number(self.error_budget_ratio)}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "service": self.service,
            "owner": self.owner,
            "target": self.target,
            "window": self.window,
            "error_budget_ratio": round(self.error_budget_ratio, 9),
            "measurement_query": self.query(),
            "metrics": [ref.to_dict() for ref in metric_references(self.query())],
            "runbook": self.runbook_anchor,
            "burns": [policy.to_dict() for policy in self.burn_policies],
        }


def _rule_slug(identifier: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", identifier.lower()).strip("_")


# --------------------------------------------------------------------------- PromQL parsing
def metric_references(expression: str) -> tuple[MetricReference, ...]:
    """Every metric (and its matchers) a PromQL expression names, in source order.

    A focused parser, not a PromQL engine: it strips the constructs that are not metric
    references (range selectors, grouping clauses, call arguments) and reads what is left.
    That is enough for the question the contract test asks — *does this expression name a
    metric and a label the endpoint actually exposes* — and it is exactly as strict as it
    needs to be: anything it cannot recognise as a keyword or a declared metric is reported.
    """
    references: list[MetricReference] = []
    labels_by_name: dict[str, dict[str, str]] = {}
    for match in _MATCHER_BLOCK.finditer(expression):
        before = expression[: match.start()]
        names = _IDENTIFIER.findall(before)
        if not names:
            continue
        name = names[-1]
        labels: dict[str, str] = {}
        for label, _operator, value in _LABEL_MATCHER.findall(match.group(1)):
            labels[label] = value
        references.append(MetricReference(name=name, labels=labels))
        labels_by_name.setdefault(name, {}).update(labels)

    residue = _GROUPING_CLAUSE.sub(" ", _MATCHER_BLOCK.sub(" ", expression))
    residue = _RANGE_SELECTOR.sub(" ", residue)
    seen = {reference.name for reference in references}
    for match in _IDENTIFIER.finditer(residue):
        name = match.group(0)
        if name in _KEYWORDS or name in seen:
            continue
        if residue[match.end() :].lstrip().startswith("("):
            continue  # a function or aggregation call, not a metric
        references.append(MetricReference(name=name, labels=labels_by_name.get(name, {})))
        seen.add(name)
    return tuple(references)


def _family_for(name: str, families: Mapping[str, MetricFamily]) -> MetricFamily | None:
    for suffix in _HISTOGRAM_SUFFIXES:
        if name.endswith(suffix) and name[: -len(suffix)] in families:
            return families[name[: -len(suffix)]]
    return families.get(name)


def validate_slos(
    slos: Iterable[SLO],
    *,
    families: Mapping[str, MetricFamily] | None = None,
    internal: Iterable[str] = (),
) -> tuple[Finding, ...]:
    """The metric contract: every reference resolves to an exposed family and label.

    ``internal`` names the series this repository records itself (the generated burn-rate
    rules), which are legitimately not in :data:`METRIC_FAMILIES`.
    """
    declared = families if families is not None else {f.name: f for f in METRIC_FAMILIES}
    internal_names = set(internal)
    findings: list[Finding] = []
    for slo in slos:
        if not slo.sli_query:
            findings.append(
                Finding("empty-query", slo.id, "the definition has no measurement query")
            )
            continue
        if not 0.0 < slo.target < 1.0:
            findings.append(
                Finding(
                    "bad-target",
                    slo.id,
                    f"target {slo.target!r} is not a fraction between 0 and 1",
                )
            )
        if _WINDOW_PLACEHOLDER not in slo.sli_query:
            findings.append(
                Finding(
                    "no-window-placeholder",
                    slo.id,
                    f"the measurement query does not use {_WINDOW_PLACEHOLDER}, so the burn "
                    "rules cannot be re-windowed from it",
                )
            )
        elif slo.window not in _windows_in(slo.query()):
            findings.append(
                Finding(
                    "window-not-used",
                    slo.id,
                    f"the objective window {slo.window!r} does not appear as a range selector in "
                    "the measurement query",
                )
            )
        for reference in metric_references(slo.query()):
            if reference.name in internal_names:
                continue
            family = _family_for(reference.name, declared)
            if family is None:
                findings.append(
                    Finding(
                        "unknown-metric",
                        slo.id,
                        f"{reference.name!r} is not exposed by /metrics "
                        f"(declared: {', '.join(sorted(declared))})",
                    )
                )
                continue
            allowed = set(family.label_names)
            if reference.is_bucket:
                allowed.add("le")
            for label, value in reference.labels.items():
                if label not in allowed:
                    findings.append(
                        Finding(
                            "unknown-label",
                            slo.id,
                            f"{reference.name!r} has no label {label!r} "
                            f"(declared: {', '.join(sorted(allowed))})",
                        )
                    )
                    continue
                vocabulary = _label_vocabulary(family, label)
                if vocabulary is None:
                    continue
                for alternative in re.split(r"\|", value):
                    if alternative and alternative not in vocabulary:
                        findings.append(
                            Finding(
                                "unknown-label-value",
                                slo.id,
                                f"{reference.name}{{{label}={alternative!r}}} selects a value "
                                "the deployment does not emit "
                                f"(known: {', '.join(sorted(vocabulary))})",
                            )
                        )
    return tuple(findings)


def _windows_in(expression: str) -> set[str]:
    """Every range-selector window the expression uses, e.g. ``{"5m", "1h"}``."""
    return {
        selector[1:-1].strip()
        for selector in _RANGE_SELECTOR.findall(expression)
        if _WINDOW_PLACEHOLDER not in selector
    }


# ------------------------------------------------------------------------------- loading
def _require(mapping: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in mapping:
        msg = f"{where}: missing required key {key!r}"
        raise ValueError(msg)
    return mapping[key]


def load_slos(directory: str | Path = DEFAULT_SLO_DIR) -> tuple[SLO, ...]:
    """Load every definition in ``directory`` (``*.yaml``), ordered by id."""
    root = Path(directory)
    if not root.is_dir():
        msg = f"no SLO directory at {root}"
        raise FileNotFoundError(msg)
    slos: list[SLO] = []
    for path in sorted(root.glob("*.yaml")):
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            msg = f"{path}: expected a mapping, got {type(raw).__name__}"
            raise ValueError(msg)
        where = path.name
        objective = _require(raw, "objective", where)
        indicator = _require(raw, "indicator", where)
        runbook = raw.get("runbook") or {}
        slos.append(
            SLO(
                id=str(_require(raw, "id", where)),
                title=str(_require(raw, "title", where)),
                service=str(_require(raw, "service", where)),
                owner=str(_require(raw, "owner", where)),
                description=str(raw.get("description", "")).strip(),
                target=float(_require(objective, "target", f"{where}:objective")),
                window=str(_require(objective, "window", f"{where}:objective")),
                sli_query=str(_require(indicator, "sli_query", f"{where}:indicator")).strip(),
                runbook_doc=str(runbook.get("doc", "docs/operator-guide.md")),
                runbook_section=str(runbook.get("section", "")),
            )
        )
    identifiers = [slo.id for slo in slos]
    duplicates = {item for item in identifiers if identifiers.count(item) > 1}
    if duplicates:
        msg = f"duplicate SLO ids: {', '.join(sorted(duplicates))}"
        raise ValueError(msg)
    return tuple(sorted(slos, key=lambda slo: slo.id))


# ------------------------------------------------------------------- alert-rule generation
_HEADER: Final = (
    "# ARACHNE error-budget burn alerts — GENERATED, do not edit by hand (REQ-OPS-007).\n"
    "#\n"
    "# `python -m arachne.ops.slo --render` writes this file from the definitions in\n"
    "# deploy/observability/slos/; `--check` fails when the two disagree, so the objective and\n"
    "# the alert that guards it can never drift apart.\n"
    "#\n"
    "# Two rates per objective, the multi-window pair the SRE workbook recommends:\n"
    "#   * fast (14.4x over 1h, 2% of a 30-day budget) — page now.\n"
    "#   * slow (6x over 6h, 5% of a 30-day budget) — a ticket, before it becomes a page.\n"
    "#\n"
    "# Recording rules first: the burn rate is `(1 - sli) / error_budget`, so what the alert\n"
    "# compares against its threshold is the arithmetically meaningful quantity, not a ratio\n"
    "# an operator has to convert in their head at 3 a.m.\n"
)


def render_alert_rules(slos: Sequence[SLO]) -> str:
    """Render the Prometheus rule file for every objective, deterministically."""
    rules: list[dict[str, Any]] = []
    for slo in slos:
        for policy in slo.burn_policies:
            rules.append(
                {
                    "record": slo.sli_recording_name(policy.lookback),
                    "expr": slo.query(policy.lookback),
                    "labels": {"slo": slo.id, "service": slo.service},
                }
            )
            rules.append(
                {
                    "record": slo.burn_recording_name(policy.lookback),
                    "expr": slo.burn_expression(policy),
                    "labels": {"slo": slo.id, "service": slo.service},
                }
            )
        for policy in slo.burn_policies:
            rules.append(
                {
                    "alert": f"ArachneSlo{_camel(slo.id)}{policy.severity.capitalize()}Burn",
                    "expr": (
                        f"{slo.burn_recording_name(policy.lookback)} > {_number(policy.threshold)}"
                    ),
                    "for": policy.for_duration,
                    "labels": {
                        "severity": policy.severity,
                        "slo": slo.id,
                        "service": slo.service,
                        "owner": slo.owner,
                    },
                    "annotations": {
                        "summary": (
                            f"{slo.title}: burning the error budget {_number(policy.threshold)}x "
                            f"faster than allowed over {policy.lookback}"
                        ),
                        "description": (
                            f"The {slo.window} budget of {_number(slo.error_budget_ratio * 100)}% "
                            f"is being spent at {_number(policy.threshold)}x over "
                            f"{policy.lookback}. "
                            f"Objective: {_number(slo.target * 100)}%. Query: {slo.query()}"
                        ),
                        "runbook_url": slo.runbook_anchor,
                    },
                }
            )
    document = {"groups": [{"name": "arachne-slo-burn", "rules": rules}]}
    body: str = yaml.safe_dump(document, sort_keys=False, width=200, default_flow_style=False)
    return _HEADER + body


def _camel(identifier: str) -> str:
    return "".join(part.capitalize() for part in re.split(r"[^a-zA-Z0-9]+", identifier) if part)


def recorded_series(slos: Sequence[SLO]) -> tuple[str, ...]:
    """The series the generated rules define, which the contract test treats as internal."""
    names: list[str] = []
    for slo in slos:
        for policy in slo.burn_policies:
            names.extend(
                (slo.sli_recording_name(policy.lookback), slo.burn_recording_name(policy.lookback))
            )
    return tuple(names)


# ------------------------------------------------------------------------------- default
def _repo_root() -> Path:
    """The checkout root, found from this module's location (``src/arachne/ops/slo.py``)."""
    return Path(__file__).resolve().parents[3]


def default_slo_dir() -> Path:
    return _repo_root() / DEFAULT_SLO_DIR


def default_alert_rules() -> Path:
    return _repo_root() / DEFAULT_ALERT_RULES


def default_dashboard() -> Path:
    return _repo_root() / DEFAULT_DASHBOARD


def _dashboard_panel(slo: SLO, *, kind: str, grid_pos: dict[str, int]) -> dict[str, Any]:
    """One dashboard panel, addressed to the provisioned Prometheus datasource."""
    if kind == "sli":
        title = f"{slo.title} — current"
        targets = [{"expr": slo.query(), "legendFormat": "SLI"}]
        panel_type = "stat"
        extra: dict[str, Any] = {
            "fieldConfig": {
                "defaults": {
                    "unit": "percentunit",
                    "min": 0,
                    "max": 1,
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "red", "value": None},
                            {"color": "green", "value": slo.target},
                        ],
                    },
                },
                "overrides": [],
            },
            "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": ""}},
        }
    else:
        title = f"{slo.title} — budget burn rate"
        targets = [
            {
                "expr": slo.burn_recording_name(policy.lookback),
                "legendFormat": f"{policy.lookback} ({policy.threshold:g}x = {policy.severity})",
            }
            for policy in slo.burn_policies
        ]
        panel_type = "timeseries"
        extra = {
            "fieldConfig": {
                "defaults": {"unit": "none", "custom": {"drawStyle": "line", "fillOpacity": 10}},
                "overrides": [],
            },
            "options": {"legend": {"displayMode": "list", "placement": "bottom"}},
        }
    return {
        "id": len(grid_pos),
        "title": title,
        "type": panel_type,
        "datasource": {"type": "prometheus", "uid": "${datasource}"},
        "gridPos": grid_pos,
        "targets": [
            {**target, "refId": chr(ord("A") + index)} for index, target in enumerate(targets)
        ],
        "description": (
            f"{slo.description} Objective {slo.target * 100:g}% over {slo.window}. "
            f"Runbook: {slo.runbook_anchor}"
        ),
        **extra,
    }


def render_dashboard(slos: Sequence[SLO]) -> str:
    """Render the Grafana dashboard for the objectives, deterministically.

    A dashboard is a shipped artefact like the alert rules, and for the same reason: a panel
    that measures the wrong thing is indistinguishable from a healthy service. Generating it
    from the definitions means the query on the panel *is* the measurement query the objective
    is scored by, and ``--check`` fails when the committed JSON and the definitions disagree.
    """
    panels: list[dict[str, Any]] = []
    for index, slo in enumerate(slos):
        row = index * 2
        panels.append(
            _dashboard_panel(slo, kind="sli", grid_pos={"h": 8, "w": 12, "x": 0, "y": row * 8})
        )
        panels.append(
            _dashboard_panel(slo, kind="burn", grid_pos={"h": 8, "w": 12, "x": 12, "y": row * 8})
        )
    document = {
        "annotations": {"list": []},
        "editable": False,
        "panels": panels,
        "refresh": "1m",
        "schemaVersion": 39,
        "tags": ["arachne", "slo", "generated"],
        "templating": {
            "list": [
                {
                    "name": "datasource",
                    "label": "Prometheus",
                    "type": "datasource",
                    "query": "prometheus",
                }
            ]
        },
        "time": {"from": "now-7d", "to": "now"},
        "timezone": "utc",
        "title": "ARACHNE — service-level objectives",
        "uid": "arachne-slo",
        "version": 1,
    }
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def dashboard_queries(document: str) -> tuple[str, ...]:
    """Every PromQL expression a dashboard's panels name (so it can be contract-checked)."""
    parsed = json.loads(document)
    queries: list[str] = []
    for panel in parsed.get("panels", []):
        for target in panel.get("targets", []):
            expression = target.get("expr")
            if isinstance(expression, str):
                queries.append(expression)
    return tuple(queries)


def check(
    *,
    slo_dir: Path | None = None,
    rules_path: Path | None = None,
    dashboard_path: Path | None = None,
) -> tuple[Finding, ...]:
    """The whole gate: the metric contract and the committed artefacts matching the definitions."""
    directory = slo_dir or default_slo_dir()
    target = rules_path or default_alert_rules()
    slos = load_slos(directory)
    findings = list(validate_slos(slos, internal=recorded_series(slos)))
    expected = render_alert_rules(slos)
    if not target.exists():
        findings.append(Finding("missing-rules", "-", f"no alert rules at {target}"))
    elif target.read_text(encoding="utf-8") != expected:
        findings.append(
            Finding(
                "stale-rules",
                "-",
                f"{target} is not what the definitions generate; run "
                "`python -m arachne.ops.slo --render`",
            )
        )
    dashboard = dashboard_path or default_dashboard()
    expected_dashboard = render_dashboard(slos)
    if not dashboard.exists():
        findings.append(Finding("missing-dashboard", "-", f"no dashboard at {dashboard}"))
    elif dashboard.read_text(encoding="utf-8") != expected_dashboard:
        findings.append(
            Finding(
                "stale-dashboard",
                "-",
                f"{dashboard} is not what the definitions generate; run "
                "`python -m arachne.ops.slo --render`",
            )
        )
    else:
        # The panels' own queries go through the same contract as the definitions.
        for expression in dashboard_queries(expected_dashboard):
            for reference in metric_references(expression):
                if reference.name in set(recorded_series(slos)):
                    continue
                if _family_for(reference.name, {f.name: f for f in METRIC_FAMILIES}) is None:
                    findings.append(
                        Finding(
                            "unknown-metric",
                            "dashboard",
                            f"a panel measures {reference.name!r}, which /metrics does not expose",
                        )
                    )
    return tuple(findings)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m arachne.ops.slo",
        description="Service-level objectives: the metric contract and the burn-rate alerts.",
    )
    parser.add_argument("--slo-dir", type=Path, default=None, help="Directory of definitions.")
    parser.add_argument(
        "--rules", type=Path, default=None, help="The generated Prometheus rules file."
    )
    parser.add_argument("--check", action="store_true", help="Fail on a contract violation.")
    parser.add_argument(
        "--render", action="store_true", help="Rewrite the rules and the dashboard from the SLOs."
    )
    parser.add_argument("--json", action="store_true", help="Print the definitions as JSON.")
    args = parser.parse_args(argv)

    slo_dir = args.slo_dir or default_slo_dir()
    rules_path = args.rules or default_alert_rules()
    try:
        if args.render:
            slos = load_slos(slo_dir)
            rules_path.parent.mkdir(parents=True, exist_ok=True)
            rules_path.write_text(render_alert_rules(slos), encoding="utf-8")
            dashboard = default_dashboard()
            dashboard.parent.mkdir(parents=True, exist_ok=True)
            dashboard.write_text(render_dashboard(slos), encoding="utf-8")
            typer.echo(f"wrote {rules_path} and {dashboard} from {len(slos)} definition(s)")
            return 0
        if args.json:
            slos = load_slos(slo_dir)
            typer.echo(json.dumps([slo.to_dict() for slo in slos], indent=2))
            return 0
        findings = check(slo_dir=slo_dir, rules_path=rules_path)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        return 2
    if findings:
        for finding in findings:
            typer.echo(f"FAIL {finding}", err=True)
        return 1
    slos = load_slos(slo_dir)
    typer.echo(
        f"ok: {len(slos)} SLO(s), every metric reference exposed by /metrics, "
        "burn alerts in step with the definitions"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - the module entry point
    raise SystemExit(main())
