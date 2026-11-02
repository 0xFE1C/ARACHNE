"""Post-exploitation signal hunting: Sigma rules, deception triggers and AD paths.

Three checks that look for signs an attacker is *already inside* — and none of which takes a
post-exploitation action, so building them is defensive:

``m6.sigma-hunt-rules``
    Ships the detection-as-code corpus (Kerberoasting 4769, AS-REP 4768, LSASS access,
    web-worker-to-shell, lateral-movement shares, scheduled-task persistence) and, *only* when
    a deployment grants log access, runs the rules over exported JSON-lines telemetry
    (research ch06#23, and the discovery methods #18/#21/#22 the rules encode).
``m6.deception-listeners``
    The optional deception module of ch06#25: reports which honeytoken fired, when, and from
    where, from a trigger log. Off by default on top of the opt-in check itself.
``m6.ad-attack-path``
    A read-only BloodHound-style path analysis (ch06#19): given an exported graph it finds the
    shortest escalation paths from an ordinary principal to Domain Admin.

The two switch-gated checks (deception, AD path) are ``enabled_by_default=False`` *and* read
local files only; the Sigma check reads nothing until ``ARACHNE_M6_LOG_ACCESS`` is set.
"""

from __future__ import annotations

from collections import deque
from collections.abc import AsyncIterator, Iterable, Mapping
from pathlib import Path
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m6.corpus import M6Corpus
from arachne.modules.m6.feeds import iter_json_events, load_sigma_rules, match_event
from arachne.modules.m6.support import (
    artifact_evidence,
    corpus_for,
    estate_owner,
    finding_cap,
    iter_repo_files,
    local_root,
    m6_candidate,
    read_json,
    read_text,
    skip,
)

__all__ = ["AdAttackPath", "DeceptionListeners", "SigmaHuntRules"]

#: BloodHound-style export file names a repository may carry.
_AD_EXPORT_GLOBS = (
    "*bloodhound*.json",
    "ad-export.json",
    "bloodhound.json",
    "**/bloodhound/*.json",
    "**/ad/*.json",
)

_ALL_KINDS = (
    TargetKind.URL,
    TargetKind.DOMAIN,
    TargetKind.IP,
    TargetKind.GIT,
    TargetKind.CLOUD,
)


def _log_files(ctx: CheckContext, corpus: M6Corpus) -> tuple[tuple[Path, str], ...]:
    """JSON-lines telemetry files: repo-local globs plus the configured log paths."""
    globs = corpus.sigma_log_globs()
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    bases: list[Path] = []
    root = local_root(ctx) if ctx.asset.kind in {"git", "cloud"} else None
    if root is not None and root.exists():
        bases.append(root)
    for configured in ctx.config.m6.log_paths:
        path = Path(configured).expanduser()
        if path.is_file():
            out.append((path, path.name))
            seen.add(path)
        elif path.is_dir():
            bases.append(path)
    for base in bases:
        for path in iter_repo_files(
            base,
            globs,
            max_files=ctx.config.m6.max_repo_files,
            max_bytes=ctx.config.m6.max_file_bytes,
        ):
            if path in seen:
                continue
            seen.add(path)
            try:
                label = path.relative_to(base).as_posix()
            except ValueError:  # pragma: no cover - outside the base
                label = path.name
            out.append((path, label))
    return tuple(out)


# --------------------------------------------------------------------------- Sigma
class SigmaHuntRules(Module):
    """``m6.sigma-hunt-rules`` — ship and (granted) run post-exploit Sigma rules (ch06#23)."""

    metadata = CheckMetadata(
        id="m6.sigma-hunt-rules",
        version="1.0",
        title="Post-exploitation Sigma hunt rules",
        description=(
            "Ships a Sigma rule set for post-exploitation discovery activity — Kerberoasting "
            "(4769), AS-REP roasting (4768), LSASS access, web-worker-to-shell, lateral "
            "movement over admin shares and scheduled-task persistence — so findings stay "
            "SIEM-queryable, and, only when an explicit log-access grant is present, runs the "
            "rules over exported JSON-lines telemetry (research ch06#23). Without the grant it "
            "ingests nothing."
        ),
        module="M6",
        name="sigma-hunt-rules",
        research_ref="ch06#18-23",
        framework=("WSTG-INFO-05", "ATT&CK-T1059", "CWE-778"),
        cwe="CWE-778",
        target_kinds=_ALL_KINDS,
        severity_hint="high",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and asset.kind in {
            "url",
            "domain",
            "host",
            "git",
            "cloud",
        }

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not estate_owner(ctx):
            yield skip(ctx, "estate check: it runs once per scan, on the estate's owner asset")
            return
        rules = load_sigma_rules(ctx.config.m6.sigma_rules)
        yield ctx.info(
            f"{len(rules)} Sigma rule(s) available for deployment",
            detail=(
                "the rule set is shipped with the scan; deploy the emitted rules to the SIEM "
                "or grant ARACHNE_M6_LOG_ACCESS to hunt local telemetry"
            ),
            evidence=(
                artifact_evidence(
                    {
                        "signal": "sigma-ruleset",
                        "family": "hunting",
                        "rule_count": len(rules),
                        "rule_ids": [rule.id for rule in rules],
                        "titles": [rule.title for rule in rules],
                        "log_access": bool(ctx.config.m6.log_access),
                    },
                    source="sigma",
                ),
            ),
        )
        if not ctx.config.m6.log_access:
            yield skip(
                ctx,
                "no log-access grant: set ARACHNE_M6_LOG_ACCESS=true to hunt the exported "
                "telemetry ('Safety')",
            )
            return
        corpus = corpus_for(ctx)
        files = _log_files(ctx, corpus)
        if not files:
            yield skip(ctx, "log access granted but no telemetry files were found")
            return
        produced = 0
        for path, label in files:
            text = read_text(path, limit=ctx.config.m6.max_file_bytes)
            if text is None:
                continue
            for event in iter_json_events(text):
                for rule in rules:
                    if not match_event(rule, event):
                        continue
                    produced += 1
                    yield m6_candidate(
                        ctx,
                        f"Post-exploit activity: {rule.title}",
                        artifact={
                            "signal": "sigma-hit",
                            "family": "hunting",
                            "rule_id": rule.id,
                            "rule_title": rule.title,
                            "level": rule.level,
                            "tags": list(rule.tags),
                            "location": label,
                            "event_id": event.get("EventID") or event.get("event_id"),
                        },
                        cwe="CWE-778",
                        confidence=0.7,
                        detail=f"{label}: {rule.title} ({rule.level}) matched a telemetry event",
                        source=label,
                    )
                    if produced >= finding_cap(ctx):
                        return
                    break
        if not produced:
            yield ctx.clean(
                f"no post-exploit discovery activity in {len(files)} telemetry file(s)",
                detail="the shipped Sigma rules matched no event",
            )


# --------------------------------------------------------------------------- deception
class DeceptionListeners(Module):
    """``m6.deception-listeners`` — honeytoken trigger monitoring (ch06#25, opt-in)."""

    metadata = CheckMetadata(
        id="m6.deception-listeners",
        version="1.0",
        title="Deception / honeytoken trigger monitoring",
        description=(
            "Reports honeytoken or honeypot triggers from a local trigger log — which token "
            "fired, from where and when — so an operator learns of attacker contact that no "
            "vulnerability scan would otherwise see (research ch06#25). Off by default: it is "
            "opt-in and additionally requires ARACHNE_M6_DECEPTION=true."
        ),
        module="M6",
        name="deception-listeners",
        research_ref="ch06#25",
        framework=("WSTG-INFO-05", "ATT&CK-T1078", "CWE-778"),
        cwe="CWE-778",
        target_kinds=_ALL_KINDS,
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        enabled_by_default=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and asset.kind in {
            "url",
            "domain",
            "host",
            "git",
            "cloud",
        }

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not estate_owner(ctx):
            yield skip(ctx, "estate check: it runs once per scan, on the estate's owner asset")
            return
        if not ctx.config.m6.deception:
            yield skip(
                ctx,
                "deception monitoring is off: set ARACHNE_M6_DECEPTION=true to read the "
                "honeytoken trigger log",
            )
            return
        corpus = corpus_for(ctx)
        token_fields = corpus.deception_token_fields()
        source_fields = corpus.deception_source_fields()
        time_fields = corpus.deception_time_fields()
        files = _log_files(ctx, corpus)
        if not files:
            yield skip(ctx, "deception monitoring is on but no trigger log was found")
            return
        produced = 0
        seen_tokens: set[str] = set()
        for path, label in files:
            text = read_text(path, limit=ctx.config.m6.max_file_bytes)
            if text is None:
                continue
            for event in iter_json_events(text):
                token = _first_field(event, token_fields)
                if token is None or token in seen_tokens:
                    continue
                seen_tokens.add(token)
                produced += 1
                yield m6_candidate(
                    ctx,
                    f"Honeytoken triggered: {token}",
                    artifact={
                        "signal": "honeytoken-trigger",
                        "family": "deception",
                        # Named "decoy" rather than "token": a honeytoken is not a secret, but
                        # a field literally named "token" would be redacted at capture time and
                        # the operator would lose which decoy fired.
                        "decoy": token,
                        "source": _first_field(event, source_fields),
                        "at": _first_field(event, time_fields),
                        "location": label,
                    },
                    cwe="CWE-778",
                    confidence=0.8,
                    detail=(
                        f"{label}: honeytoken {token} was triggered"
                        + (
                            f" from {_first_field(event, source_fields)}"
                            if _first_field(event, source_fields)
                            else ""
                        )
                    ),
                    source=label,
                )
                if produced >= finding_cap(ctx):
                    return
        if not produced:
            yield ctx.clean(
                "no honeytoken trigger recorded",
                detail="the deception listeners saw no trigger in the read window",
            )


# --------------------------------------------------------------------------- AD paths
class AdAttackPath(Module):
    """``m6.ad-attack-path`` — read-only BloodHound-style path analysis (ch06#19, opt-in)."""

    metadata = CheckMetadata(
        id="m6.ad-attack-path",
        version="1.0",
        title="Active Directory attack-path analysis",
        description=(
            "Analyses an exported AD graph (BloodHound-style nodes and escalation edges) for "
            "the shortest paths from an ordinary principal to Domain Admin, so a defender can "
            "close the highest-value ones first (research ch06#19). Read-only: it parses a "
            "local export and computes paths; it never authenticates, binds or queries AD. Off "
            "by default (opt-in)."
        ),
        module="M6",
        name="ad-attack-path",
        research_ref="ch06#19",
        framework=("WSTG-CONF-01", "WSTG-ATHZ-03", "CWE-269"),
        cwe="CWE-269",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        enabled_by_default=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and asset.kind in {"git", "cloud"}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        root = local_root(ctx)
        if root is None or not root.exists():
            yield skip(ctx, "no local AD export to analyse (declare a repo:/path target)")
            return
        corpus = corpus_for(ctx)
        graph: Mapping[str, Any] | None = None
        for path in iter_repo_files(root, _AD_EXPORT_GLOBS, max_files=200):
            data = read_json(path)
            if isinstance(data, Mapping) and ("nodes" in data or "edges" in data):
                graph = data
                break
        if graph is None:
            yield skip(
                ctx,
                "no BloodHound-style AD export found (expected a JSON document with "
                "'nodes' and 'edges')",
            )
            return
        paths = _shortest_paths(graph, corpus)
        if not paths:
            yield ctx.clean(
                "no escalation path to Domain Admin in the exported AD graph",
                detail="no non-privileged principal reaches a Domain Admin group",
            )
            return
        for node_path, hops in paths[: finding_cap(ctx)]:
            yield m6_candidate(
                ctx,
                f"AD attack path to Domain Admin: {' > '.join(node_path[:6])}",
                artifact={
                    "signal": "ad-path",
                    "family": "ad",
                    "start": node_path[0],
                    "goal": node_path[-1],
                    "hops": list(hops),
                    "length": len(node_path) - 1,
                },
                cwe="CWE-269",
                confidence=0.65,
                detail=(
                    f"{node_path[0]} reaches {node_path[-1]} in {len(node_path) - 1} hop(s) "
                    "via " + " -> ".join(hops)
                ),
                source=node_path[0],
            )


# --------------------------------------------------------------------------- helpers
def _first_field(event: Mapping[str, Any], fields: Iterable[str]) -> str | None:
    for field in fields:
        if field in event and event[field] not in (None, ""):
            return str(event[field])
        lowered = field.lower()
        for key, value in event.items():
            if str(key).lower() == lowered and value not in (None, ""):
                return str(value)
    return None


def _shortest_paths(
    graph: Mapping[str, Any], corpus: M6Corpus
) -> tuple[tuple[tuple[str, ...], tuple[str, ...]], ...]:
    """BFS from every non-privileged principal to a Domain Admin node (bounded)."""
    nodes = graph.get("nodes") or ()
    edges = graph.get("edges") or ()
    admin_labels = {label.lower() for label in corpus.ad_domain_admin_labels()}
    escalation = {edge.lower() for edge in corpus.ad_escalation_edges()}

    names: dict[str, str] = {}
    admins: set[str] = set()
    for node in nodes:
        if not isinstance(node, Mapping):
            continue
        identifier = str(node.get("id") or node.get("objectid") or node.get("name") or "")
        if not identifier:
            continue
        label = str(node.get("label") or node.get("type") or "")
        properties = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
        display = str((properties or {}).get("name") or node.get("name") or identifier)
        names[identifier] = display
        group_names = {str(group).lower() for group in (properties or {}).get("groups") or ()}
        if (
            label.lower() in admin_labels
            or group_names & admin_labels
            or display.lower() in admin_labels
        ):
            admins.add(identifier)
    if not admins:
        return ()
    adjacency: dict[str, list[tuple[str, str]]] = {}
    for edge in edges:
        if not isinstance(edge, Mapping):
            continue
        source = str(edge.get("source") or edge.get("from") or "")
        target = str(edge.get("target") or edge.get("to") or "")
        kind = str(edge.get("label") or edge.get("type") or "")
        if not source or not target or kind.lower() not in escalation:
            continue
        adjacency.setdefault(source, []).append((target, kind))

    results: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    for start in names:
        if start in admins:
            continue
        path = _bfs(start, admins, adjacency)
        if path is not None:
            node_path, edge_path = path
            results.append((tuple(names.get(item, item) for item in node_path), tuple(edge_path)))
    results.sort(key=lambda item: len(item[0]))
    return tuple(results)


def _bfs(
    start: str, goals: set[str], adjacency: Mapping[str, list[tuple[str, str]]]
) -> tuple[list[str], list[str]] | None:
    queue: deque[tuple[str, list[str], list[str]]] = deque([(start, [start], [])])
    visited = {start}
    while queue:
        node, path, hops = queue.popleft()
        if len(hops) >= 6:
            continue
        for target, kind in adjacency.get(node, ()):
            if target in visited:
                continue
            if target in goals:
                return [*path, target], [*hops, kind]
            visited.add(target)
            queue.append((target, [*path, target], [*hops, kind]))
    return None
