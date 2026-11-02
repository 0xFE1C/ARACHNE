"""The screen registry: the 14 screens of the state matrix (REQ-UIX-005).

``.spec/06-ui-ux.md`` §5 is a matrix of 14 screens x 5 states, and its whole point is that the
matrix is *checked* rather than asserted in prose. This module is the machine-readable form of
that table: one entry per screen naming its template, its route and which of the five states
apply (``n/a`` is a decision — the sign-in screen has no content to be empty and no role that
could be refused).

Two things read it:

* ``tests/unit/test_ui_states.py`` renders every entry's template once per applicable state and
  fails if a state produces a traceback or fails to emit its ``data-state`` marker. That is the
  template test REQ-UIX-005's acceptance criteria ask for, and it is also why the module carries
  a small :func:`render_context` per screen: a template test has to be able to render the
  *loaded* page without running a scan or serving a request.
* ``tests/unit/test_ui_states.py::test_the_matrix_matches_the_specification`` compares this table
  with ``06-ui-ux.md`` §5 directly, so a screen cannot be dropped from the matrix, nor a state
  quietly marked "n/a", without failing the build.

The contexts here are *minimum viable* render contexts. They are deliberately not the shapes the
routes build — a route's context is tested by the integration suite; this is the smallest input
that exercises a template's loaded branch, kept small on purpose so it is obvious when a template
starts depending on a new variable.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from arachne.api.workspace import MAX_BULK_FINDINGS, shortcut_sheet

__all__ = ["SCREENS", "SCREEN_STATES", "ScreenSpec", "matrix"]

#: The five states, in the specification's column order.
SCREEN_STATES: tuple[str, ...] = ("loading", "empty", "error", "partial", "refused")

#: The 14 screens of §5, in row order.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True, slots=True)
class ScreenSpec:
    """One row of the §5 matrix."""

    id: str
    title: str
    template: str
    route: str
    #: state -> does the specification require it for this screen?
    states: dict[str, bool]
    #: A function returning the smallest context that renders the *loaded* page.
    context: Callable[[], dict[str, Any]] = field(repr=False)

    @property
    def applicable(self) -> tuple[str, ...]:
        return tuple(state for state in SCREEN_STATES if self.states[state])


# --------------------------------------------------------------------------- small fixtures
def _counts(**over: int) -> dict[str, int]:
    base = dict.fromkeys(SEVERITIES, 0)
    base.update(over)
    return base


def _scan(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": 7,
        "target": "example.com",
        "status": "completed",
        "engine": "heuristic",
        "created_at": "2026-11-01T12:00:00+00:00",
        "started_at": "2026-11-01T12:00:01+00:00",
        "finished_at": "2026-11-01T12:00:30+00:00",
        "counts": _counts(critical=1),
        "total": 1,
        "running": False,
    }
    base.update(over)
    return base


def _finding_row() -> dict[str, Any]:
    return {
        "id": 42,
        "scan_id": 7,
        "severity": "high",
        "title": "Reflected XSS in search",
        "status": "open",
        "module": "M3",
        "check_id": "M3/xss-reflected@1.0",
        "asset": {"kind": "url", "value": "https://www.example.com/"},
        "asset_kind": "url",
        "asset_value": "https://www.example.com/",
        "cwe": "CWE-79",
        "cve": None,
        "confidence": 0.7,
        "research_ref": "ch03#4",
        "remediation_id": None,
        "created_at": "2026-11-01T12:00:00+00:00",
    }


def _finding_item() -> dict[str, Any]:
    return {
        "finding": _finding_row(),
        "detail": {
            "description": "The search parameter is reflected unescaped.",
            "remediation": None,
            "cvss": None,
            "cvss_vector": None,
            "owasp": None,
            "cwe": "CWE-79",
            "cve": None,
            "low_confidence": False,
        },
        "finding_id": 42,
        "evidence": [{"id": 1, "kind": "http_response", "sha256": "a" * 64, "payload": {}}],
    }


def _attack_path() -> dict[str, Any]:
    return {
        "id": "AP-1",
        "asset": "api.example.com",
        "severity": "critical",
        "fully_verified": True,
        "business_severity": "critical",
        "criticality": "tier-1",
        "cheapest_break": "parameterise /api/login",
        "cheapest_finding_id": "F-000042",
        "hops": [
            {
                "finding_id": "F-000042",
                "stage": "initial-access",
                "check_id": "M3/sqli-oracle",
                "asset": "api.example.com",
                "severity": "critical",
                "verified": True,
                "verifying_check": None,
                "evidence_refs": ["E-000001"],
            }
        ],
    }


def _project() -> dict[str, Any]:
    return {"id": 1, "slug": "default", "name": "Default workspace"}


def _project_record() -> Any:
    """A stand-in with the attributes ``posture.html`` reads off the project record."""

    class _Record:
        name = "Default workspace"
        slug = "default"
        id = 1

    return _Record()


def _estate() -> dict[str, Any]:
    return {
        "generated_at": "2026-11-01T12:00:00+00:00",
        "open": _counts(high=1),
        "open_total": 1,
        "fix_loop": {
            "closed_by_verification": 0,
            "reopened_regressions": 0,
            "still_open_verifications": 1,
        },
        "drift": [],
        "inventory": {},
        "watched_scopes": [],
        "scans": [],
    }


def _login_context() -> dict[str, Any]:
    return {"next": "/ui/", "error": None, "keys_configured": True, "sso_enabled": False}


def _dashboard_context() -> dict[str, Any]:
    return {
        "severities": SEVERITIES,
        "aggregate": _counts(),
        "trend": [{"scan_id": 7, "total": 1, "counts": _counts()}],
        "trend_max": 1,
        "scans": [_scan()],
    }


def _findings_context() -> dict[str, Any]:
    return {
        "findings": [_finding_item()],
        "total": 1,
        "severities": SEVERITIES,
        "filters": {"severity": "", "status": "", "module": "", "q": "", "scan": ""},
        "filtered": False,
        "cursor": "",
        "limit": "50",
        "next_href": None,
        "project": _project(),
        # The workspace's own inputs (REQ-UIX-006). The matrix renders the *loaded* page, so it
        # renders the writable, unselected one; the empty and refused cells come from the state
        # flags the matrix test sets on top of this.
        "can_write": True,
        "selected": (),
        "focused_id": None,
        "scroll": 0,
        "shortcuts": shortcut_sheet(),
        "bulk_limit": MAX_BULK_FINDINGS,
        "detail_query": "",
        "notice": None,
        "notice_kind": "ok",
        "undo": None,
        "error": None,
    }


def _finding_detail_context() -> dict[str, Any]:
    return {
        "finding": _finding_row(),
        "detail": _finding_item()["detail"],
        "evidence": _finding_item()["evidence"],
        # §4.4's way back, and the two lower panels the detail screen gained in WP-05.
        "list_href": "/ui/findings",
        "selection_count": 0,
        "authorization": (),
        "history": (),
    }


def _scans_context() -> dict[str, Any]:
    return {"scans": [_scan()], "targets": [], "severities": SEVERITIES, "project": _project()}


def _scan_detail_context() -> dict[str, Any]:
    return {
        "scan": _scan(),
        "steps": [{"step": "recon", "status": "completed", "attempts": 1, "error": None}],
        "assets": [{"kind": "url", "value": "https://www.example.com/"}],
        "severities": SEVERITIES,
        "filters": {"module": "", "severity": "", "cwe": "", "asset": "", "q": ""},
        "findings": [_finding_item()],
    }


def _report_context() -> dict[str, Any]:
    return {"scan_id": 7, "body": "# Security Assessment Report\n"}


def _attack_paths_context() -> dict[str, Any]:
    return {
        "scan_id": 7,
        "scan": _scan(),
        "paths": [_attack_path()],
        "graph": '<svg role="img" aria-label="attack paths"></svg>',
    }


def _posture_context() -> dict[str, Any]:
    return {
        "project": _project_record(),
        "severities": SEVERITIES,
        "estate": _estate(),
        "trend_svg": '<svg role="img" aria-label="posture trend"></svg>',
        "coverage_svg": '<svg role="img" aria-label="control coverage"></svg>',
        "coverage": [],
        "coverage_scan": None,
    }


def _modules_context() -> dict[str, Any]:
    return {
        "modules": [
            {
                "id": "M3",
                "version": "1.0",
                "step": "checks",
                "checks": [
                    {
                        "id": "m3.sqli-oracle",
                        "title": "SQL injection",
                        "version": "1.0",
                        "research_ref": "ch03#1",
                        "cwe": "CWE-89",
                        "framework": "WSTG-INPV-05, API1:2023, CWE-89",
                        "active": False,
                        "opt_in": False,
                        "ran": True,
                    }
                ],
            }
        ],
        # §4.10: the Modules screen *is* the coverage ledger, so its minimum context carries
        # the same tally the route passes from build_ledger().
        "coverage": {
            "checks": 1,
            "wstg": {"mapped": 1, "out_of_scope": 0, "gap": 96, "total": 97, "in_scope": 97},
            "api": {"mapped": 1, "total": 10},
            "cwe_only": 0,
            "generated_at": "2026-11-02",
        },
        "config": {
            "database": "sqlite:///arachne.db",
            "per_host_rate": 5,
            "global_rate": 20,
            "api_rate": 60,
            "tls_required": False,
            "scope_hosts": [],
            "scope_domains": [],
            "webhooks": [],
            "engine": "heuristic",
        },
    }


def _schedules_context() -> dict[str, Any]:
    return {
        "schedules": [
            {
                "spec": {
                    "id": "nightly",
                    "cron": "0 3 * * *",
                    "enabled": True,
                    "target": "fixtures/lab.yaml",
                },
                "state": {"last_run_at": None, "next_run_at": "2026-11-02T03:00:00+00:00"},
            }
        ]
    }


def _quality_context() -> dict[str, Any]:
    return {
        "project": _project_record(),
        "scope_all": False,
        "version": 1,
        "error": None,
        "suppressions": [
            {
                "id": 1,
                "kind": "rule",
                "check_id": "m3.xss-reflected",
                "asset_pattern": None,
                "reason": "hardened at the WAF",
                "actor": "operator",
                "active": True,
            }
        ],
        "acceptances": [
            {
                "id": 1,
                "finding_id": 42,
                "check_id": None,
                "owner": "platform-team",
                "expires_at": "2026-12-31T00:00:00+00:00",
                "justification": "mitigated by the network control",
                "revoked_at": None,
            }
        ],
    }


def _feeds_context() -> dict[str, Any]:
    empty = {"feeds": 0, "entries": 0}
    return {
        "stats": {
            "directory": "/var/lib/arachne/feeds",
            "by_kind": {"epss": empty, "kev": empty, "cve": empty},
        },
        "feeds": [
            {
                "id": 1,
                "kind": "epss",
                "name": "epss-2026-10-29",
                "version": None,
                "record_count": 10,
                "imported_by": "operator",
                "path": "/var/lib/arachne/feeds/epss.json",
            }
        ],
        "active_epss": None,
        "active_kev": None,
        "freshness": [
            {
                "kind": "epss",
                "age_hours": 3.0,
                "sla_hours": 24.0,
                "stale": False,
                "label": "3.0 h old",
            },
            {
                "kind": "kev",
                "age_hours": None,
                "sla_hours": 72.0,
                "stale": False,
                "label": "shipped snapshot",
            },
        ],
        "error": None,
    }


def _plugins_context() -> dict[str, Any]:
    return {
        "installed": {"checks": []},
        "formats": [],
        "marketplace": [],
        "marketplace_version": "1.0",
        "install_enabled": False,
    }


# --------------------------------------------------------------------------- the registry
def _states(*, empty: bool = True, refused: bool = True) -> dict[str, bool]:
    return dict.fromkeys(SCREEN_STATES, True)


def _sign_in_states() -> dict[str, bool]:
    states = _states()
    states["empty"] = False  # §5: n/a — a form has no content to be empty
    states["refused"] = False  # §5: n/a — there is no role to refuse at the sign-in screen
    return states


SCREENS: tuple[ScreenSpec, ...] = (
    ScreenSpec(
        id="sign-in",
        title="Sign in",
        template="login.html",
        route="/ui/login",
        states=_sign_in_states(),
        context=_login_context,
    ),
    ScreenSpec(
        id="overview",
        title="Overview",
        template="dashboard.html",
        route="/ui/",
        states=_states(),
        context=_dashboard_context,
    ),
    ScreenSpec(
        id="findings",
        title="Findings workspace",
        template="findings.html",
        route="/ui/findings",
        states=_states(),
        context=_findings_context,
    ),
    ScreenSpec(
        id="finding-detail",
        title="Finding detail",
        template="finding_detail.html",
        route="/ui/findings/{finding_id}",
        states=_states(),
        context=_finding_detail_context,
    ),
    ScreenSpec(
        id="scans",
        title="Scans",
        template="scans.html",
        route="/ui/scans",
        states=_states(),
        context=_scans_context,
    ),
    ScreenSpec(
        id="scan-detail",
        title="Scan detail",
        template="scan_detail.html",
        route="/ui/scans/{scan_id}",
        states=_states(),
        context=_scan_detail_context,
    ),
    ScreenSpec(
        id="report",
        title="Report",
        template="report_text.html",
        route="/ui/scans/{scan_id}/report",
        states=_states(),
        context=_report_context,
    ),
    ScreenSpec(
        id="attack-paths",
        title="Attack paths",
        template="attack_paths.html",
        route="/ui/scans/{scan_id}/attack-paths",
        states=_states(),
        context=_attack_paths_context,
    ),
    ScreenSpec(
        id="posture",
        title="Posture",
        template="posture.html",
        route="/ui/posture",
        states=_states(),
        context=_posture_context,
    ),
    ScreenSpec(
        id="modules",
        title="Modules",
        template="modules.html",
        route="/ui/modules",
        states=_states(),
        context=_modules_context,
    ),
    ScreenSpec(
        id="schedules",
        title="Schedules",
        template="schedules.html",
        route="/ui/schedules",
        states=_states(),
        context=_schedules_context,
    ),
    ScreenSpec(
        id="quality",
        title="Quality",
        template="quality.html",
        route="/ui/quality",
        states=_states(),
        context=_quality_context,
    ),
    ScreenSpec(
        id="feeds",
        title="Feeds",
        template="feeds.html",
        route="/ui/feeds",
        states=_states(),
        context=_feeds_context,
    ),
    ScreenSpec(
        id="plugins",
        title="Plugins",
        template="plugins.html",
        route="/ui/plugins",
        states=_states(),
        context=_plugins_context,
    ),
)


def matrix() -> dict[str, dict[str, bool]]:
    """The §5 matrix as ``{screen id: {state: applicable}}``."""
    return {screen.id: dict(screen.states) for screen in SCREENS}
