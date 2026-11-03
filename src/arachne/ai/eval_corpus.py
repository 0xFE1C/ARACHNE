"""Build the offline evaluation corpus (REQ-AGENT-009) — the labelling is data, not a mood.

The corpus is committed as ``tests/eval/fixtures/ai-eval-cases-v1.jsonl`` and this module is how
it was produced, so a reviewer can check *why* a case carries the label it carries instead of
taking 240 lines of JSON on trust. It is deterministic by construction — no clock, no randomness,
no network, no filesystem — and
``tests/eval/test_corpus.py`` asserts the committed fixture is exactly what
:func:`cases_jsonl` emits, so the file and its rationale cannot drift apart.

**How a label is derived.** Every case is a candidate finding and one *evidence profile*. The
profile is the observable truth: a marker in the captured evidence, a response status, and what
those mean for triage:

================== ============================= ========== ==============================
profile            marker                        status     triage label
================== ============================= ========== ==============================
``exposed-secret`` ``live-credential-exposed``   ``200``    severity escalated one step, not an FP
``open-service``   ``service-banner-disclosed``  ``200``    the check's own severity hint
``hardening``      ``security-header-absent``    ``200``    the check's own severity hint
``guarded``        ``access-denied-response``    ``403``    ``fp_likely``: the check saw a refusal
``placeholder``    ``default-placeholder-page``  ``200``    ``fp_likely``: a default page, not a hit
================== ============================= ========== ==============================

The severity hint comes from the check table below (one entry per check, mirroring the shipped
catalogue's modules), so a triage label is "what the check claims, corrected by what the capture
shows" — the rule a human reviewer applies. Narrative labels are the marker and the status the
capture shows, because that is what the prose must carry. Correlate labels are the group's shared
root cause, named from one phrase the member titles carry.

**Held out.** Nothing in ``src/arachne/templates/ai/prompts/`` was written against these cases:
the labels come from the catalogue and the capture (above), and the responder that scores them
reads only the rendered prompt. Rotating the corpus means emitting ``v2`` with a new
profile/theme table and re-baselining in the same act — which the digest pinned in the baseline
makes impossible to do by accident.

Emit a corpus (the ``.jsonl`` goes to stdout, so nothing here touches a path — redirect it into
the fixture file, and bump :data:`CORPUS_VERSION` when the tables change)::

    python -m arachne.ai.eval_corpus > tests/eval/fixtures/ai-eval-cases-v1.jsonl
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

__all__ = [
    "CHECKS",
    "CORPUS_VERSION",
    "GROUPS_PER_THEME",
    "PROFILES",
    "THEMES",
    "build_cases",
    "cases_jsonl",
    "main",
]

#: The corpus version. Bump it when the tables below change: the baseline pins the version *and*
#: the file digest, so an un-bumped edit fails the gate rather than passing silently.
CORPUS_VERSION: Final = "v1"

#: ``(module, name, cwe, severity hint)`` — the check catalogue the corpus draws on. It mirrors
#: the shipped modules' declared severities (M1 discovery is informational, M4 exposure is not).
CHECKS: Final[tuple[tuple[str, str, str | None, str], ...]] = (
    ("M1", "dork-sweep", "CWE-200", "low"),
    ("M1", "url-harvest", "CWE-200", "low"),
    ("M1", "robots-exposure", "CWE-200", "low"),
    ("M1", "subdomain-takeover", "CWE-284", "medium"),
    ("M2", "smb-enum", "CWE-200", "high"),
    ("M2", "tls-config", "CWE-326", "medium"),
    ("M2", "smtp-open-relay", "CWE-284", "high"),
    ("M2", "ipv6-parity", "CWE-200", "info"),
    ("M3", "api-surface", "CWE-200", "medium"),
    ("M3", "upload-audit", "CWE-434", "high"),
    ("M3", "cors-misconfig", "CWE-942", "medium"),
    ("M3", "dom-sink", "CWE-79", "high"),
    ("M4", "env-file-probe", "CWE-200", "high"),
    ("M4", "backup-file-probe", "CWE-538", "high"),
    ("M4", "git-config", "CWE-527", "high"),
    ("M4", "default-creds", "CWE-521", "critical"),
    ("M5", "mcp-surface", "CWE-200", "medium"),
    ("M5", "agentic-write", "CWE-284", "high"),
    ("M6", "genai-key-leak", "CWE-798", "medium"),
    ("M6", "model-card", "CWE-200", "low"),
)

#: ``profile → (name, marker, status, fp_likely, escalates)`` — the observable truth of a capture.
PROFILES: Final[tuple[tuple[str, str, int, bool, bool], ...]] = (
    ("exposed-secret", "live-credential-exposed", 200, False, True),
    ("open-service", "service-banner-disclosed", 200, False, False),
    ("hardening", "security-header-absent", 200, False, False),
    ("guarded", "access-denied-response", 403, True, False),
    ("placeholder", "default-placeholder-page", 200, True, False),
)

#: ``(root-cause key, phrase)`` — the shared weakness a correlation group has. The phrase is what
#: the member titles carry and what :data:`arachne.ai.eval.ROOT_CAUSE_KEYWORDS` reads back. Each
#: phrase is deliberately unlike any check name, so a check's own title can never be mistaken for
#: the group's shared cause.
THEMES: Final[tuple[tuple[str, str], ...]] = (
    ("exposed-configuration", "configuration drift"),
    ("unauthenticated-datastore", "unauthenticated datastore"),
    ("missing-hardening", "missing header"),
    ("weak-transport", "tls version"),
    ("legacy-protocol", "legacy smb dialect"),
)

#: How many correlation groups each theme contributes (5 themes, 8 each = 40 cases).
GROUPS_PER_THEME: Final = 8

_SEVERITIES: Final[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")

#: The evidence row ids the corpus mints. Fixed numbers, not an allocator: the corpus is data and
#: two builds of it must be byte-identical.
_RESPONSE_ID: Final = 1001
_NOTE_ID: Final = 1002


def build_cases() -> tuple[dict[str, Any], ...]:
    """Every case, in a stable order (triage, narrative, then correlate)."""
    cases: list[dict[str, Any]] = []
    for check in CHECKS:
        for profile in PROFILES:
            cases.append(_triage_case(check, profile))
            cases.append(_narrative_case(check, profile))
    cases.extend(_correlate_cases())
    return tuple(cases)


def cases_jsonl(cases: Sequence[Mapping[str, Any]] | None = None) -> str:
    """The corpus as the committed ``.jsonl`` (one compact object per line, trailing newline)."""
    rows = cases if cases is not None else build_cases()
    return "".join(json.dumps(dict(row), sort_keys=True) + "\n" for row in rows)


# --------------------------------------------------------------------------- builders


def _check_id(check: tuple[str, str, str | None, str]) -> str:
    return f"{check[0].lower()}.{check[1]}"


def _title(check: tuple[str, str, str | None, str]) -> str:
    return f"{check[1].replace('-', ' ').capitalize()} is exposed"


def _asset(check: tuple[str, str, str | None, str]) -> str:
    return f"https://{check[0].lower()}.target.example/{check[1]}"


def _evidence(profile: tuple[str, str, int, bool, bool]) -> tuple[dict[str, Any], ...]:
    name, marker, status, _fp, _escalates = profile
    return (
        {
            "id": _RESPONSE_ID,
            "kind": "http_response",
            "source": "https://target.example",
            "payload": {
                "status_code": status,
                "notable": marker,
                "signals": [f"profile:{name}"],
                "headers": {"content-type": "text/plain"},
            },
        },
        {
            "id": _NOTE_ID,
            "kind": "note",
            "payload": {"detail": f"capture classified as {name}"},
        },
    )


def _severity_label(hint: str, profile: tuple[str, str, int, bool, bool]) -> tuple[str, bool]:
    """``(severity, fp_likely)`` — the check's claim, corrected by what the capture shows."""
    _name, _marker, _status, fp_likely, escalates = profile
    if fp_likely:
        return "info", True
    if not escalates:
        return hint, False
    try:
        index = _SEVERITIES.index(hint)
    except ValueError:
        return hint, False
    return _SEVERITIES[min(len(_SEVERITIES) - 1, index + 1)], False


def _triage_case(
    check: tuple[str, str, str | None, str], profile: tuple[str, str, int, bool, bool]
) -> dict[str, Any]:
    severity, fp_likely = _severity_label(check[3], profile)
    return {
        "case_id": f"triage-{check[0].lower()}-{check[1]}-{profile[0]}",
        "stage": "triage",
        "check_id": _check_id(check),
        "module": check[0],
        "title": _title(check),
        "cwe": check[2],
        "severity_hint": check[3],
        "asset": _asset(check),
        "evidence": list(_evidence(profile)),
        "label": {"severity": severity, "fp_likely": fp_likely, "profile": profile[0]},
    }


def _narrative_case(
    check: tuple[str, str, str | None, str], profile: tuple[str, str, int, bool, bool]
) -> dict[str, Any]:
    return {
        "case_id": f"narrative-{check[0].lower()}-{check[1]}-{profile[0]}",
        "stage": "narrative",
        "check_id": _check_id(check),
        "module": check[0],
        "title": _title(check),
        "cwe": check[2],
        "severity_hint": check[3],
        "asset": _asset(check),
        "evidence": list(_evidence(profile)),
        # The narrative must carry the fact the capture shows — the marker, and the status that
        # qualifies it. Two facts per case, so recall is a real fraction rather than all-or-none.
        "label": {"facts": [profile[1], f"status {profile[2]}"]},
    }


def _correlate_cases() -> Iterable[dict[str, Any]]:
    for theme_index, (key, phrase) in enumerate(THEMES):
        for group_index in range(GROUPS_PER_THEME):
            offset = (theme_index * GROUPS_PER_THEME + group_index) % len(CHECKS)
            members = [
                _correlate_member(CHECKS[(offset + step) % len(CHECKS)], phrase)
                for step in range(3)
            ]
            host = f"host-{theme_index}{group_index}.example"
            yield {
                # The case id names the theme, so it must never reach the prompt as the trigger:
                # that would leak the label into the thing being measured. The harness passes the
                # asset instead (``ai.eval._run_correlate``).
                "case_id": f"correlate-{key}-{group_index:02d}",
                "stage": "correlate",
                "check_id": "correlation.group",
                "module": "M5",
                "title": f"Compounding findings on {host}",
                "cwe": None,
                "severity_hint": "high",
                "asset": host,
                "evidence": [
                    {"id": 2001 + step, "kind": "note", "payload": {"detail": f"member {step}"}}
                    for step in range(3)
                ],
                "members": [list(member) for member in members],
                "label": {"root_cause": key},
            }


def _correlate_member(check: tuple[str, str, str | None, str], phrase: str) -> tuple[str, str, str]:
    """One group member as ``(label, severity, title)`` — the title carries the shared phrase."""
    return (
        f"{check[0].lower()}.target.example",
        check[3],
        f"{check[1].replace('-', ' ')} exposes the {phrase} weakness",
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Emit the corpus to stdout (redirect it into the fixture path)."""
    del argv
    sys.stdout.write(cases_jsonl())
    return 0


if __name__ == "__main__":  # pragma: no cover - manual invocation
    raise SystemExit(main())
