"""Golden-file comparison for rendered artifacts (S26, REQ-ECOS-004/005/006).

REQ-ECOS-004 asks for *golden screenshots* at the gate and REQ-ECOS-005/006 for golden reports.
This is how those artifacts are stored and compared: a committed file under
``tests/report_qa/golden/`` and an exact comparison, with a deliberate way to re-bless.

Why exact bytes: a normalized "close enough" comparison is how a golden suite stops catching
the thing it exists for. The artifacts here are deterministic by construction — the report
renderers take every clock from the DTO, and the SVG builders iterate sorted, timestamp-free
data — so equality is achievable and any difference is a real change.

Re-blessing::

    ARACHNE_GOLDEN_UPDATE=1 pytest tests/report_qa/test_ecos_golden.py

which rewrites the files and *fails* the run, so a blessing can never pass silently in CI.
Review the diff before committing it; that diff is the review.

For the two artifacts that cannot be byte-stable — a live HTML page carries the wall-clock time
it rendered and the operator label — :func:`normalize` collapses exactly those volatile tokens
(never the parts under test), and the docstring says so where it is used.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

__all__ = ["GOLDEN_ENV", "GOLDEN_ROOT", "assert_golden", "normalize", "read_golden"]

#: Set to any non-empty value to rewrite the goldens instead of asserting.
GOLDEN_ENV = "ARACHNE_GOLDEN_UPDATE"

#: Where the committed goldens live.
GOLDEN_ROOT = Path(__file__).resolve().parents[1] / "report_qa" / "golden"

#: The volatile tokens :func:`normalize` collapses. Each is something that legitimately differs
#: between two runs of the same code (a render time, a session label) and nothing that the test
#: is asserting. Anything not matched here is compared verbatim.
_VOLATILE: tuple[tuple[re.Pattern[str], str], ...] = (
    # ISO-8601 timestamps (report ``generated_at``, a scan's ``created_at``).
    (re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+00:00|Z)?"), "<TIMESTAMP>"),
    # A UTC datetime rendered by Python's repr (``2026-10-31 12:00:00+00:00``).
    (re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2}"), "<TIMESTAMP>"),
    # The signed-in operator label in the header (``label · role``). Anchored on the role so
    # this cannot swallow the many other ``muted small`` spans the pages use for content.
    (
        re.compile(r'(<span class="muted small">)[^<]*· (?:viewer|scanner|admin)(</span>)'),
        r"\1<PRINCIPAL>\2",
    ),
)


def normalize(text: str) -> str:
    """Collapse the volatile tokens a live page carries (see :data:`_VOLATILE`)."""
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return text


def _golden_path(name: str) -> Path:
    target = (GOLDEN_ROOT / name).resolve()
    if GOLDEN_ROOT.resolve() not in target.parents:
        msg = f"golden name {name!r} escapes the golden directory"
        raise ValueError(msg)
    return target


def read_golden(name: str) -> str:
    """The committed golden ``name`` (relative to ``golden/``)."""
    return _golden_path(name).read_text(encoding="utf-8")


def assert_golden(name: str, produced: str, *, update_env: str = GOLDEN_ENV) -> None:
    """Assert ``produced`` equals the committed golden, or re-bless it when asked.

    A missing golden is a failure with instructions rather than an implicit pass — a new
    artifact must be added deliberately, not discovered by a green run.
    """
    path = _golden_path(name)
    if os.environ.get(update_env):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(produced, encoding="utf-8")
        raise AssertionError(
            f"{name}: golden rewritten (ARACHNE_{update_env.removeprefix('ARACHNE_')}=1); "
            "review the diff and re-run without the variable"
        )
    if not path.is_file():
        raise AssertionError(
            f"{name}: no committed golden at {path}. Create it with "
            f"{update_env}=1 pytest and review the file before committing it."
        )
    expected = path.read_text(encoding="utf-8")
    if expected != produced:
        raise AssertionError(
            f"{name} differs from the committed golden.\n"
            f"{_first_difference(expected, produced)}\n"
            f"If the change is intended, re-bless with {update_env}=1 and review the diff."
        )


def _first_difference(expected: str, produced: str) -> str:
    """A short, line-oriented report of where two documents diverge."""
    expected_lines = expected.splitlines()
    produced_lines = produced.splitlines()
    for index, (want, got) in enumerate(zip(expected_lines, produced_lines, strict=False), 1):
        if want != got:
            return (
                f"  first difference at line {index}:\n"
                f"    golden:   {want[:160]}\n"
                f"    produced: {got[:160]}"
            )
    return (
        f"  line counts differ: golden {len(expected_lines)}, produced {len(produced_lines)} "
        "(the prefix matches, so the change is at or after the end of one document)"
    )
