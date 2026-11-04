"""A module the mutation gate tests *itself* against — a test fixture, never shipped code.

``tests/unit/test_mutation_gate.py`` mutates this file and runs
``tests/fixtures/mutation/test_subject.py`` against the mutant, so the gate's own machinery
(load the altered module, run the real tests, classify the verdict) is exercised end to end on
something whose answer is known ahead of time.

``unused_helper`` is deliberately unreached by its test file: it is the control case for
"survived", and a gate that cannot report a survivor as a survivor is not measuring anything.
"""

from __future__ import annotations

#: A module-level switch the covering test asserts on (a `bool-literal` mutation target).
ENABLED: bool = True


def threshold(value: int, *, limit: int = 10) -> bool:
    """True when ``value`` is within ``limit``, inclusive (a `compare-op` mutation target)."""
    return value <= limit


def describe(value: int) -> str:
    """A two-branch label (a `compare-op` mutation target with a clear expected answer)."""
    return "small" if value < 100 else "large"


def unused_helper(value: int) -> bool:
    """Unreached by the covering test: a mutant here must be *reported*, not quietly killed."""
    return value > 1000
