"""A deliberately hanging test: the timeout gate's acceptance fixture (REQ-QUAL-012).

This module is **not** collected by the suite — pytest only collects ``test_*.py`` files, and
this one is named ``hanging.py``. ``tests/unit/test_quality_gates.py`` runs it explicitly, as
a subprocess, and asserts that the configured per-test timeout fails it and names it.
"""

from __future__ import annotations

import time


def test_this_test_hangs() -> None:
    """Sleep far past the configured timeout; pytest-timeout must kill it."""
    time.sleep(600)
