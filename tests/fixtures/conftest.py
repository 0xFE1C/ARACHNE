"""Fixture-tree collection guard.

``tests/fixtures/`` holds *data* — including, since S27, a small repository that the fix
engine is pointed at (``fix-lab/``). That repository ships its own test suite, which is run
by ``arachne fix submit`` as the patch's gate and must not be collected as part of ARACHNE's
own suite: it is the fixture's subject, not ARACHNE's tests.
"""

from __future__ import annotations

collect_ignore_glob = ["fix-lab/*"]
