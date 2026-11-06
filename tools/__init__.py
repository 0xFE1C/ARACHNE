"""Development tooling — build-time gates, outside the distribution (REQ-QUAL-015).

Nothing in this package is part of the product. It exists so the programme can check its own
process record: :mod:`tools.wp_check` verifies a completed work package from the repository
(commits, diffs, file contents, exit codes) rather than from what the tracker claims, and
:mod:`tools.preamble_check` compares every work-package preamble with the single canonical
text byte-for-byte.

It is deliberately **not** under ``src/``. The tools read the build-time scaffolding
(``.spec/``, ``PROMPT.md``, ``STATE.md``), and a shipped file may not name those paths
(REQ-DOC-006). Both requirements hold at once only while the tooling lives outside the
packaged tree, which is why the tools are here and why the packaging configuration excludes
this directory from the wheel and the sdist (asserted by
``tests/doc/test_development_tooling.py``).
"""

from __future__ import annotations

__all__: list[str] = []
