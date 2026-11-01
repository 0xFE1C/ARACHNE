"""Delivery-surface integrations (S26, REQ-ECOS-003).

The scanner already produces the finding schema every forge can read; this package turns
that schema into the *review* surface a pipeline renders on a pull request — GitHub
workflow-command annotations and a GitLab Code Quality report — plus the glue the shipped
GitHub Action and GitLab CI component call.

Nothing here talks to a network, a database or a subprocess: :mod:`arachne.ecos.ci_gate`
is a pure document producer so it can be unit-tested byte-for-byte, and the DB-backed
runner lives in :mod:`arachne.tools.ci_annotate`.
"""

from __future__ import annotations

__all__: list[str] = []
