"""ARACHNE — defensive automated vulnerability-detection and reporting system.

This package is built in stages (the decision record for each is in ``docs/adr/``). Stage S1
delivers the project
scaffold: configuration, structured logging, the audit event schema, secret redaction,
the token-bucket rate limiter, the SSRF-by-design URL safety layer, the shared scoped
HTTP client (ADR-05), the data layer with Alembic migrations, and the ``arachne`` CLI
entry point.
"""

from __future__ import annotations

__all__ = ["__version__"]

# Single source of truth for the runtime version; kept in sync with pyproject.toml.
__version__ = "0.1.0"
