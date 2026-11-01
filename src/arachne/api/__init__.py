"""FastAPI application, auth, web UI and webhooks (spec 01- F-07-02/03, F-06-06; S12).

The interface layer of docs/spec/02- §1: the REST API and the web UI a human uses. It
depends on the scanner; the scanner never depends on it — :func:`create_app` is imported
lazily by the CLI's ``serve`` command and by tests, so a plain scan installs no ASGI stack.

Public surface:

* :func:`~arachne.api.app.create_app` — build the ASGI app (JSON API + UI).
* :class:`~arachne.api.auth.ApiKeyStore` / :class:`~arachne.api.auth.Role` — authentication.
* :class:`~arachne.api.webhooks.WebhookNotifier` — the F-06-06 integrations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from arachne.api.auth import ApiKeyStore, Principal, Role

if TYPE_CHECKING:  # pragma: no cover - typing only
    from fastapi import FastAPI

__all__ = ["ApiKeyStore", "Principal", "Role", "create_app"]


def create_app(*args: Any, **kwargs: Any) -> FastAPI:
    """Build the ARACHNE ASGI app (imports :mod:`arachne.api.app` on demand)."""
    from arachne.api.app import create_app as _create_app

    return _create_app(*args, **kwargs)
