"""Plugin ecosystem helpers: the marketplace catalogue and the installer (F-09-01, S14).

Two halves, deliberately separate:

* :mod:`arachne.plugins.marketplace` is **read-only data** — a versioned catalogue of
  packages an operator can list, search and install. It answers "what exists?" without
  executing anything.
* :mod:`arachne.plugins.installer` is the **one write path** — it turns a local path or a
  git URL into an installed distribution, then re-runs discovery and reports what appeared.
  It is the only module besides ``report/pdf_backend.py`` allowed to start a process, and
  the call shape is asserted by ``tests/unit/test_http_hygiene.py``.

Both plugin families use the mechanism the scanner already has: entry points. Checks and
modules register under ``arachne.modules``; report formats under ``arachne.report_formats``.
Nothing in the core package names a plugin, which is what "installable without core changes"
means in practice.
"""

from __future__ import annotations

from typing import Any

from arachne.plugins.marketplace import (
    CATALOG_RESOURCE,
    MarketplaceCatalog,
    MarketplaceEntry,
    load_marketplace,
)

__all__ = [
    "CATALOG_RESOURCE",
    "MarketplaceCatalog",
    "MarketplaceEntry",
    "installed_plugins",
    "load_marketplace",
]


def installed_plugins() -> dict[str, list[dict[str, Any]]]:
    """The plugins this process can see, split by family (built-ins excluded).

    A check plugin is "installed" when the module it registered carries a non-builtin
    ``origin``; a report format likewise. The functions are imported lazily so importing
    this package does not build either registry.
    """
    from arachne.modules.registry import ModuleRegistry
    from arachne.report import default_registry

    check_plugins: list[dict[str, object]] = []
    for group in ModuleRegistry.discover().groups:
        if group.origin == "builtin":
            continue
        check_plugins.append(
            {
                "module": group.id,
                "title": group.title,
                "version": group.version,
                "origin": group.origin,
                "checks": [metadata.id for metadata in group.metadata()],
            }
        )
    format_plugins = [
        item.summary() for item in default_registry().formats if item.origin != "builtin"
    ]
    return {"checks": check_plugins, "report_formats": format_plugins}
