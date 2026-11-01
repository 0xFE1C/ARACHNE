"""Harness for M6 check-level tests.

M6's checks read local artifacts (a web root, a repository, a log export), the shared web crawl
and the discovery step's persisted inventory. The M5 harness already provides exactly that
shape — a loopback-scoped live client, a seeded asset and a crawl — so M6 reuses it with M6
settings. This module is the thin, discoverable name for that.
"""

from __future__ import annotations

from arachne.core.config import M6Settings, WebSettings
from arachne.modules.base import Asset
from tests.helpers.m5 import M5Harness, make_m5_harness

__all__ = ["M6Harness", "make_m6_harness"]

#: M6 uses the same harness shape as M5 (client + step context + crawl).
M6Harness = M5Harness


def make_m6_harness(
    *,
    asset: Asset | None = None,
    m6: M6Settings | None = None,
    web: WebSettings | None = None,
    allowed_hosts: tuple[str, ...] = ("127.0.0.1",),
) -> M6Harness:
    """A loopback harness with M6 settings and one seeded asset."""
    return make_m5_harness(asset=asset, m6=m6 or M6Settings(), web=web, allowed_hosts=allowed_hosts)
