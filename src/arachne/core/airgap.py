"""Air-gapped mode: the egress allowlist that makes "no external connectivity" real (S25).

REQ-RESIL-001 asks for a mode that "runs the full heuristic pipeline with zero external
connectivity". A flag that merely *turns features off* is a configuration convention, not a
guarantee: the next feature added forgets to check it. So air-gapped mode is enforced where
every packet is already decided — the single HTTP egress path
(:class:`~arachne.core.http.ScopedHttpClient`) and the non-HTTP prober
(:class:`~arachne.core.net.NetClient`) — as a **second, stricter allowlist**:

* the *deployment* target scope stays what it is (that is what authorizes scanning the
  customer's estate, and the scan still needs it), and
* nothing else is reachable, whatever the calling feature believed.

That single gate is what makes the four refusals structural rather than remembered: a feed
sync, an OSINT provider, a cloud AI endpoint, a webhook target, an OTLP collector, an IdP's
discovery document and a plugin download are all *outside* the target scope, so in
air-gapped mode their first request is refused and audited instead of silently succeeding.
:data:`EXTRA_ALLOWED_FEATURES` names the two things an operator may still want locally
(an on-premises model server and an internal feed mirror); both are opt-in by host, never
by default.

The pipeline itself never depends on any of that: heuristic mode needs no provider, the CVE
index is a shipped file, and content arrives as a **signed offline pack**
(``arachne.resil.packs``) that the operator carries in by hand.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from arachne.core.config import Settings
from arachne.core.errors import SafetyError

__all__ = [
    "AIRGAP_REFUSAL",
    "AirgapError",
    "AirgapPolicy",
    "build_airgap_policy",
    "feature_refusal",
]

AIRGAP_REFUSAL: Final = (
    "refused: this deployment runs air-gapped (ARACHNE_AIRGAPPED=true), so the only "
    "reachable hosts are the configured scan targets; import a signed content pack "
    "(`arachne packs import`) instead of reaching an external service"
)

#: Features that are egress by nature. Named so an operator reading the audit trail sees
#: *what* was attempted, and so a future feature has an obvious place to register.
EGRESS_FEATURES: Final[tuple[str, ...]] = (
    "intel.sync",
    "intel.provider",
    "ai.provider",
    "webhook.delivery",
    "tracing.export",
    "plugin.install",
    "sso.discovery",
    "purple.alerts",
    "content.pack.fetch",
    "update.check",
)

#: The two local services an air-gapped estate may legitimately run. Both are inert until
#: the operator names them (an on-premises model server, an internal feed mirror).
EXTRA_ALLOWED_FEATURES: Final[tuple[str, ...]] = ("ai.local", "intel.mirror")


class AirgapError(SafetyError):
    """An egress attempt refused because the deployment is air-gapped."""


@dataclass(frozen=True, slots=True)
class AirgapPolicy:
    """Which hosts air-gapped mode still allows.

    ``allowed_hosts`` is *additional* to the deployment scope: an operator who runs an
    on-premises model endpoint names it here. Nothing is allowed by default, so an empty
    configuration means "targets only".
    """

    enabled: bool = False
    allowed_hosts: tuple[str, ...] = ()

    def allows_host(self, host: str | None, *, scope_hosts: tuple[str, ...] = ()) -> bool:
        """True when ``host`` is reachable while air-gapped."""
        if not self.enabled:
            return True
        if not host:
            return False
        candidate = host.strip().lower().rstrip(".")
        return any(_matches(candidate, allowed) for allowed in (*self.allowed_hosts, *scope_hosts))

    def refusal(self, host: str | None, *, scope_hosts: tuple[str, ...] = ()) -> str | None:
        """The refusal reason for ``host``, or ``None`` when it is allowed."""
        if self.allows_host(host, scope_hosts=scope_hosts):
            return None
        return f"{AIRGAP_REFUSAL} (attempted host: {host or 'unknown'})"


def _matches(candidate: str, allowed: str) -> bool:
    entry = allowed.strip().lower().rstrip(".")
    if not entry:
        return False
    if entry.startswith("*."):
        return candidate.endswith(entry[1:])
    return candidate == entry or candidate.endswith("." + entry)


def build_airgap_policy(settings: Settings | None = None) -> AirgapPolicy:
    """The policy this deployment's settings describe."""
    from arachne.core.config import get_settings

    effective = settings or get_settings()
    airgap = effective.airgap
    return AirgapPolicy(enabled=airgap.enabled, allowed_hosts=airgap.allowed_hosts)


def feature_refusal(policy: AirgapPolicy, feature: str, *, host: str | None = None) -> str | None:
    """The refusal reason for a named egress *feature* (``None`` when allowed).

    A feature-level guard for the paths that would otherwise fail opaquely — a plugin
    installer driving a subprocess, say, or a feed sync reading a mirror URL. The
    host-level gate in the HTTP client is the backstop; this is the one that produces an
    actionable, audited message.
    """
    if not policy.enabled:
        return None
    if feature in EXTRA_ALLOWED_FEATURES and host and policy.allows_host(host):
        return None
    return f"{AIRGAP_REFUSAL} (feature: {feature})"
