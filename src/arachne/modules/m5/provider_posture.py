"""DigitalOcean read-only posture (WP-12, REQ-DET-017).

The cloud breadth requirement asks for either real posture coverage or an explicit
``not_supported`` row. DigitalOcean is the provider this release covers properly: four
documented ``GET`` operations, a vault-supplied ``cloud-token`` credential, and policies over
fields the API actually returns. OCI and Alibaba Cloud are recorded ``not_supported`` with
their reasons in :mod:`arachne.modules.cloud_providers`; that is the honest half of the
requirement, not a silent gap.

The check sends exactly the operations the provider row declares (a test asserts the set).

* ``do-database-public`` — a managed database cluster with no private-network UUID, so the
  public connection endpoint is the only path to it.
* ``do-database-no-trusted-sources`` — a cluster that declares an empty ``trusted_sources``
  list: the field's own shape says "no source restriction".
* ``do-firewall-open-ssh`` — an inbound firewall rule that admits TCP 22 from ``0.0.0.0/0``
  or ``::/0``.
* ``do-loadbalancer-plaintext`` — a load balancer with an HTTP forwarding rule and no
  ``redirect_http_to_https``.
* ``do-no-cloud-firewall`` — the account has droplets and no firewall at all.

Nothing is written: every call is a GET, the token is injected by the credential broker into
one request and is already redacted in the exchange the check receives, and no result
carries the token or the account's response headers.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.core.vault import CLOUD_CREDENTIAL_KINDS
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.cloud_providers import by_provider
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import EndpointCheck, finding_cap, m5_candidate, skip

__all__ = ["DigitalOceanPosture"]

#: The provider row this check implements. The operations are read from the table, so the
#: declaration and the implementation cannot drift apart silently.
_PROVIDER = by_provider()["digitalocean"]
_DEFAULT_BASE: Final = "https://api.digitalocean.com"
_OPEN_SSH_PORTS: Final = {"22", "22-22", "all", "0-65535"}


@dataclass(frozen=True, slots=True)
class _Observation:
    """One policy breach on one resource."""

    policy: str
    resource: str
    detail: str
    observed: Mapping[str, Any]
    severity: str = "medium"


class DigitalOceanPosture(EndpointCheck, Module):
    """``m5.do-posture`` — DigitalOcean account posture (read-only, ch05#1)."""

    metadata = CheckMetadata(
        id="m5.do-posture",
        module="M5",
        name="do-posture",
        version="1.0",
        title="DigitalOcean account exposes a database, firewall or load balancer",
        description=(
            "Reads the DigitalOcean account's droplets, managed databases, load balancers and "
            "firewalls with four documented GET operations and reports the posture conditions "
            "the account's own fields carry: a managed database with no private network or no "
            "trusted sources, an inbound firewall rule open to SSH from the internet, a load "
            "balancer serving HTTP without a redirect, and droplets with no cloud firewall "
            "(research ch05#1; REQ-DET-017). The bearer token comes from the credential vault "
            "and is injected by the broker; the check never sees it. Nothing is created, "
            "modified or deleted."
        ),
        research_ref="ch05#1",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-16"),
        compliance=("ISO-A.8.32", "CSF-ID.RA-07"),
        cwe="CWE-16",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=4,
        requires_active_checks=True,
        requires_credentials=("cloud-token",),
    )

    def supports(self, asset: Asset) -> bool:
        """Only an asset that names a DigitalOcean/``endpoint:`` base applies."""
        if not super().supports(asset):
            return False
        return _base_for(asset.value) is not None

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        base = _base_for(ctx.asset.value)
        if base is None:
            yield skip(
                ctx,
                "no DigitalOcean endpoint reference: declare digitalocean:[<base>] or "
                "endpoint:<read-only-api-base>",
            )
            return
        if ctx.http is None:
            yield skip(ctx, "no HTTP client in this run: the DigitalOcean check is a live read")
            return
        credentials = ctx.credentials
        if credentials is None or not credentials.selected_labels(CLOUD_CREDENTIAL_KINDS):
            yield skip(
                ctx,
                "no cloud-token credential selected: declare one with --credential and scope "
                "it to the DigitalOcean API host (the check never runs unauthenticated)",
            )
            return

        root = base.rstrip("/")
        documents: dict[str, Mapping[str, Any]] = {}
        for method, path in _PROVIDER.operations:
            assert method == "GET"  # the table refuses anything else at construction
            exchange = await credentials.authorized_get(ctx.http, root + path)
            if exchange is None:
                yield skip(
                    ctx,
                    "no cloud-token credential was released for this endpoint (unselected, "
                    "unscoped or revoked); the refusal is on the audit trail",
                )
                return
            if exchange.status_code in {401, 403}:
                yield skip(
                    ctx,
                    f"the DigitalOcean API refused the credential ({exchange.status_code}); "
                    "no unauthenticated fallback is attempted",
                )
                return
            if not exchange.ok:
                continue
            try:
                document = json.loads(exchange.body)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(document, Mapping):
                documents[path] = document

        observations = _evaluate(documents)
        if not observations:
            yield ctx.clean(
                "no DigitalOcean posture breach found",
                detail=(
                    f"read {len(documents)} of {len(_PROVIDER.operations)} documented "
                    "read-only operations"
                ),
            )
            return
        for index, observation in enumerate(observations):
            yield m5_candidate(
                ctx,
                f"DigitalOcean posture: {observation.policy} on {observation.resource}",
                artifact={
                    "signal": "cloud-provider-posture",
                    "family": "cloud-provider",
                    "provider": "digitalocean",
                    "policy": observation.policy,
                    "resource": observation.resource,
                    "observed": dict(observation.observed),
                    "severity_hint": observation.severity,
                },
                confidence=0.85,
                detail=observation.detail,
                source=observation.resource,
            )
            if index + 1 >= finding_cap(ctx):
                return


# --------------------------------------------------------------------------- reference
def _base_for(value: str) -> str | None:
    provider, separator, reference = value.strip().partition(":")
    if not separator:
        return None
    lowered = provider.lower()
    if lowered in {"digitalocean", "do"}:
        rest = reference.strip()
        if not rest:
            return _DEFAULT_BASE
        return rest if "://" in rest else f"https://{rest}"
    if lowered == "endpoint" and reference:
        return reference if "://" in reference else f"https://{reference}"
    return None


# --------------------------------------------------------------------------- policies
def _evaluate(documents: Mapping[str, Mapping[str, Any]]) -> tuple[_Observation, ...]:
    out: list[_Observation] = []
    out.extend(_databases(documents.get("/v2/databases", {})))
    out.extend(_firewalls(documents.get("/v2/firewalls", {})))
    out.extend(_load_balancers(documents.get("/v2/load_balancers", {})))
    droplets = _items(documents.get("/v2/droplets", {}), "droplets")
    firewalls = _items(documents.get("/v2/firewalls", {}), "firewalls")
    if droplets and not firewalls:
        out.append(
            _Observation(
                policy="do-no-cloud-firewall",
                resource="account",
                detail=(
                    f"{len(droplets)} droplet(s) and no cloud firewall: network filtering is "
                    "left to each droplet's own configuration"
                ),
                observed={"droplets": len(droplets), "firewalls": 0},
            )
        )
    return tuple(out)


def _databases(document: Mapping[str, Any]) -> list[_Observation]:
    out: list[_Observation] = []
    for cluster in _items(document, "databases"):
        name = _name(cluster)
        observed = {
            "private_network_uuid": cluster.get("private_network_uuid"),
            "trusted_sources": cluster.get("trusted_sources"),
            "engine": cluster.get("engine"),
        }
        if not cluster.get("private_network_uuid"):
            out.append(
                _Observation(
                    policy="do-database-public",
                    resource=name,
                    detail=(
                        f"managed database {name} has no private-network UUID: the public "
                        "connection endpoint is the only path"
                    ),
                    observed=observed,
                    severity="high",
                )
            )
        sources = cluster.get("trusted_sources")
        if isinstance(sources, Sequence) and not isinstance(sources, (str, bytes)) and not sources:
            out.append(
                _Observation(
                    policy="do-database-no-trusted-sources",
                    resource=name,
                    detail=(
                        f"managed database {name} declares an empty trusted_sources list: no "
                        "source restriction is recorded"
                    ),
                    observed=observed,
                    severity="high",
                )
            )
    return out


def _firewalls(document: Mapping[str, Any]) -> list[_Observation]:
    out: list[_Observation] = []
    for firewall in _items(document, "firewalls"):
        name = _name(firewall)
        rules = firewall.get("inbound_rules")
        if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
            continue
        for rule in rules:
            if not isinstance(rule, Mapping):
                continue
            ports = str(rule.get("ports", ""))
            if ports not in _OPEN_SSH_PORTS:
                continue
            sources = rule.get("sources")
            addresses = sources.get("addresses") if isinstance(sources, Mapping) else None
            if not isinstance(addresses, Sequence) or isinstance(addresses, (str, bytes)):
                continue
            open_addresses = [
                str(address) for address in addresses if str(address) in {"0.0.0.0/0", "::/0"}
            ]
            if not open_addresses:
                continue
            out.append(
                _Observation(
                    policy="do-firewall-open-ssh",
                    resource=name,
                    detail=(f"firewall {name} admits TCP {ports} from {', '.join(open_addresses)}"),
                    observed={
                        "ports": ports,
                        "sources": open_addresses,
                        "protocol": rule.get("protocol"),
                    },
                    severity="high",
                )
            )
    return out


def _load_balancers(document: Mapping[str, Any]) -> list[_Observation]:
    out: list[_Observation] = []
    for balancer in _items(document, "load_balancers"):
        name = _name(balancer)
        if balancer.get("redirect_http_to_https") is True:
            continue
        rules = balancer.get("forwarding_rules")
        if not isinstance(rules, Sequence) or isinstance(rules, (str, bytes)):
            continue
        plaintext = [
            str(rule.get("entry_protocol", ""))
            for rule in rules
            if isinstance(rule, Mapping) and str(rule.get("entry_protocol", "")).lower() == "http"
        ]
        if not plaintext:
            continue
        out.append(
            _Observation(
                policy="do-loadbalancer-plaintext",
                resource=name,
                detail=(
                    f"load balancer {name} accepts HTTP forwarding without redirecting to HTTPS"
                ),
                observed={
                    "entry_protocols": plaintext,
                    "redirect_http_to_https": balancer.get("redirect_http_to_https"),
                },
            )
        )
    return out


def _items(document: Mapping[str, Any], key: str) -> list[Mapping[str, Any]]:
    value = document.get(key)
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def _name(resource: Mapping[str, Any]) -> str:
    name = resource.get("name")
    if isinstance(name, str) and name:
        return name
    identifier = resource.get("id")
    return str(identifier) if identifier is not None else "unnamed"
