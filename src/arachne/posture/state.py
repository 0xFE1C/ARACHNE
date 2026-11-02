"""Cloud-config state: snapshots, the drift diff, and the posture policies (S23, REQ-POSTURE-001).

Continuous posture needs a *state* model before it needs a scan: what did the estate look
like last time, what does it look like now, and what changed. Everything here is pure —
the M5 check fetches and feeds the document in, the baseline store (``data/``) persists
what this module computed, and nothing here touches a network or a database.

Three properties the drift detector depends on:

* **Normalization.** The three providers' read-only list responses do not agree on
  shapes, so each supported response shape is parsed into one resource form
  (:class:`CloudResource`) with a small, typed config the policies and the diff can read.
  The normalized export itself (``{"provider": ..., "resources": [...]}``) is the
  preferred input — an operator's read-only collector endpoint or the lab serves it —
  and the AWS ``DescribeSecurityGroups``, Azure ``List`` and GCP ``aggregatedList``
  response shapes are parsed directly, read-only GETs all.
* **Stable identity.** A resource is ``(provider, service, id)`` — its key survives
  reordering and cosmetic field churn, so "changed" means the *configuration* changed
  (``config_hash``), not that the JSON moved.
* **Deltas carry before/after.** A change is only a finding if the operator can see what
  it was: every :class:`ResourceDelta` names the keys that changed and holds both
  configurations (redacted upstream — the snapshot is evidence, so it goes through the
  same capture path as everything else).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal

from arachne.core.errors import ConfigurationError

__all__ = [
    "CloudResource",
    "CloudSnapshot",
    "PolicyViolation",
    "PosturePolicy",
    "ResourceDelta",
    "canonical_config",
    "config_hash",
    "diff_snapshots",
    "evaluate_policies",
    "parse_snapshot_document",
    "resource_key_of",
]

#: The change kinds a delta can carry (the drift vocabulary).
ChangeKind = Literal["added", "removed", "modified"]

_MAX_RESOURCES: Final = 5_000
_MAX_CONFIG_DEPTH: Final = 6


# --------------------------------------------------------------------------- model


def resource_key_of(provider: str, service: str, resource_id: str) -> str:
    """The stable identity of one resource across runs (``aws:s3/bucket-name``)."""
    return f"{provider.strip().lower()}:{service.strip().lower()}/{resource_id.strip()}"


def canonical_config(config: Mapping[str, Any]) -> str:
    """The canonical JSON form the hash and the diff compare (sorted keys, no floats)."""
    return json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)


def config_hash(config: Mapping[str, Any]) -> str:
    """SHA-256 of :func:`canonical_config` — the digest a drift comparison uses."""
    return hashlib.sha256(canonical_config(config).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CloudResource:
    """One resource's observed configuration, normalized across providers."""

    provider: str
    service: str
    resource_id: str
    config: dict[str, Any] = field(default_factory=dict)
    name: str = ""
    region: str = ""

    @property
    def key(self) -> str:
        return resource_key_of(self.provider, self.service, self.resource_id)


@dataclass(frozen=True, slots=True)
class CloudSnapshot:
    """One collection pass over one scope: the state the estate was in."""

    provider: str
    resources: tuple[CloudResource, ...]
    source: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    account: str = ""

    def by_key(self) -> dict[str, CloudResource]:
        return {resource.key: resource for resource in self.resources}


@dataclass(frozen=True, slots=True)
class ResourceDelta:
    """One resource's change against the last baseline — with both configurations."""

    resource_key: str
    change: ChangeKind
    #: The configuration before (``None`` for an added resource) and after
    #: (``None`` for a removed one) — what a delta finding's artifact carries.
    before: dict[str, Any] | None
    after: dict[str, Any] | None
    #: The config keys whose values differ (sorted); empty for add/remove.
    changed_keys: tuple[str, ...] = ()
    provider: str = ""
    service: str = ""


# --------------------------------------------------------------------------- parsing


def _resource_from_entry(entry: Mapping[str, Any], provider: str, *, source: str) -> CloudResource:
    service = str(entry.get("service") or entry.get("type") or "unknown").strip().lower()
    resource_id = str(entry.get("id") or entry.get("resource_id") or "").strip()
    if not resource_id:
        raise ConfigurationError(f"{source}: a snapshot resource needs an id (got {entry!r:.120})")
    config = entry.get("config")
    normalized: dict[str, Any] = (
        dict(config)
        if isinstance(config, Mapping)
        else {
            key: value
            for key, value in entry.items()
            if key not in {"id", "resource_id", "service", "type", "name", "region", "provider"}
        }
    )
    return CloudResource(
        provider=provider,
        service=service,
        resource_id=resource_id,
        config=_bounded_config(normalized, source=source),
        name=str(entry.get("name") or ""),
        region=str(entry.get("region") or ""),
    )


def _bounded_config(config: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    """A shallow, bounded copy: the diff and the policies read scalars, not forests."""
    if len(config) > 128:
        raise ConfigurationError(f"{source}: a snapshot resource config carries more than 128 keys")
    return {str(key): config[key] for key in sorted(config)[:128]}


def _flatten(value: Any, *, prefix: str = "", depth: int = 0) -> dict[str, Any]:
    """Flatten nested mappings into dotted keys so policies can address one path."""
    if depth >= _MAX_CONFIG_DEPTH or not isinstance(value, Mapping):
        return {prefix: value} if prefix else {}
    out: dict[str, Any] = {}
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, Mapping):
            out.update(_flatten(item, prefix=path, depth=depth + 1))
        else:
            out[path] = item
    return out


def _parse_aws(doc: Mapping[str, Any], *, source: str) -> CloudSnapshot:
    """AWS ``DescribeSecurityGroups``-shape (read-only list response)."""
    resources: list[CloudResource] = []
    for index, group in enumerate(doc.get("securityGroups") or ()):
        if not isinstance(group, Mapping):
            continue
        cidrs: list[str] = []
        for permission in group.get("IpPermissions") or ():
            if not isinstance(permission, Mapping):
                continue
            for item in permission.get("IpRanges") or ():
                if isinstance(item, Mapping) and item.get("CidrIp"):
                    cidrs.append(str(item["CidrIp"]))
        open_to_world = any(cidr in {"0.0.0.0/0", "::/0"} for cidr in cidrs)
        resources.append(
            CloudResource(
                provider="aws",
                service="ec2",
                resource_id=str(group.get("GroupId") or f"security-group-{index}"),
                name=str(group.get("GroupName") or ""),
                region=str(doc.get("region") or ""),
                config={
                    "type": "security-group",
                    "open_to_world": open_to_world,
                    "open_cidrs": sorted(set(cidrs)),
                    "vpc_id": str(group.get("VpcId") or ""),
                },
            )
        )
    return CloudSnapshot(
        provider="aws",
        resources=tuple(resources[:_MAX_RESOURCES]),
        source=source,
        account=str(doc.get("ownerId") or ""),
    )


def _parse_azure(doc: Mapping[str, Any], *, source: str) -> CloudSnapshot:
    """Azure ``List``-shape: ``{"value": [{id, type, properties}]}`` (read-only)."""
    resources: list[CloudResource] = []
    for index, item in enumerate(doc.get("value") or ()):
        if not isinstance(item, Mapping):
            continue
        properties = item.get("properties")
        flat = _flatten(properties if isinstance(properties, Mapping) else {})
        full_type = str(item.get("type") or "resource")
        kind = full_type.rsplit("/", 1)[-1]
        service = _azure_service_of(full_type)
        config: dict[str, Any] = {"type": kind}
        for key, value in flat.items():
            lowered = key.lower()
            if "publicaccess" in lowered or "publicnetworkaccess" in lowered:
                config["public"] = str(value).lower() in {"enabled", "true"}
            if "encryptionenabled" in lowered or lowered.endswith("encryption.enabled"):
                config["encrypted"] = bool(value)
            if "publicipaddress" in lowered or "publicnetworking" in lowered:
                config["publicly_accessible"] = str(value).lower() in {"enabled", "true"}
        resources.append(
            CloudResource(
                provider="azure",
                service=service,
                resource_id=str(item.get("name") or f"resource-{index}"),
                name=str(item.get("name") or ""),
                config=_bounded_config(config, source=source),
            )
        )
    return CloudSnapshot(
        provider="azure",
        resources=tuple(resources[:_MAX_RESOURCES]),
        source=source,
    )


def _azure_service_of(full_type: str) -> str:
    """``Microsoft.Storage/storageAccounts`` → ``storage`` (the policy service family).

    The namespace after ``Microsoft.``/``Microsoft.Network``-style prefix is the family
    the estate policies are written against; an unrecognized shape falls back to the
    resource type's last segment, lowercased.
    """
    namespace, _, _ = full_type.partition("/")
    if "." in namespace and namespace.lower().startswith(("microsoft.", "microsoftclassiccompute")):
        return namespace.split(".", 1)[1].lower()
    return full_type.rsplit("/", 1)[-1].lower()


def _parse_gcp(doc: Mapping[str, Any], *, source: str) -> CloudSnapshot:
    """GCP ``aggregatedList``-shape: ``{"items": {zone: {buckets|instances|...}}}``."""
    resources: list[CloudResource] = []
    items = doc.get("items")
    if isinstance(items, Mapping):
        for scope, families in items.items():
            if not isinstance(families, Mapping):
                continue
            for family, entries in families.items():
                if not isinstance(entries, list):
                    continue
                for index, entry in enumerate(entries[:64]):
                    if not isinstance(entry, Mapping):
                        continue
                    flat = _flatten(entry)
                    config: dict[str, Any] = {"type": family}
                    for key, value in flat.items():
                        if key.endswith("publicAccessPrevention"):
                            config["public"] = str(value).lower() in {"unspecified", "inherited"}
                        if key.endswith("publiclyAccessible"):
                            config["publicly_accessible"] = bool(value)
                        if ".iamPolicy" in key or key.endswith(".bindings"):
                            config["wildcard_actions"] = '"*"' in json.dumps(value, default=str)
                    name = str(entry.get("name") or f"{family}-{index}")
                    resources.append(
                        CloudResource(
                            provider="gcp",
                            service=str(family).rstrip("s") or "resource",
                            resource_id=name,
                            name=name,
                            region=str(scope),
                            config=_bounded_config(config, source=source),
                        )
                    )
    return CloudSnapshot(
        provider="gcp",
        resources=tuple(resources[:_MAX_RESOURCES]),
        source=source,
    )


def parse_snapshot_document(doc: Any, *, source: str = "<snapshot>") -> CloudSnapshot:
    """Parse a collected cloud-config document into a :class:`CloudSnapshot`.

    The normalized export (``provider`` + ``resources``) is the canonical shape; the AWS
    ``DescribeSecurityGroups``, Azure ``List`` and GCP ``aggregatedList`` read-only
    response shapes are recognized from their own markers so a provider API endpoint can
    be watched directly. Anything else is refused, never guessed.
    """
    if not isinstance(doc, Mapping):
        msg = f"{source}: a cloud-config snapshot must be a JSON object"
        raise ConfigurationError(msg)
    provider = str(doc.get("provider") or "").strip().lower()
    resources_raw = doc.get("resources")
    if provider and isinstance(resources_raw, list):
        if len(resources_raw) > _MAX_RESOURCES:
            msg = f"{source}: snapshot carries more than {_MAX_RESOURCES} resources"
            raise ConfigurationError(msg)
        resources = tuple(
            _resource_from_entry(entry, provider, source=source)
            for entry in resources_raw
            if isinstance(entry, Mapping)
        )
        return CloudSnapshot(
            provider=provider,
            resources=resources,
            source=source,
            account=str(doc.get("account") or ""),
        )
    if "securityGroups" in doc:
        return _parse_aws(doc, source=source)
    if "value" in doc and isinstance(doc.get("value"), list):
        return _parse_azure(doc, source=source)
    if "items" in doc and isinstance(doc.get("items"), Mapping):
        return _parse_gcp(doc, source=source)
    msg = (
        f"{source}: unrecognised snapshot shape — expected the normalized export "
        "(provider + resources) or an AWS/Azure/GCP read-only list response"
    )
    raise ConfigurationError(msg)


# --------------------------------------------------------------------------- drift


def diff_snapshots(
    baseline: Mapping[str, Mapping[str, Any]],
    snapshot: CloudSnapshot,
) -> tuple[ResourceDelta, ...]:
    """Diff a snapshot against the last baseline (REQ-POSTURE-001).

    ``baseline`` maps resource key → the stored row (``config``/``provider``/``service``).
    The result is sorted for determinism (removals, additions, then modifications, each
    alphabetical). A resource whose config is byte-identical produces nothing — the
    drift vocabulary is about *changes*, not about re-reporting the estate.
    """
    current = snapshot.by_key()
    deltas: list[ResourceDelta] = []
    removed = sorted(set(baseline) - set(current))
    added = sorted(set(current) - set(baseline))
    for key in removed:
        row = baseline[key]
        before = dict(row.get("config") or {})
        deltas.append(
            ResourceDelta(
                resource_key=key,
                change="removed",
                before=before,
                after=None,
                provider=str(row.get("provider") or snapshot.provider),
                service=str(row.get("service") or ""),
            )
        )
    for key in added:
        resource = current[key]
        deltas.append(
            ResourceDelta(
                resource_key=key,
                change="added",
                before=None,
                after=dict(resource.config),
                provider=resource.provider,
                service=resource.service,
            )
        )
    modified: list[ResourceDelta] = []
    for key in sorted(set(current) & set(baseline)):
        resource = current[key]
        before_row = baseline[key]
        before = dict(before_row.get("config") or {})
        after = dict(resource.config)
        if config_hash(before) == config_hash(after):
            continue
        changed = set(before) ^ set(after)
        for shared in set(before) & set(after):
            if canonical_config({"v": before[shared]}) != canonical_config({"v": after[shared]}):
                changed.add(shared)
        modified.append(
            ResourceDelta(
                resource_key=key,
                change="modified",
                before=before,
                after=after,
                changed_keys=tuple(sorted(changed)),
                provider=str(before_row.get("provider") or resource.provider),
                service=str(before_row.get("service") or resource.service),
            )
        )
    return tuple(deltas) + tuple(modified)


# --------------------------------------------------------------------------- policies


@dataclass(frozen=True, slots=True)
class PosturePolicy:
    """One estate policy as data (corpus section ``posture.policies``).

    ``key`` may be a dotted path into the (flattened) resource config; the policy fires
    when the value at that path equals ``equals``. ``service`` optionally narrows the
    rule to one service family (``storage``, ``database``, ``iam``, ``network``).
    """

    id: str
    severity: str
    key: str
    equals: Any
    service: str = ""
    hint: str = ""

    def matches(self, resource: CloudResource) -> bool:
        """Whether this policy applies to ``resource``: no service filter, or the
        resource's service (or its explicit ``type``) is the policy's."""
        if not self.service:
            return True
        return self.service in {resource.service, str(resource.config.get("type") or "")}


@dataclass(frozen=True, slots=True)
class PolicyViolation:
    """One resource's breach of one policy, with what the policy saw."""

    policy_id: str
    severity: str
    resource_key: str
    provider: str
    service: str
    observed: Any
    hint: str = ""

    def to_artifact(self) -> dict[str, Any]:
        return {
            "rule": self.policy_id,
            "severity_hint": self.severity,
            "resource": self.resource_key,
            "provider": self.provider,
            "service": self.service,
            "observed": self.observed,
        }


def config_violates(config: Mapping[str, Any], policy: PosturePolicy) -> bool:
    """Whether one (possibly flattened) resource config breaches ``policy``.

    The single predicate :func:`evaluate_policies` and the drift path share, so a delta
    finding's "the new state breaches X" and the point-in-time evaluation cannot disagree.
    """
    observed = _config_at(dict(config), policy.key)
    if observed is _MISSING:
        return False
    return canonical_config({"v": observed}) == canonical_config({"v": policy.equals})


def _config_at(config: Mapping[str, Any], key: str) -> Any:
    """The value a policy addresses: exact, dotted path, or a unique ``.key`` suffix.

    The suffix match is what lets a policy say ``public`` and hit a provider response
    that nests it (``nested.public``); when several different values share the suffix the
    lookup is ambiguous and refuses to fire — a policy must never breach on a guess.
    """
    if key in config:
        return config[key]
    flattened = _flatten(config)
    if key in flattened:
        return flattened[key]
    suffix = f".{key}"
    matches = {name: value for name, value in flattened.items() if name.endswith(suffix)}
    if not matches:
        return _MISSING
    values = {canonical_config({"v": value}) for value in matches.values()}
    if len(values) != 1:
        return _MISSING
    return next(iter(matches.values()))


_MISSING: Final = object()


def evaluate_policies(
    snapshot: CloudSnapshot,
    policies: Iterable[PosturePolicy],
) -> tuple[PolicyViolation, ...]:
    """Evaluate the estate policies over one snapshot (point-in-time posture).

    Order is deterministic: by resource key, then policy id. A policy that matches no
    resource is not an error — an empty estate passes.
    """
    violations: list[PolicyViolation] = []
    for resource in sorted(snapshot.resources, key=lambda item: item.key):
        for policy in policies:
            if not policy.matches(resource):
                continue
            if not config_violates(resource.config, policy):
                continue
            observed = _config_at(resource.config, policy.key)
            violations.append(
                PolicyViolation(
                    policy_id=policy.id,
                    severity=policy.severity,
                    resource_key=resource.key,
                    provider=resource.provider,
                    service=resource.service,
                    observed=observed,
                    hint=policy.hint,
                )
            )
    return tuple(violations)
