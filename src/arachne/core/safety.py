"""SSRF-by-design URL safety (F-08-03) and the deny-by-default scope guard (F-01-02).

Nothing leaves the process without passing through :func:`validate_url`: the scheme is
checked against an allowlist, the host is checked against the declared scope, and every
address the host resolves to is checked against a private/reserved range policy. A URL
that fails any check raises :class:`~arachne.core.errors.UnsafeUrlError` or
:class:`~arachne.core.errors.OutOfScopeError` and is audited.

Two types live here:

* :func:`validate_url` — the per-request gate used by the shared HTTP client.
* :class:`Scope` — the compiled, checkable form of "what this scan may touch". S2 compiles
  a scan's target definition (plus its exclusions, F-01-01) into a ``Scope``; the scope is
  the only thing the request path consults, so a scan cannot widen itself at runtime.
  ``Scope`` understands four allow dimensions (exact hosts/globs, domain suffixes, CIDR
  networks, URL prefixes) and the matching exclusion dimensions, and an **empty scope
  allows nothing**.

Threat model handled here: a target that returns ``Location: http://169.254.169.254/`` or
``http://127.0.0.1:8080/admin`` in a redirect, or that is reachable through an
ambiguous IP encoding (``http://2130706433/``) or a DNS name resolving to internal
space. Resolution happens *before* the request, and because the HTTP client follows
redirects hop by hop (``follow_redirects=False`` internally), every hop is validated
the same way — including re-resolving the host, which is what defeats a rebinding
response.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Protocol
from urllib.parse import urlsplit

from arachne.core.errors import ConfigurationError, OutOfScopeError, UnsafeUrlError

#: An IPv4 or IPv6 network, as returned by :func:`ipaddress.ip_network`.
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

__all__ = [
    "DEFAULT_ALLOWED_SCHEMES",
    "HostResolver",
    "ResolvedUrl",
    "Scope",
    "ScopeDecision",
    "SocketResolver",
    "StaticResolver",
    "UrlSafetyPolicy",
    "classify_ip",
    "host_in_domain",
    "host_matches_glob",
    "is_valid_hostname",
    "normalize_host",
    "ref_matches",
    "subnet_of",
    "url_under_prefix",
    "validate_url",
]

DEFAULT_ALLOWED_SCHEMES: Final[frozenset[str]] = frozenset({"http", "https"})

#: Hostname suffixes that always resolve to internal names in practice; blocking them
#: costs nothing and removes a whole class of SSRF mistakes.
_INTERNAL_HOST_SUFFIXES: Final[tuple[str, ...]] = (
    ".localhost",
    ".local",
    ".internal",
    ".home.arpa",
    ".lan",
    ".intranet",
)

#: Cloud metadata endpoints that must never be reachable through a scan.
_METADATA_HOSTS: Final[frozenset[str]] = frozenset(
    {"metadata.google.internal", "metadata.goog", "instance-data", "metadata"}
)

_AMBIGUOUS_IP_HOST: Final[re.Pattern[str]] = re.compile(r"^(?:0[xX][0-9a-fA-F]+|[0-9]+)$")
_HOSTNAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?$"
)


@dataclass(frozen=True, slots=True)
class UrlSafetyPolicy:
    """Policy applied to every target-supplied URL."""

    allowed_schemes: frozenset[str] = DEFAULT_ALLOWED_SCHEMES
    allow_private_ips: bool = False
    allow_loopback: bool = False
    allow_link_local: bool = False


@dataclass(frozen=True, slots=True)
class ResolvedUrl:
    """A validated URL plus the addresses it resolved to."""

    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...] = field(default_factory=tuple)

    @property
    def host_port(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def origin(self) -> str:
        return f"{self.scheme}://{self.host_port}"


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    allowed: bool
    reason: str


def normalize_host(host: str) -> str:
    """Lower-case a host, drop a single trailing dot, keep it otherwise verbatim.

    Shared by the scope guard and the target model so the two can never disagree about
    what ``Example.COM.`` refers to.
    """
    return host.strip().lower().rstrip(".")


def host_matches_glob(host: str, pattern: str) -> bool:
    """Match ``host`` against a literal host or a ``*.`` subdomain glob.

    ``*.example.com`` matches subdomains only — never the apex. That asymmetry is
    deliberate: an operator who means "example.com and everything under it" writes both
    ``example.com`` and ``*.example.com``, or uses a domain entry, which does mean both.
    """
    candidate = normalize_host(pattern)
    if not candidate:
        return False
    normalized = normalize_host(host)
    if candidate.startswith("*."):
        return normalized.endswith(f".{candidate[2:]}")
    return normalized == candidate


def host_in_domain(host: str, domain: str) -> bool:
    """Match ``host`` against a domain suffix: the apex itself *or* a subdomain."""
    candidate = normalize_host(domain).lstrip("*").lstrip(".")
    if not candidate:
        return False
    normalized = normalize_host(host)
    return normalized == candidate or normalized.endswith(f".{candidate}")


def is_valid_hostname(host: str) -> bool:
    """True for a syntactically valid DNS name (an IP literal is *not* a hostname)."""
    normalized = normalize_host(host)
    if not normalized or not _HOSTNAME_RE.match(normalized):
        return False
    return not _is_ip_literal(normalized)


def url_under_prefix(url: str, prefix: str) -> bool:
    """True when ``url`` is ``prefix`` or lives below it.

    The comparison is on normalized text (lower-case scheme and host, default port made
    explicit, trailing-slash-insensitive for the bare origin), which is enough to make
    ``https://Example.COM/api`` and ``https://example.com:443/api/v1`` compare equal.
    It is deliberately **not** a substring test: ``/api`` must not match ``/apiary``.
    """
    normalized_url = _normalize_url_for_prefix(url)
    normalized_prefix = _normalize_url_for_prefix(prefix)
    if not normalized_url or not normalized_prefix:
        return False
    if normalized_url == normalized_prefix:
        return True
    return normalized_url.startswith(normalized_prefix.rstrip("/") + "/")


def _normalize_url_for_prefix(url: str) -> str:
    """Scheme+host+port and path, lower-cased where the spec says it is case-insensitive."""
    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = normalize_host(parts.hostname or "")
    if not scheme or not host:
        return ""
    try:
        explicit_port = parts.port
    except ValueError:
        return ""
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    default_port = 443 if scheme == "https" else 80
    authority = host if port == default_port else f"{host}:{port}"
    path = parts.path or "/"
    return f"{scheme}://{authority}{path}"


def _host_of_ref(value: str) -> str | None:
    """The host of a Git reference in URL or scp-like form."""
    if "://" in value:
        return normalize_host(urlsplit(value).hostname or "") or None
    if "@" in value and ":" in value:
        return normalize_host(value.split("@", 1)[1].split(":", 1)[0]) or None
    return None


def subnet_of(inner: IPNetwork, outer: IPNetwork) -> bool:
    """Version-safe ``inner.subnet_of(outer)`` (IPv4/IPv6 are never compared)."""
    if isinstance(inner, ipaddress.IPv4Network) and isinstance(outer, ipaddress.IPv4Network):
        return inner.subnet_of(outer)
    if isinstance(inner, ipaddress.IPv6Network) and isinstance(outer, ipaddress.IPv6Network):
        return inner.subnet_of(outer)
    return False


def ref_matches(pattern: str, value: str) -> bool:
    """Match a Git/cloud reference against a pattern: exact, or a trailing ``*`` prefix."""
    candidate = pattern.strip()
    if not candidate:
        return False
    if candidate.endswith("*"):
        return value.startswith(candidate[:-1])
    return value == candidate


def _parse_networks(networks: tuple[str, ...], *, field_name: str) -> tuple[IPNetwork, ...]:
    """Parse CIDR strings, raising a configuration error naming the offending value."""
    parsed: list[IPNetwork] = []
    for entry in networks:
        raw = entry.strip()
        if not raw:
            continue
        try:
            parsed.append(ipaddress.ip_network(raw, strict=False))
        except ValueError as exc:
            raise ConfigurationError(f"{field_name}: {raw!r} is not a valid CIDR network") from exc
    return tuple(parsed)


def _address_in(networks: tuple[IPNetwork, ...], host: str) -> bool:
    """True when ``host`` is an IP literal inside one of ``networks``."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in networks)


class HostResolver(Protocol):
    """Resolves a hostname to addresses (injectable for tests)."""

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        """Return the addresses ``host`` resolves to. Raise ``OSError`` on failure."""
        ...


class SocketResolver:
    """Default resolver: ``getaddrinfo`` off the event loop."""

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        def _resolve() -> tuple[str, ...]:
            infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
            seen: dict[str, None] = {}
            for info in infos:
                seen.setdefault(str(info[4][0]), None)
            return tuple(seen)

        return await asyncio.to_thread(_resolve)


class StaticResolver:
    """Test resolver returning a fixed address set (or raising)."""

    def __init__(self, addresses: tuple[str, ...] | dict[str, tuple[str, ...]]) -> None:
        self._addresses = addresses

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        if isinstance(self._addresses, dict):
            if host not in self._addresses:
                msg = f"no DNS record for {host}"
                raise OSError(msg)
            return self._addresses[host]
        return self._addresses


@dataclass(frozen=True, slots=True)
class Scope:
    """Deny-by-default allowlist of what a scan may contact (F-01-01/02/09).

    Four allow dimensions, matched independently:

    ``allowed_hosts``
        exact hostnames and ``*.`` subdomain globs (``*.example.com`` is subdomains only).
    ``allowed_domains``
        domain suffixes — the apex *and* every subdomain (``example.com`` covers
        ``example.com`` and ``api.example.com``).
    ``allowed_networks``
        CIDR ranges, matched against IP-literal hosts (a declared range is an explicit
        statement about addresses, never about names: a hostname that happens to resolve
        into the range is still out of scope — deny by default).
    ``url_prefixes``
        URL prefixes, as declared by a URL target (``https://host/api/`` scopes the path,
        not only the host). A URL is allowed when it sits under a declared prefix *or*
        when its host matches one of the host/domain/network dimensions: every dimension
        is one of the operator's declarations, so the allowlist is exactly what was
        declared and never wider.
    ``allowed_refs``
        Git and cloud references (``https://github.com/org/repo.git``, ``aws:123456789012``,
        or a trailing-``*`` prefix such as ``aws:*``). A reference has no host to check, so
        it needs its own dimension for a deployment allowlist to be able to express it.

    :meth:`check_value` is the dispatcher the orchestrator and the step context use: give
    it a target kind and value and it applies the right dimension. An unknown kind is
    denied (fail closed).

    An empty scope allows nothing. ``excluded_*`` always wins over any allow, because
    exclusions are part of the target definition the operator signed off on (F-01-01).
    """

    allowed_hosts: tuple[str, ...] = ()
    allowed_domains: tuple[str, ...] = ()
    excluded_hosts: tuple[str, ...] = ()
    allowed_networks: tuple[str, ...] = ()
    excluded_domains: tuple[str, ...] = ()
    excluded_networks: tuple[str, ...] = ()
    url_prefixes: tuple[str, ...] = ()
    excluded_url_prefixes: tuple[str, ...] = ()
    allowed_refs: tuple[str, ...] = ()
    excluded_refs: tuple[str, ...] = ()
    #: Local artifact roots (S29, REQ-DEPTH-005): the filesystem prefixes an *offline*
    #: artifact check may read. A separate dimension for the same reason ``allowed_refs`` is
    #: one: an artifact has no host, so no host-shaped rule can express it, and an operator
    #: must be able to grant exactly one build directory rather than "the filesystem".
    allowed_artifacts: tuple[str, ...] = ()
    excluded_artifacts: tuple[str, ...] = ()
    #: Parsed ``allowed_networks``; derived, never passed in (see ``__post_init__``).
    _networks: tuple[IPNetwork, ...] = field(default=(), init=False, repr=False, compare=False)
    _excluded_networks_parsed: tuple[IPNetwork, ...] = field(
        default=(), init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        # Validate and pre-parse once: a scope is constructed from operator input, so a
        # typo in a CIDR must fail at the boundary, not silently allow nothing at request
        # time. ``object.__setattr__`` is how a frozen slots dataclass derives fields.
        object.__setattr__(
            self, "_networks", _parse_networks(self.allowed_networks, field_name="allowed_networks")
        )
        object.__setattr__(
            self,
            "_excluded_networks_parsed",
            _parse_networks(self.excluded_networks, field_name="excluded_networks"),
        )

    @classmethod
    def deny_all(cls) -> Scope:
        """The default: nothing is in scope."""
        return cls()

    @classmethod
    def from_hosts(cls, hosts: list[str] | tuple[str, ...]) -> Scope:
        return cls(allowed_hosts=tuple(hosts))

    @property
    def is_empty(self) -> bool:
        """True when no dimension can allow anything (the deny-by-default state)."""
        allows = (
            self.allowed_hosts,
            self.allowed_domains,
            self.allowed_networks,
            self.url_prefixes,
            self.allowed_refs,
            self.allowed_artifacts,
        )
        return not any(allows)

    def describe(self) -> dict[str, list[str]]:
        """JSON-safe summary of the declared dimensions (used in plans and reports)."""
        return {
            "allowed_hosts": list(self.allowed_hosts),
            "allowed_domains": list(self.allowed_domains),
            "allowed_networks": list(self.allowed_networks),
            "url_prefixes": list(self.url_prefixes),
            "allowed_refs": list(self.allowed_refs),
            "allowed_artifacts": list(self.allowed_artifacts),
            "excluded_hosts": list(self.excluded_hosts),
            "excluded_domains": list(self.excluded_domains),
            "excluded_networks": list(self.excluded_networks),
            "excluded_url_prefixes": list(self.excluded_url_prefixes),
            "excluded_refs": list(self.excluded_refs),
            "excluded_artifacts": list(self.excluded_artifacts),
        }

    # ------------------------------------------------------------------ matching
    def _exclusion_reason(self, host: str) -> str | None:
        """Return the exclusion that covers ``host``, or ``None``."""
        if any(host_matches_glob(host, pattern) for pattern in self.excluded_hosts):
            return "host is explicitly excluded"
        if any(host_in_domain(host, domain) for domain in self.excluded_domains):
            return "domain is explicitly excluded"
        if _address_in(self._excluded_networks_parsed, host):
            return "address is inside an excluded network"
        return None

    def _exclusion_reason_url(self, url: str) -> str | None:
        if any(url_under_prefix(url, prefix) for prefix in self.excluded_url_prefixes):
            return "url is inside an excluded URL prefix"
        return None

    def check(self, host: str) -> ScopeDecision:
        """Decide whether ``host`` (a name or an IP literal) may be contacted."""
        if self.is_empty:
            return ScopeDecision(False, "scope is empty (deny by default)")
        normalized = normalize_host(host)
        if not normalized:
            return ScopeDecision(False, "missing host")
        excluded = self._exclusion_reason(normalized)
        if excluded is not None:
            return ScopeDecision(False, excluded)
        if any(host_matches_glob(normalized, pattern) for pattern in self.allowed_hosts):
            return ScopeDecision(True, "host allowlisted")
        if any(host_in_domain(normalized, domain) for domain in self.allowed_domains):
            return ScopeDecision(True, "domain allowlisted")
        if _address_in(self._networks, normalized):
            return ScopeDecision(True, "address is inside an allowed network")
        return ScopeDecision(False, "host is not in the declared scope")

    def check_url(self, url: str) -> ScopeDecision:
        """Decide whether ``url`` may be requested (the request path's entry point).

        Exclusions are evaluated first so that "excluded" is always the reported reason
        even when the URL would otherwise be allowed; then a declared URL prefix allows
        the URL; otherwise host/domain/network matching decides. Denying when nothing
        matches is what keeps the scope an allowlist.
        """
        if self.is_empty:
            return ScopeDecision(False, "scope is empty (deny by default)")
        host = normalize_host(urlsplit(url).hostname or "")
        if not host:
            return ScopeDecision(False, "missing host")
        excluded = self._exclusion_reason(host) or self._exclusion_reason_url(url)
        if excluded is not None:
            return ScopeDecision(False, excluded)
        if any(url_under_prefix(url, prefix) for prefix in self.url_prefixes):
            return ScopeDecision(True, "url prefix allowlisted")
        return self.check(host)

    def check_network(self, value: str) -> ScopeDecision:
        """Decide whether a CIDR target may be scanned.

        A network is allowed only when it sits *inside* a declared network: a declared
        range is an address-space boundary, and a target spilling past it is not the range
        the operator authorized. An exclusion denies a network only when it covers the
        whole target — excluding one address inside a declared range is a normal (and
        supported) case, and the per-address exclusion still applies to every request
        through :meth:`check`.
        """
        if self.is_empty:
            return ScopeDecision(False, "scope is empty (deny by default)")
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return ScopeDecision(False, "unparseable network")
        for excluded in self._excluded_networks_parsed:
            if subnet_of(network, excluded):
                return ScopeDecision(False, "network is entirely inside an excluded network")
        for allowed in self._networks:
            if subnet_of(network, allowed):
                return ScopeDecision(True, "network is inside an allowed network")
        return ScopeDecision(False, "network is not in the declared scope")

    def check_ref(self, value: str) -> ScopeDecision:
        """Decide whether a Git/cloud reference (a target with no host) is allowed."""
        if self.is_empty:
            return ScopeDecision(False, "scope is empty (deny by default)")
        if any(ref_matches(pattern, value) for pattern in self.excluded_refs):
            return ScopeDecision(False, "reference is explicitly excluded")
        if any(ref_matches(pattern, value) for pattern in self.allowed_refs):
            return ScopeDecision(True, "reference allowlisted")
        return ScopeDecision(False, "reference is not in the declared scope")

    def check_artifact(self, path: str) -> ScopeDecision:
        """Decide whether a local artifact path may be read by an offline check.

        Path-prefix semantics, the filesystem analogue of ``url_prefixes``: a declared root
        grants the artifacts *under* it, and nothing else. Comparison is on the normalised
        path, so ``/srv/builds`` and ``/srv/builds/`` are the same grant while ``/srv/builds2``
        is not covered by either. An exclusion inside a granted root always wins.
        """
        if self.is_empty:
            return ScopeDecision(False, "scope is empty (deny by default)")
        candidate = os.path.normpath(str(Path(path.strip()).expanduser()))
        if not candidate.startswith(os.sep):
            return ScopeDecision(False, "artifact path is not absolute")
        for excluded in self.excluded_artifacts:
            root = os.path.normpath(str(Path(excluded).expanduser())).rstrip("/")
            if candidate == root or candidate.startswith(f"{root}/"):
                return ScopeDecision(False, "artifact is inside an excluded path")
        for allowed in self.allowed_artifacts:
            root = os.path.normpath(str(Path(allowed).expanduser())).rstrip("/")
            if candidate == root or candidate.startswith(f"{root}/"):
                return ScopeDecision(True, "artifact path allowlisted")
        return ScopeDecision(False, "artifact is not in the declared scope")

    def check_value(self, kind: str, value: str) -> ScopeDecision:
        """Decide whether a value of a given target/asset ``kind`` may be contacted.

        The single dispatcher used by the orchestrator's plan-time gate and by the step
        context when it records a discovered asset, so the two can never disagree. An
        unknown kind is denied: fail closed.
        """
        if kind == "url":
            return self.check_url(value)
        if kind in {"host", "domain", "domain_pattern", "ip"}:
            return self.check(value)
        if kind in {"cidr", "network"}:
            return self.check_network(value)
        if kind == "git":
            decision = self.check_ref(value)
            if decision.allowed:
                return decision
            host = _host_of_ref(value)
            if host is not None:
                return self.check(host)
            return decision
        if kind == "cloud":
            return self.check_ref(value)
        if kind == "artifact":
            return self.check_artifact(value)
        return ScopeDecision(False, f"unsupported target kind {kind!r}")


def classify_ip(ip: str, policy: UrlSafetyPolicy | None = None) -> str | None:
    """Return a block reason for ``ip``, or ``None`` when it is acceptable.

    Order matters: ``ipaddress`` reports several categories at once (``::1`` is loopback,
    private *and* reserved; ``169.254.169.254`` is link-local and private), and the most
    specific — the one an operator needs in the audit log — must win. ``reserved`` is
    checked before ``private`` so ``240.0.0.0/4`` is reported as reserved rather than
    lumped in with RFC1918 space, and the metadata address is never described as merely
    "private".
    """
    policy = policy or UrlSafetyPolicy()
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "unparseable-address"

    if address.is_unspecified:
        return "unspecified-address"
    if address.is_loopback:
        # Symmetric between families (REQ-DET-007). ``ipaddress`` reports ``::1`` as
        # *reserved* as well as loopback (``127.0.0.1`` is not reserved), so falling through
        # to the reserved check made the explicit ``allow_loopback`` opt-in cover IPv4 and
        # silently not IPv6. The default is unchanged: without the opt-in both are refused,
        # and the reason stays the most specific one.
        return None if policy.allow_loopback else "loopback-address"
    if address.is_link_local and not policy.allow_link_local:
        return "link-local-address"
    if address.is_multicast:
        return "multicast-address"
    if address.is_reserved:
        return "reserved-address"
    if address.is_private and not policy.allow_private_ips:
        return "private-address"
    return None


def _normalize_host(raw_host: str, *, policy: UrlSafetyPolicy) -> tuple[str, str | None]:
    """Validate a hostname literal; return ``(host, block_reason)``."""
    host = raw_host.strip().lower()
    if not host:
        return host, "missing-host"
    if host.endswith("."):
        host = host.rstrip(".")

    if "\\" in host or "%" in host or any(ch.isspace() for ch in host):
        return host, "malformed-host"
    if host in _METADATA_HOSTS:
        return host, "metadata-endpoint"
    for suffix in _INTERNAL_HOST_SUFFIXES:
        if host == suffix.lstrip(".") or host.endswith(suffix):
            return host, "internal-hostname"
    if _AMBIGUOUS_IP_HOST.match(host):
        # 2130706433 / 0x7f000001 style encodings bypass naive string checks.
        return host, "ambiguous-ip-encoding"

    if "[" in host or "]" in host:  # IPv6 literal as it appears inside a URL
        try:
            address = ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
        except ValueError:
            return host, "malformed-host"
        return str(address), None

    try:
        return str(ipaddress.ip_address(host)), None
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(host):
        return host, "malformed-host"
    return host, None


async def validate_url(
    url: str,
    scope: Scope | None = None,
    *,
    policy: UrlSafetyPolicy | None = None,
    resolver: HostResolver | None = None,
) -> ResolvedUrl:
    """Validate a target-supplied URL; raise on any policy violation.

    Steps: parse → scheme allowlist → host sanity → scope allowlist → DNS resolution →
    per-address range policy. Returns the resolved URL so the caller can record exactly
    what was contacted.
    """
    effective_policy = policy or UrlSafetyPolicy()
    effective_scope = scope if scope is not None else Scope.deny_all()
    effective_resolver: HostResolver = resolver or SocketResolver()

    if not url or url.strip() != url or any(ch.isspace() for ch in url):
        raise UnsafeUrlError("URL contains whitespace or is empty", url=url, reason="malformed-url")

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in effective_policy.allowed_schemes:
        raise UnsafeUrlError(
            f"URL scheme {scheme or '(none)'!r} is not allowed",
            url=url,
            reason="scheme-not-allowed",
        )

    host, block = _normalize_host(parts.hostname or "", policy=effective_policy)
    if block is not None:
        raise UnsafeUrlError(f"URL host rejected: {block}", url=url, reason=block)

    try:
        explicit_port = parts.port
    except ValueError as exc:
        raise UnsafeUrlError("URL port is invalid", url=url, reason="invalid-port") from exc
    # `port or default` would silently turn an explicit :0 into the scheme default.
    port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise UnsafeUrlError("URL port out of range", url=url, reason="invalid-port")

    if _is_ip_literal(host):
        # Literal addresses are classified before the scope check so an operator always
        # gets the specific reason ("private-address", "loopback-address", ...) even for a
        # host that was not declared in scope.
        literal_reason = classify_ip(host, effective_policy)
        if literal_reason is not None:
            raise UnsafeUrlError(
                f"address {host} is out of policy ({literal_reason})",
                url=url,
                reason=literal_reason,
            )

    decision = effective_scope.check_url(url)
    if not decision.allowed:
        raise OutOfScopeError(
            f"host {host!r} is not in scope: {decision.reason}",
            url=url,
            reason=decision.reason,
        )

    if _is_ip_literal(host):
        addresses: tuple[str, ...] = (host,)
    else:
        # Names are resolved only after the scope check: an out-of-scope host must not
        # even generate a DNS query.
        try:
            addresses = await effective_resolver.resolve(host, port)
        except OSError as exc:
            raise UnsafeUrlError(
                f"DNS resolution failed for {host!r}",
                url=url,
                reason="dns-failure",
            ) from exc
        if not addresses:
            raise UnsafeUrlError(
                f"host {host!r} resolved to no addresses",
                url=url,
                reason="dns-empty",
            )

    for address in addresses:
        reason = classify_ip(address, effective_policy)
        if reason is not None:
            raise UnsafeUrlError(
                f"host {host!r} resolves to blocked address {address} ({reason})",
                url=url,
                reason=reason,
            )

    return ResolvedUrl(url=url, scheme=scheme, host=host, port=port, addresses=tuple(addresses))


def _is_ip_literal(host: str) -> bool:
    """True when ``host`` is already an IP address (no DNS lookup needed)."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
