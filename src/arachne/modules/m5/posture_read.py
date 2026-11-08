"""Shared read-only machinery for the WP-32 posture families (REQ-DET-025).

WP-31's AWS family established the shape this module reuses for **Azure**, **GCP** and
**Kubernetes**: a *closed* operation allowlist, a client that refuses anything outside it, a
vault-supplied credential that never crosses the module boundary, one bounded enumeration per
policy, and a decoy-clean verdict. The three new providers differ from AWS only in the wire
details — they read JSON over a bearer token instead of XML/JSON over SigV4 — so the guard,
the client and the reporting shape live here once and each provider module supplies its own
operations and checks.

**Read-only is the control, and it is a closed allowlist.** Every call a family can make is one
entry of that family's frozen tuple of :class:`CloudReadOperation` records. The operation object
is the parameter: :meth:`CloudReadClient.get` refuses an object that is not a member of the
family's tuple, and :class:`CloudReadOperation` refuses a non-``GET`` method, a relative path or
an action name that does not open with a read verb at construction. "The scanner issued a
create/modify/delete call" is therefore unrepresentable rather than merely untested — which is
the deliverable the requirement's third bullet names, asserted by
``tests/unit/test_cloud_posture.py`` and, on the wire, against the fixture's own request log.

**Credentials come from the vault and never cross the module boundary.** A check declares
``requires_credentials=("cloud-token",)`` and calls the broker
(:meth:`~arachne.creds.broker.CredentialBroker.authorized_get`), which selects a credential of
that kind scoped to the endpoint URL, injects the bearer token into **one** request and hands
back a redacted exchange. No finding, evidence payload, detail string or log line in these
modules ever carries the token, which is what the integration test asserts against a planted
lab secret.

**The endpoint is declared, not guessed.** Each family reads a cloud target whose reference
names the read-only API base the operator's least-privilege credential is scoped to —
``azure-posture:<base>``, ``gcp-posture:<base>`` or ``k8s-posture:<base>``. The checks join
their operation's documented path onto that base; they never synthesise a per-service host from
a bare identifier, because guessing the host would make the scope gate depend on a guess rather
than on an operator declaration.

**Nothing is exhaustive.** One finding is established from the first page: each check
enumerates at most ``ARACHNE_M5_CLOUD_MAX_RESOURCES`` resources and stops, because "this
namespace is public" is decided by that namespace, not by the account's full inventory.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final
from urllib.parse import urlencode

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.core.vault import CLOUD_CREDENTIAL_KINDS
from arachne.modules.base import Asset, CheckMetadata, SeverityHint
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import http_or_skip, m5_candidate, skip

__all__ = [
    "MUTATION_VERBS",
    "READ_VERBS",
    "CloudReadClient",
    "CloudReadOperation",
    "CloudReadOperationError",
    "CloudRefusedError",
    "CloudReply",
    "base_for",
    "bool_of",
    "get",
    "items_of",
    "posture_metadata",
    "str_of",
    "text_of",
]

#: The action-name prefixes a read operation may carry. A family's operation names open with
#: the verb (``listStorageAccounts``, ``getNodeProxyConfigz``), so the guard can be a prefix
#: test rather than a substring one — a substring test would refuse an honest name such as
#: ``listAddressPools`` because it contains ``Add``.
READ_VERBS: Final[tuple[str, ...]] = (
    "list",
    "get",
    "read",
    "describe",
    "head",
    "query",
    "lookup",
    "search",
)

#: Mutation verbs refused by prefix. The list is deliberately broad, so a new
#: ``createSomething`` cannot slip into a table unnoticed; it is the readable half of the
#: allowlist test, which also asserts the closed tuples themselves.
MUTATION_VERBS: Final[tuple[str, ...]] = (
    "abort",
    "accept",
    "add",
    "allocate",
    "apply",
    "associate",
    "attach",
    "authorize",
    "cancel",
    "complete",
    "copy",
    "create",
    "delete",
    "deregister",
    "detach",
    "disable",
    "disassociate",
    "enable",
    "import",
    "insert",
    "invoke",
    "modify",
    "move",
    "patch",
    "post",
    "publish",
    "purge",
    "put",
    "reboot",
    "register",
    "release",
    "remove",
    "replace",
    "reset",
    "restore",
    "resume",
    "revoke",
    "rotate",
    "run",
    "schedule",
    "send",
    "set",
    "start",
    "stop",
    "tag",
    "terminate",
    "untag",
    "update",
    "upload",
    "withdraw",
)

#: The only HTTP method any of these families may use. A ``POST`` that merely names a read
#: action (GCP's ``getIamPolicy``, say) is still refused: the read surface these modules need
#: is available over ``GET``, and keeping the method closed is cheaper to verify than a
#: per-service exception.
_METHODS: Final[frozenset[str]] = frozenset({"GET"})


class CloudReadOperationError(ValueError):
    """An operation that is not a read, or not one this build knows, was requested."""


# --------------------------------------------------------------------------- operations
@dataclass(frozen=True, slots=True)
class CloudReadOperation:
    """One read-only provider API call, as a family's allowlist represents it.

    ``path`` is the documented path the family's base is joined onto and may carry ``{name}``
    placeholders the caller fills from a resource identifier or a configured project/
    subscription — the placeholders are data, never a verb. ``query`` is the operation's
    fixed parameters (an ``api-version``, a filter), encoded verbatim.
    """

    action: str
    path: str
    query: tuple[tuple[str, str], ...] = ()
    method: str = "GET"

    def __post_init__(self) -> None:
        if self.method not in _METHODS:
            msg = f"{self.action}: {self.method} is not a read method (GET only)"
            raise CloudReadOperationError(msg)
        lowered = self.action.lower()
        if not any(lowered.startswith(verb) for verb in READ_VERBS):
            msg = f"{self.action!r} does not open with a read verb"
            raise CloudReadOperationError(msg)
        if any(lowered.startswith(verb) for verb in MUTATION_VERBS):
            msg = f"{self.action!r} opens with a mutation verb and is unrepresentable"
            raise CloudReadOperationError(msg)
        if not self.path.startswith("/"):
            msg = f"{self.action}: path {self.path!r} must be absolute"
            raise CloudReadOperationError(msg)
        for name, _value in self.query:
            if not name:
                msg = f"{self.action}: a query parameter has no name"
                raise CloudReadOperationError(msg)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"


# --------------------------------------------------------------------------- reference
def base_for(value: str, *references: str) -> str | None:
    """The read-only API base a ``<reference>:<base>`` cloud target names, or ``None``.

    ``references`` are the accepted spellings (``azure-posture``, ``azure`` ...). A bare host
    is given an ``https://`` scheme; an explicit scheme is kept, so a loopback lab fixture can
    declare ``http://127.0.0.1:port``.
    """
    provider, separator, reference = value.strip().partition(":")
    if not separator or provider.lower() not in {name.lower() for name in references}:
        return None
    rest = reference.strip()
    if not rest:
        return None
    return rest if "://" in rest else f"https://{rest}"


# --------------------------------------------------------------------------- responses
class CloudRefusedError(RuntimeError):
    """A read could not be made: no credential, a refused credential or a failed call."""


@dataclass(frozen=True, slots=True)
class CloudReply:
    """One decoded answer: its status, the parsed document (``None`` on 404) and the
    redacted exchange the evidence carries."""

    action: str
    status: int
    data: Any
    exchange: Any = None

    @property
    def missing(self) -> bool:
        """True when the API answered "there is no such thing" (a 404 with no body)."""
        return self.status == 404 and self.data is None

    @property
    def failed(self) -> bool:
        """True when the call itself failed (a 5xx, a 4xx other than 404)."""
        return not 200 <= self.status < 300 and self.status != 404

    def mapping(self) -> Mapping[str, Any]:
        return self.data if isinstance(self.data, Mapping) else {}


# --------------------------------------------------------------------------- field access
def get(document: Any, *names: str, default: Any = None) -> Any:
    """The first value whose key matches one of ``names`` case-insensitively."""
    if not isinstance(document, Mapping):
        return default
    wanted = {name.lower() for name in names}
    for key, value in document.items():
        if str(key).lower() in wanted:
            return value
    return default


def text_of(document: Any, *names: str, default: str = "") -> str:
    """A scalar field as text (``""`` when it is absent or a container)."""
    value = get(document, *names)
    if value is None:
        return default
    if isinstance(value, (Mapping, list, tuple)):
        return default
    return str(value)


def str_of(document: Any, *names: str) -> str | None:
    """A scalar field as text, or ``None`` when it is absent or a container."""
    value = get(document, *names)
    if isinstance(value, (Mapping, list, tuple)) or value is None:
        return None
    return str(value)


def bool_of(document: Any, *names: str, default: bool | None = None) -> bool | None:
    value = get(document, *names)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "enabled"}:
            return True
        if lowered in {"false", "0", "no", "disabled", ""}:
            return False
    return default


def items_of(value: Any, *names: str) -> list[Mapping[str, Any]]:
    """``value`` (or the field ``names`` of it) as a list of mappings.

    Handles the shapes the three providers use: a bare list (Kubernetes' ``items``), a
    ``value``/``items`` envelope (Azure ARM, GCP), and a single mapping that is the only item.
    """
    found = value
    if names:
        found = get(value, *names)
        if found is None:
            found = value
    if isinstance(found, Mapping):
        nested = found.get("value", found.get("items"))
        if nested is not None and nested is not found:
            found = nested
    if not isinstance(found, Sequence) or isinstance(found, (str, bytes)):
        return []
    return [item for item in found if isinstance(item, Mapping)]


# --------------------------------------------------------------------------- the client
class CloudReadClient:
    """Issues read-only provider calls, bounded by one family's operation allowlist.

    The client owns no credential: every call goes through the broker's ``authorized_get``,
    which injects the bearer token into one request and returns a redacted exchange. What the
    client does own is the *guard*: the operation must be a member of the family's tuple, and
    the URL is built from that operation alone, so a check cannot smuggle a path or a query of
    its own invention into a call.
    """

    def __init__(
        self,
        ctx: CheckContext,
        base: str,
        *,
        operations: frozenset[CloudReadOperation],
        values: Mapping[str, str] | None = None,
    ) -> None:
        self.ctx = ctx
        self.base = base.rstrip("/")
        self.operations = operations
        self.values = dict(values or {})
        self.issued: list[str] = []

    def url_for(
        self,
        operation: CloudReadOperation,
        *,
        values: Mapping[str, str] | None = None,
        extra_query: Sequence[tuple[str, str]] = (),
    ) -> str:
        if operation not in self.operations:
            msg = f"{operation.action!r} is not a declared read operation"
            raise CloudReadOperationError(msg)
        filled = {**self.values, **(values or {})}
        path = operation.path.format(**filled) if "{" in operation.path else operation.path
        params: list[tuple[str, str]] = []
        for name, value in operation.query:
            params.append((name, value.format(**filled) if "{" in value else value))
        params.extend(extra_query)
        url = f"{self.base}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    async def get(
        self,
        operation: CloudReadOperation,
        *,
        values: Mapping[str, str] | None = None,
        extra_query: Sequence[tuple[str, str]] = (),
        required: bool = True,
    ) -> CloudReply:
        """Issue one read and decode its answer.

        ``required`` is the difference between "this is the call the check is about" (a
        failure is reported as a skip, because the posture cannot be told) and "this is one
        resource's sub-document" (a 404 is a fact about that resource and a mapping is
        returned with ``data=None``).
        """
        http, skipped = http_or_skip(self.ctx)
        if skipped is not None:
            raise CloudRefusedError(skipped.detail or "no HTTP client in this run")
        credentials = self.ctx.credentials
        if credentials is None:
            raise CloudRefusedError("no credential broker is wired for this step")
        url = self.url_for(operation, values=values, extra_query=extra_query)
        exchange = await credentials.authorized_get(http, url)
        if exchange is None:
            raise CloudRefusedError(
                "no cloud-token credential was released for this endpoint (unselected, "
                "unscoped or revoked); the refusal is on the audit trail"
            )
        self.issued.append(operation.action)
        status = int(exchange.status_code)
        if status in {401, 403}:
            raise CloudRefusedError(
                f"the API refused the credential (HTTP {status}); no unauthenticated "
                "fallback is attempted"
            )
        if status == 404:
            return CloudReply(action=operation.action, status=status, data=None, exchange=exchange)
        if not exchange.ok:
            if required:
                raise CloudRefusedError(
                    f"the API answered HTTP {status} for {operation.action}; the posture "
                    "cannot be established"
                )
            return CloudReply(action=operation.action, status=status, data=None, exchange=exchange)
        try:
            data = json.loads(exchange.body)
        except (json.JSONDecodeError, ValueError) as exc:
            if required:
                raise CloudRefusedError(
                    f"the answer to {operation.action} was not valid JSON: {exc}"
                ) from exc
            data = None
        return CloudReply(action=operation.action, status=status, data=data, exchange=exchange)


# --------------------------------------------------------------------------- observations
@dataclass(frozen=True, slots=True)
class Observation:
    """One policy breach on one resource — the unit a check emits."""

    policy: str
    resource: str
    detail: str
    observed: Mapping[str, Any] = field(default_factory=dict)
    severity: str = "medium"
    title: str = ""
    exchanges: tuple[Any, ...] = ()
    provider: str = ""


# --------------------------------------------------------------------------- base check
class PostureCheck:
    """A family's shared shape: resolve the base, get a client, evaluate, report.

    A concrete check declares its metadata, the provider tag, its scope area, the read actions
    it issues and an ``evaluate`` that returns observations. Everything else — the credential
    gate, the client construction, the skip wording and the candidate shape — lives here, so a
    family reads as a catalogue of provider mistakes rather than as thirty copies of a preamble.

    A plain mixin rather than a :class:`~arachne.modules.base.Module` subclass, for the same
    reason WP-31's ``_AwsPostureCheck`` is: the base refuses to be created without metadata and
    a family base has none of its own. A concrete check is declared
    ``class X(PostureCheck, EndpointCheck, Module)``.
    """

    metadata: ClassVar[CheckMetadata]
    #: The reference prefix this family accepts (``azure-posture`` and any alias).
    references: ClassVar[tuple[str, ...]] = ()
    #: The signal/family tag every finding carries, and the provider label in the artifact.
    family: ClassVar[str] = ""
    provider: ClassVar[str] = ""
    #: The scope area the requirement names — the check's owner.
    area: ClassVar[str] = ""
    #: The read actions this check may issue, in order (asserted against the allowlist).
    reads: ClassVar[tuple[CloudReadOperation, ...]] = ()
    #: The family's closed operation allowlist.
    operations: ClassVar[tuple[CloudReadOperation, ...]] = ()

    def supports(self, asset: Asset) -> bool:
        # ``super()`` resolves to ``EndpointCheck`` in a concrete check's MRO; mypy cannot see
        # a mixin's future siblings, hence the same ignore WP-31's check uses.
        return bool(super().supports(asset)) and base_for(asset.value, *self.references) is not None  # type: ignore[misc]

    def identity(self, ctx: CheckContext) -> tuple[dict[str, str], str | None]:
        """``(placeholders, skip reason)`` for the reference's own identifiers.

        A family whose paths need a project or a subscription fills them from configuration
        here; when the identifier is absent the check skips with its reason rather than
        guessing one, because a guessed identifier is a request to a resource the operator
        never declared.
        """
        return {}, None

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        raise NotImplementedError

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _http, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        base = base_for(ctx.asset.value, *self.references)
        if base is None:
            yield skip(
                ctx,
                f"no {self.family} base: declare a cloud target {self.references[0]}:<base> "
                "(the read-only API base the least-privilege credential is scoped to)",
            )
            return
        credentials = ctx.credentials
        if credentials is None or not credentials.selected_labels(CLOUD_CREDENTIAL_KINDS):
            yield skip(
                ctx,
                "no cloud-token credential selected: declare one with --credential and scope "
                "it to the API host (the checks never run unauthenticated)",
            )
            return
        values, reason = self.identity(ctx)
        if reason is not None:
            yield skip(ctx, reason)
            return
        client = CloudReadClient(ctx, base, operations=frozenset(self.operations), values=values)
        try:
            observations = await self.evaluate(ctx, client)
        except CloudRefusedError as exc:
            yield skip(ctx, str(exc))
            return
        if not observations:
            yield ctx.clean(
                self._clean_title(),
                detail=(
                    f"read {len(client.issued)} documented read-only operation(s) against the "
                    f"{self.provider} {self.area} surface; no breach of this policy found "
                    "(each enumeration is bounded at ARACHNE_M5_CLOUD_MAX_RESOURCES resources)"
                ),
            )
            return
        for index, observation in enumerate(observations[: _finding_cap(ctx)]):
            yield m5_candidate(
                ctx,
                observation.title
                or f"{self.provider} posture: {observation.policy} on {observation.resource}",
                artifact={
                    "signal": self.family,
                    "family": self.family,
                    "provider": observation.provider or self.provider,
                    "area": self.area,
                    "policy": observation.policy,
                    "resource": observation.resource,
                    "observed": dict(observation.observed),
                    "severity_hint": observation.severity,
                    # The two facts a reviewer needs to accept the finding as a *read*.
                    "operations": list(dict.fromkeys(client.issued)),
                    "read_only": True,
                    "state_changed": False,
                },
                exchanges=observation.exchanges,
                cwe=self.metadata.cwe,
                confidence=0.85,
                detail=observation.detail,
                source=f"{self.area}:{observation.resource}",
            )
            if index + 1 >= _finding_cap(ctx):
                break

    def _clean_title(self) -> str:
        return f"no {self.metadata.name.replace('-', ' ')} found"


def _finding_cap(ctx: CheckContext) -> int:
    return max(1, ctx.config.m5.max_findings_per_check)


def limit(ctx: CheckContext, items: Sequence[Any]) -> list[Any]:
    """Bound one enumeration: the first ``cloud_max_resources`` entries, in order."""
    return list(items[: max(1, ctx.config.m5.cloud_max_resources)])


def exchanges_of(*replies: CloudReply) -> tuple[Any, ...]:
    return tuple(reply.exchange for reply in replies if reply.exchange is not None)


def posture_metadata(
    *,
    name: str,
    title: str,
    description: str,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    compliance: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
) -> CheckMetadata:
    """One check's metadata: L1, safe, read-only, default-on, credential-gated."""
    return CheckMetadata(
        id=f"m5.{name}",
        module="M5",
        name=name,
        version="1.0",
        title=title,
        description=description,
        research_ref=research_ref,
        cwe=cwe,
        framework=framework,
        compliance=compliance,
        severity_hint=severity,
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        target_kinds=(TargetKind.CLOUD,),
        requires_active_checks=True,
        requires_credentials=("cloud-token",),
    )
