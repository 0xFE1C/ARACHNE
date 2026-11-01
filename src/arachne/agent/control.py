"""The agent's client side: how an ``arachne agent`` talks to its deployment (S16).

A :class:`ControlPlane` is the four verbs of the agent protocol — register, heartbeat,
lease, complete — and there are exactly two implementations:

* :class:`HttpControlPlane` — the remote agent's path: calls to the deployment's
  ``/api/v1/agent`` routes, authenticated with an existing API key (a scanner-role key;
  REQ-SCALE-004). The key label is what the deployment records, and the agent never
  gains more than a scanner can do. The requests go through the one scoped HTTP client
  (ADR-05) with a scope pinned to exactly the deployment's host — the agent's own
  egress is as auditable and as bounded as a scan's.
* :class:`DirectControlPlane` — an agent embedded in the same process as its store
  (tests, and a single-host deployment that runs the worker next to the database). It
  calls :class:`~arachne.agent.service.AgentService` directly and converts to the same
  DTOs, so the loop above it cannot tell the two apart.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import urlsplit

from arachne.core.config import Settings
from arachne.core.errors import ControlPlaneError
from arachne.core.http import ScopedHttpClient
from arachne.core.safety import Scope
from arachne.data.queue_store import QueueEntry

if TYPE_CHECKING:
    from arachne.agent.service import AgentService

__all__ = [
    "AgentLease",
    "ControlPlane",
    "DirectControlPlane",
    "HttpControlPlane",
    "lease_from_payload",
    "lease_payload",
]

#: API version prefix every agent route lives under.
_AGENT_PREFIX = "/api/v1/agent"


@dataclass(frozen=True, slots=True)
class AgentLease:
    """One scan an agent holds the lease for (JSON-friendly, dialect-free)."""

    scan_id: int
    attempts: int = 1
    project_id: int | None = None
    schedule_id: str | None = None
    previous_scan_id: int | None = None
    requested_by: str | None = None


def lease_payload(entry: QueueEntry) -> dict[str, Any]:
    """Serialize a queue entry onto the wire (the lease route's response body)."""
    return {
        "scan_id": entry.scan_id,
        "attempts": entry.attempts,
        "project_id": entry.project_id,
        "schedule_id": entry.schedule_id,
        "previous_scan_id": entry.previous_scan_id,
        "requested_by": entry.requested_by,
    }


def lease_from_payload(payload: dict[str, Any]) -> AgentLease:
    """The client-side inverse of :func:`lease_payload` (strict about the shape)."""
    try:
        return AgentLease(
            scan_id=int(payload["scan_id"]),
            attempts=int(payload.get("attempts") or 1),
            project_id=payload.get("project_id"),
            schedule_id=payload.get("schedule_id"),
            previous_scan_id=payload.get("previous_scan_id"),
            requested_by=payload.get("requested_by"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        msg = f"the deployment returned a malformed lease: {exc}"
        raise ControlPlaneError(msg) from exc


class ControlPlane(Protocol):
    """The four agent verbs, over HTTP or in-process."""

    async def register(
        self,
        name: str,
        *,
        node: str | None = None,
        version: str | None = None,
        concurrency: int | None = None,
    ) -> dict[str, Any]: ...

    async def heartbeat(self, name: str) -> dict[int, bool]:
        """Renew the agent's held leases; ``False`` for a scan it must abort."""
        ...

    async def lease(self, name: str, *, cap: int, ttl_s: float) -> tuple[AgentLease, ...]: ...

    async def complete(self, name: str, scan_id: int) -> bool: ...

    async def close(self) -> None: ...


class HttpControlPlane:
    """The remote agent's control plane: API-key authenticated calls to the deployment.

    Egress goes through :class:`~arachne.core.http.ScopedHttpClient` (ADR-05: one HTTP
    path), with the scope pinned to exactly the deployment's host. The policy, resolver
    and transport come from the agent's own settings unless a caller overrides them —
    an agent inside a private network talking to an internal API runs with the same
    ``ARACHNE_ALLOW_PRIVATE_IPS`` posture it scans with, and every control call leaves
    an ``http.request`` audit line on the agent side too.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        settings: Settings | None = None,
        transport: Any = None,
        resolver: Any = None,
        policy: Any = None,
        auditor: Any = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        host = urlsplit(self._base).hostname or ""
        if not host:
            msg = f"the deployment URL {base_url!r} has no host"
            raise ControlPlaneError(msg)
        effective = settings or Settings()
        self._client = ScopedHttpClient(
            settings=effective,
            scope=Scope(allowed_hosts=(host,)),
            policy=policy if policy is not None else effective.safety.policy,
            resolver=resolver,
            auditor=auditor,
            transport=transport,
        )

    async def register(
        self,
        name: str,
        *,
        node: str | None = None,
        version: str | None = None,
        concurrency: int | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": name}
        if node is not None:
            payload["node"] = node
        if version is not None:
            payload["version"] = version
        if concurrency is not None:
            payload["concurrency"] = concurrency
        data = await self._post("register", payload)
        return dict(data.get("agent") or {})

    async def heartbeat(self, name: str) -> dict[int, bool]:
        data = await self._post("heartbeat", {"name": name})
        renewals = data.get("renewals") or {}
        try:
            return {int(scan_id): bool(ok) for scan_id, ok in dict(renewals).items()}
        except (TypeError, ValueError) as exc:
            msg = f"the deployment returned a malformed heartbeat: {exc}"
            raise ControlPlaneError(msg) from exc

    async def lease(self, name: str, *, cap: int, ttl_s: float) -> tuple[AgentLease, ...]:
        data = await self._post("lease", {"name": name, "cap": cap, "ttl_s": ttl_s})
        leases = data.get("leases") or []
        return tuple(lease_from_payload(item) for item in leases)

    async def complete(self, name: str, scan_id: int) -> bool:
        data = await self._post("complete", {"name": name, "scan_id": scan_id})
        return bool(data.get("released"))

    async def close(self) -> None:
        await self._client.aclose()

    async def _post(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload)
        try:
            exchange = await self._client.post(
                f"{self._base}{_AGENT_PREFIX}/{action}",
                headers={"Content-Type": "application/json", "x-api-key": self._api_key},
                content=body,
                follow_redirects=False,
            )
        except ControlPlaneError:
            raise
        except Exception as exc:
            msg = f"the control plane is unreachable ({action}): {exc}"
            raise ControlPlaneError(msg) from exc
        if exchange.status_code != 200:
            detail = ""
            try:
                detail = str(json.loads(exchange.body).get("error", {}).get("message", ""))
            except ValueError:  # pragma: no cover - a non-JSON error body
                detail = exchange.body[:200]
            msg = f"{action} refused with {exchange.status_code}: {detail}"
            raise ControlPlaneError(msg)
        try:
            data: dict[str, Any] = json.loads(exchange.body)
        except ValueError as exc:
            msg = f"the deployment returned a non-JSON {action} response"
            raise ControlPlaneError(msg) from exc
        return data


class DirectControlPlane:
    """In-process control plane over :class:`~arachne.agent.service.AgentService`."""

    def __init__(self, service: AgentService, *, principal: str = "local") -> None:
        self._service = service
        self._principal = principal

    async def register(
        self,
        name: str,
        *,
        node: str | None = None,
        version: str | None = None,
        concurrency: int | None = None,
    ) -> dict[str, Any]:
        record = self._service.register(
            name,
            principal=self._principal,
            node=node,
            version=version,
            concurrency=concurrency,
        )
        return record.to_dict()

    async def heartbeat(self, name: str) -> dict[int, bool]:
        return dict(self._service.heartbeat(name, principal=self._principal))

    async def lease(self, name: str, *, cap: int, ttl_s: float) -> tuple[AgentLease, ...]:
        entries = self._service.lease(
            name, principal=self._principal, cap=cap, ttl_s=ttl_s
        )
        return tuple(
            AgentLease(
                scan_id=entry.scan_id,
                attempts=entry.attempts,
                project_id=entry.project_id,
                schedule_id=entry.schedule_id,
                previous_scan_id=entry.previous_scan_id,
                requested_by=entry.requested_by,
            )
            for entry in entries
        )

    async def complete(self, name: str, scan_id: int) -> bool:
        return bool(self._service.complete(name, int(scan_id), principal=self._principal))

    async def close(self) -> None:
        return None
