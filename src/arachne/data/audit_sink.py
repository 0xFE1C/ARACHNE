"""Audit sink that persists events in the ``audit_log`` table (F-01-08).

Kept in :mod:`arachne.data` so the core layer stays storage-agnostic: the client emits
:class:`~arachne.core.audit.AuditEvent` objects and never learns where they go. Like
every sink, failures are logged and swallowed — an unusable audit table must not abort a
scan in progress.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import AuditEvent
from arachne.core.logging import get_logger
from arachne.data.models import AuditLog

__all__ = ["SqlAuditSink"]

_logger = get_logger("data.audit_sink")


class SqlAuditSink:
    """Append audit events as rows in ``audit_log``.

    The S25 hash-chain fields are written to their own columns (so a verifier can walk the
    chain with one ordered query) and removed from ``meta_json``, which keeps the
    serialized event identical to the payload the chain hashed: verification rebuilds the
    event from ``action`` + ``meta_json`` and recomputes
    :func:`~arachne.core.integrity.chain_digest` over exactly what was signed.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def record(self, event: AuditEvent) -> None:
        try:
            self._store(event)
        except Exception as exc:
            _logger.error(
                "failed to persist audit event",
                extra={
                    "event": "audit.sink_error",
                    "action": event.action.value,
                    "error": str(exc),
                },
            )

    def _store(self, event: AuditEvent) -> None:
        meta: dict[str, Any] = dict(event.to_dict())
        meta.pop("action", None)
        with self._session_factory() as session:
            session.add(
                AuditLog(
                    ts=event.ts,
                    actor=event.actor,
                    action=event.action.value,
                    meta_json=meta,
                    seq=event.seq,
                    prev_hash=event.prev_hash,
                    hash=event.hash,
                    signature=event.signature,
                )
            )
            session.commit()
