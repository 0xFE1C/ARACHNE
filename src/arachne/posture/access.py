"""The continuous-posture capability boundary (S23, REQ-POSTURE-001).

Like :class:`arachne.proof.access.ProofAccess` for the proof ladder, :class:`PostureAccess`
is what a check gets instead of the store: exactly one scope key (the asset it was built
for — a check cannot read another target's baseline), the deployment's drift switch, and
two verbs — read the last baseline, commit the snapshot just collected. Committing is the
*write*, and it is always the pair "diff was computed from what I read, then replaced by
what I saw", so a baseline can never silently advance past a run that reported nothing.

Every commit is audited (``posture.baseline_saved``, and ``posture.drift`` when the diff
was non-empty), so a continuous schedule's activity is in the trail even when its findings
are not.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.posture.state import CloudSnapshot, ResourceDelta, diff_snapshots

__all__ = ["PostureAccess"]


class PostureAccess:
    """What one check may do against the drift baseline of one scope — nothing more."""

    def __init__(
        self,
        store: Any,
        *,
        scope_key: str,
        auditor: Auditor | None = None,
        scan_id: int | str | None = None,
        drift_enabled: bool = True,
        clock: Any = None,
    ) -> None:
        self._store = store
        self.scope_key = scope_key
        self._auditor = auditor
        self._scan_id = scan_id
        self._drift_enabled = drift_enabled
        self._clock = clock or datetime.now

    @property
    def available(self) -> bool:
        """True when a baseline store is wired (``None``/absent store ⇒ stateless run)."""
        return self._store is not None

    @property
    def drift_enabled(self) -> bool:
        return self._drift_enabled

    # ------------------------------------------------------------------ read
    def baseline_map(self) -> dict[str, dict[str, Any]]:
        """``resource_key → {config, provider, service}`` for this scope's last baseline."""
        if not self.available:
            return {}
        return {
            record.resource_key: {
                "config": dict(record.config),
                "provider": record.provider,
                "service": record.service,
            }
            for record in self._store.baselines(self.scope_key)
        }

    # ------------------------------------------------------------------ write
    def observe(self, snapshot: CloudSnapshot) -> tuple[ResourceDelta, ...]:
        """One continuous observation: diff against the last baseline, then commit.

        The scope's **first** observation commits the baseline and reports no deltas —
        the estate appearing wholesale is the baseline being established, not drift.
        Every later observation diffs first (so the deltas describe what *was*) and then
        replaces the baseline (so the next run compares against what *is*).
        """
        if not self.available or not self._drift_enabled:
            return ()
        baseline = self.baseline_map()
        if not baseline:
            self.commit(snapshot, ())
            return ()
        deltas = diff_snapshots(baseline, snapshot)
        self.commit(snapshot, deltas)
        return deltas

    def commit(
        self,
        snapshot: CloudSnapshot,
        deltas: tuple[ResourceDelta, ...],
    ) -> int:
        """Replace this scope's baseline with ``snapshot``; audit the act. Returns rows."""
        if not self.available:
            return 0
        saved: int = int(self._store.save_baselines(self.scope_key, snapshot))
        if self._auditor is not None:
            self._auditor.record(
                AuditAction.POSTURE_BASELINE_SAVED,
                target=self.scope_key,
                scan_id=self._scan_id,
                meta={
                    "resources": saved,
                    "deltas": len(deltas),
                    "provider": snapshot.provider,
                },
            )
            if deltas:
                self._auditor.record(
                    AuditAction.POSTURE_DRIFT,
                    outcome=AuditOutcome.ALLOWED,
                    target=self.scope_key,
                    scan_id=self._scan_id,
                    meta={
                        "changes": [
                            {"resource": delta.resource_key, "change": delta.change}
                            for delta in deltas
                        ],
                    },
                )
        return saved
