"""The operator kill switch (REQ-AGENT-007).

"An operator kill switch MUST pause/abort agentic expansion mid-scan leaving a resumable
state." Three properties make that true, and they are why this is a tiny file and not a
subsystem:

**The stop is out-of-band.** A scan may be running on another node, in another process, owned by
another user. The switch is therefore a *file* both sides can reach (``ARACHNE_HYPOTHESIS_CONTROL``,
default ``.arachne/hypothesis-control.json`` beside the scheduler's state file), written by
``arachne reason pause|resume|abort`` and by the API, read by the running step between
hypotheses. No shared memory, no IPC, no queue — the same "one small durable artefact" pattern
as the scheduler's state and S15's write-ahead ledger.

**The granule is one hypothesis.** The step checks the switch before *each* proposal, so a stop
lands between two probes: an in-flight check finishes (and its result is recorded), and nothing
new starts. That is what "mid-scan" has to mean if the stop is not itself to lose work.

**Resumable by construction.** Pausing or aborting writes nothing but the journal state; the
journal already holds the proposals and the cursor (see :mod:`arachne.reasoning.model`), so
``arachne scan --resume`` continues at the next unexecuted hypothesis. The switch is *cleared* by
the resume, so a single pause does not stop every later run.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from arachne.core.logging import get_logger

__all__ = [
    "ControlDirective",
    "HypothesisControl",
    "MemoryHypothesisControl",
    "NullControl",
    "build_hypothesis_control",
]

_logger = get_logger("reasoning.control")

#: What the operator asked a scan to do. ``none`` is the absence of a directive.
ControlDirective = Literal["none", "pause", "abort"]

#: The default path (working-directory relative, like ``.arachne/schedules.json``).
DEFAULT_CONTROL_PATH = ".arachne/hypothesis-control.json"


class NullControl(Protocol):
    """The read side every caller uses: one question, one answer."""

    def directive(self, scan_id: int) -> ControlDirective: ...


@dataclass
class MemoryHypothesisControl:
    """An in-process switch (tests, and a single-process deployment that wants one anyway)."""

    directives: dict[int, ControlDirective] = field(default_factory=dict)
    #: ``True`` applies the directive to every scan id (the "stop everything" case).
    global_directive: ControlDirective = "none"

    def directive(self, scan_id: int) -> ControlDirective:
        if self.global_directive != "none":
            return self.global_directive
        return self.directives.get(scan_id, "none")

    def set(self, scan_id: int, directive: ControlDirective) -> None:
        if directive == "none":
            self.directives.pop(scan_id, None)
            return
        self.directives[scan_id] = directive

    def clear(self, scan_id: int) -> None:
        self.directives.pop(scan_id, None)
        if self.global_directive != "none":
            self.global_directive = "none"


@dataclass
class HypothesisControl:
    """A file-backed kill switch both an operator and a running scan can reach."""

    path: Path
    #: Set by the resume path: one pause stops one run, not every later one.
    clear_on_resume: bool = True

    @classmethod
    def at(cls, path: str | Path | None = None) -> HypothesisControl:
        target = Path(path).expanduser() if path else Path(DEFAULT_CONTROL_PATH)
        return cls(path=target)

    # ------------------------------------------------------------------ read
    def directive(self, scan_id: int) -> ControlDirective:
        document = self._read()
        per_scan = document.get("scans")
        if isinstance(per_scan, dict):
            value = per_scan.get(str(scan_id))
            if value == "pause" or value == "abort":
                return "pause" if value == "pause" else "abort"
        directive = document.get("directive")
        if directive == "pause" or directive == "abort":
            return "pause" if directive == "pause" else "abort"
        return "none"

    # ------------------------------------------------------------------ write
    def set(self, scan_id: int | None, directive: ControlDirective) -> ControlDirective:
        """Record a directive. ``scan_id=None`` sets the deployment-wide one."""
        document = self._read()
        if scan_id is None:
            document["directive"] = directive
        else:
            per_scan = document.setdefault("scans", {})
            assert isinstance(per_scan, dict)
            if directive == "none":
                per_scan.pop(str(scan_id), None)
            else:
                per_scan[str(scan_id)] = directive
        self._write(document)
        return directive

    def clear(self, scan_id: int | None = None) -> None:
        """Forget a directive (the resume path calls this, so a pause is not permanent)."""
        document = self._read()
        if scan_id is None:
            document["directive"] = "none"
            document["scans"] = {}
        else:
            per_scan = document.get("scans")
            if isinstance(per_scan, dict):
                per_scan.pop(str(scan_id), None)
        self._write(document)

    # ------------------------------------------------------------------ storage
    def _read(self) -> dict[str, Any]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return {}
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            # A corrupt switch must not stop a scan: an unreadable file means "no directive",
            # which is the safe direction here (the switch only ever *stops* work).
            _logger.warning(
                "hypothesis control file is not valid JSON; ignoring it",
                extra={"event": "hypothesis.control_corrupt", "path": str(self.path)},
            )
            return {}
        return document if isinstance(document, dict) else {}

    def _write(self, document: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(document, indent=2, sort_keys=True) + "\n"
        self.path.write_text(payload, encoding="utf-8")


def build_hypothesis_control(path: str | None = None) -> HypothesisControl:
    """The deployment's kill switch (a file; the default path when none is configured)."""
    return HypothesisControl.at(path or DEFAULT_CONTROL_PATH)
