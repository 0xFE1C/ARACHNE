"""Structured JSON logging .

Every log line is a single JSON object with a stable envelope, so log pipelines can
index fields without regex parsing. Secret redaction is applied by the formatter, which
means *every* handler configured through :func:`configure_logging` is safe by
construction (F-08-01): a secret passed as a log argument can never reach an output
stream.

Field layout::

    {"ts": "...", "level": "INFO", "logger": "arachne.core.http", "message": "...",
     "event": "http.request", ...arbitrary extra fields...}
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, Final

from arachne.core.redaction import redact_value

__all__ = ["JsonFormatter", "configure_logging", "get_logger"]

#: Attributes present on every ``logging.LogRecord``; anything else was passed via
#: ``extra=`` and is emitted as a top-level JSON field.
_RESERVED_ATTRS: Final[frozenset[str]] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class JsonFormatter(logging.Formatter):
    """Render a log record as a single redacted JSON object."""

    def __init__(self, *, include_extras: bool = True) -> None:
        super().__init__()
        self._include_extras = include_extras

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if self._include_extras:
            for key, value in record.__dict__.items():
                if key in _RESERVED_ATTRS or key.startswith("_"):
                    continue
                payload[key] = value
        if record.exc_info and record.exc_info[0] is not None:
            # Type and message only: a traceback can embed target data and secrets.
            payload["error_type"] = record.exc_info[0].__name__
            payload["error_message"] = str(record.exc_info[1])
        # Redaction happens last so it covers the message, the extras and the error text.
        return json.dumps(redact_value(payload), default=str, ensure_ascii=False)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced ARACHNE logger."""
    return logging.getLogger(name if name.startswith("arachne") else f"arachne.{name}")


def configure_logging(
    level: str = "INFO",
    *,
    json_output: bool = True,
    stream: Any = None,
) -> None:
    """Install the ARACHNE root handler.

    Idempotent: calling it twice replaces the previously installed handler instead of
    duplicating output. ``json_output=False`` selects a human-readable format for
    interactive CLI use — redaction still applies, because it lives in the formatter
    contract on both paths.
    """
    numeric_level = logging.getLevelNamesMapping().get(level.upper())
    if numeric_level is None:
        msg = f"unknown log level: {level!r}"
        raise ValueError(msg)

    handler = logging.StreamHandler(stream or sys.stderr)
    if json_output:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(_RedactingTextFormatter())

    root = logging.getLogger("arachne")
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric_level)
    root.propagate = False


class _RedactingTextFormatter(logging.Formatter):
    """Human-readable formatter that also redacts the rendered line."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        redacted = redact_value(rendered)
        return redacted if isinstance(redacted, str) else str(redacted)
