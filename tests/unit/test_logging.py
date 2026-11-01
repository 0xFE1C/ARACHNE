"""Structured logging tests (docs/spec/07- §4, F-08-01)."""

from __future__ import annotations

import json
import logging
import time
from io import StringIO

import pytest

from arachne.core.logging import JsonFormatter, configure_logging, get_logger

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def _record(**extras: object) -> logging.LogRecord:
    """Build a LogRecord the way a ``logger.info(..., extra={...})`` call does."""
    fields: dict[str, object] = {
        "name": "arachne.test",
        "levelno": logging.INFO,
        "levelname": "INFO",
        "pathname": __file__,
        "lineno": 1,
        "msg": "hello",
        "args": (),
        "exc_info": None,
        "created": time.time(),
    }
    fields.update(extras)
    return logging.makeLogRecord(fields)


def test_json_formatter_envelope() -> None:
    payload = json.loads(JsonFormatter().format(_record()))

    assert payload["level"] == "INFO"
    assert payload["logger"] == "arachne.test"
    assert payload["message"] == "hello"
    assert payload["ts"].endswith("+00:00")


def test_json_formatter_includes_extra_fields() -> None:
    payload = json.loads(JsonFormatter().format(_record(msg="x", event="http.request", status=200)))
    assert payload["event"] == "http.request"
    assert payload["status"] == 200


def test_json_formatter_redacts_message_and_extras() -> None:
    record = _record(msg="leaked %s", args=(AWS_KEY,), body=f"key={AWS_KEY}")
    payload = json.loads(JsonFormatter().format(record))
    assert AWS_KEY not in json.dumps(payload)
    assert "[REDACTED" in payload["message"]


def test_exception_info_is_summarized_without_a_traceback() -> None:
    try:
        raise ValueError(f"boom {AWS_KEY}")
    except ValueError:
        import sys

        record = _record(msg="failed", exc_info=sys.exc_info())
    payload = json.loads(JsonFormatter().format(record))

    assert payload["error_type"] == "ValueError"
    assert "Traceback" not in json.dumps(payload)
    assert AWS_KEY not in json.dumps(payload)


def test_non_serializable_extra_values_do_not_break_logging() -> None:
    payload = json.loads(JsonFormatter().format(_record(msg="x", weird=object())))
    assert "weird" in payload  # rendered via default=str


def test_configure_logging_is_idempotent_and_redacts() -> None:
    stream = StringIO()
    configure_logging("DEBUG", json_output=True, stream=stream)
    configure_logging("DEBUG", json_output=True, stream=stream)  # second call replaces

    root = logging.getLogger("arachne")
    assert len(root.handlers) == 1
    assert root.propagate is False

    get_logger("unit").info("token=%s", AWS_KEY)
    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    assert AWS_KEY not in lines[0]
    assert json.loads(lines[0])["logger"] == "arachne.unit"


def test_get_logger_namespaces_non_arachne_names() -> None:
    assert get_logger("thing").name == "arachne.thing"
    assert get_logger("arachne.core.x").name == "arachne.core.x"


def test_configure_logging_rejects_unknown_level() -> None:
    with pytest.raises(ValueError, match="unknown log level"):
        configure_logging("LOUD")


def test_text_formatter_still_redacts() -> None:
    stream = StringIO()
    configure_logging("INFO", json_output=False, stream=stream)
    try:
        get_logger("unit").warning("secret %s", AWS_KEY)
    finally:
        configure_logging("INFO", json_output=True)
    assert AWS_KEY not in stream.getvalue()
