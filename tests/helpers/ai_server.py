"""A stdlib, loopback-only OpenAI-compatible endpoint for the AI tests.

The AI integration tests have to exercise the *real* HTTP path — the scope gate, the auth
header, the JSON body, the structured-output request — without a model and without a network
dependency. This server is the smallest thing that is honest about that: it speaks
``POST /v1/chat/completions``, records every request body, and answers with a scripted,
schema-valid object for whichever stage the schema identifies.

It can also be told to fail after N requests (``fail_after``), which is how the "kill the
provider mid-scan" test drives the degradation chain, and to answer with unparseable text
(``garbage``), which is how the repair path is reached.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from tests.helpers.ai import DEFAULT_ANSWERS

#: ``schema property → stage``; the same rule the fake provider uses, applied to the wire body.
_STAGE_BY_PROPERTY: dict[str, str] = {
    "fp_likely": "triage",
    "key_facts": "explain",
    "steps": "remediate",
    "shared_root_cause": "correlate",
    "order": "prioritize",
}


def _user_text(body: dict[str, Any]) -> str:
    """The request's user-role content, as one string (where the evidence markers live)."""
    messages = body.get("messages")
    if isinstance(messages, list):
        return "\n".join(
            str(message.get("content") or "") for message in messages if isinstance(message, dict)
        )
    contents = body.get("contents")
    if isinstance(contents, list):
        return "\n".join(str(part) for part in contents)
    return ""


def _cited(body: dict[str, Any], stage: str, answer: dict[str, Any]) -> dict[str, Any]:
    """Add the citation the stage's schema requires (WP-15, REQ-AGENT-008).

    The ids come from the request body's own evidence markers, so this endpoint behaves like a
    model that read the prompt: if the prompt carries no evidence, no citation is produced and
    the stage must be refused by the engine — which is the behaviour the tests assert.
    """
    if stage not in {"triage", "explain", "remediate", "narrative", "correlate"}:
        return answer
    text = _user_text(body)
    ids = list(dict.fromkeys(_EVIDENCE_RE.findall(text)))
    return {**answer, "evidence_ids": ids[:2]}


_EVIDENCE_RE = re.compile(r"\[evidence\s+([^\]\s]+)\]")


def _stage_of_body(body: dict[str, Any]) -> str:
    schema = ((body.get("response_format") or {}).get("json_schema") or {}).get("schema") or {}
    properties = schema.get("properties") or {}
    keys = set(properties) if isinstance(properties, dict) else set()
    for hint, stage in _STAGE_BY_PROPERTY.items():
        if hint in keys:
            return stage
    if "narrative" in keys:
        return "narrative"
    return "unknown"


@dataclass
class FakeOpenAI:
    """A running fake endpoint. ``base_url`` is ``http://127.0.0.1:<port>/v1``."""

    answers: dict[str, dict[str, Any]] = field(default_factory=lambda: dict(DEFAULT_ANSWERS))
    #: Answer requests from this 1-based index onwards with HTTP 500 (a provider that died).
    fail_after: int | None = None
    #: Answer the first N requests with prose instead of JSON (no object at all).
    garbage_calls: int = 0
    #: Override the HTTP status (e.g. 429 or 401) to exercise the transport's mapping.
    status: int = 200
    requests: list[dict[str, Any]] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = None
    _thread: threading.Thread | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> FakeOpenAI:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b"{}"
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = {"unparseable": True}
                if not isinstance(body, dict):
                    body = {"body": body}
                owner.requests.append(
                    {
                        "path": self.path,
                        "headers": {key.lower(): value for key, value in self.headers.items()},
                        "body": body,
                    }
                )
                self._respond(body)

            def do_GET(self) -> None:
                self._send(200, {"status": "ok"})

            def _respond(self, body: dict[str, Any]) -> None:
                index = len(owner.requests)
                if owner.fail_after is not None and index >= owner.fail_after:
                    self._send(500, {"error": {"message": "the model endpoint went away"}})
                    return
                if owner.status != 200:
                    self._send(owner.status, {"error": {"message": f"status {owner.status}"}})
                    return
                if index <= owner.garbage_calls:
                    self._send(
                        200,
                        {
                            "choices": [
                                {"message": {"content": "I am not going to answer in JSON."}}
                            ],
                            "usage": {
                                "prompt_tokens": 10,
                                "completion_tokens": 5,
                                "total_tokens": 15,
                            },
                        },
                    )
                    return
                stage = _stage_of_body(body)
                answer = owner.answers.get(stage)
                if answer is None:
                    self._send(200, {"choices": [{"message": {"content": "{}"}}]})
                    return
                self._send(
                    200,
                    {
                        "id": "chatcmpl-test",
                        "object": "chat.completion",
                        "model": body.get("model", "fake-model"),
                        "choices": [
                            {
                                "index": 0,
                                "finish_reason": "stop",
                                "message": {
                                    "role": "assistant",
                                    "content": json.dumps(_cited(body, stage, answer)),
                                },
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 120,
                            "completion_tokens": 40,
                            "total_tokens": 160,
                        },
                    },
                )

            def _send(self, status: int, payload: dict[str, Any]) -> None:
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return None

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None

    def __enter__(self) -> FakeOpenAI:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # ------------------------------------------------------------------ accessors
    @property
    def port(self) -> int:
        assert self._server is not None, "the fake endpoint is not running"
        return int(self._server.server_address[1])

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def stages(self) -> list[str]:
        return [_stage_of_body(request["body"]) for request in self.requests]
