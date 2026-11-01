"""Recorded-response replay (vcrpy-style).

Live network calls in ARACHNE are optional; the tests, and an offline demonstration run,
must work against **recorded** third-party responses. A recording is plain JSON — a list of
``{method, url, status, headers, body}`` entries — so it is reviewable in a pull request and
diffable when a provider changes shape, which a binary cassette is not.

This module is deliberately free of any HTTP library (ADR-05): it only produces
:class:`~arachne.core.http.RecordedResponse` values, and ``core.http.fixture_transport``
turns them into a transport. That keeps "one module imports httpx" true even in
fixture mode.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from arachne.core.errors import ConfigurationError
from arachne.core.http import RecordedResponse

__all__ = [
    "FIXTURE_ADDRESS",
    "FixtureReplay",
    "load_fixture_routes",
]

#: The address a fixture-mode resolver returns for every host. The transport never dials, so
#: this value is only classified by the URL safety policy; it is a public documentation-range
#: address (RFC 5737 style, real but uninteresting) so the policy's private/loopback rules
#: do not have to be relaxed to run a replay.
FIXTURE_ADDRESS = "93.184.216.34"


def _routes_from_document(data: Any, *, source: str) -> dict[str, RecordedResponse]:
    """Parse one fixture document into ``{"METHOD url": RecordedResponse}``."""
    entries: list[Any]
    if isinstance(data, Mapping) and "responses" in data:
        raw = data["responses"]
        if not isinstance(raw, list):
            msg = f"{source}: 'responses' must be a list"
            raise ConfigurationError(msg)
        entries = list(raw)
    elif isinstance(data, list):
        entries = list(data)
    elif isinstance(data, Mapping):
        # Shorthand form: {"GET https://host/path": {"status": 200, "body": "..."}}
        entries = [
            dict(value, method=key.split(" ", 1)[0], url=key.split(" ", 1)[1])
            if isinstance(value, Mapping) and "url" not in value
            else value
            for key, value in data.items()
        ]
    else:
        msg = f"{source}: expected a mapping or a list of recorded responses"
        raise ConfigurationError(msg)

    routes: dict[str, RecordedResponse] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            msg = f"{source}: entry {index} is not a mapping"
            raise ConfigurationError(msg)
        if "url" not in entry or "method" not in entry:
            msg = f"{source}: entry {index} needs 'method' and 'url'"
            raise ConfigurationError(msg)
        recorded = RecordedResponse.from_dict(entry)
        routes[f"{recorded.method} {recorded.url}"] = recorded
    if not routes:
        msg = f"{source}: no recorded responses found"
        raise ConfigurationError(msg)
    return routes


def load_fixture_routes(path: str | Path) -> dict[str, RecordedResponse]:
    """Load recorded responses from a ``.json`` file or a directory of them."""
    resolved = Path(path).expanduser()
    if resolved.is_dir():
        files = sorted(resolved.glob("*.json"))
        if not files:
            msg = f"OSINT fixture directory {resolved} contains no .json recordings"
            raise ConfigurationError(msg)
    elif resolved.is_file():
        files = [resolved]
    else:
        msg = f"OSINT fixture path {resolved} does not exist"
        raise ConfigurationError(msg)

    routes: dict[str, RecordedResponse] = {}
    for fixture in files:
        try:
            data = json.loads(fixture.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"{fixture}: not valid JSON: {exc}") from exc
        except UnicodeDecodeError as exc:
            # A binary or wrongly-encoded file is a fixture-authoring mistake, and it must be
            # reported like one instead of surfacing a codec traceback to the operator.
            raise ConfigurationError(f"{fixture}: not a UTF-8 text file: {exc}") from exc
        except OSError as exc:
            raise ConfigurationError(f"cannot read {fixture}: {exc}") from exc
        routes.update(_routes_from_document(data, source=str(fixture)))
    return routes


class FixtureReplay:
    """A set of recorded responses, ready to be handed to the shared client."""

    def __init__(self, routes: Mapping[str, Any]) -> None:
        self._responses: tuple[RecordedResponse, ...] = tuple(
            item if isinstance(item, RecordedResponse) else RecordedResponse.from_dict(item)
            for item in routes.values()
        )
        if not self._responses:
            msg = "a fixture replay needs at least one recorded response"
            raise ConfigurationError(msg)

    def responses(self) -> tuple[RecordedResponse, ...]:
        return self._responses

    def address(self) -> tuple[str, ...]:
        """The addresses fixture-mode name resolution returns (the transport never dials)."""
        return (FIXTURE_ADDRESS,)

    def urls(self) -> tuple[str, ...]:
        return tuple(response.url for response in self._responses)
