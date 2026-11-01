"""Structured output: four mechanisms, one validator (F-04-03).

The spec's table is "how each provider class is *asked*"; this module is the **one place the
answer is judged**. Whatever mechanism a provider used — ``json_object``, ``json_schema``,
tool-use, ``responseMimeType``, Ollama's ``format``, or a grammar — the text lands here, is
parsed tolerantly (models wrap JSON in prose and code fences, and some prepend a sentence),
and is validated against the **pydantic model of the stage**. Every path in the engine ends at
:func:`validate`, so "structured output validates against the schema" is a property of one
function rather than of seven adapters.

Three deliberate properties:

* **The schema is generated from the model, not maintained beside it.** A stage declares a
  pydantic model and this module derives the JSON schema from it, so the schema a provider is
  given and the validator that checks the answer cannot disagree.
* **Parsing is tolerant; validation is not.** Fences, leading prose and trailing commas are
  recovered (a model that produced the right object with a fence around it is not a failure);
  a missing or mistyped field is.
* **The repair attempt gets the error, not the whole prompt again.** The budget allows
  one retry with a repair prompt; sending the validator's complaint back is what makes that
  retry worth its tokens.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from pydantic import BaseModel, ValidationError

from arachne.ai.types import StructuredOutputError

__all__ = [
    "SchemaSpec",
    "balanced_slice",
    "extract_json",
    "normalize_schema",
    "parse_structured",
    "repair_prompt",
    "validate",
]

_FENCE_RE: Final = re.compile(r"^\s*```[A-Za-z0-9_+\-]*\s*|\s*```\s*$")
_TRAILING_COMMA_RE: Final = re.compile(r",\s*([}\]])")


@dataclass(frozen=True, slots=True)
class SchemaSpec:
    """One stage's output contract: a name, a pydantic model, and the derived JSON schema."""

    name: str
    model: type[BaseModel]

    @property
    def json_schema(self) -> dict[str, Any]:
        """The provider-facing JSON schema, derived from the model."""
        return normalize_schema(self.model.model_json_schema())

    @property
    def schema_version(self) -> str:
        """A short, stable digest of the schema (recorded as provenance)."""
        import hashlib

        payload = json.dumps(self.json_schema, sort_keys=True)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]


def normalize_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Make a generated schema acceptable to strict providers (OpenAI ``strict``, Gemini).

    Three structural transformations, no semantic ones: every object gets
    ``additionalProperties: false`` (what "strict" mode requires), pydantic's ``title`` noise
    is dropped, and so are ``description`` strings. The last one is deliberate on two counts:
    a pydantic docstring is written for a maintainer, not a model (and ours embed internal
    commentary), and every description is prompt tokens paid on every call. The *meaning* of a
    field belongs in the prompt template, which has a version and a hash; the schema is the
    constraint. ``$defs``/``anyOf`` are preserved because a strict provider enforces them.
    """
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key in {"title", "description"}:
            continue
        if key == "properties" and isinstance(value, Mapping):
            out["properties"] = {str(name): normalize_schema(prop) for name, prop in value.items()}
            out.setdefault("additionalProperties", False)
            continue
        if key == "items" and isinstance(value, Mapping):
            out["items"] = normalize_schema(value)
            continue
        if key in {"anyOf", "oneOf", "allOf"} and isinstance(value, list):
            out[key] = [normalize_schema(item) for item in value if isinstance(item, Mapping)]
            continue
        if key == "$defs" and isinstance(value, Mapping):
            out[key] = {str(name): normalize_schema(item) for name, item in value.items()}
            continue
        out[key] = value
    if out.get("type") == "object":
        out.setdefault("additionalProperties", False)
    return out


def balanced_slice(text: str, start: int, opener: str, closer: str) -> str | None:
    """The balanced ``opener..closer`` slice starting at ``start`` (string-aware).

    A hand-written scanner rather than a regex: nesting, quoted strings and escapes are exactly
    where a regex stops working, and the input is model-generated text.
    """
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == opener:
            depth += 1
        elif character == closer:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def extract_json(text: str | None) -> Any:
    """Parse the JSON object in ``text``, tolerating fences, prose and trailing commas."""
    if text is None:
        msg = "the provider returned no text"
        raise StructuredOutputError(msg)
    candidate = _FENCE_RE.sub("", text.strip()).strip()
    for attempt in (candidate, _TRAILING_COMMA_RE.sub(r"\1", candidate)):
        try:
            return json.loads(attempt)
        except (ValueError, TypeError):
            pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = candidate.find(opener)
        if start < 0:
            continue
        window = balanced_slice(candidate, start, opener, closer)
        if window is None:
            continue
        for attempt in (window, _TRAILING_COMMA_RE.sub(r"\1", window)):
            try:
                return json.loads(attempt)
            except (ValueError, TypeError):
                continue
    raise StructuredOutputError(
        "the provider's answer contains no parseable JSON object "
        f"(first 120 characters: {candidate[:120]!r})"
    )


def validate(payload: Any, spec: SchemaSpec) -> dict[str, Any]:
    """Validate ``payload`` against the stage's model and return the normalized mapping."""
    if not isinstance(payload, Mapping):
        raise StructuredOutputError(
            f"stage {spec.name}: expected a JSON object, got {type(payload).__name__}"
        )
    try:
        model = spec.model.model_validate(dict(payload))
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise StructuredOutputError(
            f"stage {spec.name}: output does not match the schema: {'; '.join(parts)}"
        ) from exc
    return model.model_dump(mode="json")


def parse_structured(text: str, spec: SchemaSpec) -> dict[str, Any]:
    """The whole path: text in, validated mapping out (or :class:`StructuredOutputError`)."""
    return validate(extract_json(text), spec)


def repair_prompt(error: str, spec: SchemaSpec) -> str:
    """The one repair attempt the budget allows, carrying the validator's complaint."""
    return (
        "Your previous answer was rejected by the schema validator. "
        f"Reason: {error}. "
        "Reply with a single JSON object that matches the schema exactly and nothing else."
    )
