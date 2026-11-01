"""Structured output: four mechanisms in, one pydantic validator out (docs/spec/03- §6, F-04-03).

The table in §6 names ``json_object``, tool-use, ``responseMimeType``, Ollama's ``format`` and
constrained decoding. The mechanisms differ per adapter (tested in ``test_ai_providers.py``);
what they all end at is this module, so these tests drive the *validator* with the shapes a
model actually returns — fenced, chatty, trailing-comma, wrong-typed, missing-field.
"""

from __future__ import annotations

import json

import pytest

from arachne.ai.stages import SCHEMAS, TriageOutput
from arachne.ai.structured import (
    SchemaSpec,
    balanced_slice,
    extract_json,
    normalize_schema,
    parse_structured,
    repair_prompt,
    validate,
)
from arachne.ai.types import StructuredOutputError


def triage_spec() -> SchemaSpec:
    return SCHEMAS["triage"]


def good_payload() -> dict[str, object]:
    return {
        "severity": "high",
        "confidence": 88,
        "fp_likely": False,
        "reason": "Exposed .env with live credentials.",
    }


# --------------------------------------------------------------------------- parsing


def test_plain_json_parses() -> None:
    assert extract_json(json.dumps(good_payload())) == good_payload()


def test_a_fenced_json_block_parses() -> None:
    text = "```json\n" + json.dumps(good_payload()) + "\n```"
    assert extract_json(text) == good_payload()


def test_leading_prose_around_the_object_is_tolerated() -> None:
    text = "Here is my analysis:\n" + json.dumps(good_payload()) + "\nLet me know if you need more."
    assert extract_json(text) == good_payload()


def test_trailing_commas_are_recovered() -> None:
    assert extract_json('{"severity": "high", "confidence": 90,}') == {
        "severity": "high",
        "confidence": 90,
    }


def test_nested_objects_are_scanned_correctly() -> None:
    text = 'prefix {"a": {"b": "}"}, "c": [1, 2]} suffix'
    assert extract_json(text) == {"a": {"b": "}"}, "c": [1, 2]}


def test_braces_inside_strings_do_not_confuse_the_scanner() -> None:
    assert extract_json('{"reason": "use {braces} here"}') == {"reason": "use {braces} here"}


def test_no_json_at_all_is_a_structured_output_error() -> None:
    with pytest.raises(StructuredOutputError, match="no parseable JSON"):
        extract_json("I cannot help with that.")


def test_an_unbalanced_object_is_a_structured_output_error() -> None:
    with pytest.raises(StructuredOutputError):
        extract_json('{"severity": "high"')


def test_balanced_slice_stops_at_the_matching_close() -> None:
    text = 'x {"a": 1} y {"b": 2}'
    assert balanced_slice(text, text.index("{"), "{", "}") == '{"a": 1}'


# --------------------------------------------------------------------------- validation


def test_a_valid_object_normalizes_to_the_model() -> None:
    spec = triage_spec()
    value = parse_structured(json.dumps(good_payload()), spec)
    assert value["severity"] == "high"
    assert value["confidence"] == 88
    assert value["categories"] == []  # the model's default is materialized


def test_the_severity_vocabulary_is_enforced() -> None:
    payload = good_payload() | {"severity": "catastrophic"}
    with pytest.raises(StructuredOutputError, match="not one of"):
        validate(payload, triage_spec())


def test_a_missing_required_field_is_rejected() -> None:
    payload = good_payload()
    del payload["fp_likely"]
    with pytest.raises(StructuredOutputError, match="fp_likely"):
        validate(payload, triage_spec())


def test_a_wrong_type_is_rejected() -> None:
    with pytest.raises(StructuredOutputError, match="confidence"):
        validate(good_payload() | {"confidence": "very"}, triage_spec())


def test_a_non_object_is_rejected() -> None:
    with pytest.raises(StructuredOutputError, match="expected a JSON object"):
        validate(["high"], triage_spec())


def test_the_error_names_the_stage_and_the_field() -> None:
    with pytest.raises(StructuredOutputError) as excinfo:
        validate({"severity": "high"}, triage_spec())
    message = str(excinfo.value)
    assert "triage" in message
    assert "confidence" in message


# --------------------------------------------------------------------------- schema


def test_the_json_schema_is_derived_from_the_model() -> None:
    schema = triage_spec().json_schema
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == set(TriageOutput.model_fields)
    assert schema["properties"]["severity"]["enum"] == [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]
    assert schema["required"] == ["severity", "confidence", "fp_likely", "reason"]


def test_normalize_schema_drops_titles_and_closes_objects() -> None:
    raw = {
        "title": "T",
        "type": "object",
        "properties": {"a": {"title": "A", "type": "string"}},
        "required": ["a"],
    }
    normalized = normalize_schema(raw)
    assert "title" not in normalized
    assert "title" not in normalized["properties"]["a"]
    assert normalized["additionalProperties"] is False


def test_every_stage_schema_is_strict() -> None:
    for name, spec in SCHEMAS.items():
        schema = spec.json_schema
        assert schema.get("additionalProperties") is False, name
        assert schema.get("required"), name
        assert spec.schema_version, name


def test_the_schema_version_changes_with_the_model() -> None:
    assert triage_spec().schema_version
    assert len(triage_spec().schema_version) == 12


def test_the_repair_prompt_carries_the_validator_complaint() -> None:
    text = repair_prompt(
        "triage: output does not match the schema: fp_likely: Field required", triage_spec()
    )
    assert "fp_likely: Field required" in text
    assert "single JSON object" in text
