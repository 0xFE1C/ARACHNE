"""Recorded-fixture loading and replay .

Fixture loading is the part of the test infrastructure that ships in ``src/`` (so a real
deployment can run ``--osint-fixtures``), which means it needs its own tests: a recording
format that silently accepts a malformed entry is worse than no recording format at all.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.helpers.checks import OSINT_FIXTURES

from arachne.core.errors import ConfigurationError
from arachne.core.http import RecordedResponse
from arachne.modules.providers.fixtures import FIXTURE_ADDRESS, FixtureReplay, load_fixture_routes


def write(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ------------------------------------------------------------------ the canonical form
def test_the_canonical_form_is_a_list_of_recordings(tmp_path: Path) -> None:
    fixture = write(
        tmp_path / "one.json",
        {
            "description": "one provider",
            "responses": [
                {"method": "GET", "url": "https://a.example/x", "status": 200, "body": "hi"},
                {"method": "GET", "url": "https://a.example/y", "headers": {"x": "1"}},
            ],
        },
    )
    routes = load_fixture_routes(fixture)
    assert set(routes) == {"GET https://a.example/x", "GET https://a.example/y"}
    assert routes["GET https://a.example/x"].body == "hi"
    assert routes["GET https://a.example/y"].status == 200
    assert routes["GET https://a.example/y"].headers == {"x": "1"}


def test_a_bare_list_is_accepted_too(tmp_path: Path) -> None:
    fixture = write(
        tmp_path / "bare.json", [{"method": "GET", "url": "https://a.example/x", "body": "hi"}]
    )
    assert load_fixture_routes(fixture)["GET https://a.example/x"].body == "hi"


def test_the_shorthand_mapping_form_keyed_by_method_and_url(tmp_path: Path) -> None:
    """``{"GET https://host/path": {...}}`` — compact enough to write by hand."""
    fixture = write(
        tmp_path / "shorthand.json",
        {"GET https://a.example/x": {"status": 404, "body": "gone"}},
    )
    route = load_fixture_routes(fixture)["GET https://a.example/x"]
    assert route.status == 404 and route.body == "gone"


def test_a_directory_loads_and_merges_every_recording(tmp_path: Path) -> None:
    write(tmp_path / "a.json", [{"method": "GET", "url": "https://a.example/1", "body": "1"}])
    write(tmp_path / "b.json", [{"method": "GET", "url": "https://a.example/2", "body": "2"}])
    routes = load_fixture_routes(tmp_path)
    assert len(routes) == 2


def test_a_later_recording_wins_for_the_same_url(tmp_path: Path) -> None:
    write(tmp_path / "a.json", [{"method": "GET", "url": "https://a.example/1", "body": "first"}])
    write(tmp_path / "b.json", [{"method": "GET", "url": "https://a.example/1", "body": "second"}])
    assert load_fixture_routes(tmp_path)["GET https://a.example/1"].body == "second"


# ------------------------------------------------------------------ error paths
def test_a_missing_path_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_fixture_routes(tmp_path / "nope")


def test_an_empty_directory_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match=r"contains no \.json recordings"):
        load_fixture_routes(tmp_path)


def test_invalid_json_is_reported_with_the_file(tmp_path: Path) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not valid JSON"):
        load_fixture_routes(broken)


def test_a_non_utf8_file_is_reported_as_a_fixture_problem(tmp_path: Path) -> None:
    """A binary file must not surface a codec traceback to the operator."""
    fixture = tmp_path / "unreadable.json"
    fixture.write_bytes(b"\xff\xfe\x00")
    with pytest.raises(ConfigurationError, match="not a UTF-8 text file"):
        load_fixture_routes(fixture)


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("just a string", "expected a mapping or a list"),
        ({"responses": "nope"}, "'responses' must be a list"),
        ({"responses": ["nope"]}, "is not a mapping"),
        ({"responses": [{"method": "GET"}]}, "needs 'method' and 'url'"),
        ({"responses": []}, "no recorded responses found"),
    ],
)
def test_a_malformed_document_is_refused(tmp_path: Path, document: object, message: str) -> None:
    fixture = write(tmp_path / "bad.json", document)
    with pytest.raises(ConfigurationError, match=message):
        load_fixture_routes(fixture)


def test_recorded_response_round_trips() -> None:
    recorded = RecordedResponse.from_dict(
        {"method": "get", "url": "https://a/x", "status": 201, "headers": {"a": 1}, "body": "b"}
    )
    assert recorded.method == "GET"
    assert recorded.to_dict() == {
        "method": "GET",
        "url": "https://a/x",
        "status": 201,
        "headers": {"a": "1"},
        "body": "b",
    }


# ------------------------------------------------------------------ the replay object
def test_replay_exposes_its_responses_and_address() -> None:
    replay = FixtureReplay({"GET https://a/x": RecordedResponse("GET", "https://a/x", body="hi")})
    assert replay.urls() == ("https://a/x",)
    assert replay.address() == (FIXTURE_ADDRESS,)
    assert len(replay.responses()) == 1


def test_replay_accepts_plain_dicts() -> None:
    replay = FixtureReplay({"k": {"method": "GET", "url": "https://a/x", "body": "hi"}})
    assert replay.responses()[0].body == "hi"


def test_replay_needs_at_least_one_recording() -> None:
    with pytest.raises(ConfigurationError, match="needs at least one recorded response"):
        FixtureReplay({})


def test_the_shipped_osint_recordings_are_loadable() -> None:
    """The fixtures the tests and the offline demo depend on must stay parseable."""
    routes = load_fixture_routes(OSINT_FIXTURES)
    assert len(routes) >= 15
    assert any("crt.sh" in url for url in routes)
    assert all(route.method == "GET" for route in routes.values())
