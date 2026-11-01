"""The signature system: the Nuclei-compatible subset (docs/spec/04- §2.2, F-05-02).

Two properties matter most: the community template shape imports unchanged, and nothing a
template says can execute. The matchers are the nuclei vocabulary (status/word/regex/dsl/size)
and the extractors are regex/JSONPath/key-value, all evaluated over a :class:`Subject` the
engine builds from evidence.
"""

from __future__ import annotations

import pytest

from arachne.analyzer.model import Candidate, EvidenceFact
from arachne.analyzer.signatures import (
    Extractor,
    Matcher,
    Signature,
    SignatureLibrary,
    Subject,
    load_signatures,
    parse_signature,
    parse_signatures,
    select_jsonpath,
    signature_ids,
)
from arachne.core.errors import ConfigurationError

NUCLEI = {
    "id": "exposed-env-file",
    "info": {
        "name": "Exposed environment file",
        "severity": "high",
        "description": "A dotenv file is served as static content.",
        "tags": ["exposure", "secrets"],
        "reference": ["https://example.com/ref"],
    },
    "http": [
        {
            "method": "GET",
            "path": ["{{BaseURL}}/.env"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "regex", "part": "body", "regex": ["(?m)^[A-Z][A-Z0-9_]{2,}=.+$"]},
            ],
            "extractors": [
                {
                    "type": "regex",
                    "name": "keys",
                    "part": "body",
                    "group": 1,
                    "regex": ["(?m)^([A-Z_]+)="],
                },
            ],
        }
    ],
}


def subject(**overrides: object) -> Subject:
    base = {
        "http": True,
        "url": "https://example.com/.env",
        "method": "GET",
        "status": 200,
        "headers": {"content-type": "text/plain", "server": "nginx"},
        "body": "AWS_ACCESS_KEY_ID=AKIA\nDB_PASSWORD=hunter2",
    }
    base.update(overrides)
    return Subject(**base)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- parsing


def test_a_nuclei_template_parses() -> None:
    signature = parse_signature(NUCLEI)
    assert signature.id == "exposed-env-file"
    assert signature.name == "Exposed environment file"
    assert signature.severity == "high"
    assert signature.tags == ("exposure", "secrets")
    assert signature.references == ("https://example.com/ref",)
    assert signature.request_paths == ("{{BaseURL}}/.env",)
    assert len(signature.requests) == 1
    assert signature.requests[0].matchers_condition == "and"


def test_a_template_file_may_hold_a_list_of_templates() -> None:
    second = {**NUCLEI, "id": "second-template"}
    templates = parse_signatures([NUCLEI, second], source="test")
    assert [item.id for item in templates] == ["exposed-env-file", "second-template"]


def test_a_native_signature_reads_a_non_http_subject() -> None:
    signature = parse_signature(
        {
            "id": "openssh-banner",
            "info": {"name": "OpenSSH banner", "severity": "info"},
            "subject": "banner",
            "field": "banner",
            "matchers": [{"type": "regex", "regex": ["SSH-2\\.0-OpenSSH_"]}],
            "extractors": [
                {"type": "regex", "name": "version", "group": 1, "regex": ["OpenSSH_([0-9.]+)"]}
            ],
        }
    )
    assert signature.subject == "banner"
    assert signature.kind == "native"
    assert signature.requests[0].matchers[0].type == "regex"


@pytest.mark.parametrize(
    "document",
    [
        {"id": "no-matchers", "requests": [{"path": ["/x"]}]},
        {"id": "bad-type", "requests": [{"path": ["/x"], "matchers": [{"type": "js"}]}]},
        {
            "id": "bad-severity",
            "info": {"severity": "urgent"},
            "requests": [{"path": ["/x"], "matchers": [{"type": "status", "status": [200]}]}],
        },
        {"id": "empty-matcher", "requests": [{"path": ["/x"], "matchers": [{"type": "word"}]}]},
        {
            "id": "bad-condition",
            "requests": [
                {
                    "path": ["/x"],
                    "matchers-condition": "xor",
                    "matchers": [{"type": "status", "status": [200]}],
                }
            ],
        },
    ],
)
def test_invalid_templates_are_refused(document: dict[str, object]) -> None:
    with pytest.raises(ConfigurationError):
        parse_signature(document, source="test")


def test_a_dsl_matcher_must_parse() -> None:
    with pytest.raises(ConfigurationError, match="invalid condition"):
        parse_signature(
            {
                "id": "bad-dsl",
                "requests": [
                    {
                        "path": ["/x"],
                        "matchers": [{"type": "dsl", "dsl": ["status_code == "]}],
                    }
                ],
            }
        )


# --------------------------------------------------------------------------- matchers


def test_status_word_regex_size_matchers() -> None:
    assert Matcher(type="status", status=(200,)).match(subject())
    assert not Matcher(type="status", status=(404,)).match(subject())
    assert Matcher(type="word", words=("DB_PASSWORD",)).match(subject())
    assert not Matcher(type="word", words=("not-here",)).match(subject())
    assert Matcher(type="word", words=("db_password",), case_insensitive=True).match(subject())
    assert not Matcher(type="word", words=("db_password",), case_insensitive=False).match(subject())
    assert Matcher(type="regex", regex=("^AWS_",)).match(subject())
    assert Matcher(type="size", size=(len(subject().body.encode()),)).match(subject())


def test_matcher_parts_select_headers_or_everything() -> None:
    assert Matcher(type="word", part="header", words=("nginx",)).match(subject())
    assert not Matcher(type="word", part="body", words=("nginx",)).match(subject())
    assert Matcher(type="word", part="header", words=("content-type: text/plain",)).match(subject())
    assert Matcher(type="word", part="all", words=("HTTP 200", "AWS_")).match(subject())


def test_the_matcher_condition_decides_and_or() -> None:
    both = Matcher(type="word", words=("AWS_", "AWS_"), condition="and")
    one_missing = Matcher(type="word", words=("AWS_", "missing"), condition="and")
    assert both.match(subject())
    assert not one_missing.match(subject())
    assert Matcher(type="word", words=("AWS_", "missing"), condition="or").match(subject())


def test_a_dsl_matcher_reads_the_fixed_fact_space() -> None:
    matcher = Matcher(
        type="dsl",
        dsl=("status_code == 200", 'body contains "AWS_"'),
        condition="and",
    )
    assert matcher.match(subject())
    assert not Matcher(type="dsl", dsl=("status_code == 404",)).match(subject())
    assert Matcher(type="dsl", dsl=("content_length > 10",)).match(subject())


def test_a_negative_matcher_inverts() -> None:
    assert Matcher(type="status", status=(200,), negative=True).match(subject(status=404))
    assert not Matcher(type="status", status=(200,), negative=True).match(subject())


# --------------------------------------------------------------------------- extractors


def test_regex_extractor_returns_named_groups() -> None:
    extractor = Extractor(type="regex", name="keys", regex=("(?m)^([A-Z_]+)=",), group=1)
    assert extractor.extract(subject()) == ("AWS_ACCESS_KEY_ID", "DB_PASSWORD")


def test_json_extractor_walks_a_jsonpath() -> None:
    body = '{"data": {"items": [{"id": 1}, {"id": 2}]}, "name": "x"}'
    extractor = Extractor(type="json", name="ids", json=("$.data.items[*].id",))
    assert extractor.extract(subject(body=body)) == ("1", "2")
    assert Extractor(type="json", json=("$.name",)).extract(subject(body=body)) == ("x",)
    assert Extractor(type="json", json=("$..id",)).extract(subject(body=body)) == ("1", "2")
    assert Extractor(type="json", json=("$.nope",)).extract(subject(body=body)) == ()
    assert Extractor(type="json", json=("$.name",)).extract(subject(body="not json")) == ()


def test_kval_extractor_reads_key_value_lines() -> None:
    extractor = Extractor(type="kval", kval=("DB_PASSWORD",))
    assert extractor.extract(subject()) == ("hunter2",)


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("$.a", (1,)),
        ("$.a.b", (2,)),
        ("$['a']['b']", (2,)),
        ("$.list[1]", (20,)),
        ("$.list[*]", (10, 20)),
        ("$..key", ("v",)),
        ("$.nope", ()),
    ],
)
def test_jsonpath_subset(expression: str, expected: tuple[object, ...]) -> None:
    document = {"a": {"b": 2, "z": 1}, "list": [10, 20], "deep": {"x": {"key": "v"}}}
    if expression == "$.a":
        document = {"a": 1, "list": [10, 20], "deep": {"key": "v"}}
    if expression == "$.a" or expression == "$['a']['b']" or expression == "$.a.b":
        assert select_jsonpath(document, expression) == expected
    else:
        assert select_jsonpath(document, expression) == expected


@pytest.mark.parametrize("expression", ["a.b", "$.", "$[", "$[?(@.x)]", "$.a[abc]"])
def test_unsupported_jsonpath_is_refused(expression: str) -> None:
    with pytest.raises(ConfigurationError):
        select_jsonpath({"a": 1}, expression)


# --------------------------------------------------------------------------- matching


def candidate(
    *,
    path: str = "https://example.com/.env",
    body: str = "AWS_ACCESS_KEY_ID=x",
    extra: tuple[EvidenceFact, ...] = (),
) -> Candidate:
    return Candidate(
        scan_id=1,
        title="t",
        check_id="m4.env-file-probe",
        check_module="M4",
        check_name="env-file-probe",
        asset_kind="url",
        asset_value=path,
        evidence=(
            EvidenceFact("http_request", {"method": "GET", "url": path}, source=path),
            EvidenceFact(
                "http_response", {"status_code": 200, "headers": {}, "body": body}, source=path
            ),
            *extra,
        ),
    )


def test_the_library_matches_a_candidate_against_a_template_path() -> None:
    library = SignatureLibrary([parse_signature(NUCLEI)])
    matches = library.match(candidate())
    assert [item.signature_id for item in matches] == ["exposed-env-file"]
    assert matches[0].extracted["keys"] == ("AWS_ACCESS_KEY_ID",)


def test_a_template_does_not_match_a_different_path() -> None:
    library = SignatureLibrary([parse_signature(NUCLEI)])
    assert library.match(candidate(path="https://example.com/index.html")) == ()


def test_a_templated_path_matches_any_url_of_that_method() -> None:
    template = parse_signature(
        {
            "id": "templated",
            "requests": [
                {
                    "method": "POST",
                    "path": ["{{BaseURL}}/api/{{id}}"],
                    "matchers": [{"type": "status", "status": [200]}],
                }
            ],
        }
    )
    library = SignatureLibrary([template])
    post = Candidate(
        scan_id=1,
        title="t",
        asset_kind="url",
        asset_value="https://example.com/api/42",
        evidence=(
            EvidenceFact("http_request", {"method": "POST"}, source="https://example.com/api/42"),
            EvidenceFact(
                "http_response",
                {"status_code": 200, "headers": {}, "body": ""},
                source="https://example.com/api/42",
            ),
        ),
    )
    assert [item.signature_id for item in library.match(post)] == ["templated"]
    # A GET capture of the same path must not satisfy a POST template.
    get_candidate = Candidate(
        scan_id=1,
        title="t",
        asset_kind="url",
        asset_value="https://example.com/api/42",
        evidence=(
            EvidenceFact("http_request", {"method": "GET"}, source="https://example.com/api/42"),
            EvidenceFact(
                "http_response",
                {"status_code": 200, "headers": {}, "body": ""},
                source="https://example.com/api/42",
            ),
        ),
    )
    assert library.match(get_candidate) == ()


def test_a_native_signature_matches_a_payload_field() -> None:
    signature = parse_signature(
        {
            "id": "openssh-banner",
            "subject": "note",
            "field": "service.identity.banner",
            "matchers": [{"type": "regex", "regex": ["SSH-2\\.0-OpenSSH_"]}],
        }
    )
    library = SignatureLibrary([signature])
    matching = Candidate(
        scan_id=1,
        title="t",
        asset_kind="host",
        asset_value="10.0.0.5",
        evidence=(
            EvidenceFact(
                "note",
                {"service": {"identity": {"product": "OpenSSH", "banner": "SSH-2.0-OpenSSH_8.5"}}},
            ),
        ),
    )
    assert [item.signature_id for item in library.match(matching)] == ["openssh-banner"]
    non_matching = Candidate(
        scan_id=1,
        title="t",
        asset_kind="host",
        asset_value="10.0.0.5",
        evidence=(EvidenceFact("note", {"service": {"identity": {"banner": "HTTP/1.1 200"}}}),),
    )
    assert library.match(non_matching) == ()
    # A native signature never reads an HTTP response body.
    assert library.match(candidate()) == ()


def test_the_bundled_corpus_loads_and_is_deterministic() -> None:
    signatures = load_signatures(include_bundled=True)
    ids = signature_ids(signatures)
    assert "exposed-env-file" in ids
    assert "exposed-git-config" in ids
    assert "openssh-version-banner" in ids
    assert ids == tuple(sorted(ids))
    # Loading twice yields the same corpus (data files, no discovery order dependency).
    assert signature_ids(load_signatures()) == ids


def test_duplicate_signature_ids_are_refused(tmp_path) -> None:
    path = tmp_path / "dupe.yaml"
    path.write_text(
        """id: exposed-env-file
info:
  name: duplicate of a bundled template
requests:
  - path: [/x]
    matchers:
      - type: status
        status: [200]
""",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="duplicate signature id"):
        load_signatures([tmp_path], include_bundled=True)


def test_a_missing_signature_directory_is_refused(tmp_path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_signatures([tmp_path / "nope"], include_bundled=False)


def test_a_signature_object_without_requests_or_subject_is_refused() -> None:
    with pytest.raises(ValueError, match="requests"):
        Signature(id="empty-signature", name="nothing")


_ = load_signatures  # documented public API
_ = subject
