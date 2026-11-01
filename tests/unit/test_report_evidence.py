"""Evidence projection: kind mapping, redaction, truncation and ids ."""

from __future__ import annotations

from datetime import UTC, datetime

from arachne.core.redaction import contains_secret
from arachne.data.finding_store import EvidenceRecord
from arachne.report.evidence import (
    DEFAULT_EVIDENCE_BODY_LIMIT,
    map_kind,
    project_evidence,
    summarize_evidence,
    truncate_text,
)

NOW = datetime(2026, 10, 27, tzinfo=UTC)


def record(kind: str, payload: dict[str, object], *, number: int = 1) -> EvidenceRecord:
    return EvidenceRecord(id=number, kind=kind, payload=payload, sha256=None, created_at=NOW)


def test_internal_kinds_map_onto_the_spec_vocabulary() -> None:
    assert map_kind("tls_certificate") == "tls_cert"
    assert map_kind("file_path") == "file_artifact"
    assert map_kind("http_request") == "http_request"
    assert map_kind("cloud_api") == "cloud_api"
    # An unknown kind passes through rather than being silently renamed.
    assert map_kind("plugin_kind") == "plugin_kind"


def test_a_payload_is_redacted_again_projection_time() -> None:
    body = (
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345\n"
        "DB_PASSWORD=hunter2hunter2\n"
        "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    )
    entries, refs = project_evidence([record("http_response", {"status_code": 200, "body": body})])
    payload = entries[0].payload["body"]
    assert "hunter2hunter2" not in payload
    assert "wJalrXUtnFEMI" not in payload
    assert "abcdefghijklmnop" not in payload
    assert "[REDACTED" in payload
    assert not contains_secret(payload)
    assert refs == {1: "E-0001"}


def test_bodies_are_truncated_at_the_report_limit() -> None:
    body = "x" * (DEFAULT_EVIDENCE_BODY_LIMIT + 100)
    entries, _ = project_evidence([record("http_response", {"status_code": 200, "body": body})])
    payload = entries[0].payload
    assert len(payload["body"]) < len(body) + 100
    assert payload["body_truncated"] is True
    assert "truncated" in payload["body"]
    short, was_truncated = truncate_text("short", 100)
    assert (short, was_truncated) == ("short", False)


def test_evidence_ids_follow_capture_order_and_start_offset() -> None:
    rows = [
        record("http_request", {"method": "GET", "url": "https://t.example/a"}, number=7),
        record("http_response", {"status_code": 200}, number=3),
    ]
    entries, refs = project_evidence(rows, start=5)
    assert [entry.id for entry in entries] == ["E-0005", "E-0006"]
    assert refs == {3: "E-0005", 7: "E-0006"}


def test_evidence_summaries_name_the_useful_facts() -> None:
    assert (
        summarize_evidence("http_request", {"method": "POST", "url": "https://t.example/x"})
        == "POST https://t.example/x"
    )
    response = summarize_evidence(
        "http_response",
        {"status_code": 403, "body": "nope", "captured_patterns": ["jwt"]},
    )
    assert "HTTP 403" in response
    assert "4 bytes" in response
    assert "matched patterns: jwt" in response
    assert summarize_evidence("artifact", {"a": 1, "b": 2}) == ("machine-readable artifact (a, b)")


def test_a_captured_sha256_is_preserved_and_a_missing_one_is_computed() -> None:
    entries, _ = project_evidence(
        [
            record("http_request", {"method": "GET", "url": "https://t.example/"}, number=1),
        ]
    )
    assert entries[0].sha256 is not None
    assert len(entries[0].sha256 or "") == 64


def test_a_url_query_secret_is_redacted_in_the_payload() -> None:
    entries, _ = project_evidence(
        [record("http_request", {"method": "GET", "url": "https://t.example/x?token=abc123456789"})]
    )
    assert "abc123456789" not in entries[0].payload["url"]
    assert "token=[REDACTED" in entries[0].payload["url"]
