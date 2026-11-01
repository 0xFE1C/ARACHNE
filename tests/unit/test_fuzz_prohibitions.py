"""The prohibition table applied to fuzzing (S30, area FUZZ, REQ-FUZZ-001).

Two directions matter equally, and both are asserted here. The table must **bite**: a destructive
statement, a shell metacharacter, a destructive command, a remaining-infrastructure verb, a
credential/account mutation and an obfuscation encoding are all refused. And it must not **over-
reach**: a path traversal, a NUL byte, a quote, an angle bracket and an over-long field are all
legitimate fuzzing material — each is a finding this program exists to produce — so refusing them
would delete the capability while looking careful.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import FuzzPayloadRefused
from arachne.fuzz.prohibitions import (
    DESTRUCTIVE_SQL_HEADS,
    FORBIDDEN_SEQUENCES,
    HTTP_READ_ONLY_METHODS,
    OPERATION_PROTOCOLS,
    READ_ONLY_OPERATIONS,
    READ_ONLY_VERBS,
    ProhibitionSummary,
    fuzz_payload_problems,
    grammar_operation_problems,
    operation_is_destructive,
    require_non_destructive,
)


@pytest.mark.parametrize(
    ("payload", "expected_class"),
    [
        (b"1' ; DELETE FROM accounts", "sql"),
        (b"; TRUNCATE TABLE audit_log", "sql"),
        (b"$(id)", "shell"),
        (b"a;rm -rf /tmp/x", "shell"),
        (b"rm -rf /", "destructive-command"),
        (b"mkfs.ext4 /dev/sda1", "destructive-command"),
        (b"shutdown -h now", "remaining-infrastructure"),
        (b"factory reset", "remaining-infrastructure"),
        (b"set password for admin", "credential-mutation"),
        (b"ALTER USER root IDENTIFIED BY x", "sql"),
        (b"cGFzc3dvcmQ= base64", "evasion"),
    ],
)
def test_the_table_refuses_each_prohibited_class(payload: bytes, expected_class: str) -> None:
    verdict = fuzz_payload_problems(payload)
    assert not verdict.ok, f"{payload!r} should be refused"
    assert expected_class in verdict.classes
    with pytest.raises(FuzzPayloadRefused):
        require_non_destructive(payload)


@pytest.mark.parametrize(
    "payload",
    [
        b"../../../../etc/passwd",
        b"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        b"..%252f..%252fetc%252fpasswd",
        b"'\"",
        b"<a1>\"'1",
        b"a\x00b",
        b"a" * 255,
        b"1' AND '1'='2",
        b"1 AND 1=1",
        b"1' AND SLEEP(5)-- -",
        b"%00",
        b"\r\n\r\n",
        b'{"a":1}',
        b"\x00\x01\x02\xff\xfe",
        b"PING\r\n",
    ],
)
def test_the_table_does_not_refuse_legitimate_fuzzing_material(payload: bytes) -> None:
    """A traversal, a quote, a NUL and an over-long field are the findings, not the harm."""
    verdict = fuzz_payload_problems(payload)
    assert verdict.ok, f"{payload!r} was refused: {verdict.problems}"


def test_a_binary_message_is_matched_on_its_readable_text_not_its_raw_bytes() -> None:
    """A TLS key share is high-entropy noise; it must not be able to spell a prohibition."""
    noise = bytes(range(256)) * 4
    assert fuzz_payload_problems(noise).ok


def test_the_sql_head_list_is_the_proof_ladders_and_not_a_second_copy() -> None:
    from arachne.core.proof import PROHIBITED_SQL_HEADS

    assert DESTRUCTIVE_SQL_HEADS is PROHIBITED_SQL_HEADS


def test_the_evasion_class_is_the_proof_ladders_own_rule() -> None:
    """One implementation: area FUZZ calls the ladder's ``encode_free`` rather than a copy."""
    from arachne.core.proof import encode_free

    with pytest.raises(Exception):  # noqa: B017 - the ladder's own refusal type
        encode_free("base64 payload")
    assert "evasion" in fuzz_payload_problems(b"run base64 here").classes


def test_the_table_names_covers_and_operations_for_a_report() -> None:
    summary = ProhibitionSummary().to_dict()
    assert set(summary["classes"]) == set(FORBIDDEN_SEQUENCES)
    assert summary["destructive_sql_heads"] == sorted(DESTRUCTIVE_SQL_HEADS)
    assert summary["protocols"]["modbus"] == sorted(READ_ONLY_OPERATIONS["modbus"])
    assert summary["verbs"]["redis"] == sorted(READ_ONLY_VERBS["redis"])
    assert "POST" in summary["http_methods"]
    assert set(summary["http_methods"]) == set(HTTP_READ_ONLY_METHODS)


# --------------------------------------------------------------------------- operations


@pytest.mark.parametrize(
    ("protocol", "code", "destructive"),
    [
        ("modbus", 0x03, False),
        ("modbus", 0x2B, False),
        ("modbus", 0x05, True),  # Write Single Coil
        ("modbus", 0x06, True),  # Write Single Register
        ("modbus", 0x0F, True),  # Write Multiple Coils
        ("modbus", 0x10, True),  # Write Multiple Registers
        ("modbus", 0x08, True),  # Diagnostics
        ("dnp3", 0x09, False),  # REQUEST_LINK_STATUS
        ("dnp3", 0x02, False),  # TEST_LINK_STATES
        ("dnp3", 0x00, True),  # RESET_LINK_STATES
        ("dnp3", 0x01, True),  # RESET_USER_PROCESS
        ("snmp", 0xA0, False),  # GetRequest
        ("snmp", 0xA5, False),  # GetBulkRequest
        ("snmp", 0xA3, True),  # SetRequest
        ("s7comm", 0x04, False),  # Read Var
        ("s7comm", 0x05, True),  # Write Var
        ("s7comm", 0x28, True),  # PLC Stop
        ("s7comm", 0x29, True),  # PLC Control
        ("bacnet", 12, False),  # ReadProperty
        ("bacnet", 15, True),  # WriteProperty
        ("bacnet", 17, True),  # DeviceCommunicationControl
        ("ldap", 0x63, False),  # searchRequest
        ("ldap", 0x66, True),  # modifyRequest
        ("ldap", 0x4A, True),  # delRequest
        ("ldap", 0x77, True),  # extendedRequest (passwdModify)
    ],
)
def test_the_operation_table_answers_for_every_shipped_protocol(
    protocol: str, code: int, destructive: bool
) -> None:
    assert operation_is_destructive(protocol, code) is destructive


def test_a_protocol_with_no_operation_table_is_not_judged_by_one() -> None:
    """HTTP, DNS and TLS carry no operation code; the payload table is what constrains them."""
    for protocol in ("http", "dns", "tls", "rdp", "ntlmssp", "redis", "arc1"):
        assert operation_is_destructive(protocol, 0x10) is False
    assert OPERATION_PROTOCOLS  # the protocols that *are* judged are declared


def test_a_grammar_that_declares_a_write_operation_is_told_which_values_are_allowed() -> None:
    problems = grammar_operation_problems("modbus", (0x01, 0x10))
    assert len(problems) == 1
    assert "0x10 is not a declared read-only modbus operation" in problems[0]
    assert "allowed:" in problems[0]
    assert grammar_operation_problems("arc1", (0x10,)) == ()
