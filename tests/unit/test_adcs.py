"""``m2.adcs-enum``'s decision table and its boundary (REQ-DET-014).

The interesting half of the AD CS check is not the wire — it is the *decision*: which published
attribute patterns are reported, which are not, and what a finding is allowed to claim. This
suite drives the condition table directly, with no socket, so every branch is pinned:

* each ESC condition fires on the attribute pattern it names and on nothing else;
* the hardened pattern (the decoy) fires *no* condition;
* a condition never crosses object classes — a CA's ``flags`` cannot produce a template finding;
* the machine-readable artifact names the ESC class as **context** and records
  ``exploitation_attempted: false``; and
* the module contains no CA-service path, no enrolment call and no LDAP write operation.
"""

from __future__ import annotations

import ast
from pathlib import Path

from arachne.modules.m2 import wire
from arachne.modules.m2.adcs import (
    ADCS_ESC_CONDITIONS,
    CA_ATTRIBUTES,
    ENROLLMENT_SERVICE_CLASS,
    ESC_CLASSES_NOT_ASSESSED,
    NON_EXPLOITATION_NOTE,
    TEMPLATE_ATTRIBUTES,
    TEMPLATE_CLASS,
    AdcsObject,
    EscCondition,
    esc_conditions_for,
)

ADCS_MODULE = Path(__file__).resolve().parents[2] / "src" / "arachne" / "modules" / "m2" / "adcs.py"

#: A template that trips ESC1 and nothing else: an enrollee-supplied subject, client auth, v2.
ESC1_TEMPLATE = {
    "msPKI-Certificate-Name-Flag": ("1",),
    "msPKI-Enrollment-Flag": ("0",),
    "msPKI-Template-Schema-Version": ("2",),
    "pKIExtendedKeyUsage": ("1.3.6.1.5.5.7.3.2",),
}

#: A CA that trips ESC6 and nothing else.
ESC6_CA = {"flags": (str(0x00040000),), "cn": ("lab-issuing-ca",)}

#: The hardened pattern: the same object shapes with every condition removed.
SAFE_TEMPLATE = {
    "msPKI-Certificate-Name-Flag": ("0",),
    "msPKI-Enrollment-Flag": ("0",),
    "msPKI-Template-Schema-Version": ("2",),
    "pKIExtendedKeyUsage": ("1.3.6.1.5.5.7.3.1",),
}
SAFE_CA = {"flags": ("0",), "cn": ("lab-hardened-ca",)}


def codes(pairs: tuple[tuple[EscCondition, str], ...]) -> list[str]:
    return [condition.code for condition, _ in pairs]


# ------------------------------------------------------------------ each condition fires
def test_esc1_fires_on_an_enrollee_supplied_subject_with_client_auth() -> None:
    assert codes(esc_conditions_for(TEMPLATE_CLASS, ESC1_TEMPLATE)) == ["ESC1"]


def test_esc1_needs_both_halves() -> None:
    no_name_flag = {**ESC1_TEMPLATE, "msPKI-Certificate-Name-Flag": ("0",)}
    assert codes(esc_conditions_for(TEMPLATE_CLASS, no_name_flag)) == []
    server_only = {**ESC1_TEMPLATE, "pKIExtendedKeyUsage": ("1.3.6.1.5.5.7.3.1",)}
    assert codes(esc_conditions_for(TEMPLATE_CLASS, server_only)) == []


def test_esc2_fires_on_any_purpose_or_a_missing_usage() -> None:
    any_purpose = {
        **SAFE_TEMPLATE,
        "pKIExtendedKeyUsage": ("1.3.6.1.4.1.311.10.3.12",),
    }
    assert codes(esc_conditions_for(TEMPLATE_CLASS, any_purpose)) == ["ESC2"]
    no_usage = {k: v for k, v in SAFE_TEMPLATE.items() if k != "pKIExtendedKeyUsage"}
    assert codes(esc_conditions_for(TEMPLATE_CLASS, no_usage)) == ["ESC2"]


def test_esc3_fires_on_the_enrolment_agent_usage() -> None:
    agent = {**SAFE_TEMPLATE, "pKIExtendedKeyUsage": ("1.3.6.1.4.1.311.20.2.1",)}
    assert codes(esc_conditions_for(TEMPLATE_CLASS, agent)) == ["ESC3"]


def test_esc9_fires_on_the_no_security_extension_flag() -> None:
    flagged = {**SAFE_TEMPLATE, "msPKI-Enrollment-Flag": (str(0x00080000),)}
    assert codes(esc_conditions_for(TEMPLATE_CLASS, flagged)) == ["ESC9"]


def test_esc15_fires_on_a_v1_template_with_an_enrollee_supplied_subject() -> None:
    v1 = {**ESC1_TEMPLATE, "msPKI-Template-Schema-Version": ("1",)}
    assert codes(esc_conditions_for(TEMPLATE_CLASS, v1)) == ["ESC1", "ESC15"]


def test_esc6_fires_on_a_ca_that_honours_a_supplied_san() -> None:
    assert codes(esc_conditions_for(ENROLLMENT_SERVICE_CLASS, ESC6_CA)) == ["ESC6"]


# ------------------------------------------------------------------ the decoy and the scoping
def test_the_hardened_pattern_fires_nothing() -> None:
    assert esc_conditions_for(TEMPLATE_CLASS, SAFE_TEMPLATE) == ()
    assert esc_conditions_for(ENROLLMENT_SERVICE_CLASS, SAFE_CA) == ()


def test_a_condition_never_crosses_object_classes() -> None:
    """A CA object's attributes cannot produce a template finding, and the reverse holds."""
    template_only = {"ESC1", "ESC2", "ESC3", "ESC9", "ESC15"}
    ca_only = {"ESC6"}
    assert {item.code for item in ADCS_ESC_CONDITIONS} == template_only | ca_only
    for item in ADCS_ESC_CONDITIONS:
        assert item.object_class == (
            TEMPLATE_CLASS if item.code in template_only else ENROLLMENT_SERVICE_CLASS
        )
    # The CA flag cannot produce a template code, nor a template flag a CA code.
    assert (
        not set(codes(esc_conditions_for(ENROLLMENT_SERVICE_CLASS, ESC1_TEMPLATE))) & template_only
    )
    assert not set(codes(esc_conditions_for(TEMPLATE_CLASS, ESC6_CA))) & ca_only


def test_an_unreadable_flag_value_is_not_guessed() -> None:
    """A non-numeric flag is "no condition", never a parse error and never a finding."""
    garbage = {
        "msPKI-Certificate-Name-Flag": ("garbage",),
        "pKIExtendedKeyUsage": ("1.3.6.1.5.5.7.3.1",),
    }
    assert codes(esc_conditions_for(TEMPLATE_CLASS, garbage)) == []
    assert codes(esc_conditions_for(ENROLLMENT_SERVICE_CLASS, {"flags": ("",)})) == []


def test_every_condition_names_its_object_class_and_a_published_esc_code() -> None:
    for condition in ADCS_ESC_CONDITIONS:
        assert condition.code.startswith("ESC")
        assert condition.object_class in {TEMPLATE_CLASS, ENROLLMENT_SERVICE_CLASS}
        assert condition.title
        assert condition.context.startswith(condition.code), condition.code
        assert "not assessed" in condition.context or "did not assess" in condition.context


def test_the_unassessed_classes_are_named_with_a_reason() -> None:
    codes_named = {code for code, _ in ESC_CLASSES_NOT_ASSESSED}
    assert {"ESC4", "ESC5", "ESC7", "ESC8", "ESC10"} <= codes_named
    assert all(reason for _, reason in ESC_CLASSES_NOT_ASSESSED)
    # ...and no unassessed class is also decided here.
    assert not codes_named & {condition.code for condition in ADCS_ESC_CONDITIONS}


def test_the_non_exploitation_note_states_the_boundary() -> None:
    assert "does not attempt exploitation" in NON_EXPLOITATION_NOTE
    assert "no certificate was requested" in NON_EXPLOITATION_NOTE
    assert "no template was modified" in NON_EXPLOITATION_NOTE


def test_the_attribute_lists_name_only_the_two_classes_read() -> None:
    for attributes in (TEMPLATE_ATTRIBUTES, CA_ATTRIBUTES):
        assert "objectClass" in attributes
        assert not any("security" in name.lower() for name in attributes), attributes


# ------------------------------------------------------------------ the boundary, at source
def _tree() -> ast.AST:
    return ast.parse(ADCS_MODULE.read_text(encoding="utf-8"))


def _documented_text() -> str:
    """Every docstring in the module, lowercased — the prose a token check must ignore."""
    parts: list[str] = []
    for node in ast.walk(_tree()):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                parts.append(doc)
    return "\n".join(parts).lower()


def test_no_ldap_write_operation_is_constructed() -> None:
    """No modify/add/delete request is built, and no write tag byte appears in the module."""
    literals = {
        node.value
        for node in ast.walk(_tree())
        if isinstance(node, ast.Constant) and isinstance(node.value, int)
    }
    for tag in wire.LDAP_WRITE_TAGS:
        assert tag not in literals, hex(tag)


def test_the_only_egress_is_the_scoped_net_client() -> None:
    """AD CS enumeration opens no socket and no HTTP client of its own.

    Every byte leaves through ``client.tcp`` — the scan's scoped, rate-limited, audited network
    client — so the scope gate cannot be bypassed by this check.
    """
    identifiers = {node.id for node in ast.walk(_tree()) if isinstance(node, ast.Name)}
    identifiers |= {node.attr for node in ast.walk(_tree()) if isinstance(node, ast.Attribute)}
    for forbidden in ("open_connection", "create_connection", "urlopen", "httpx", "aiohttp"):
        assert forbidden not in identifiers, forbidden

    # Calls made on the network client are exactly its one read-only primitive.
    on_client = {
        node.func.attr
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "client"
    }
    assert on_client <= {"tcp"}, on_client


def test_the_check_builds_only_read_operations() -> None:
    """Every `wire.build_*` call in the module is a bind or a search."""
    built = {
        node.func.attr
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr.startswith("build_")
    }
    assert built <= {"build_ldap_bind_request", "build_ldap_search"}, built


def test_the_module_names_no_ca_service_or_enrolment_primitive_in_its_code() -> None:
    """The CA service is never addressed: no such token in any *excluding-docstring* literal.

    The module's prose states the boundary and therefore names the CA endpoints; that is
    documentation, and this suite's job is to prove the code cannot act on one.
    """
    documented = _documented_text()
    text = ADCS_MODULE.read_text(encoding="utf-8").lower()
    for token in ("certsrv", "icertadmin", "icertrequest", "webenrollment"):
        occurrences = text.count(token)
        assert occurrences == documented.count(token), (token, occurrences)


# ------------------------------------------------------------------ the stream parser
def _ldap_message(message_id: int, application: bytes) -> bytes:
    """One LDAPMessage: SEQUENCE { INTEGER messageID, <application element> }."""
    return wire.ber_tlv(0x30, wire.ber_tlv(0x02, wire.ber_int(message_id)) + application)


def _search_entry(dn: str) -> bytes:
    return _ldap_message(
        2,
        wire.ber_tlv(0x67, wire.ber_tlv(0x04, dn.encode()) + wire.ber_tlv(0x30, b"")),
    )


def _search_done(result_code: int = 0) -> bytes:
    return _ldap_message(
        2,
        wire.ber_tlv(
            0x65,
            wire.ber_tlv(0x02, wire.ber_int(result_code))
            + wire.ber_tlv(0x04, b"")
            + wire.ber_tlv(0x04, b""),
        ),
    )


def test_the_reply_stream_parser_reads_every_message() -> None:
    """A search answer is a stream: entries *and* the done message, not just the first."""
    messages = wire.iter_ldap_messages(_search_entry("CN=a") + _search_done())
    assert [message.tag for message in messages] == [0x67, 0x65]
    assert messages[0].object_name == "CN=a"
    assert messages[1].result_code == 0


def test_the_stream_parser_ignores_a_truncated_tail() -> None:
    """A bounded read may cut the last message; the entries that arrived are still readable."""
    messages = wire.iter_ldap_messages(_search_entry("CN=a") + b"\x30\x82\xff")
    assert len(messages) == 1


def test_the_search_builder_scopes_and_filters_explicitly() -> None:
    """The ADCS search is a subtree search with an explicit or-filter — pinned in bytes."""
    payload = wire.build_ldap_search(
        2,
        "CN=Public Key Services,CN=Services,CN=Configuration,DC=lab",
        scope=wire.LDAP_SCOPE_SUBTREE,
        attributes=("objectClass", "cn"),
        filter_body=wire.ldap_filter_or(
            [
                wire.ldap_filter_present(TEMPLATE_CLASS),
                wire.ldap_filter_present(ENROLLMENT_SERVICE_CLASS),
            ]
        ),
    )
    assert wire.LDAP_SEARCH_REQUEST.to_bytes(1, "big") in payload
    assert TEMPLATE_CLASS.encode() in payload
    assert ENROLLMENT_SERVICE_CLASS.encode() in payload
    assert b"\x0a\x01\x02" in payload  # scope = wholeSubtree
    # The older rootDSE builder is untouched by this addition.
    legacy = wire.build_ldap_search_request(2)
    assert b"namingContexts" in legacy


def test_an_enumerated_object_carries_only_the_attributes_read() -> None:
    item = AdcsObject(
        object_class=TEMPLATE_CLASS,
        dn="CN=t,CN=Certificate Templates,CN=Public Key Services",
        name="t",
        attributes={"cn": ("t",)},
    )
    assert item.object_class == TEMPLATE_CLASS
    assert item.attributes == {"cn": ("t",)}
