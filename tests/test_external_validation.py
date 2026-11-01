"""External-validation artifacts (REQ-TRUST-007).

The release gate for REQ-TRUST-007 is "artifacts present; review", so this suite
pins the three published artifacts — the vulnerability disclosure policy
(`SECURITY.md`), the RFC 9116 `security.txt`, and the external penetration-test
report — as present and well-formed. It is deliberately structural and offline:
it reads the files, never touches the network, and asserts shape rather than
prose so the documents can be edited without breaking the build.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

CODE_ROOT = Path(__file__).resolve().parents[1]
SECURITY_MD = CODE_ROOT / "SECURITY.md"
SECURITY_TXT = CODE_ROOT / "docs" / "security.txt"
PENTEST_REPORT = CODE_ROOT / "docs" / "external-pentest-report.md"

# RFC 9116 field lines: a field name of letters/hyphens, a colon, a space, a value.
_FIELD_RE = re.compile(r"^[A-Za-z-]+: .+$")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------- SECURITY.md


def test_the_vulnerability_disclosure_policy_is_present() -> None:
    assert SECURITY_MD.is_file()


def test_the_policy_names_a_reporting_contact_a_timeline_and_a_safe_harbour() -> None:
    text = _text(SECURITY_MD)
    lowered = text.lower()

    # A way to report, and the disclosure timeline. The reporting channel is the
    # repository's private security advisory form (the project has no mailbox; the
    # earlier placeholder address pointed at a domain nobody operated).
    assert "security/advisories/new" in text, "the policy names the reporting channel"
    assert "mailto:" in lowered or "security advis" in lowered
    assert "disclosure" in lowered
    assert "90 days" in lowered

    # A safe-harbour statement (both spellings accepted).
    assert "safe harbour" in lowered or "safe harbor" in lowered


def test_the_policy_names_each_external_validation_artifact() -> None:
    lowered = _text(SECURITY_MD).lower()
    assert "vulnerability disclosure policy" in lowered
    assert "security.txt" in lowered
    assert "penetration" in lowered


def test_the_policy_states_that_unauthorized_use_is_prohibited() -> None:
    lowered = _text(SECURITY_MD).lower()
    assert "authoriz" in lowered
    # The defensive posture is the reason, not a disclaimer bolted on.
    assert "defensive" in lowered


# --------------------------------------------------------------- security.txt


def _security_txt_fields() -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in _text(SECURITY_TXT).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        assert _FIELD_RE.match(stripped), f"not an RFC 9116 field line: {line!r}"
        name, _, value = stripped.partition(": ")
        fields[name] = value
    return fields


def test_security_txt_is_rfc_9116_shaped_and_has_the_required_fields() -> None:
    fields = _security_txt_fields()

    for required in ("Contact", "Expires", "Preferred-Languages", "Canonical"):
        assert required in fields, f"missing required field: {required}"

    assert fields["Contact"].startswith("mailto:") or fields["Contact"].startswith("https:")
    assert fields["Canonical"].startswith("https:")
    assert "en" in fields["Preferred-Languages"].lower()


def test_security_txt_has_a_comment_header() -> None:
    first_line = _text(SECURITY_TXT).splitlines()[0]
    assert first_line.startswith("#")
    assert "security.txt" in first_line


def test_security_txt_expires_in_the_future_within_a_year() -> None:
    expires_raw = _security_txt_fields()["Expires"]
    # Normalise the RFC 3339 trailing "Z" before handing it to fromisoformat.
    expires = datetime.fromisoformat(expires_raw.replace("Z", "+00:00"))
    assert expires.tzinfo is not None

    now = datetime.now(UTC)
    assert expires > now, "security.txt has expired"
    assert expires - now <= timedelta(days=366), "Expires is more than a year ahead"


# ------------------------------------------------------- pentest report


def test_the_external_pentest_report_is_present_and_flagged_placeholder() -> None:
    text = _text(PENTEST_REPORT)
    assert "PLACEHOLDER" in text.upper()
    # The placeholder must not read as a passed test.
    lowered = text.lower()
    assert "no external" in lowered or "no test" in lowered
    assert "not a security claim" in lowered or "no security claim" in lowered


def test_the_pentest_report_has_a_methodology_section() -> None:
    lowered = _text(PENTEST_REPORT).lower()
    assert "methodology" in lowered
    assert "scope" in lowered
    assert "rules of engagement" in lowered or "in scope" in lowered


def test_the_pentest_report_has_severity_and_sla_tables() -> None:
    lowered = _text(PENTEST_REPORT).lower()
    assert "cvss v3.1" in lowered
    assert "sla" in lowered
    # The severity ladder and its CVSS mapping.
    assert "critical" in lowered and "high" in lowered and "medium" in lowered


def test_the_pentest_report_has_a_placeholder_findings_register() -> None:
    lowered = _text(PENTEST_REPORT).lower()
    assert "findings register" in lowered
    assert "none recorded yet" in lowered
    # The register is empty and says so.
    assert "absence of findings is not a security claim" in lowered or (
        "empty" in lowered and "not a security claim" in lowered
    )
