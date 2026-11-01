"""The M6 corpus, feeds and the bounded Sigma evaluator (S11, F-09-04).

These are the data-integrity tests: every regex compiles, every signature has a severity, the
EPSS/LPE/Sigma loaders round-trip and can be overridden by an operator file, and the Sigma
matcher fires on the events its rules describe and *not* on their benign controls.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from arachne.core.errors import ConfigurationError
from arachne.modules.m6.corpus import load_corpus, load_wordlist, parse_corpus
from arachne.modules.m6.feeds import (
    load_epss,
    load_lpe_index,
    load_sigma_rules,
    match_event,
)

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


# --------------------------------------------------------------------------- corpus
def test_the_corpus_loads_with_its_sections() -> None:
    corpus = load_corpus()
    assert corpus.version
    assert len(corpus.webshell_signatures()) >= 8
    assert len(corpus.secret_detectors()) >= 15
    assert corpus.webshell_script_extensions()
    heuristics = corpus.webshell_heuristics()
    assert heuristics["max_line_length"] > 0
    assert corpus.genai_endpoint_paths()
    assert corpus.genai_key_patterns()
    assert corpus.ad_domain_admin_labels()
    assert corpus.deception_token_fields()


def test_every_webshell_signature_has_a_severity_hint() -> None:
    for signature in load_corpus().webshell_signatures():
        assert signature.severity in {"info", "low", "medium", "high", "critical"}
        assert signature.id


def test_a_corpus_with_a_bad_regex_fails_at_load() -> None:
    with pytest.raises(ConfigurationError, match="not a valid regex"):
        corpus = parse_corpus(
            {
                "version": "1",
                "webshell": {"signatures": [{"id": "bad", "pattern": "(["}]},
            },
            source="test",
        )
        corpus.webshell_signatures()


def test_an_absent_section_is_tolerated() -> None:
    corpus = parse_corpus({"version": "1"}, source="test")
    assert corpus.webshell_signatures() == ()
    assert corpus.genai_endpoint_paths() == ()


def test_a_non_mapping_corpus_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="mapping"):
        parse_corpus(["not", "a", "mapping"], source="test")


def test_the_served_path_wordlist_is_short_and_specific() -> None:
    entries = load_wordlist("wordlists/served-shell-paths.txt")
    assert 3 <= len(entries) <= 100
    assert all(not entry.startswith("#") for entry in entries)
    assert "shell.php" in entries


def test_the_wordlist_honours_an_operator_override(tmp_path: Path) -> None:
    override = tmp_path / "wordlists"
    override.mkdir()
    (override / "served-shell-paths.txt").write_text("mine.php\n", encoding="utf-8")
    assert load_wordlist("wordlists/served-shell-paths.txt", override_dir=tmp_path) == ("mine.php",)


# --------------------------------------------------------------------------- EPSS / KEV
def test_the_epss_snapshot_loads_and_ranks() -> None:
    snapshot = load_epss()
    entry = snapshot.get("CVE-2021-4034")
    assert entry is not None and entry.kev is True
    assert snapshot.rank("CVE-2021-4034") > 0.5
    assert snapshot.rank("CVE-0000-0000") == 0.0


def test_an_operator_epss_csv_overrides_the_snapshot() -> None:
    snapshot = load_epss(FIXTURES / "logs" / "epss.csv")
    # The CSV sets CVE-2021-4034 to 0.10, overriding the snapshot's 0.89.
    assert snapshot.rank("CVE-2021-4034") == pytest.approx(0.10)
    # And adds a row the snapshot may not carry.
    assert snapshot.get("CVE-2021-23017") is not None


def test_a_kev_feed_marks_a_cve_exploited(tmp_path: Path) -> None:
    kev = tmp_path / "kev.json"
    kev.write_text('{"vulnerabilities": [{"cveID": "CVE-2021-23017"}]}', encoding="utf-8")
    snapshot = load_epss(kev_path=kev)
    entry = snapshot.get("CVE-2021-23017")
    assert entry is not None and entry.kev is True


def test_the_lpe_index_loads_as_a_cve_index() -> None:
    index = load_lpe_index()
    assert index.index_version
    products = {entry.product for entry in index.entries}
    assert "policykit" in products
    assert "linux-kernel" in products


# --------------------------------------------------------------------------- Sigma
def test_the_sigma_rules_load_and_are_sigma_shaped() -> None:
    rules = load_sigma_rules()
    assert len(rules) >= 5
    for rule in rules:
        assert rule.title and rule.id and rule.condition
        assert rule.selections, f"{rule.id} has no selections"
        assert rule.logsource


def test_a_kerberoasting_event_matches_and_an_aes_one_does_not() -> None:
    rules = {rule.id: rule for rule in load_sigma_rules()}
    kerberoast = next(rule for rule in rules.values() if "Kerberoasting" in rule.title)
    assert match_event(
        kerberoast,
        {"EventID": 4769, "TicketEncryptionType": "0x17", "ServiceName": "MSSQLSvc/db"},
    )
    # AES encryption means it is not a roast.
    assert not match_event(
        kerberoast,
        {"EventID": 4769, "TicketEncryptionType": "0x12", "ServiceName": "HTTP/web"},
    )
    # A machine account is filtered out.
    assert not match_event(
        kerberoast,
        {"EventID": 4769, "TicketEncryptionType": "0x17", "ServiceName": "DC01$"},
    )


def test_an_lsass_access_event_matches() -> None:
    rules = {rule.title: rule for rule in load_sigma_rules()}
    rule = next(rule for title, rule in rules.items() if "LSASS" in title)
    assert match_event(
        rule,
        {
            "EventID": 10,
            "TargetImage": r"C:\Windows\system32\lsass.exe",
            "SourceImage": r"C:\Users\Public\tool.exe",
        },
    )
    # A known good source is filtered out.
    assert not match_event(
        rule,
        {
            "EventID": 10,
            "TargetImage": r"C:\Windows\system32\lsass.exe",
            "SourceImage": r"C:\Windows\system32\svchost.exe",
        },
    )


def test_a_rule_the_evaluator_cannot_honour_does_not_raise() -> None:
    from arachne.modules.m6.feeds import SigmaRule

    rule = SigmaRule(
        title="unsupported",
        id="x",
        level="low",
        selections={"selection": {"EventID": 1}},
        condition="1 of selection*",
    )
    assert match_event(rule, {"EventID": 1}) is False


def test_an_operator_sigma_directory_overrides_the_shipped_rules(tmp_path: Path) -> None:
    (tmp_path / "custom.yml").write_text(
        yaml.safe_dump(
            {
                "title": "custom",
                "id": "custom-1",
                "level": "high",
                "logsource": {"product": "test"},
                "detection": {"selection": {"EventID": 9999}, "condition": "selection"},
            }
        ),
        encoding="utf-8",
    )
    rules = load_sigma_rules(tmp_path)
    assert len(rules) == 1 and rules[0].id == "custom-1"
