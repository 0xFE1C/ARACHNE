"""CMDB criticality parsing and the lookup index (S23, REQ-POSTURE-006).

The import is fail-closed on malformed rows (a silently missing tier-1 host is worse than
a failed import), the tier ladder is 1..4, and the index answers exact host first with the
most specific wildcard as the fallback.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError
from arachne.posture.cmdb import CriticalityIndex, parse_cmdb

_CSV = "host,tier,name\npayments.example.com,1,Payments\nbuild.example.com,4,Builders\n"

_JSON = (
    '[{"host": "api.example.com", "tier": 2, "name": "API"}, {"host": "*.example.com", "tier": 3}]'
)


def test_a_csv_import_parses_rows() -> None:
    entries = parse_cmdb(_CSV, source="test")
    assert [(item.host, item.tier, item.name) for item in entries] == [
        ("payments.example.com", 1, "Payments"),
        ("build.example.com", 4, "Builders"),
    ]


def test_a_json_import_parses_rows() -> None:
    entries = parse_cmdb(_JSON, source="test")
    assert entries[0].host == "api.example.com"
    assert entries[0].tier == 2
    assert entries[1].host == "*.example.com"


def test_a_malformed_row_is_refused_not_skipped() -> None:
    with pytest.raises(ConfigurationError):
        parse_cmdb("host,tier\npayments.example.com,9\n", source="test")
    with pytest.raises(ConfigurationError):
        parse_cmdb("host,tier\npayments.example.com,high\n", source="test")
    with pytest.raises(ConfigurationError):
        parse_cmdb("name\nfoo\n", source="test")
    with pytest.raises(ConfigurationError):
        parse_cmdb("[{nope}]", source="test")
    with pytest.raises(ConfigurationError):
        parse_cmdb("not json at all", source="test")


def test_an_over_cap_import_is_refused() -> None:
    rows = ",".join(f'{{"host": "h{i}", "tier": 1}}' for i in range(5))
    with pytest.raises(ConfigurationError):
        parse_cmdb(f"[{rows}]", source="test", max_rows=4)


def test_the_index_prefers_exact_then_the_most_specific_wildcard() -> None:
    index = CriticalityIndex(
        {
            "payments.example.com": 1,
            "*.example.com": 3,
            "example.com": 4,
        }
    )
    assert index.lookup("payments.example.com") == 1
    assert index.lookup("api.example.com") == 3  # the wildcard
    assert index.lookup("example.com") == 4
    assert index.lookup("elsewhere.org") is None
    assert index.lookup("") is None


def test_a_deeper_wildcard_wins_over_a_shallower_one() -> None:
    index = CriticalityIndex({"*.example.com": 3, "*.payments.example.com": 1})
    assert index.lookup("api.payments.example.com") == 1
    assert index.lookup("api.example.com") == 3


def test_an_empty_index_is_falsy() -> None:
    assert not CriticalityIndex({})
    assert CriticalityIndex({"a": 1})
