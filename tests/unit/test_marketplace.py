"""The plugin marketplace catalogue (F-09-01, S14)."""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.errors import ConfigurationError
from arachne.plugins.marketplace import (
    CHECK_ENTRY_POINT_GROUP,
    FORMAT_ENTRY_POINT_GROUP,
    MarketplaceCatalog,
    load_marketplace,
)


def test_the_bundled_catalogue_lists_both_example_plugins() -> None:
    catalogue = load_marketplace()
    names = [entry.name for entry in catalogue.entries]
    assert "arachne-example-check-plugin" in names
    assert "arachne-example-report-plugin" in names
    kinds = {entry.name: entry.kind for entry in catalogue.entries}
    assert kinds["arachne-example-check-plugin"] == "check"
    assert kinds["arachne-example-report-plugin"] == "report-format"


def test_the_catalogue_entry_point_groups_match_the_registries() -> None:
    from arachne.modules import registry
    from arachne.report import formats

    assert registry.ENTRY_POINT_GROUP == CHECK_ENTRY_POINT_GROUP
    assert formats.ENTRY_POINT_GROUP == FORMAT_ENTRY_POINT_GROUP


def test_sources_point_at_real_directories() -> None:
    """The shipped entries are installable offline, which is what makes the demo honest."""
    root = Path(__file__).resolve().parents[2]
    for entry in load_marketplace().entries:
        if entry.source.startswith(("git+", "http")):
            continue
        path = root / entry.source
        assert (path / "pyproject.toml").is_file(), f"{entry.name}: {path} is not a package"


def test_search_matches_name_description_and_tags() -> None:
    catalogue = load_marketplace()
    by_name = catalogue.search("report-plugin")
    assert [item.name for item in by_name] == ["arachne-example-report-plugin"]
    by_tag = catalogue.search("m4")
    assert any(item.name == "arachne-example-check-plugin" for item in by_tag)
    assert catalogue.search("") == catalogue.entries


def test_listing_marks_uninstalled_entries() -> None:
    rows = load_marketplace().listing()
    # The examples are not installed in the test environment.
    assert all(isinstance(row["installed"], bool) for row in rows)
    assert any(row["installed"] is False for row in rows)


def test_a_custom_catalogue_is_loaded_from_a_path(tmp_path: Path) -> None:
    path = tmp_path / "index.yaml"
    path.write_text(
        """
version: "9"
updated: "2026-01-01"
plugins:
  - name: local-plugin
    kind: check
    description: a local one
    version: "1.0"
    source: /tmp/local-plugin
    entry_point_group: arachne.modules
"""
    )
    catalogue = load_marketplace(path)
    assert catalogue.version == "9"
    assert catalogue.get("LOCAL-PLUGIN") is not None  # case-insensitive lookup
    assert catalogue.to_dict()["source"].endswith("index.yaml")


@pytest.mark.parametrize(
    "document, message",
    [
        ("plugins: not-a-list\n", "'plugins' must be a list"),
        ("plugins:\n  - name: x\n    kind: nonsense\n    source: /tmp/x\n", "unknown kind"),
        ("plugins:\n  - name: x\n    kind: check\n", "invalid marketplace entry"),
        (
            "plugins:\n  - name: x\n    kind: check\n    source: /a\n"
            "  - name: x\n    kind: check\n    source: /b\n",
            "appears twice",
        ),
    ],
)
def test_a_bad_catalogue_is_refused_with_the_reason(
    tmp_path: Path, document: str, message: str
) -> None:
    path = tmp_path / "index.yaml"
    path.write_text(document)
    with pytest.raises(ConfigurationError, match=message):
        load_marketplace(path)


def test_a_missing_catalogue_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_marketplace(tmp_path / "nope.yaml")


def test_an_empty_catalogue_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "index.yaml"
    path.write_text("")
    catalogue = load_marketplace(path)
    assert catalogue == MarketplaceCatalog(source=str(path))
