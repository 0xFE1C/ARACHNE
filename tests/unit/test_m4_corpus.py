"""The M4 probe corpus and its wordlists (managed data, F-09-04).

The corpus is the part of M4 an operator is most likely to tune, so its loader has to be
as trustworthy as the shipped data: every regex compiles, a missing section degrades to
"no entries" rather than an exception, an operator file replaces the packaged one, and a
wordlist is bounded so a project-supplied list cannot turn a probe into a campaign.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.errors import ConfigurationError
from arachne.modules.m4.corpus import (
    load_corpus,
    load_wordlist,
    parse_corpus,
)


# --------------------------------------------------------------------------- shipped data
def test_the_shipped_corpus_parses_and_covers_every_family() -> None:
    corpus = load_corpus()
    # 1.1 (WP-29) added the infrastructure-artifact groups (REQ-DET-022).
    assert corpus.version == "1.1"
    assert len(corpus.env_paths()) >= 10
    assert {"git", "svn", "hg"} <= {probe.family for probe in corpus.vcs_probes()}
    assert ".sql" in corpus.backup_extensions()
    assert corpus.backup_priority()[0] == "db.sql"
    assert len(corpus.sourcemap_document_keys()) >= 2
    assert "/swagger.json" in corpus.api_doc_paths()
    assert any(probe.family == "actuator-env" for probe in corpus.debug_probes())
    assert "/files/" in corpus.directory_paths()
    assert {"Jenkins", "Grafana", "Kibana", "Prometheus", "Consul", "phpMyAdmin"} <= {
        panel.product for panel in corpus.dashboards()
    }
    assert {"endpoint", "s3", "gcs", "azure"} <= {
        provider.name for provider in corpus.bucket_providers()
    }
    assert len(corpus.key_paths()) >= 8
    assert "content-security-policy" in corpus.header_baseline(https=True)
    assert corpus.cors_origins()
    assert corpus.email_dkim_selectors()
    assert "/dav/" in corpus.webdav_paths()
    assert {"next", "return"}.isdisjoint(corpus.metadata_sink_hints())
    assert corpus.user_fields() and corpus.valid_markers()
    assert corpus.unauth_path_hints()
    assert {item.product for item in corpus.credential_products()} >= {"Jenkins"}


def test_the_shipped_artifact_groups_cover_every_check_family() -> None:
    """WP-29's groups: one per check, every probe carrying a marker or a binary suffix."""
    corpus = load_corpus()
    groups = corpus.artifact_groups()
    assert len(groups) == 24, groups
    assert len(set(groups)) == len(groups)
    binary = set(corpus.artifact_binary_extensions())
    assert {".tfplan", ".swp", ".ds_store"} <= binary
    # The two credential-bearing groups are confirmed by the redactor rather than by a marker,
    # so they are the only groups whose probes may carry neither (the WP-29 acceptance test
    # drives those two against the redaction assertions).
    detector_groups = {"dvcs_credentials", "ci_pipeline_secret"}
    for group in groups:
        probes = corpus.artifact_probes(group)
        assert probes, group
        assert all(probe.path.startswith("/") for probe in probes), group
        for probe in probes:
            if group in detector_groups:
                continue
            # Every other probe is confirmable without decoding a body: its own marker, or a
            # suffix the corpus declares binary.
            suffix = f".{probe.path.rpartition('.')[2].lower()}"
            assert probe.markers or suffix in binary, probe.path
    # An unknown group degrades to "no probes" rather than raising, so an operator-supplied
    # corpus without the section still runs every other M4 check.
    assert corpus.artifact_probes("no-such-group") == ()
    assert corpus.artifact_min_bytes() > 0


def test_the_shipped_wordlists_are_bounded_and_deduplicated() -> None:
    for name in (
        "wordlists/backup-names.txt",
        "wordlists/hidden-paths.txt",
        "wordlists/bucket-names.txt",
    ):
        entries = load_wordlist(name)
        assert entries, name
        assert len(entries) == len(set(entries)), name
        assert all(not entry.startswith("#") for entry in entries), name
    # The two bucket names that matter most come first, so a bounded probe exercises both
    # a public and a denied answer.
    assert load_wordlist("wordlists/bucket-names.txt")[:2] == ("backup", "private")


def test_a_wordlist_limit_is_honoured_and_capped() -> None:
    assert len(load_wordlist("wordlists/hidden-paths.txt", limit=3)) == 3
    assert len(load_wordlist("wordlists/hidden-paths.txt", limit=10_000)) <= 500


def test_the_sourcemap_pattern_finds_the_reference() -> None:
    pattern = load_corpus().sourcemap_reference_regex()
    assert pattern is not None
    match = pattern.search("//# sourceMappingURL=app.js.map")
    assert match is not None and match.group(1) == "app.js.map"
    assert pattern.search("var x = 1;") is None


# --------------------------------------------------------------------------- loading rules
def test_an_operator_corpus_replaces_the_packaged_one(tmp_path: Path) -> None:
    custom = tmp_path / "probes.yaml"
    custom.write_text(
        "version: '9.9'\nenv:\n  paths: ['/.custom-env']\n  markers: ['CUSTOM_KEY=']\n",
        encoding="utf-8",
    )
    corpus = load_corpus(str(custom))
    assert corpus.version == "9.9"
    assert corpus.env_paths() == ("/.custom-env",)
    # Every other family degrades to "no entries" rather than failing.
    assert corpus.vcs_probes() == ()
    assert corpus.dashboards() == ()
    assert corpus.bucket_providers() == ()


def test_a_directory_override_loads_its_probes_file(tmp_path: Path) -> None:
    (tmp_path / "probes.yaml").write_text("version: '2.0'\n", encoding="utf-8")
    assert load_corpus(str(tmp_path)).version == "2.0"


def test_a_missing_or_malformed_corpus_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        load_corpus(str(tmp_path / "nope.yaml"))
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ConfigurationError, match=r"no probes\.yaml"):
        load_corpus(str(empty))
    broken = tmp_path / "broken.yaml"
    broken.write_text("version: '1.0'\nenv: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not valid YAML"):
        load_corpus(str(broken))
    with pytest.raises(ConfigurationError, match=r"'version' is required"):
        parse_corpus({"env": {}})


def test_a_broken_regex_fails_at_load_time() -> None:
    with pytest.raises(ConfigurationError, match="not a valid regex"):
        parse_corpus(
            {
                "version": "1.0",
                "env": {"assignment_regex": "([unclosed"},
            }
        )


def test_an_operator_wordlist_wins_over_the_packaged_one(tmp_path: Path) -> None:
    wordlists = tmp_path / "wordlists"
    wordlists.mkdir()
    (wordlists / "hidden-paths.txt").write_text("# comment\ncustom-path\n", encoding="utf-8")
    assert load_wordlist("wordlists/hidden-paths.txt", override_dir=str(tmp_path)) == (
        "custom-path",
    )
    # A name the operator directory does not hold still comes from the package.
    assert load_wordlist("wordlists/bucket-names.txt", override_dir=str(tmp_path))
