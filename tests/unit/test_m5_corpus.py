"""The M5 corpus and its typed accessors (F-09-04).

The corpus is the module's documentation of what it sends, so the tests here are about the
loader's contract: a broken regex fails at load time, every family's accessor returns the shape
the checks consume, and an operator override replaces the shipped data.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.core.errors import ConfigurationError
from arachne.modules.m5.corpus import (
    load_corpus,
    load_wordlist,
    parse_corpus,
)


def test_the_shipped_corpus_loads_and_exposes_every_family() -> None:
    corpus = load_corpus()
    assert corpus.version
    assert corpus.bucket_providers()
    assert corpus.firebase_rtdb_paths()
    assert corpus.supabase_tables()
    assert corpus.tfstate_paths()
    assert corpus.iac_patterns()
    assert corpus.k8s_kubelet_paths()
    assert corpus.registry_catalog_path().startswith("/v2/")
    assert corpus.docker_api_paths()
    assert corpus.image_dockerfile_names()
    assert corpus.secret_patterns()
    assert corpus.cicd_patterns()
    assert corpus.sbom_vulnerable()
    assert corpus.imds_targets()
    assert corpus.iam_read_only_permissions()


def test_an_endpoint_bucket_provider_is_shipped() -> None:
    """The lab/cloud-lab form ``endpoint:<url>`` needs a provider entry to be probed."""
    providers = {provider.name: provider for provider in load_corpus().bucket_providers()}
    assert {"endpoint", "s3", "gcs", "azure"} <= set(providers)
    assert providers["endpoint"].listing_markers


def test_a_malformed_corpus_fails_at_load_time() -> None:
    with pytest.raises(ConfigurationError, match=r"not a valid regex|invalid"):
        parse_corpus(
            {
                "version": "x",
                "secrets": {"patterns": {"bad": "("}},
            }
        )


def test_a_corpus_without_a_version_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="version"):
        parse_corpus({})


def test_wordlists_load_and_ignore_comments() -> None:
    buckets = load_wordlist("wordlists/bucket-names.txt")
    assert buckets and "backup" in buckets
    assert not [entry for entry in buckets if entry.startswith("#")]
    repos = load_wordlist("wordlists/image-repos.txt")
    assert "api" in repos


def test_an_operator_directory_overrides_the_packaged_wordlist(tmp_path: Path) -> None:
    target = tmp_path / "wordlists"
    target.mkdir()
    (target / "bucket-names.txt").write_text("only-this-name\n# comment\n", encoding="utf-8")
    assert load_wordlist("wordlists/bucket-names.txt", override_dir=str(tmp_path)) == (
        "only-this-name",
    )


def test_sbom_index_entries_carry_a_fix_version() -> None:
    for component in load_corpus().sbom_vulnerable():
        assert component.name and component.below and component.cve
        assert component.severity in {"low", "medium", "high", "critical"}
