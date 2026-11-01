"""Feed-driven check synthesis (REQ-AGENT-004): proposals, versions, parity, no deployment.

The requirement's four conditions are four tests: a proposal is derived from feed data, it
bumps the check version, it cannot be approved without parity, and there is no code path from
a proposal into the live registry. The last one is the important one, and it is checked
structurally (the registry's check set is unchanged and the artifact writer refuses the live
catalogue directory) rather than by the absence of a function named ``deploy``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from arachne.core.catalog import load_catalog
from arachne.core.errors import ConfigurationError
from arachne.modules.registry import ModuleRegistry
from arachne.quality.synthesis import (
    CheckProposal,
    CheckSynthesizer,
    FeedHint,
    ParityEvidence,
    approve,
    write_artifacts,
)

HINT = FeedHint(
    cve="CVE-2021-44228",
    product="Apache Log4j",
    summary="JNDI features do not protect against attacker-controlled LDAP lookups.",
    source="feed:kev",
    known_exploited=True,
    cvss=10.0,
)


def test_a_proposal_is_derived_from_feed_data_and_names_its_source() -> None:
    proposals = CheckSynthesizer(catalogue_version="1.8").propose([HINT])
    assert len(proposals) == 1
    proposal = proposals[0]
    assert proposal.check_id == "m2.cve-2021-44228-apache-log4j"
    assert proposal.based_on.cve == "CVE-2021-44228"
    assert "CVE-2021-44228" in proposal.description
    assert proposal.status == "proposed"
    assert proposal.catalogue_version == "1.8"


def test_a_new_check_starts_at_zero_and_an_existing_one_is_bumped() -> None:
    synthesizer = CheckSynthesizer()
    new = synthesizer.propose([HINT])[0]
    assert new.previous_version is None and new.proposed_version == "0.1.0"
    bumped = synthesizer.propose([HINT], existing_versions={new.check_id: "0.1.0"})[0]
    assert bumped.bumped
    assert bumped.previous_version == "0.1.0"
    assert bumped.proposed_version == "0.2.0"


def test_a_malformed_cve_is_refused_at_construction() -> None:
    with pytest.raises(ValueError, match="CVE"):
        FeedHint(cve="2021-44228")


def test_the_artifacts_are_reviewable(tmp_path: Path) -> None:
    proposals = CheckSynthesizer().propose([HINT])
    manifest = write_artifacts(proposals, tmp_path / "proposals")
    folder = tmp_path / "proposals" / proposals[0].check_id
    assert manifest.exists()
    assert {path.name for path in folder.iterdir()} == {
        "check.yaml",
        "test_proposed_check.py",
        "REVIEW.md",
        "proposal.json",
    }
    row = yaml.safe_load((folder / "check.yaml").read_text(encoding="utf-8"))
    assert row["module"] == "M2" and row["version"] == "0.1.0"
    checklist = (folder / "REVIEW.md").read_text(encoding="utf-8")
    assert "parity" in checklist and "bumped" in checklist
    scaffold = (folder / "test_proposed_check.py").read_text(encoding="utf-8")
    assert "pytest.fail" in scaffold, "the scaffold must fail until a developer fills it in"
    document = json.loads(manifest.read_text(encoding="utf-8"))
    assert document["deployed"] is False
    assert document["proposals"][0]["check_id"] == proposals[0].check_id


def test_the_live_registry_is_untouched_by_synthesis(tmp_path: Path) -> None:
    before_checks = len(ModuleRegistry.discover().metadata())
    before_catalogue = len(load_catalog().checks)
    proposals = CheckSynthesizer().propose([HINT])
    write_artifacts(proposals, tmp_path / "proposals")
    assert len(ModuleRegistry.discover().metadata()) == before_checks
    assert len(load_catalog().checks) == before_catalogue
    # And the proposed id is not in either: a proposal is not a check.
    assert proposals[0].check_id not in {item.id for item in load_catalog().checks}


def test_the_writer_refuses_the_live_catalogue_directory(tmp_path: Path) -> None:
    proposals = CheckSynthesizer().propose([HINT])
    live = Path(__file__).resolve().parents[2] / "src" / "arachne" / "templates" / "plan"
    with pytest.raises(ConfigurationError, match="shipped catalogue"):
        write_artifacts(proposals, live)
    # A path that *is* the live catalogue file (however it is spelled) is refused too.
    with pytest.raises(ConfigurationError, match="live catalogue"):
        write_artifacts(
            proposals, tmp_path / "src" / "arachne" / "templates" / "plan" / "check_catalog.yaml"
        )


def test_a_proposal_cannot_be_approved_without_parity() -> None:
    proposal = CheckSynthesizer().propose([HINT])[0]
    with pytest.raises(ConfigurationError, match="parity"):
        approve(
            proposal,
            parity=ParityEvidence(ok=False, suite="arachne-lab"),
            reviewer="alice",
        )
    with pytest.raises(ConfigurationError, match="named reviewer"):
        approve(proposal, parity=ParityEvidence(ok=True), reviewer="  ")
    approved = approve(
        proposal,
        parity=ParityEvidence(ok=True, suite="arachne-lab", detail="detection 94%"),
        reviewer="alice",
    )
    assert approved.status == "approved"
    assert approved.approved_by == "alice"
    assert approved.parity is not None and approved.parity.ok


def test_a_duplicate_cve_is_proposed_once() -> None:
    proposals = CheckSynthesizer().propose([HINT, HINT])
    assert len(proposals) == 1


def test_the_proposal_document_round_trips(tmp_path: Path) -> None:
    proposal = CheckSynthesizer().propose([HINT])[0]
    write_artifacts([proposal], tmp_path / "proposals")
    document = json.loads(
        (tmp_path / "proposals" / proposal.check_id / "proposal.json").read_text(encoding="utf-8")
    )
    restored = CheckProposal.from_document(document)
    assert restored.check_id == proposal.check_id
    assert restored.catalogue_row()["version"] == proposal.proposed_version
    assert restored.based_on.known_exploited
