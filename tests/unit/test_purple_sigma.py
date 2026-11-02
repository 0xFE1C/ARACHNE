"""Sigma alignment against the M6 hunt library (S24, REQ-VALID-004).

The alignment's value is that it is an *evaluation*, not a claim: the telemetry each
replayable action declares is fed to the same matcher M6 uses on ingested logs. These tests
pin the three verdicts that matter — a hit, the deliberate miss, and the fact that the
verdicts come from real rule files rather than a hard-coded table.
"""

from __future__ import annotations

from pathlib import Path

from arachne.modules.m6.feeds import SigmaRule, load_sigma_rules, match_event
from arachne.purple.attack import load_technique_map
from arachne.purple.sigma import align_action, align_actions, rule_techniques, shipped_rules

#: The demonstrated miss: the L4 data-manipulation marker. It is a real, safe, replayable
#: proof action and the shipped library has no rule for its technique — which is exactly
#: what the alignment exists to say out loud.
DELIBERATE_MISS = "m3.state-marker"


def test_the_alignment_evaluates_every_shipped_action_against_the_hunt_library() -> None:
    replay = load_technique_map()
    alignments = align_actions(tuple(replay.actions.values()))
    assert len(alignments) == len(replay.actions)
    for item in alignments:
        assert item.rule_count >= 1
        assert item.verdict in {"rule-hit", "rule-miss"}
        assert item.event_summary
        assert item.fields
        # The verdict is reproducible: the same evaluation, run again, agrees.
        again = align_action(replay.require(item.check_id), shipped_rules())
        assert again.verdict == item.verdict
        assert again.hits == item.hits


def test_a_shell_spawning_action_is_a_rule_hit_on_the_shipped_web_worker_rule() -> None:
    """The hit half: a web worker spawning a shell is exactly what the library looks for."""
    replay = load_technique_map()
    alignment = align_action(replay.require("m3.rce-echo"), shipped_rules())
    assert alignment.verdict == "rule-hit"
    titles = [title for _, title, _, _ in alignment.hits]
    assert any("worker spawning a shell" in title for title in titles)
    rule_id, _, level, techniques = alignment.hits[0]
    assert rule_id == "8f2c1a10-0e11-4a2b-9c33-6b0e5d7a1004"
    assert level == "high"
    assert "T1059" in techniques


def test_the_l4_marker_is_the_demonstrated_rule_miss() -> None:
    """REQ-VALID-004's acceptance: the Sigma-aligned report shows a deliberate miss."""
    replay = load_technique_map()
    alignment = align_action(replay.require(DELIBERATE_MISS), shipped_rules())
    assert alignment.verdict == "rule-miss"
    assert alignment.hits == ()
    assert alignment.techniques == ("T1565.001",)
    # The library was *evaluated* (it is a gap in the rule set, not a skipped check).
    assert alignment.rule_count == len(shipped_rules())
    assert alignment.looked_but_missed == alignment.rule_count
    document = alignment.to_dict()
    assert document["verdict"] == "rule-miss"
    assert document["hits"] == []
    assert document["event"]["summary"]


def test_the_rule_technique_tags_are_read_from_the_rule_not_assumed() -> None:
    """With no rule file, a tag that is not a technique id is skipped, never guessed."""
    tagged = SigmaRule(
        title="t",
        id="1",
        level="high",
        tags=("attack.credential_access", "attack.t1558.003", "not-a-technique", "attack.T1059"),
    )
    assert rule_techniques(tagged) == ("T1558.003", "T1059")
    assert rule_techniques(SigmaRule(title="t", id="1", level="low")) == ()


def test_the_alignment_uses_the_library_it_is_given() -> None:
    """An operator's own rule set is what gets evaluated — loaded from disk, not baked in."""
    rules = load_sigma_rules()
    assert len(rules) == len(shipped_rules())
    with_rules = align_actions(tuple(load_technique_map().actions.values()), rules)
    assert {item.verdict for item in with_rules} == {"rule-hit", "rule-miss"}

    # A directory with a single narrow copy of the web-worker rule: the shell actions hit
    # it and everything else misses, which proves the verdicts follow the files.
    narrowed = SigmaRule(
        title="Web worker spawning a shell",
        id="8f2c1a10-0e11-4a2b-9c33-6b0e5d7a1004",
        level="high",
        tags=("attack.execution", "attack.t1059"),
        selections={
            "selection": {
                "EventID": 1,
                "ParentImage|endswith": ["/php-fpm"],
                "Image|endswith": ["/sh"],
            }
        },
    )
    assert match_event(
        narrowed, {"EventID": 1, "ParentImage": "/usr/sbin/php-fpm", "Image": "/bin/sh"}
    )
    replay = load_technique_map()
    assert align_action(replay.require("m3.cmdi-oob"), (narrowed,)).verdict == "rule-hit"
    assert align_action(replay.require("m3.sqli-oob"), (narrowed,)).verdict == "rule-miss"


def test_a_rule_miss_states_the_gap_and_the_evaluated_count(tmp_path: Path) -> None:
    """The report line for a miss must say what was evaluated, not just "no hit"."""
    replay = load_technique_map()
    alignment = align_action(replay.require(DELIBERATE_MISS), shipped_rules())
    assert alignment.to_dict()["rules_evaluated"] == len(shipped_rules())
    assert str(tmp_path)  # the fixture argument keeps the test's scope honest
