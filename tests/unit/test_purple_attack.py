"""The ATT&CK replay catalogue (S24, REQ-VALID-001/004).

The map is data, but it is load-bearing data: it decides which actions a purple run may
replay, which technique each one exercises and what telemetry each one produces. These
tests pin the parts a wrong map would silently ruin — the id grammar, the parent/sub-
technique matching rule, the level cross-check, and the map's own refusals.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from arachne.core.errors import ConfigurationError
from arachne.modules.registry import ModuleRegistry
from arachne.purple.attack import (
    NO_EVASION_POLICY,
    TACTICS,
    load_technique_map,
    normalize_technique,
    technique_matches,
    technique_parent,
)


def test_the_shipped_map_loads_and_covers_the_whole_ladder() -> None:
    """Every proof level L1-L4 is replayable, and every action maps to a real technique."""
    replay = load_technique_map()
    assert replay.version
    levels = {action.level for action in replay.actions.values()}
    assert levels == {"L1", "L2", "L3", "L4"}
    for action in replay.actions.values():
        assert action.tactic in TACTICS
        assert action.techniques
        for technique in action.techniques:
            assert technique == normalize_technique(technique)
        assert action.event.fields, action.check_id
        assert action.event.summary, action.check_id


def test_every_replay_action_is_a_real_check_at_the_declared_level() -> None:
    """The map cannot lie about the ladder: the catalogue is the authority.

    This is the property the orchestrator's gate also enforces at plan time; pinning it
    here means a map edit that drifts from the registry fails in the fast suite.
    """
    replay = load_technique_map()
    declared = {
        metadata.id: metadata.proof.value for metadata in ModuleRegistry.discover().metadata()
    }
    for check_id, action in replay.actions.items():
        assert check_id in declared, f"{check_id} is not a shipped check"
        assert declared[check_id] == action.level, (
            f"{check_id}: map says {action.level}, catalogue says {declared[check_id]}"
        )


def test_the_map_refuses_an_unknown_action() -> None:
    replay = load_technique_map()
    with pytest.raises(ConfigurationError, match=r"not a replayable purple-team action"):
        replay.require("m3.no-such-check")
    with pytest.raises(ConfigurationError, match=r"not a replayable purple-team action"):
        replay.select(("m3.cmdi-oob", "m3.invented"))


def test_technique_ids_normalize_from_every_form_seen_in_the_wild() -> None:
    assert normalize_technique("attack.t1059.004") == "T1059.004"
    assert normalize_technique("T1190") == "T1190"
    assert normalize_technique("t1565.001") == "T1565.001"
    assert technique_parent("T1059.004") == "T1059"
    assert technique_parent("T1059") == "T1059"
    for bad in ("1059", "T105", "technique", "T1059.9999"):
        with pytest.raises(ValueError):
            normalize_technique(bad)


def test_matching_counts_parents_and_sub_techniques_but_not_siblings() -> None:
    """The coverage rule, stated once: see the whole family, never a sibling."""
    assert technique_matches("T1059.004", "T1059.004")
    assert technique_matches("T1059.004", "T1059"), "a parent alert sees the sub-technique"
    assert technique_matches("T1059", "T1059.004"), "a finer rule is not a miss"
    assert not technique_matches("T1059.001", "T1059.004"), "siblings are not each other"
    assert not technique_matches("T1190", "T1059")


def test_a_broken_map_is_refused_rather_than_silently_emptied(tmp_path: Path) -> None:
    broken = tmp_path / "attck-map.yaml"
    broken.write_text("version: '1.0'\nactions: []\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match=r"declares no actions"):
        load_technique_map(broken)

    bad_tactic = tmp_path / "bad-tactic.yaml"
    bad_tactic.write_text(
        "version: '1.0'\nactions:\n"
        "  - check: m3.cmdi-oob\n    title: t\n    level: L2\n    tactic: sneaking\n"
        "    techniques: [T1059]\n    telemetry: {summary: s, event: {EventID: 1}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match=r"not an ATT&CK tactic"):
        load_technique_map(bad_tactic)

    bad_level = tmp_path / "bad-level.yaml"
    bad_level.write_text(
        "version: '1.0'\nactions:\n"
        "  - check: m3.cmdi-oob\n    title: t\n    level: L9\n    tactic: execution\n"
        "    techniques: [T1059]\n    telemetry: {summary: s, event: {EventID: 1}}\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match=r"is not L1\.\.L4"):
        load_technique_map(bad_level)


def test_no_evasion_anywhere_in_the_purple_package() -> None:
    """The hard rule of the area, as a checkable property (REQ-VALID-003).

    Purple-team tests are designed to be seen. This test parses the package's own source
    and refuses the machinery evasion would need — an encoder, an obfuscator, a packet
    splitter, a timing trick, a raw-socket escape. It reads *code*, not prose, so the
    package may document what it refuses. It is deliberately blunt: the point is that the
    capability is absent, not that it is currently unused.
    """
    import ast

    package = Path(__file__).resolve().parents[2] / "src" / "arachne" / "purple"
    forbidden_modules = {
        "base64",
        "binascii",
        "codecs",
        "gzip",
        "marshal",
        "pickle",
        "quopri",
        "uu",
        "zlib",
    }
    forbidden_names = re.compile(
        r"^(?:b64\w*|rot13|obfuscat\w*|evad\w*|stealth\w*|encode\w*|escape\w*|fromhex|"
        r"to_bytes|quote\w*|unquote\w*|socket)$",
        re.IGNORECASE,
    )
    offenders: list[str] = []
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".", 1)[0]
                    if root in forbidden_modules:
                        offenders.append(f"{path.name}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".", 1)[0]
                if root in forbidden_modules:
                    offenders.append(f"{path.name}:{node.lineno}: from {node.module} import")
            elif isinstance(node, ast.Attribute) and forbidden_names.match(node.attr):
                offenders.append(f"{path.name}:{node.lineno}: .{node.attr}")
            elif isinstance(node, ast.Name) and forbidden_names.match(node.id):
                offenders.append(f"{path.name}:{node.lineno}: {node.id}")
    assert offenders == [], f"evasion-capable code found in the purple package: {offenders}"

    assert "No encoding" in NO_EVASION_POLICY
    assert "SEEN" in NO_EVASION_POLICY


def test_the_shipped_payload_strings_are_plaintext_and_nonce_shaped() -> None:
    """Every emitted payload is the ladder's own declared payload, in the clear.

    The wire-level half of the no-evasion rule: the OOB token, the L3 ``echo`` payload and
    the calm marker all carry the nonce verbatim and contain no encoding or escaping.
    """
    from arachne.core.proof import command_payload, poc_marker, validate_nonce

    nonce = "abcdef0123456789abcdef01"
    validate_nonce(nonce)
    marker = poc_marker(nonce, "command execution (one-shot echo)")
    payload = command_payload(nonce)
    assert nonce in marker and nonce in payload
    assert payload == f"echo arachne-{nonce}"
    for text in (marker, payload):
        # No percent/base64/hex escaping, no quoting, nothing transformed: the nonce
        # appears as itself, which is what makes the artifact visibly a test.
        assert "%" not in text and "=" not in text and "\\" not in text
        assert text == text.strip()
