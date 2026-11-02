"""The content-pack review pipeline refuses what it must (S26, REQ-ECOS-001).

REQ-ECOS-001's hard rule, and this WP's: *the review pipeline must reject a malicious pack
(bad signature or unsafe check) by test*. These are safety tests in the sense
``tests/test_safety.py`` uses it — the property under test is that hostile input cannot reach a
running scan, and a regression here is a security regression, not a feature regression.

Every rejection path is exercised individually so the *reason* is pinned, not merely the
outcome: "unsigned" and "signed by another deployment" and "signed by an untrusted key" are
three different operator actions, and a pipeline that collapsed them into one "refused" would
be technically safe and operationally useless.

The fixtures below are *inert strings*: they are never imported or executed, only parsed as
source by the scanner under test.

The last test closes the loop the requirement actually cares about: a refused pack must not
*load*, which is enforced at the import boundary (``arachne packs import``), not only at review
time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import reset_settings_cache
from arachne.core.signing import DeploymentSigner
from arachne.plugins.review import (
    DECISION_LISTED,
    DECISION_REJECTED,
    review_pack,
    review_pack_bytes,
)
from arachne.resil.packs import build_pack, read_pack

KEY = "s26-review-integrity-key-0000001"
runner = CliRunner()
signer = DeploymentSigner(KEY)


# --------------------------------------------------------------------------- helpers
def _tree(tmp_path: Path, members: dict[str, str]) -> Path:
    root = tmp_path / "src"
    root.mkdir(parents=True, exist_ok=True)
    for name, body in members.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


#: The declared metadata a well-formed check pack carries: what it is and where it registers.
GOOD_META: dict[str, object] = {
    "kind": "check",
    "entry_point_group": "arachne.modules",
    "checks": ["m4.example-added-check"],
}

#: A minimal, honest third-party check: pure, no network, no side effects.
GOOD_CHECK = {
    "plugin.py": (
        "from arachne.modules.base import Module\n\n"
        "class AddedCheck(Module):\n"
        "    id = 'm4.example-added-check'\n"
    ),
    "checks/added.yaml": "checks:\n  - name: m4.example-added-check\n    proof: L1\n",
}


def _pack(
    tmp_path: Path,
    members: dict[str, str],
    *,
    meta: dict[str, object] | None = None,
    signer_: DeploymentSigner | None = signer,
) -> bytes:
    archive, _manifest, _signature = build_pack(
        {"checks": _tree(tmp_path, members)},
        name="third-party-pack",
        version="1.0.0",
        signer=signer_,
        meta=dict(GOOD_META if meta is None else meta),
    )
    return archive


# --------------------------------------------------------------------------- happy path
def test_a_clean_signed_pack_passes_every_gate_and_is_listed(tmp_path: Path) -> None:
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK), signer=signer)
    assert report.listed is True
    assert report.decision == DECISION_LISTED
    assert [gate.gate for gate in report.gates] == ["signature", "safety", "parity"]
    assert all(gate.passed for gate in report.gates)
    assert report.blockers == ()
    assert report.digest


# --------------------------------------------------------------------------- bad signature
def test_an_unsigned_pack_is_refused(tmp_path: Path) -> None:
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK, signer_=None), signer=signer)
    assert report.listed is False
    assert report.decision == DECISION_REJECTED
    codes = {item.code for item in report.blockers}
    assert "signature.unsigned" in codes
    # The reason names the missing signature, not a generic failure.
    signature = report.gate("signature")
    assert signature is not None and "no signature" in signature.detail


def test_a_pack_signed_by_another_deployment_is_refused(tmp_path: Path) -> None:
    elsewhere = DeploymentSigner("another-deployments-key-00000001")
    archive = _pack(tmp_path, GOOD_CHECK, signer_=elsewhere)
    report = review_pack_bytes(archive, signer=signer)
    assert report.listed is False
    assert "signature.invalid" in {item.code for item in report.blockers}
    signature = report.gate("signature")
    assert signature is not None and "signed by another deployment" in signature.detail


def test_a_pack_that_cannot_be_verified_without_a_key_is_refused(tmp_path: Path) -> None:
    """A deployment with no content key cannot verify, so it cannot list."""
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK), signer=None)
    assert report.listed is False
    assert {item.code for item in report.blockers} == {"signature.no_key"}


def test_a_pack_signed_by_an_untrusted_key_is_refused(tmp_path: Path) -> None:
    """A valid signature from a key this deployment does not trust is still a refusal."""
    report = review_pack(
        read_pack(_pack(tmp_path, GOOD_CHECK), signer=signer),
        signer=signer,
        trusted_key_ids=["a-different-trusted-key"],
    )
    assert report.listed is False
    assert {item.code for item in report.blockers} == {"signature.untrusted_key"}


def test_the_trusted_key_list_admits_the_deployment_key(tmp_path: Path) -> None:
    report = review_pack(
        read_pack(_pack(tmp_path, GOOD_CHECK), signer=signer),
        signer=signer,
        trusted_key_ids=[signer.key_id],
    )
    assert report.listed is True


def test_a_file_that_is_not_a_pack_is_a_rejection_not_a_crash(tmp_path: Path) -> None:
    report = review_pack_bytes(b"this is not a gzipped tarball", signer=signer)
    assert report.listed is False
    assert report.decision == DECISION_REJECTED
    assert report.blockers  # the parse error is carried as the reason


# --------------------------------------------------------------------------- unsafe check
def test_a_pack_that_starts_a_process_is_refused(tmp_path: Path) -> None:
    """The canonical "unsafe check": it shells out while claiming to be a detector."""
    members = {
        "plugin.py": (
            "import subprocess\n\n"
            "def check(target):\n"
            "    return subprocess.run(['id'], capture_output=True)\n"
        )
    }
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is False
    codes = {item.code for item in report.blockers}
    assert "import.blocked" in codes
    safety = report.gate("safety")
    assert safety is not None and safety.passed is False
    assert any("subprocess" in item.message for item in report.blockers)


def test_a_pack_that_executes_dynamic_code_is_refused(tmp_path: Path) -> None:
    members = {"plugin.py": "def check(t):\n    return eval('1 + 1')\n"}
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is False
    assert "call.dynamic_code" in {item.code for item in report.blockers}


def test_a_pack_that_imports_dynamic_code_is_refused(tmp_path: Path) -> None:
    members = {"plugin.py": "def check(t):\n    return __import__('os').getcwd()\n"}
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is False
    assert "call.dynamic_code" in {item.code for item in report.blockers}


def test_a_pack_that_opens_its_own_socket_is_refused(tmp_path: Path) -> None:
    members = {"plugin.py": "import socket\n\n\ndef check(t):\n    return socket.socket()\n"}
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is False
    assert "import.blocked" in {item.code for item in report.blockers}


def test_a_pack_that_imports_a_raw_http_library_is_refused(tmp_path: Path) -> None:
    """All egress goes through the shared HTTP client (ADR-05); a pack may not bypass it.

    The fixture names a banned library but performs nothing: the gate refuses at the *import*,
    which is the earliest and cheapest point — a pack cannot even reach code that would build a
    destination, let alone dial one.
    """
    members = {
        "plugin.py": (
            "import urllib.request\n\n"
            "# A real pack would use it here; the import alone is the refusal.\n"
            "OPENER = urllib.request\n"
        )
    }
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is False
    assert "import.blocked" in {item.code for item in report.blockers}


def test_a_state_changing_check_without_attestation_is_refused(tmp_path: Path) -> None:
    """An L3 check that does not require the state-change attestation is the unsafe check."""
    members = {
        "checks/stateful.yaml": (
            "checks:\n"
            "  - name: m3.example-state-marker\n"
            "    proof: L3\n"
            "    requires_state_attestation: false\n"
        )
    }
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is False
    codes = {item.code for item in report.blockers}
    assert "content.state_change_without_attestation" in codes


def test_an_l3_check_that_requires_the_attestation_is_allowed(tmp_path: Path) -> None:
    members = {
        "plugin.py": "def check(t):\n    return None\n",
        "checks/stateful.yaml": (
            "checks:\n"
            "  - name: m3.example-state-marker\n"
            "    proof: L3\n"
            "    requires_state_attestation: true\n"
        ),
    }
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is True


def test_a_member_that_does_not_parse_is_refused(tmp_path: Path) -> None:
    members = {"plugin.py": "def check(:\n    pass\n"}
    report = review_pack_bytes(_pack(tmp_path, members), signer=signer)
    assert report.listed is False
    assert "syntax_error" in {item.code for item in report.blockers}


# --------------------------------------------------------------------------- parity
def test_a_pack_that_replaces_a_builtin_check_is_refused(tmp_path: Path) -> None:
    """Claiming a built-in check id is substitution, not addition."""
    meta = {**GOOD_META, "checks": ["m3.cmdi-oob"]}
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK, meta=meta), signer=signer)
    assert report.listed is False
    assert {item.code for item in report.blockers} == {"parity.check_id_collision"}


def test_a_pack_that_shadows_a_builtin_report_format_is_refused(tmp_path: Path) -> None:
    meta: dict[str, object] = {
        **GOOD_META,
        "kind": "report-format",
        "entry_point_group": "arachne.report_formats",
        "formats": ["json"],
    }
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK, meta=meta), signer=signer)
    assert report.listed is False
    assert {item.code for item in report.blockers} == {"parity.format_collision"}


def test_a_pack_that_declares_nothing_about_itself_is_refused(tmp_path: Path) -> None:
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK, meta={}), signer=signer)
    assert report.listed is False
    codes = {item.code for item in report.blockers}
    assert {"parity.kind_missing", "parity.group_missing"} <= codes


def test_a_kind_that_does_not_match_its_entry_point_group_is_refused(tmp_path: Path) -> None:
    meta = {**GOOD_META, "kind": "report-format"}
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK, meta=meta), signer=signer)
    assert report.listed is False
    assert {item.code for item in report.blockers} == {"parity.group_mismatch"}


def test_an_unknown_entry_point_group_is_refused(tmp_path: Path) -> None:
    meta = {**GOOD_META, "entry_point_group": "arachne.anything"}
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK, meta=meta), signer=signer)
    assert report.listed is False
    assert {item.code for item in report.blockers} == {"parity.group_unknown"}


# --------------------------------------------------------------------------- provenance
def test_the_review_report_records_every_gate_and_its_reasons(tmp_path: Path) -> None:
    """The record an operator and an auditor both read."""
    report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK, signer_=None), signer=signer)
    payload = report.to_dict()
    assert payload["decision"] == DECISION_REJECTED
    assert payload["listed"] is False
    assert payload["format"] == "arachne-pack-review/1"
    gates = {gate["gate"]: gate for gate in payload["gates"]}
    assert gates["signature"]["passed"] is False
    assert gates["safety"]["passed"] is True
    assert gates["parity"]["passed"] is True
    assert gates["signature"]["findings"][0]["severity"] == "block"


@pytest.fixture
def deployment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'review.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    monkeypatch.setenv("ARACHNE_INTEGRITY_KEY", KEY)
    monkeypatch.setenv("ARACHNE_CONTENT_DIR", str(tmp_path / "content"))
    reset_settings_cache()
    assert runner.invoke(app, ["db", "upgrade"]).exit_code == 0
    return tmp_path


def test_the_provenance_store_keeps_the_verdict_for_the_reviewed_digest(deployment: Path) -> None:
    from arachne.core.config import get_settings
    from arachne.data.services import build_services

    signed = deployment / "signed.tar.gz"
    signed.write_bytes(_pack(deployment / "a", GOOD_CHECK))
    result = runner.invoke(app, ["plugin", "review", str(signed), "--publish", "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["listed"] is True

    services = build_services(get_settings())
    try:
        assert services.pack_reviews is not None
        record = services.pack_reviews.find("third-party-pack", "1.0.0", payload["digest"])
        assert record is not None and record.listed is True
        # The digest binds the verdict: different bytes are not "listed".
        assert services.pack_reviews.is_listed("third-party-pack", "1.0.0", "0" * 64) is False
    finally:
        services.close()


def test_a_refused_pack_exits_non_zero_and_records_the_reasons(deployment: Path) -> None:
    hostile = deployment / "hostile.tar.gz"
    hostile.write_bytes(
        _pack(
            deployment / "b",
            {
                "plugin.py": (
                    "import subprocess\n\n\ndef check(t):\n    return subprocess.run(['id'])\n"
                )
            },
        )
    )
    result = runner.invoke(app, ["plugin", "review", str(hostile), "--publish"])
    assert result.exit_code == 2, result.output
    assert "REJECTED" in result.output
    assert "import.blocked" in result.output


def test_an_unreviewed_pack_cannot_be_imported_when_review_is_required(deployment: Path) -> None:
    """REQ-ECOS-001 at the load boundary: verification is not enough, review is required."""
    pack = deployment / "unreviewed.tar.gz"
    pack.write_bytes(_pack(deployment / "c", GOOD_CHECK))
    result = runner.invoke(app, ["packs", "import", str(pack)])
    assert result.exit_code == 1, result.output
    assert "no listed review" in result.output
    # Nothing was installed.
    assert not (deployment / "content" / "third-party-pack").exists()

    # After a published review, the same pack imports.
    reviewed = runner.invoke(app, ["plugin", "review", str(pack), "--publish"])
    assert reviewed.exit_code == 0, reviewed.output
    imported = runner.invoke(app, ["packs", "import", str(pack)])
    assert imported.exit_code == 0, imported.output
    assert (deployment / "content" / "third-party-pack" / "1.0.0").is_dir()


def test_the_reviewed_pack_flow_works_end_to_end_over_the_cli(deployment: Path) -> None:
    """REQ-ECOS-001 + G6 item 4: a third-party pack through the pipeline, via the operator's CLI.

    The whole flow an operator performs, with nothing stubbed: build the content tree, declare
    what the pack is, export it signed, review it and publish the verdict, then import it. The
    declaration is what makes the parity gate able to say "this adds a check" rather than "this
    replaces one" — which is why ``packs export`` takes metadata options at all.
    """
    source = deployment / "src"
    (source / "checks").mkdir(parents=True)
    (source / "checks" / "added.yaml").write_text(
        "checks:\n  - name: m4.example-added-check\n    proof: L1\n", encoding="utf-8"
    )
    (source / "plugin.py").write_text(
        "def check(target):\n    return {'ok': True}\n", encoding="utf-8"
    )
    pack = deployment / "third-party.tar.gz"

    exported = runner.invoke(
        app,
        [
            "packs",
            "export",
            "--out",
            str(pack),
            "--name",
            "third-party-pack",
            "--version",
            "2.0.0",
            "--content",
            str(source),
            "--pack-kind",
            "check",
            "--entry-point-group",
            "arachne.modules",
            "--check-id",
            "m4.example-added-check",
            "--json",
        ],
    )
    assert exported.exit_code == 0, exported.output
    assert json.loads(exported.output)["declared"]["kind"] == "check"

    reviewed = runner.invoke(app, ["plugin", "review", str(pack), "--publish", "--json"])
    assert reviewed.exit_code == 0, reviewed.output
    verdict = json.loads(reviewed.output)
    assert verdict["listed"] is True
    assert all(gate["passed"] for gate in verdict["gates"])

    imported = runner.invoke(app, ["packs", "import", str(pack), "--json"])
    assert imported.exit_code == 0, imported.output
    assert (deployment / "content" / "third-party-pack" / "2.0.0").is_dir()

    # The verdict is in the provenance the marketplace listing reads.
    listed = runner.invoke(app, ["plugin", "marketplace", "--json"])
    assert listed.exit_code == 0, listed.output


def test_a_declared_collision_is_refused_over_the_cli(deployment: Path) -> None:
    """The same flow with the pack claiming a built-in check id: refused, and not imported."""
    source = deployment / "src"
    (source / "checks").mkdir(parents=True, exist_ok=True)
    (source / "checks" / "added.yaml").write_text(
        "checks:\n  - name: m3.cmdi-oob\n    proof: L1\n", encoding="utf-8"
    )
    pack = deployment / "colliding.tar.gz"
    exported = runner.invoke(
        app,
        [
            "packs",
            "export",
            "--out",
            str(pack),
            "--name",
            "colliding-pack",
            "--version",
            "1.0.0",
            "--content",
            str(source),
            "--pack-kind",
            "check",
            "--entry-point-group",
            "arachne.modules",
            "--check-id",
            "m3.cmdi-oob",
        ],
    )
    assert exported.exit_code == 0, exported.output

    reviewed = runner.invoke(app, ["plugin", "review", str(pack), "--publish"])
    assert reviewed.exit_code == 2, reviewed.output
    assert "parity.check_id_collision" in reviewed.output

    imported = runner.invoke(app, ["packs", "import", str(pack)])
    assert imported.exit_code == 1, imported.output
    assert "no listed review" in imported.output


def test_the_review_itself_opens_no_socket(tmp_path: Path) -> None:
    """An air-gapped estate must be able to review what it is about to import.

    REQ-RESIL-001 puts packs in an estate with no route out. The review pipeline therefore has to
    be a purely local operation — it reads the pack and the shipped catalogue and writes a row —
    which this asserts by making every socket call raise. If review ever needed to consult a
    registry, an air-gapped deployment could not list anything, and the failure would surface as
    a confusing refusal rather than as a network error.
    """
    import socket

    def _no_network(*_args: object, **_kwargs: object) -> None:
        msg = "the review pipeline must not open a socket"
        raise AssertionError(msg)

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(socket, "socket", _no_network)
        monkeypatch.setattr(socket, "getaddrinfo", _no_network)
        monkeypatch.setattr(socket, "create_connection", _no_network)
        report = review_pack_bytes(_pack(tmp_path, GOOD_CHECK), signer=signer)
        assert report.listed is True
    finally:
        monkeypatch.undo()


def test_a_compiled_or_native_member_is_refused(tmp_path: Path) -> None:
    """A member the AST scan cannot read must not be a pass.

    A pack is data. A ``.pyc``/``.so`` member is either a mistake or code hidden inside
    something the scanner cannot parse, so it is refused rather than waved through.
    """
    root = _tree(tmp_path, {"plugin.py": "def check(t):\n    return None\n"})
    (root / "sneaky.pyc").write_bytes(b"\x00\x01\x02 not real bytecode")
    archive, _manifest, _signature = build_pack(
        {"checks": root}, name="opaque", version="1.0.0", signer=signer, meta=dict(GOOD_META)
    )
    report = review_pack_bytes(archive, signer=signer)
    assert report.listed is False
    assert "member.opaque_code" in {item.code for item in report.blockers}


def test_review_requirement_can_be_waived_for_a_lab(
    deployment: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The documented escape hatch: an operator who wants unreviewed content must say so."""
    monkeypatch.setenv("ARACHNE_PLUGIN_REQUIRE_REVIEW", "false")
    reset_settings_cache()
    pack = deployment / "lab.tar.gz"
    pack.write_bytes(_pack(deployment / "d", GOOD_CHECK))
    result = runner.invoke(app, ["packs", "import", str(pack)])
    assert result.exit_code == 0, result.output
    assert (deployment / "content" / "third-party-pack" / "1.0.0").is_dir()
