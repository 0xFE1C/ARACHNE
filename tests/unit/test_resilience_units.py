"""Resilience units: air-gap, content packs, leader election, autoscaling, migrations.

Five independent mechanisms, each pinned to the property the requirement states:

* REQ-RESIL-001 — the air-gap allowlist refuses a non-target host at the HTTP client, and a
  pack that is unsigned, tampered or malformed installs nothing.
* REQ-RESIL-002 — two replicas cannot hold one lease at once, an expired lease is free, and
  the release path hands it on; and the release migration is expand-only.
* REQ-RESIL-003 — the queue-depth arithmetic, its clamp and the scale-to-zero cooldown.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from tests.conftest import build_settings

from arachne.core.airgap import AirgapError, AirgapPolicy, build_airgap_policy, feature_refusal
from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import AirgapSettings
from arachne.core.errors import ContentPackError
from arachne.core.signing import DeploymentSigner
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.leader_store import LeaderElector
from arachne.data.models import Base
from arachne.resil.autoscale import ScaleToZeroPolicy, StaticDepthSource, plan_replicas
from arachne.resil.migrations import check_expand_only, contract_operations, revision_order
from arachne.resil.packs import (
    CONTENT_PREFIX,
    MANIFEST_NAME,
    PACK_SIGNATURE_NAME,
    build_pack,
    install_pack,
    installed_packs,
    read_pack,
)

KEY = "s25-unit-test-integrity-key-0001"
OTHER_KEY = "s25-unit-test-integrity-key-0002"
CODE_ROOT = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- air-gap
def test_the_policy_allows_everything_when_it_is_off() -> None:
    policy = AirgapPolicy(enabled=False)
    assert policy.allows_host("anything.example.com")
    assert policy.refusal("anything.example.com") is None


def test_the_policy_allows_only_the_scope_and_the_named_extras() -> None:
    policy = AirgapPolicy(enabled=True, allowed_hosts=("ollama.internal",))
    assert policy.allows_host("lab.example.com", scope_hosts=("lab.example.com",))
    assert policy.allows_host("ollama.internal")
    assert not policy.allows_host("feeds.nvd.nist.gov", scope_hosts=("lab.example.com",))
    assert not policy.allows_host(None)


@pytest.mark.asyncio
async def test_the_http_client_refuses_an_external_host_and_audits_it(
    make_client: object,
) -> None:
    """The gate is on the shared egress path, so *every* feature inherits it.

    The instance's own scope allows the external host (which is exactly what a webhook or an
    OTLP client does — it pins its scope to the URL it was configured with). The air-gap
    allowlist is a *second*, stricter gate that only the deployment's scan targets pass, so
    the request is refused where the scope gate would have let it through.
    """
    from arachne.core.safety import Scope

    sink = MemoryAuditSink()
    settings = replace(build_settings(), airgap=AirgapSettings(enabled=True))
    client = make_client(  # type: ignore[operator]
        settings=settings,
        scope=Scope(allowed_hosts=("updates.vendor.example",)),
        addresses=("93.184.216.34",),
    )
    client.auditor = Auditor(sink, actor="pytest")
    with pytest.raises(AirgapError, match="air-gapped"):
        await client.get("https://updates.vendor.example/pack.json")
    assert AuditAction.AIRGAP_BLOCKED.value in sink.actions()


def test_a_named_local_service_is_still_reachable() -> None:
    """The mode is not "no network": an operator's own mirror stays reachable by name."""
    from arachne.core.safety import Scope

    sink = MemoryAuditSink()
    settings = replace(
        build_settings(),
        airgap=AirgapSettings(enabled=True, allowed_hosts=("mirror.internal",)),
    )
    policy = build_airgap_policy(settings)
    assert policy.allows_host("mirror.internal", scope_hosts=("lab.example",))
    assert policy.refusal("feeds.nvd.nist.gov", scope_hosts=("lab.example",)) is not None
    del sink, Scope


def test_feature_refusal_names_the_feature() -> None:
    policy = AirgapPolicy(enabled=True)
    assert feature_refusal(policy, "plugin.install") is not None
    assert feature_refusal(AirgapPolicy(enabled=False), "plugin.install") is None
    # A named local service is allowed through when it is on the allowlist.
    assert (
        feature_refusal(
            AirgapPolicy(enabled=True, allowed_hosts=("ollama.internal",)),
            "ai.local",
            host="ollama.internal",
        )
        is None
    )


def test_the_airgap_policy_is_built_from_settings() -> None:
    settings = replace(build_settings(), airgap=AirgapSettings(enabled=True, allowed_hosts=("x",)))
    policy = build_airgap_policy(settings)
    assert policy.enabled and policy.allowed_hosts == ("x",)


# --------------------------------------------------------------------------- content packs
def _tree(root: Path) -> Path:
    (root / "plan").mkdir(parents=True, exist_ok=True)
    (root / "plan" / "check_catalog.yaml").write_text("version: 1.9\n", encoding="utf-8")
    (root / "m6").mkdir(parents=True, exist_ok=True)
    (root / "m6" / "rules.yaml").write_text("rules: []\n", encoding="utf-8")
    return root


def test_a_signed_pack_round_trips(tmp_path: Path) -> None:
    signer = DeploymentSigner(KEY)
    source = _tree(tmp_path / "src")
    archive, _manifest, signature = build_pack(
        {"checks": source / "plan", "rules": source / "m6"},
        name="enterprise-baseline",
        version="1.0.0",
        signer=signer,
    )
    assert signature is not None
    pack = read_pack(archive, signer=signer)
    assert pack.manifest.name == "enterprise-baseline"
    assert pack.manifest.kinds() == {"checks": 1, "rules": 1}
    assert len(pack.files) == 2
    assert pack.key_id == signer.key_id


def test_a_pack_signed_by_another_key_is_refused(tmp_path: Path) -> None:
    source = _tree(tmp_path / "src")
    archive, _, _ = build_pack(
        {"checks": source / "plan"}, name="p", version="1", signer=DeploymentSigner(OTHER_KEY)
    )
    with pytest.raises(ContentPackError, match="signature does not verify"):
        read_pack(archive, signer=DeploymentSigner(KEY))


def test_an_unsigned_pack_is_refused_by_default_and_accepted_explicitly(tmp_path: Path) -> None:
    source = _tree(tmp_path / "src")
    archive, _, signature = build_pack({"checks": source / "plan"}, name="p", version="1")
    assert signature is None
    # With a key configured, an unsigned pack fails the signature check.
    with pytest.raises(ContentPackError, match="signature does not verify"):
        read_pack(archive, signer=DeploymentSigner(KEY))
    # With no key configured, the failure names the configuration rather than the pack.
    with pytest.raises(ContentPackError, match="no content key is configured"):
        read_pack(archive, signer=None)
    # The explicit exception accepts it and records that it was unsigned.
    pack = read_pack(archive, signer=DeploymentSigner(KEY), require_signature=False)
    assert pack.signature is None


def test_a_pack_with_no_key_configured_is_refused(tmp_path: Path) -> None:
    source = _tree(tmp_path / "src")
    archive, _, _ = build_pack(
        {"checks": source / "plan"}, name="p", version="1", signer=DeploymentSigner(KEY)
    )
    with pytest.raises(ContentPackError, match="no content key is configured"):
        read_pack(archive, signer=None)


def test_a_tampered_manifest_is_refused(tmp_path: Path) -> None:
    """The signature covers the manifest; editing what the pack claims breaks it."""
    import json

    signer = DeploymentSigner(KEY)
    source = _tree(tmp_path / "src")
    archive, _manifest, _ = build_pack(
        {"checks": source / "plan"}, name="p", version="1", signer=signer
    )

    # The manifest's own claim about a file changes; the signature does not follow.
    original = json.loads(_members(archive)[MANIFEST_NAME].decode())
    original["files"][0]["sha256"] = "0" * 64
    members = dict(_members(archive))
    members[MANIFEST_NAME] = json.dumps(original, sort_keys=True, separators=(",", ":")).encode()
    rebuilt = _rebuild(members)
    with pytest.raises(ContentPackError, match="signature does not verify"):
        read_pack(rebuilt, signer=signer)


def test_a_tampered_file_is_refused_even_with_a_valid_signature(tmp_path: Path) -> None:
    """Two independent checks: the manifest signature *and* each file's digest."""
    signer = DeploymentSigner(KEY)
    source = _tree(tmp_path / "src")
    archive, _manifest, _ = build_pack(
        {"checks": source / "plan"}, name="p", version="1", signer=signer
    )
    members = dict(_members(archive))
    target = next(name for name in members if name.startswith(CONTENT_PREFIX))
    members[target] = b"version: 999\n"  # the payload changed, the manifest did not
    with pytest.raises(ContentPackError, match="does not match its manifest"):
        read_pack(_rebuild(members), signer=signer)


def test_a_pack_without_a_manifest_is_refused() -> None:
    with pytest.raises(ContentPackError, match=r"no manifest\.json"):
        read_pack(_rebuild({}), signer=None, require_signature=False)


def test_an_undeclared_extra_file_is_refused(tmp_path: Path) -> None:
    signer = DeploymentSigner(KEY)
    source = _tree(tmp_path / "src")
    archive, _, _ = build_pack({"checks": source / "plan"}, name="p", version="1", signer=signer)
    members = dict(_members(archive))
    members[f"{CONTENT_PREFIX}checks/backdoor.yaml"] = b"evil: true\n"
    with pytest.raises(ContentPackError, match="does not declare"):
        read_pack(_rebuild(members), signer=signer)


def test_a_pack_member_that_escapes_the_content_directory_is_refused() -> None:
    with pytest.raises(ContentPackError, match="escapes the content directory"):
        read_pack(
            _rebuild({MANIFEST_NAME: b"{}", "../../etc/passwd": b"x"}),
            signer=None,
            require_signature=False,
        )


def test_a_pack_that_is_not_a_tarball_is_refused() -> None:
    with pytest.raises(ContentPackError, match="not a readable gzip tar archive"):
        read_pack(b"not a pack", signer=None, require_signature=False)


def test_an_unknown_format_version_is_refused(tmp_path: Path) -> None:
    import json

    members = {
        MANIFEST_NAME: json.dumps(
            {
                "format": "arachne-content-pack/99",
                "name": "p",
                "version": "1",
                "files": [{"path": "content/x", "sha256": "0", "size": 0}],
            }
        ).encode()
    }
    with pytest.raises(ContentPackError, match="unsupported content pack format"):
        read_pack(_rebuild(members), signer=None, require_signature=False)


def test_installing_writes_into_a_staging_then_moves(tmp_path: Path) -> None:
    signer = DeploymentSigner(KEY)
    source = _tree(tmp_path / "src")
    archive, _manifest, _ = build_pack(
        {"checks": source / "plan"}, name="base", version="2.1", signer=signer
    )
    pack = read_pack(archive, signer=signer)
    result = install_pack(pack, content_dir=tmp_path / "content")
    assert result.directory == tmp_path / "content" / "base" / "2.1"
    # Members keep their ``kind`` segment: a pack root packs as <kind>/<relative path>.
    assert (result.directory / "checks" / "check_catalog.yaml").is_file()
    # The manifest and its signature travel with the installed content, so a later audit can
    # re-verify what is on disk rather than only what was imported.
    assert (result.directory / MANIFEST_NAME).is_file()
    assert (result.directory / PACK_SIGNATURE_NAME).is_file()
    # A failed install must not leave a half-tree behind.
    assert not list((tmp_path / "content").glob("**/*.staging"))
    listed = installed_packs(tmp_path / "content")
    assert len(listed) == 1 and listed[0]["key_id"] == signer.key_id


def test_re_installing_the_same_version_replaces_it(tmp_path: Path) -> None:
    signer = DeploymentSigner(KEY)
    source = _tree(tmp_path / "src")
    archive, _, _ = build_pack({"checks": source / "plan"}, name="base", version="1", signer=signer)
    pack = read_pack(archive, signer=signer)
    first = install_pack(pack, content_dir=tmp_path / "content")
    second = install_pack(pack, content_dir=tmp_path / "content", replace=True)
    assert first.directory == second.directory


# --------------------------------------------------------------------------- leader election
@pytest.fixture
def session_factory(tmp_path: Path) -> object:
    engine = create_db_engine(settings=build_settings())
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def test_two_replicas_cannot_hold_one_lease(session_factory: object) -> None:
    factory = session_factory  # type: ignore[assignment]
    first = LeaderElector(factory, name="scheduler", holder="replica-a", ttl_s=60)
    second = LeaderElector(factory, name="scheduler", holder="replica-b", ttl_s=60)
    assert first.try_acquire()
    assert first.is_leader()
    assert not second.try_acquire()
    assert not second.is_leader()
    # The holder renews its own lease (no self-eviction on a long tick).
    assert first.try_acquire()
    assert second.state().holder == "replica-a"
    assert second.state().token == first.state().token


def test_an_expired_lease_is_free_without_cleanup(session_factory: object) -> None:
    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from arachne.data.models import LeaderLease

    factory = session_factory  # type: ignore[assignment]
    holder = LeaderElector(factory, name="scheduler", holder="replica-a", ttl_s=60)
    assert holder.try_acquire()
    # Simulate the holder being SIGKILLed: its lease row simply stays where it is until it
    # expires. Nothing has to run for the next replica to take over.
    with factory() as session:  # type: ignore[operator]
        row = session.scalar(select(LeaderLease).where(LeaderLease.name == "scheduler"))
        assert row is not None
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.commit()
    successor = LeaderElector(factory, name="scheduler", holder="replica-b", ttl_s=60)
    assert successor.try_acquire()
    assert successor.state().holder == "replica-b"
    assert not holder.try_acquire() or holder.state().holder == "replica-b"


def test_release_gives_the_lease_up(session_factory: object) -> None:
    factory = session_factory  # type: ignore[assignment]
    first = LeaderElector(factory, name="scheduler", holder="replica-a", ttl_s=600)
    second = LeaderElector(factory, name="scheduler", holder="replica-b", ttl_s=600)
    signer = DeploymentSigner(KEY)
    del signer
    assert first.try_acquire()
    assert first.release(reason="shutdown")
    assert second.try_acquire()
    assert second.is_leader()


def test_lease_transitions_are_audited(session_factory: object) -> None:
    factory = session_factory  # type: ignore[assignment]
    sink = MemoryAuditSink()
    elector = LeaderElector(
        factory,
        name="scheduler",
        holder="replica-a",
        ttl_s=60,
        auditor=Auditor(sink, actor="pytest"),
    )
    assert elector.try_acquire()
    elector.release()
    assert AuditAction.LEADER_ACQUIRED.value in sink.actions()
    assert AuditAction.LEADER_LOST.value in sink.actions()


def test_a_bad_lease_definition_is_refused(session_factory: object) -> None:
    factory = session_factory  # type: ignore[assignment]
    with pytest.raises(ValueError, match="needs a name"):
        LeaderElector(factory, name="  ")
    with pytest.raises(ValueError, match="positive TTL"):
        LeaderElector(factory, name="x", ttl_s=0)


# --------------------------------------------------------------------------- autoscaling
def test_the_replica_count_is_the_ceiling_of_depth_over_per_replica() -> None:
    assert plan_replicas(0, per_replica=4).desired == 0
    assert plan_replicas(1).desired == 1
    assert plan_replicas(4).desired == 1
    assert plan_replicas(5).desired == 2
    assert plan_replicas(40, per_replica=4, max_replicas=50).desired == 10


def test_the_clamp_wins_over_the_arithmetic() -> None:
    decision = plan_replicas(100, per_replica=1, min_replicas=0, max_replicas=8)
    assert decision.desired == 8
    assert decision.clamped
    assert "clamped to max_replicas" in decision.reason


def test_scale_to_zero_is_reachable_with_no_floor() -> None:
    decision = plan_replicas(0, min_replicas=0)
    assert decision.scale_to_zero
    assert "scale-to-zero is allowed" in decision.reason


def test_a_floor_keeps_a_worker_warm() -> None:
    decision = plan_replicas(0, min_replicas=1)
    assert decision.desired == 1
    assert not decision.scale_to_zero


def test_impossible_replica_bounds_are_refused() -> None:
    with pytest.raises(ValueError, match="per_replica"):
        plan_replicas(1, per_replica=0)
    with pytest.raises(ValueError, match="min_replicas"):
        plan_replicas(1, min_replicas=5, max_replicas=2)


def test_the_cooldown_holds_one_worker_before_scaling_to_zero() -> None:
    clock = _Clock()
    policy = ScaleToZeroPolicy(idle_cooldown_s=300.0, clock=clock.monotonic)
    busy = policy.decide(9, per_replica=4, max_replicas=8)
    assert busy.desired == 3
    warming = policy.decide(0, per_replica=4, max_replicas=8)
    assert warming.desired == 1 and "cooldown" in warming.reason
    clock.advance(301)
    asleep = policy.decide(0, per_replica=4, max_replicas=8)
    assert asleep.scale_to_zero
    # A burst resets the idle timer.
    assert policy.decide(1, per_replica=4, max_replicas=8).desired == 1
    assert policy.decide(0, per_replica=4, max_replicas=8).desired == 1


def test_the_static_depth_source_can_script_a_sequence() -> None:
    source = StaticDepthSource(script=[0, 5, 0])
    assert [source.depth() for _ in range(3)] == [0, 5, 0]
    source.set(7)
    assert source.depth() == 7


# --------------------------------------------------------------------------- migrations
def test_the_release_migration_is_expand_only() -> None:
    """The head revision is the upgrade being rolled out; it must be online-safe.

    Pinned to the graph's head rather than to a revision number, so the invariant survives each
    stage's migration: whatever ``alembic upgrade head`` is about to apply must not narrow,
    rename or drop anything. It must also be the revision ``data/schema.py`` expects, which is
    what keeps ``LATEST_SCHEMA_REVISION`` honest (S25; the assertion is on the *expand-only
    vocabulary* rather than on one revision's exact operation list, so a stage whose change is a
    single new table — S27's ``fix_proposals`` — satisfies it without loosening the rule, and so
    does a column-only stage — WP-14's residue attestation).
    """
    from arachne.data.schema import LATEST_SCHEMA_REVISION

    report = check_expand_only(CODE_ROOT / "migrations" / "versions")
    assert report.revisions, report.to_dict()
    assert report.revisions == (LATEST_SCHEMA_REVISION,), report.to_dict()
    assert report.expand_only, report.to_dict()
    assert report.expand_operations, report.to_dict()
    expand_vocabulary = {
        "add_column",
        "create_table",
        "create_index",
        "create_unique_constraint",
    }
    assert set(report.expand_operations) <= expand_vocabulary, report.to_dict()
    # The head must actually *do* one of them. The assertion used to name ``create_table``
    # specifically, which pinned it to whichever stage last added a table: a column-only stage
    # — two nullable columns on ``scans`` (REQ-PROOF-017) — is equally expand-only and failed
    # for no reason. ``test_a_contract_operation_is_detected_in_source`` below still holds the
    # checker to naming a contract operation when one is present.
    assert set(report.expand_operations) & expand_vocabulary, report.to_dict()


def test_a_contract_operation_is_detected_in_source() -> None:
    source = (
        "def upgrade():\n"
        "    op.drop_column('findings', 'signature')\n"
        "    op.alter_column('audit_log', 'seq', nullable=False)\n"
        "    op.rename_table('a', 'b')\n"
        "    op.add_column('x', sa.Column('y', sa.Integer()))\n"
    )
    findings = contract_operations(source, revision="9001")
    operations = {finding.operation for finding in findings}
    assert {"drop_column", "set_not_null", "rename_table"} <= operations
    assert "add_column" not in operations


def test_an_opaque_operation_is_reported_for_review() -> None:
    findings = contract_operations(
        "def upgrade():\n    op.execute('delete from t')\n", revision="1"
    )
    assert findings and findings[0].severity == "medium"


def test_the_downgrade_is_not_inspected() -> None:
    source = "def downgrade():\n    op.drop_column('a', 'b')\n"
    assert contract_operations(source, revision="1") == ()


def test_the_revision_order_follows_down_revision() -> None:
    """The chain is linear and ordered: every revision sorts after the one it revises."""
    from arachne.data.schema import LATEST_SCHEMA_REVISION

    order = revision_order(CODE_ROOT / "migrations" / "versions")
    assert order[0] == "0001"
    assert order[-1] == LATEST_SCHEMA_REVISION
    assert order == tuple(sorted(order))
    # Consecutive, not merely sorted: a gap would mean a revision nothing can reach.
    assert order == tuple(f"{number:04d}" for number in range(1, len(order) + 1))


def test_a_bad_pack_argument_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ContentPackError, match="unsafe pack name or version"):
        install_pack(_minimal_pack(".."), content_dir=tmp_path / "content")


def test_settings_expose_the_content_directory() -> None:
    settings = replace(build_settings(), airgap=AirgapSettings(enabled=True, content_dir="/tmp/c"))
    assert str(settings.content_dir) == "/tmp/c"


# --------------------------------------------------------------------------- helpers
class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _members(archive: bytes) -> dict[str, bytes]:
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        return {
            info.name: (tar.extractfile(info).read() if tar.extractfile(info) else b"")
            for info in tar.getmembers()
        }


def _rebuild(members: dict[str, bytes]) -> bytes:
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _minimal_pack(name: str) -> object:
    from arachne.resil.packs import ContentPack, PackFile, PackManifest

    return ContentPack(
        manifest=PackManifest(
            name=name,
            version="1",
            files=(PackFile(path=f"{CONTENT_PREFIX}x", sha256="0" * 64, size=0),),
        ),
        files={f"{CONTENT_PREFIX}x": b""},
        signature=None,
        key_id=None,
    )


def test_a_settings_httpx_transport_is_untouched() -> None:  # pragma: no cover - sanity
    assert httpx.MockTransport is not None
