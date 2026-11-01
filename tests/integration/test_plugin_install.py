"""DONE criterion S14-2: a third-party check plugin and a third-party report format plugin
install and work without a core change (F-09-01).

The test is deliberately end-to-end:

1. build real wheels from the two worked examples in ``examples/plugins/`` (a dependency-free
   wheel writer, so this runs on a host with no build backend and no network);
2. install them through **the production installer** (``install_and_verify``), into a
   temporary ``--target`` directory rather than the test venv;
3. assert the check appears in ``ModuleRegistry.discover()`` and the format in
   ``ReportFormatRegistry``, both discovered through their entry points;
4. render a report with the installed format and run the installed check against a scripted
   HTTP client.

Nothing in ``src/arachne`` mentions either plugin: the only contract is the entry-point group.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.helpers.plugin_wheel import build_wheel

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.http import RecordedResponse, ScopedHttpClient, fixture_transport
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy
from arachne.modules.registry import ModuleRegistry
from arachne.plugins.installer import InstallRequest, PluginInstallError, install_and_verify
from arachne.report import default_registry, render_report, reset_format_cache

PLUGIN_ROOT = Path(__file__).resolve().parents[2] / "examples" / "plugins"


@pytest.fixture(scope="module")
def installed(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Build and pip-install both example wheels into a temp target directory."""
    base = tmp_path_factory.mktemp("plugins")
    wheels = base / "wheels"
    check_wheel = build_wheel(
        wheels,
        name="arachne-example-plugin",
        version="0.1.0",
        package_dir=PLUGIN_ROOT / "arachne_example_plugin" / "src" / "arachne_example_plugin",
        entry_points={
            "arachne.modules": {"example-version-banner": "arachne_example_plugin:PLUGIN_GROUP"}
        },
    )
    report_wheel = build_wheel(
        wheels,
        name="arachne-example-report-plugin",
        version="0.1.0",
        package_dir=(
            PLUGIN_ROOT / "arachne_example_report_plugin" / "src" / "arachne_example_report_plugin"
        ),
        entry_points={
            "arachne.report_formats": {"example-csv": "arachne_example_report_plugin:CSV_FORMAT"}
        },
    )
    target = base / "target"
    for wheel in (check_wheel, report_wheel):
        result, _ = install_and_verify(
            str(wheel), target=str(target), extra_args=("--no-deps",), timeout_s=300
        )
        assert result.ok, result.stderr
    try:
        yield target
    finally:
        # Never leak the plugin into another test's registry (the count-pinning tests in
        # tests/unit assert the built-in shape).
        sys.path[:] = [entry for entry in sys.path if entry != str(target)]
        importlib.invalidate_caches()
        reset_format_cache()


def test_the_check_plugin_is_discovered(installed: Path) -> None:
    registry = ModuleRegistry.discover()
    check = registry.get("m4.example-version-banner")
    assert check is not None
    assert check.metadata.version == "1.0"
    group = registry.group("M4")
    assert group is not None
    assert "example-version-banner" in group.origin
    assert "m4.example-version-banner" in [item.id for item in group.metadata()]


def test_the_report_format_plugin_is_discovered_and_renders(
    installed: Path, synthetic_report: object
) -> None:
    reset_format_cache()
    registry = default_registry()
    assert "example-csv" in registry.names()
    # The alias the plugin declares also resolves.
    assert registry.canonical("csv") == "example-csv"
    text = render_report(synthetic_report, "example-csv")  # type: ignore[arg-type]
    assert text.splitlines()[0].split(",")[:4] == [
        "finding_id",
        "scan_id",
        "severity",
        "confidence",
    ]
    assert synthetic_report.scan_id in text  # type: ignore[attr-defined]


def test_the_installed_check_runs_against_a_scripted_client(installed: Path) -> None:
    from arachne_example_plugin import ExampleVersionBanner  # type: ignore[import-not-found]
    from tests.helpers.checks import asset_for, run_check

    client = ScopedHttpClient(
        scope=Scope(allowed_hosts=("example.test",)),
        policy=UrlSafetyPolicy(allow_private_ips=True),
        resolver=StaticResolver(("93.184.216.34",)),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        transport=fixture_transport(
            [
                RecordedResponse(
                    "GET",
                    "https://example.test/server-status",
                    200,
                    {},
                    "Server Status: debug: on",
                ),
            ]
        ),
    )
    results, _ = asyncio.run(
        run_check(ExampleVersionBanner, asset_for("url", "https://example.test"), http=client)
    )
    candidates = [item for item in results if item.status == "vulnerable"]
    assert len(candidates) == 1
    assert candidates[0].check == "M4/example-version-banner@1.0"


def test_a_path_that_is_not_a_package_is_refused(tmp_path: Path) -> None:
    (tmp_path / "not-a-package").mkdir()
    with pytest.raises(PluginInstallError, match=r"no pyproject\.toml"):
        InstallRequest.parse(str(tmp_path / "not-a-package"))


def test_a_git_url_is_accepted_and_rewritten() -> None:
    request = InstallRequest.parse("https://github.com/example/arachne-plugin.git")
    assert request.kind == "git-url"
    assert request.source.startswith("git+https://")
    scp = InstallRequest.parse("git@github.com:example/arachne-plugin.git")
    assert scp.source == "git+ssh://git@github.com/example/arachne-plugin.git"


def test_an_option_shaped_source_is_refused() -> None:
    with pytest.raises(PluginInstallError, match="must not begin with"):
        InstallRequest.parse("--index-url=http://evil.example/simple")


def test_a_dry_run_executes_nothing(tmp_path: Path) -> None:
    wheel_dir = tmp_path / "wheels"
    check_wheel = build_wheel(
        wheel_dir,
        name="arachne-example-plugin",
        version="0.1.0",
        package_dir=PLUGIN_ROOT / "arachne_example_plugin" / "src" / "arachne_example_plugin",
        entry_points={
            "arachne.modules": {"example-version-banner": "arachne_example_plugin:PLUGIN_GROUP"}
        },
    )
    result, appeared = install_and_verify(str(check_wheel), dry_run=True)
    assert result.executed is False
    assert "-m pip install" in " ".join(result.stdout.split())
    assert appeared == {"checks": [], "report_formats": []}
