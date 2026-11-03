"""The six disabled capabilities, the optional-extra rule, and the egress denials (REQ-DET-015).

REQ-DET-015's safety criteria are gate conditions, and one of them is "filesystem access,
downloads, clipboard, geolocation, camera/microphone and WebRTC are disabled; a test asserts
each is off". Asserting that against a *running* browser would make the safety claim
unverifiable in the default install — the install that does not contain a browser. So the
browser's entire hardening configuration is data (:mod:`arachne.browser.hardening`) and these
tests assert the data:

* every required capability has at least one mechanism, and every mechanism it declares is
  really present in the launch argv or the context options;
* the argv is compared **by equality**, so removing the proxy, the resolver rule or the
  WebRTC policy is a visible change rather than a silent one;
* the optional extra is declared as an extra and is **not** a runtime dependency, which is what
  makes "the default and air-gapped installs never contain it" a fact rather than a promise;
* with the extra absent, nothing raises: the crawl reports itself unavailable.

``tests/integration/test_browser_lab.py`` re-asserts the same six against a running browser
when the extra is installed; this module is the unconditional half of that pair.
"""

from __future__ import annotations

import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from arachne.browser import driver, hardening
from arachne.browser.crawl import RenderedPage
from arachne.browser.driver import PlaywrightNavigator, browser_available, unavailable_reason
from arachne.browser.hardening import (
    BROWSER_EXTRA,
    CAPABILITY_MECHANISMS,
    DISABLED_CAPABILITIES,
    NON_HTTP_SCHEMES,
    all_disabled,
    capability_report,
    context_kwargs,
    launch_args,
    scheme_allowed,
)
from arachne.core.config import WebSettings
from arachne.core.target import TargetSelector

PROXY = "http://127.0.0.1:45123"
ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------ the six capabilities
def test_the_six_required_capabilities_are_exactly_the_ones_the_requirement_names() -> None:
    assert DISABLED_CAPABILITIES == (
        "filesystem",
        "downloads",
        "clipboard",
        "geolocation",
        "camera_microphone",
        "webrtc",
    )
    assert set(CAPABILITY_MECHANISMS) == set(DISABLED_CAPABILITIES)


def test_every_capability_names_a_mechanism_and_every_mechanism_is_really_configured() -> None:
    """The core assertion: six capabilities off, each by a switch that is actually present."""
    report = capability_report(PROXY)
    args = launch_args(PROXY)
    kwargs = context_kwargs()
    for capability in DISABLED_CAPABILITIES:
        row = report[capability]
        assert row["mechanisms"], f"{capability} claims to be disabled with no mechanism"
        assert row["disabled"] is True, f"{capability} is not disabled: {row}"
        for mechanism in row["mechanisms"]:
            assert mechanism["configured"] is True, (capability, mechanism)
            if mechanism["kind"] == "switch":
                assert mechanism["name"] in args or any(
                    arg.startswith(f"{mechanism['name']}=") for arg in args
                ), mechanism
            elif mechanism["kind"] == "option":
                assert mechanism["name"] in kwargs, mechanism
    assert all_disabled(PROXY) is True


def test_the_launch_argv_is_pinned_by_equality() -> None:
    """A switch cannot be dropped without this test failing: the list is compared verbatim."""
    assert launch_args(PROXY) == (
        f"--proxy-server={PROXY}",
        "--proxy-bypass-list=",
        "--host-resolver-rules=MAP * ~NOTFOUND",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--disable-file-system",
        "--disable-component-update",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-dev-shm-usage",
        "--headless=new",
    )


def test_the_browser_has_no_direct_egress_and_no_resolver_of_its_own() -> None:
    """The two switches that make the proxy the only way out, asserted individually."""
    args = launch_args(PROXY)
    assert f"--proxy-server={PROXY}" in args
    assert "--proxy-bypass-list=" in args, "an empty bypass list: nothing goes direct"
    assert "--host-resolver-rules=MAP * ~NOTFOUND" in args, "every name fails to resolve"
    assert not any(arg.startswith("--no-proxy-server") for arg in args)
    assert not any("bypass" in arg and arg != "--proxy-bypass-list=" for arg in args)


def test_the_context_denies_every_permission_and_downloads() -> None:
    kwargs = context_kwargs()
    assert kwargs["permissions"] == [], "nothing may be granted: clipboard, camera, geolocation"
    assert kwargs["accept_downloads"] is False
    assert kwargs["geolocation"] is None
    assert kwargs["service_workers"] == "block"
    assert kwargs["ignore_https_errors"] is False, "TLS verification stays on"


@pytest.mark.parametrize("scheme", NON_HTTP_SCHEMES)
def test_a_non_http_scheme_is_never_navigable(scheme: str) -> None:
    """``file:``, ``data:``, ``blob:``, ``ws:`` … are refused by the guard before the proxy."""
    assert scheme not in {"http", "https"}
    assert scheme_allowed(f"{scheme}://example.com/x") is False
    assert scheme_allowed(f"{scheme}:/etc/passwd") is False


def test_http_and_https_are_the_only_allowed_schemes() -> None:
    assert scheme_allowed("http://example.com/") is True
    assert scheme_allowed("HTTPS://Example.COM/") is True
    assert scheme_allowed("/relative/path") is False
    assert scheme_allowed("") is False
    assert scheme_allowed("example.com") is False
    assert hardening.scheme_allowed("http://example.com/") is True


# ------------------------------------------------------------------ the optional extra
def test_the_browser_is_an_extra_and_not_a_runtime_dependency() -> None:
    """The default and air-gapped installs must not contain a browser engine (R-16)."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "[project.optional-dependencies]" in text
    assert f"{BROWSER_EXTRA} = [" in text
    runtime = text.split("dependencies = [", 1)[1].split("]", 1)[0]
    assert "playwright" not in runtime
    assert "playwright" in text.split("[project.optional-dependencies]", 1)[1]


def test_the_driver_imports_playwright_only_inside_the_function_that_needs_it() -> None:
    """Importing this package must not pull the browser in (or fail when it is absent).

    The whole optional-extra rule rests on this: ``import arachne.browser`` is on the path of
    every scan (the check module imports it), so a module-level import would make the default
    install fail to start.
    """
    assert "playwright" not in sys.modules or browser_available()
    source = (ROOT / "src" / "arachne" / "browser" / "driver.py").read_text(encoding="utf-8")
    for line in source.splitlines():
        if line.startswith(("import playwright", "from playwright")):
            raise AssertionError(f"a module-level playwright import: {line}")
    # It *is* imported, just lazily: inside start(), which only runs once the probe above has
    # said the extra is available.
    assert "from playwright.async_api import async_playwright" in source


async def test_the_absence_of_the_extra_is_a_reported_value_not_an_exception(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """With the extra absent the crawl says so; it never raises out of a check.

    Asserted by forcing the availability probe to false rather than by skipping when the extra
    happens to be installed: a test that skipped would be a test that does not run on the very
    installations where the degradation matters least — and one the skip gate would have to
    allowlist.
    """
    monkeypatch.setattr(driver, "browser_available", lambda: False)
    navigator = PlaywrightNavigator(proxy_url=PROXY)
    assert navigator._page is None
    assert f"arachne[{BROWSER_EXTRA}]" in unavailable_reason()
    page = await navigator.navigate("http://example.com/")
    assert isinstance(page, RenderedPage)
    assert page.ok is False
    assert page.error is not None and BROWSER_EXTRA in page.error
    assert page.links == () and page.sink_records == ()


def test_an_install_without_the_extra_plans_and_says_the_crawl_will_skip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The install-level claim: with the extra absent, the product still plans a scan.

    REQ-DET-015's last criterion is that the product "installs, runs and air-gaps exactly as
    before" without the browser. This drives the *planner* with the crawl enabled and the
    driver absent — the state a default install is in — and asserts the plan is produced, the
    checks step carries **no** browser budget (nothing is advertised that cannot happen), and
    the reason is printed rather than left for the operator to discover.
    """
    from tests.conftest import build_scan_request

    from arachne.core.catalog import load_catalog
    from arachne.core.planner import Planner, ScanStep
    from arachne.core.target import TargetKind

    monkeypatch.setattr(driver, "browser_available", lambda: False)
    web = replace(WebSettings(), browser_crawl=True, browser_max_pages=7, browser_time_budget_s=9.0)
    planner = Planner(load_catalog(), web=web)
    request = build_scan_request(targets=(TargetSelector(kind=TargetKind.URL, value="http://x/"),))
    plan = planner.plan(
        request,
        dry_run=True,
        scope=request.target.compile_scope(),
        active_checks_allowed=True,
        handled_steps=frozenset(ScanStep),
        now=datetime(2026, 11, 3, 12, 0, tzinfo=UTC),
    )
    checks_step = next(step for step in plan.steps if step.step is ScanStep.CHECKS)
    assert checks_step.budget_pages is None and checks_step.budget_seconds is None
    assert any("no browser driver is installed" in warning for warning in plan.warnings)
    assert any("dom-xss" in warning for warning in plan.warnings)
    # And the plan is still a complete, serializable document.
    assert plan.to_dict()["plan_version"] == "1.1"


def test_an_install_with_the_extra_prints_the_budget_in_the_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other half: when the crawl *will* run, its documented budget is in the plan."""
    from tests.conftest import build_scan_request

    from arachne.core.catalog import load_catalog
    from arachne.core.planner import Planner, ScanStep
    from arachne.core.target import TargetKind

    monkeypatch.setattr(driver, "browser_available", lambda: True)
    web = replace(WebSettings(), browser_crawl=True, browser_max_pages=7, browser_time_budget_s=9.0)
    planner = Planner(load_catalog(), web=web)
    request = build_scan_request(targets=(TargetSelector(kind=TargetKind.URL, value="http://x/"),))
    plan = planner.plan(
        request,
        dry_run=True,
        scope=request.target.compile_scope(),
        active_checks_allowed=True,
        handled_steps=frozenset(ScanStep),
        now=datetime(2026, 11, 3, 12, 0, tzinfo=UTC),
    )
    checks_step = next(step for step in plan.steps if step.step is ScanStep.CHECKS)
    assert (checks_step.budget_pages, checks_step.budget_seconds) == (7, 9.0)
    assert any("7 navigation(s) / 9s" in warning for warning in plan.warnings)
    # Only the checks step crawls: no other step advertises a browser budget.
    assert all(step.budget_pages is None for step in plan.steps if step.step is not ScanStep.CHECKS)
