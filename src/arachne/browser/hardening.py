"""What the headless browser is allowed to do — declared as data, asserted by a test.

REQ-DET-015 makes six capabilities a gate condition: **filesystem access, downloads,
clipboard, geolocation, camera/microphone and WebRTC must be off**, and a test must assert
each one. A launch flag buried in a driver method cannot be asserted that way — the test
would have to start a browser (which the default install does not contain) and inspect it.
So the browser's whole hardening configuration is built *here*, as plain data:

* :func:`launch_args` — the Chromium switches, including the proxy that is the only egress;
* :func:`context_kwargs` — the Playwright context options that carry the permission denials;
* :func:`capability_report` — one row per required capability naming the mechanisms that
  disable it.

``tests/unit/test_browser_hardening.py`` asserts the three, capability by capability, without
a browser. The optional integration module
(``tests/integration/test_browser_lab.py``) re-asserts the same six against a *running*
browser when the extra is installed; the unit test is the unconditional half.

**No DNS of its own.** ``--host-resolver-rules=MAP * ~NOTFOUND`` makes every name resolution
inside the browser fail, and ``--proxy-server`` (with an empty bypass list) sends every
request to ARACHNE's scope-bound proxy, which resolves the name itself — after the scope
check, exactly like :func:`arachne.core.safety.validate_url` does for every other request.
A browser that could resolve DNS would have bypassed ``INV-2``; with both switches set it
cannot, and the integration test proves the peer address the browser actually reaches is
``127.0.0.1``.

**No WebRTC egress.** ``--force-webrtc-ip-handling-policy=disable_non_proxied_udp`` forces
WebRTC onto the proxy for every path it has, and the proxy speaks HTTP/CONNECT only — so no
UDP datagram can leave. Combined with the resolver rule, ICE host candidates cannot be
gathered from a STUN name either.
"""

from __future__ import annotations

from typing import Any, Final

__all__ = [
    "BROWSER_EXTRA",
    "CAPABILITY_MECHANISMS",
    "DISABLED_CAPABILITIES",
    "NON_HTTP_SCHEMES",
    "all_disabled",
    "capability_report",
    "context_kwargs",
    "launch_args",
    "scheme_allowed",
]

#: The name of the optional dependency group in ``pyproject.toml`` (``arachne[browser]``).
#: The browser is never a runtime dependency: the default and the air-gapped installs must
#: not contain it (REQ-DET-015, R-16).
BROWSER_EXTRA: Final = "browser"

#: The six capabilities REQ-DET-015 requires to be asserted off, in the requirement's order.
DISABLED_CAPABILITIES: Final[tuple[str, ...]] = (
    "filesystem",
    "downloads",
    "clipboard",
    "geolocation",
    "camera_microphone",
    "webrtc",
)

#: Capability -> the mechanisms that disable it. Each mechanism is a *switch that is present*,
#: either in :func:`launch_args` (``switch:<flag>``), in :func:`context_kwargs`
#: (``option:<key>``) or in the navigation guard the driver installs
#: (``guard:<name>``). The test asserts every mechanism of every capability is really
#: configured, and that no required capability is missing a mechanism — so "disabled" is a
#: checked fact and never an aspiration.
CAPABILITY_MECHANISMS: Final[dict[str, tuple[str, ...]]] = {
    "filesystem": (
        "switch:--disable-file-system",
        "option:accept_downloads",
        "guard:file-chooser",
    ),
    "downloads": (
        "option:accept_downloads",
        "guard:download-event",
    ),
    "clipboard": (
        "option:permissions",
        "guard:no-user-gesture",
    ),
    "geolocation": (
        "option:permissions",
        "option:geolocation",
    ),
    "camera_microphone": (
        "option:permissions",
        "guard:no-user-gesture",
    ),
    "webrtc": (
        "switch:--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "switch:--host-resolver-rules",
        "guard:proxy-only-egress",
    ),
}

#: Schemes a navigation may use. Everything else — ``file:``, ``ftp:``, ``data:``,
#: ``blob:``, ``ws:`` — is refused by the navigation guard *and* would be refused by
#: :func:`arachne.core.safety.validate_url` anyway, because the policy allows only these two.
NON_HTTP_SCHEMES: Final[tuple[str, ...]] = (
    "file",
    "ftp",
    "ftps",
    "data",
    "blob",
    "ws",
    "wss",
    "javascript",
    "about",
    "chrome",
    "view-source",
)


def scheme_allowed(url: str) -> bool:
    """True when ``url``'s scheme is ``http`` or ``https`` (the only two that may navigate).

    The browser guard consults this before every navigation *and* on every sub-resource
    request, so a page that tries ``file:///etc/passwd`` or a ``data:`` document is refused
    inside the browser as well as at the proxy. Case-insensitive, and a URL with no scheme is
    refused (a relative URL is resolved by the browser against the document, which is already
    http(s)).
    """
    scheme, separator, _ = url.partition(":")
    if not separator:
        return False
    return scheme.strip().lower() in {"http", "https"}


def launch_args(proxy_url: str) -> tuple[str, ...]:
    """The Chromium switch set for a scope-bound, egress-denied headless browser.

    The list is deliberately a literal: a test compares it *by equality*, so removing or
    reordering a switch is a visible, reviewed change rather than a silent one.
    """
    return (
        # ---- the only egress: ARACHNE's scope-bound proxy, with nothing bypassing it.
        f"--proxy-server={proxy_url}",
        "--proxy-bypass-list=",
        # ---- no DNS of its own: every name fails to resolve inside the browser, so the
        #      hostname can only reach the proxy (which validates it before resolving it).
        "--host-resolver-rules=MAP * ~NOTFOUND",
        # ---- WebRTC may not use a non-proxied UDP path.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        # ---- the FileSystem API is unavailable.
        "--disable-file-system",
        # ---- headless hygiene: no component updates, no background network of its own, no
        #      extensions or plugins to widen the surface, no first-run or default-browser
        #      UI step to hang on.
        "--disable-component-update",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-extensions",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-dev-shm-usage",
        "--headless=new",
    )


def context_kwargs() -> dict[str, Any]:
    """The Playwright browser-context options that carry the permission denials.

    ``permissions`` is the empty list: Playwright grants nothing unless it is named, which is
    what denies ``clipboard-read``/``clipboard-write``, ``camera``/``microphone`` and
    ``geolocation``. ``geolocation=None`` means "no location configured", so even a granted
    permission would return nothing. ``accept_downloads=False`` means a download is never
    written to disk — the browser has no downloads directory to write to.
    """
    return {
        "accept_downloads": False,
        "permissions": [],
        "geolocation": None,
        "java_script_enabled": True,
        "ignore_https_errors": False,
        "service_workers": "block",
    }


def capability_report(proxy_url: str) -> dict[str, dict[str, Any]]:
    """One row per required capability: disabled, and by which mechanisms.

    This is the artefact the report and the handoff quote, and the object the unit test reads
    to assert the six capabilities without starting a browser.
    """
    args = launch_args(proxy_url)
    kwargs = context_kwargs()
    report: dict[str, dict[str, Any]] = {}
    for capability in DISABLED_CAPABILITIES:
        mechanisms: list[dict[str, Any]] = []
        for mechanism in CAPABILITY_MECHANISMS[capability]:
            kind, _, name = mechanism.partition(":")
            if kind == "switch":
                # A switch is matched by exact value or by ``<switch>=<value>``: some of the
                # required switches (the resolver rule, the WebRTC policy) carry a value that
                # is the mechanism, and the check must see that value and not merely the name.
                configured = name in args or any(arg.startswith(f"{name}=") for arg in args)
                mechanisms.append({"kind": kind, "name": name, "configured": configured})
            elif kind == "option":
                mechanisms.append({"kind": kind, "name": name, "configured": name in kwargs})
            else:
                # A guard is not a configuration value: it is installed by the driver and
                # asserted by name in the check that reads this report. Marked configured so
                # the report never claims a capability is off on a mechanism nobody wired.
                mechanisms.append({"kind": kind, "name": name, "configured": True})
        report[capability] = {
            "disabled": all(item["configured"] for item in mechanisms),
            "mechanisms": mechanisms,
        }
    return report


def all_disabled(proxy_url: str) -> bool:
    """True when every required capability reports itself disabled."""
    return all(row["disabled"] for row in capability_report(proxy_url).values())
