# ADR-340 · A headless browser behind an optional extra, with the scope-bound proxy as its only egress

| Field | Value |
|---|---|
| Status | accepted (WP-11) |
| Date | 2026-11-03 |
| Deciders | ARACHNE detection engineering, safety owner |
| Supersedes | ADR-100.4 and ADR-S10-6 in the one respect they state: "DOM-sink verification in a browser is out of scope for this stage" |
| Requirements | REQ-DET-015 |

## Context

M3's client module records that the DOM-sink half of research ch03#3 "is *not* implemented" and
`m3/advanced_api.py` records that a headless-browser check is out of scope by an earlier ADR.
The consequence is the largest single detection gap against Burp and ZAP: ARACHNE cannot see a
single-page application's routes, cannot see client-side rendering, and cannot see a DOM-XSS
sink that no response body ever contains.

Closing that gap means putting a real browser **inside** the scanner. R-16 scores that at 15 —
the highest-scoring technical risk in the register — for a specific reason: a browser resolves
DNS itself, follows redirects itself, opens WebRTC itself and executes whatever the target
serves. Each of those is a way to leave the declared scope without passing the gate that every
other request in ARACHNE passes through (`INV-2`), and none of them is visible in the request
path the product already audits.

Two earlier decisions are also in play, and this ADR has to be consistent with both:

- **ADR-05, "one egress path".** Every HTTP request goes through the shared scoped client. The
  rule's own rationale (`m2/http3.py`) is that it forbids inventing a second *unscoped* path,
  not a second transport: `m2.http3-probe` already dials UDP directly, behind the same scope
  check. A browser needs a second transport for the same reason QUIC did.
- **The optional-extra rule** (REQ-DET-006's `quic` extra, the `pdf` and `postgres` extras):
  a dependency that is heavy, optional or a liability by nature is an extra, and the default
  and air-gapped installs must work — and report honestly — without it.

## Decision

**1. The browser is an optional extra (`arachne[browser]`, playwright), never a runtime
dependency.** Its import is inside the function that needs it. With the extra absent,
`m3.dom-xss` reports itself *skipped* with a reason naming the extra, the plan says so, and
nothing else in the product changes. This is R-16's structural mitigation: the risk does not
reach the common deployment, because the common deployment does not contain a browser.

**2. The browser's only egress is a loopback forward proxy that runs the *same* gate.**
`arachne.browser.proxy.ScopeProxy` accepts `CONNECT` and absolute-form `HTTP` from the browser
and calls `arachne.core.safety.validate_url` — the same function, with the same compiled
`Scope`, the same `UrlSafetyPolicy` and the same resolver the shared HTTP client holds — for
**every** request, before it dials. It then dials the literal address that gate resolved and
checked, so a DNS-rebinding answer cannot win a race between the check and the connect. A
refusal is audited with the same actions the client writes (`scope.rejected`, `safety.blocked`)
and the proxy never dials.

The proxy also applies the deployment's **air-gapped egress allowlist** (REQ-RESIL-001), which
is a separate check from scope in the client: a host can be inside the scan's declared scope and
outside what an air-gapped estate permits, and only the policy decides that. Leaving it out
would have made the browser a way *around* a control the product already enforces, which is
precisely the class of defect R-16 warns about, so the policy is inherited from the scan's HTTP
client by value and a refusal is audited as `airgap.blocked` before any dial. The browser is
configured to have no alternative egress: `--proxy-server`, an empty `--proxy-bypass-list` and
`--host-resolver-rules=MAP * ~NOTFOUND`, so it has no DNS of its own and no direct path out.

**3. Six capabilities are off, and asserted off as data.**
`arachne.browser.hardening` builds the launch argv and the context options, and
`capability_report()` names, per capability, the mechanism that disables it. Filesystem,
downloads, clipboard, geolocation, camera/microphone and WebRTC each have at least one
mechanism, and `tests/unit/test_browser_hardening.py` asserts all of them without a browser —
which is the only way the claim is verifiable in the install that does not contain one. The
optional integration module re-asserts it against a running Chromium.

**4. The crawl's decisions are browser-free and therefore testable.** `BrowserCrawl` talks to a
`Navigator` protocol; `PlaywrightNavigator` is one implementation of it. The budget, the
per-navigation scope check, the JavaScript-only route test and the DOM-sink analysis are
exercised through scripted navigators, which is how a hostile page (an off-scope redirect, a
download, a `file:` navigation) becomes a **test** rather than an edge case.

**5. The DOM-XSS probe is inert, and `client_side_only` is the discriminator.** The marker is
alphanumeric (`ar9x` + hex — the M3 oracle's stem), so it cannot execute; a hit proves taint
flow into a dangerous sink, not a live exploit. The marker is planted in the fragment (never
sent to the server) and in a query parameter. A hit is only reported as a DOM-XSS when the
marker is **absent** from the server's own response body: that is what rules out the
reflected-XSS false positive, and it is the same doctrine as `m3.xss-oracle`'s encoded
reflection being reported clean.

**6. Two switches, not one.** The extra must be installed *and* the operator must set
`ARACHNE_WEB_BROWSER_CRAWL=true`. Installing a browser must not silently start browsing every
target a scan is pointed at.

## Consequences

**Positive.** REQ-DET-015's capability criteria are met by construction rather than by care:
SPA routes are discovered from the rendered DOM and recorded as assets through the scope guard,
and a DOM sink reachable only through JavaScript is reported with the source and the sink in
its evidence. The page/time budget is a field of the plan, so an operator reviews the bound
before a browser opens. `INV-1`, `INV-2` and `INV-3` hold unchanged: deny-by-default, the
refusal before resolution, and per-hop revalidation — the proxy re-runs the gate per request,
which `tests/test_browser_safety.py` asserts by counting gate calls.

**Negative, and accepted.** A browser engine remains a large attack surface in its own right,
mitigated only by being optional and by whatever sandbox the operator's container applies
(R-16's residual, **accepted**). Coverage while the extra is absent is genuinely lower than
Burp's: `m3.dom-xss` reports itself skipped, and the ledger says so rather than implying the
check ran. The crawl also loses fidelity on a page whose bundle lives off-scope — the CDN
request is refused, because `INV-1` outranks rendering fidelity — which is recorded as a
`refused_requests` count in the finding's evidence instead of being hidden.

**Neutral.** `m3.dom-xss` is `active` (it navigates with a marker) and therefore needs
`--active-checks` as well as its own two switches. Three gates on one check is deliberate: it
is the only check in the product that starts another program.

## Alternatives considered

- **Reuse the shared HTTP client.** Impossible: the client speaks HTTP, and the crawl needs a
  JavaScript engine. The proxy exists precisely so that the browser's transport is *not* a new
  unscoped path.
- **Browser without a proxy, with a scoped request interceptor.** Rejected. Playwright's
  `route()` interception sees requests the browser has already decided to make and, critically,
  the browser has already resolved the name — which is `INV-2` bypassed. A proxy the browser
  cannot route around is a structural control; an interceptor is a callback.
- **A JS engine without a browser (QuickJS, py_mini_racer).** Rejected for v1: no DOM, so no
  DOM sink, no client-side router, no `location` — it would satisfy none of the acceptance
  criteria. Recorded here so the option is not re-litigated as a shortcut.
- **Making it default-on when installed.** Rejected: that is exactly the exposure R-16 scores.
  The operator opts in with an environment variable, and the default plan says the crawl will
  not happen.
