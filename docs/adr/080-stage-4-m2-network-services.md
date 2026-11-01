# ADR-080 — Stage 4: M2 Network & Services

Status: accepted (stage S4, roadmap Phase 1, M2, `research/02-`).

This records the decisions that shaped M2 and that a later stage has to keep honouring. It
follows the convention of ADR-070 (stage S3): the spec's *what* is not restated, only the
choices the spec left open, and the deviations a reviewer needs to know about.

---

## ADR-080.1 — A second egress path (`core/net.py`), with the same guarantees as ADR-05

**Context.** ADR-05 (S1) confines every HTTP interaction to `ScopedHttpClient` and enforces it
with `tests/unit/test_http_hygiene.py`. M2 talks TCP, UDP and TLS, which that client cannot
express; the naive alternative (let each check open a socket) would have put sixteen
un-scoped, un-throttled, un-audited egress points into the codebase and made F-01-02/07/08
unenforceable for half the scanner.

**Decision.** `arachne.core.net.ScopedNetClient` is the only non-HTTP egress path. For every
probe it (1) checks the host against the compiled `Scope` and every resolved address against
the same `UrlSafetyPolicy` the HTTP path uses, (2) takes per-host and global rate-limit
tokens, (3) probes through an injectable transport with per-connection timeouts, and (4)
writes one `net.probe` audit line (or `net.blocked` / `scope.rejected` for a refusal). No
module may import `socket`/`ssl` for egress: all protocol logic lives in
`modules/m2/wire.py` (bytes in, facts out, no I/O) and the checks drive it.

**Consequences.** The refusal order is IP-literal-first, matching ADR-050.1, so an operator
always sees the specific reason; a name is resolved only after the scope check, so an
out-of-scope host cannot even generate a DNS query. `tests/unit/test_net_client.py` pins the
ordering (a blocked probe consumes no token and reaches no transport). A future stage that
wants a namespace sandbox (F-08-03) substitutes the transport, not the client.

## ADR-080.2 — M2's checks share a per-step `NetworkInventory`, not the asset table

**Context.** M2's seventeen checks are the spec's separate registry entries, but they form one
pipeline: liveness → open ports → service identity → protocol posture → CVE correlation. The
hand-off between stages could live in the `assets` table, but a port or a banner is not a
target-defined asset, and one row per open port would flood the inventory the report renders.

**Decision.** The discovery step handler builds one `NetworkInventory` and attaches it to the
`StepContext`; `CheckContext.inventory` exposes it. Hosts are keyed by the string the probe
was given (an address for an IP target, the name for a domain target — the client resolves per
probe, so the inventory never has to guess which address a name meant), bounded by
`NetSettings.max_hosts`/`max_ports`.

**Consequences.** A check with nothing in the inventory costs zero packets and *says so*
(`m2.support.inventory_or_skip`), which is what keeps `run_checks`' per-check selection honest
even though the checks are independent. `cve-correlate` runs last because the registry
selection order is the pipeline order; that ordering is now load-bearing and is asserted.
A future offline/replay mode for M2 can fill the inventory from a recording instead of probing.

## ADR-080.3 — `research_ref` values follow the corpus, not the spec table

Same deviation S3 recorded for M1 (`ADR-070.3`), and for the same reason: 's M2
table numbers references up to `ch02#35`, while the corpus chapter — the universe the G-01
coverage matrix counts — has 30 numbered methods. The check **ids** are exactly the spec's
(`m2.snmp-enum`, `m2.rdp-vnc-detect`, ...); only the reference numbers differ. Mapping:
`host-discovery` 1-4, `port-scan` 4-7, `os-fingerprint` 8, `service-fingerprint` 9-10,
`tls-deep-scan` 14, `snmp-enum` 15, `smb-enum` 16, `nfs-enum` 17, `ldap-enum` 18,
`kerberos-enum` 19, `smtp-enum` 20, `db-service-probe` 22-23, `ssh-enum` 24,
`rdp-vnc-detect` 25, `ics-probe` 27, `dns-active` 28, `cve-correlate` 29. Two spec rows have
no corpus method at all (`m2`'s `ch02#32`/`ch02#33-34`/`ch02#35` do not exist), which is the
drift in action.

## ADR-080.4 — Managed data: port catalogue, CVE/EPSS index, wordlists

`templates/m2/ports.yaml` (the top-ports policy, the UDP set, and each port's *probe hint*),
`templates/m2/cve-index.yaml` (the offline CVE/EPSS snapshot) and `templates/m2/wordlists/`
are data, loaded through `importlib.resources`, validated on load, and replaceable per
deployment (`ARACHNE_PORT_CATALOG`, `ARACHNE_CVE_INDEX`, `ARACHNE_WORDLISTS_DIR`) — the
F-09-03/04 shape S3 established for the dork corpus.

Two properties are deliberate. **The port catalogue is a hint, never a conclusion**: the
fingerprinter tries the hinted protocol first and falls back to its generic suite, which is
why the lab's Redis on an ephemeral port is still identified as Redis. **Version matching
fails towards "no match"**: a version or a constraint that cannot be parsed makes the entry
unmatched, because a false CVE is worse than a missed one.

## ADR-080.5 — Active by nature: the F-01-09 gates, and what M2 does *not* do

Every M2 check except `cve-correlate` declares `type="active"` and
`requires_active_checks=True`, so a default scan withholds all of them
(`tests/unit/test_registry.py::test_m2_is_selected_only_with_the_active_checks_switch`). Three
layers sit on top of that gate:

* **UDP is off by default** (`ARACHNE_NET_ALLOW_UDP`) as well as per-check opt-in: a UDP probe
  is unacknowledged and its attribution unreliable, and the protocols it reaches (SNMP,
  BACnet) are the most sensitive in an estate.
* **`m2.ics-probe` and `m2.snmp-enum` are opt-in checks** (`enabled_by_default=False`), so
  even an authorized active scan leaves them out unless they are named.
* **Pacing where pacing is safety**: Kerberos AS-REQ probes are capped and paced (a KDC
  enumeration mistake is an account-lockout incident in the assessed domain), and SMTP
  recipient probing is capped and paced for the same reason.

**Deliberately not implemented: credential verification.** Research ch02#29-30 (default
credentials, password spraying) are out of scope for M2. The spec's own framing is that these
are "existence-verification, not weaponization", and the honest way to honour that is not to
submit a credential at all: M2 reports "this datastore answered without authentication",
never "this password works". A credential check, when a later stage adds one, is a separate
opt-in with its own lockout discipline.

## ADR-080.6 — The optional external TLS tool runs with a fixed argument vector, no shell

`ARACHNE_NET_TLS_TOOL` (testssl.sh/sslscan) is opt-in and invoked with an explicit argv list
and no shell, which is the only way ("no shell access to arbitrary commands
from target-derived data") can be reconciled with using an external tool at all: the host and
port are *argv elements*, never interpolated into a command line. It is additive — the stdlib
probe is the default, the offline path, and what the tests assert.

## ADR-080.7 — Legacy protocol probing cannot rely on `ssl` under deprecations-as-errors

CPython 3.14 deprecates `ssl.TLSVersion.TLSv1`/`TLSv1_1` *and* the `OP_NO_TLSv1*` options, and
refuses the assignment when deprecation warnings are errors — which this project's pytest
configuration arranges (`filterwarnings = ["error::DeprecationWarning:arachne.*"]`).
`warnings.catch_warnings()` + `simplefilter("ignore")` does **not** hold for the C-level
`minimum_version` setter, so TLS 1.0/1.1 cannot be *pinned* in that environment, and a probe
that reported "unsupported" would be a fabricated fact.

The design that survives it:

* TLS 1.2/1.3 are pinned directly (their members are not deprecated) and observed exactly.
* TLS 1.0/1.1 are observed through a *cap* (`OP_NO_TLSv1_2 | OP_NO_TLSv1_3`), reading back the
  version the server then negotiates; a version below the negotiated one is reported as
  **undetermined** (`TlsVersionProbe.supported is None`), never as unsupported.
* When the interpreter refuses the cap as well, every legacy version is undetermined and the
  report says so; establishing them definitively needs a stack that still speaks them
  (ADR-080.6's external tool).
* **SSLv3 is not probed at all**: OpenSSL 3 builds it out, so a Python 3.11+ client cannot
  negotiate it, and a probe could only ever answer "not supported" for every endpoint.
  `classify_version("SSLv3")` and the `sslv3-supported` index signal remain, for the external
  tool's output.

## ADR-080.8 — Endianness is explicit at every call site

`wire.py` reads both byte orders, and the two families are marked rather than inferred: DNS,
SSH, ONC RPC/XDR, MBAP and BER/DER are big-endian; SMB2 and TDS are little-endian and use
`read_le16/32/64` explicitly. This is recorded because it was a real bug (the SMB2 and TDS
parsers read big-endian and only "worked" against fixtures built the same wrong way) and
because a future protocol addition will be tempted to reuse `read_uint16`.

## ADR-080.9 — Two lab fixtures, on purpose

* `docker/docker-compose.yml` + `docker/lab/` is the documented lab (DVWA, Juice Shop, a
  misconfigured Nginx with a served `.env` and `.git`, a weak-TLS Nginx), every service
  published on `127.0.0.1` and behind the `lab` profile. It is the target for the full M1-M4
  lab scan later stages run, and it needs a container runtime.
* `tests/lab/arachne_lab.py` is a stdlib lab: real sockets on ephemeral loopback ports
  speaking minimal-but-wire-correct versions of the same protocols, plus a planted old version
  for each of OpenSSH/Nginx/Redis/MySQL. It is what `tests/integration/test_m2_scan.py`
  drives, because M2's paths are *bytes on a wire* and proving them needs real sockets — but
  requiring Docker for that would make the stage's acceptance test unrunnable in most CI
  environments. The integration suite asserts the DONE criteria (host/ports/services/TLS
  issues, CVE correlation for the planted versions, evidence and audit for every probe) in
  ~20 s with no container runtime.

The two fixtures are expected to stay equivalent in observable behaviour; the Docker one is
authoritative when both are available.

## ADR-080.10 — A derived URL asset is not scanned twice

S2's discovery step derives `https://host/` and `http://host/` for every seeded host, so a
scan of `ip 127.0.0.1` also carries two URL assets naming the same host. Without a rule, every
M2 check would run three times over that host and raise three copies of each finding, and the
plan's request estimate would be wrong by the same factor. `m2.support.NetworkCheck.supports`
therefore skips URL assets whose `meta["source"]` is a derived source
(`DERIVED_URL_SOURCES`), while a URL the operator declared outright is kept — then it *is* the
target.

## ADR-080.11 — `NetworkCheck` is a mixin, and `Module` stays strict

`Module.__init_subclass__` refuses a subclass without metadata, so an intermediate base class
cannot inherit it. M2's checks therefore declare `class PortScan(NetworkCheck, Module)`: the
mixin narrows `supports()` (ADR-080.10) and the ABC keeps its import-time metadata guarantee.

## ADR-080.12 — Superseded/deferred details

* **`m1.internetdb-triage` and `m2.cve-correlate` overlap** (both can surface CVEs for an
  address). They are kept separate: M1's is a third-party index lookup, M2's is correlation of
  *fingerprinted* versions. Cross-module de-duplication is the correlation engine's job
  (`05-` "Deduplication & overlap rules", S5), keyed on CWE + asset.
* **`m4.db-exposure` vs `m2.db-service-probe`** is the spec's own named overlap; M2 keeps the
  fingerprint/exposure finding and M4 (S7) is expected to merge by CWE rather than re-probe.
* **Oracle TNS** is recognised by port but not fingerprinted (no wire parser); the port is
  still reported as an exposed database port, and no version is claimed.
* **ICMP** is best-effort: an unprivileged process without a ping socket reports
  `state="unavailable"` rather than "host down", and the TTL-based OS hint is explicitly a
  heuristic, not a fingerprint.
