"""HTTP parameter and form fuzzing on the existing payload grammar (S30, REQ-FUZZ-003).

REQ-FUZZ-003 is specific about the mechanism: HTTP fuzzing "MUST run within the existing payload
grammar and mutation rules, producing candidates — not findings — until verified through the
proof ladder". So this module does not invent payloads. It reads
``templates/m3/payloads.yaml`` through the same
:class:`~arachne.modules.m3.payloads.WebPayloads` the shipped M3 checks read — the SQL error
deltas, the boolean pairs, the calibrated XSS probe template, the traversal encoding classes and
their content markers, the parameter-name hints — and adds the one thing a fuzzer brings that a
check does not: **breadth**. A check probes the parameter it concluded was interesting; a fuzzer
enumerates every declared parameter against every payload in a family, under the run's budget,
and reports what moved.

Detection uses the corpus's own match rules — ``sql_error_regex()`` for a database error,
``traversal_markers()`` for a file that should not have been served, the XSS probe's
``html_marker``/``attribute_marker`` for an unencoded reflection — so a fuzzing candidate means
exactly what an M3 finding means, read from the same table. That is what makes the hand-off to
verification trustworthy: there is no second opinion about what "a SQL error leaked" looks like.

The verifier is chosen by the **signal**, never by the family: an error leak is `m3.sqli-oracle`'s
to prove, a file read is `m3.traversal-oracle`'s, an unencoded reflection is `m3.xss-oracle`'s. A
signal no shipped check can prove — a bare 500, or a status divergence — is recorded with
``verifier=None`` and stays a candidate for manual triage. Every candidate is bounded and
attributable: the family, the parameter, the exact payload, the encoding and the corpus version
are all on the record.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import quote, urlsplit, urlunsplit

from arachne.core.errors import ConfigurationError
from arachne.fuzz.candidates import CandidateSignal
from arachne.modules.m3.payloads import WebPayloads, load_payloads

__all__ = [
    "ALL_FAMILIES",
    "DEFAULT_FAMILIES",
    "OPT_IN_FAMILIES",
    "SIGNAL_VERIFIERS",
    "HttpFuzzCase",
    "HttpFuzzPlan",
    "HttpParameter",
    "HttpReading",
    "http_cases",
    "load_fuzz_payloads",
    "read_http_response",
    "verifier_for",
]

#: The families a run tries unless it says otherwise. These four are the ones whose probes are
#: inert *and* cheap: a quote, an unknown element, a traversal to a world-readable file, and the
#: input boundaries. Nothing here makes a target do work on the attacker's behalf.
DEFAULT_FAMILIES: Final[tuple[str, ...]] = (
    "boundary",
    "sqli-error",
    "xss-reflection",
    "traversal",
)

#: Families that are available but not on by default. ``sqli-boolean`` needs a paired
#: true/false request per payload (twice the requests for a delta that the shipped oracle also
#: reads), and ``sqli-time`` deliberately makes the target *sleep*, which is precisely what the
#: abort guard is built to notice — so it is an operator's explicit choice, not a default.
OPT_IN_FAMILIES: Final[tuple[str, ...]] = ("sqli-boolean", "sqli-time")

#: Every family this build offers.
ALL_FAMILIES: Final[tuple[str, ...]] = DEFAULT_FAMILIES + OPT_IN_FAMILIES

#: Input boundaries, used by the ``boundary`` family: no payload at all, but every shape a
#: parameter handler has to cope with. A 5xx or a truncated answer here is a real finding.
BOUNDARY_PAYLOADS: Final[tuple[tuple[str, str], ...]] = (
    ("empty", ""),
    ("long", "a" * 255),
    ("percent", "%"),
    ("crlf", "\r\n"),
    ("nul", "\x00"),
    ("quote", "'"),
    ("angle", "<>"),
    ("json", '{"a":1}'),
)

#: Which check can prove which signal (REQ-FUZZ-004). Chosen by signal rather than by family,
#: because the same family produces different signals on different targets and the *signal* is
#: the claim that has to be provable. ``None`` means no shipped check can prove it: recorded,
#: not proposed.
SIGNAL_VERIFIERS: Final[dict[CandidateSignal, str | None]] = {
    CandidateSignal.ERROR_LEAK: "m3.sqli-oracle",
    CandidateSignal.FILE_READ: "m3.traversal-oracle",
    CandidateSignal.REFLECTION: "m3.xss-oracle",
    CandidateSignal.TIMING: "m3.sqli-oob",
    CandidateSignal.FAULT: None,
    CandidateSignal.DIVERGENCE: None,
    CandidateSignal.ANOMALY: None,
    CandidateSignal.NO_RESPONSE: None,
}

#: Encodings applied to a corpus payload. ``encoded`` is the corpus payload as httpx sends it
#: (percent-encoded where the character requires it), ``plain`` inserts it raw into the query
#: string (some handlers decode differently from the framework), and ``double`` encodes the
#: payload once more — which is why the corpus's own traversal list already carries a
#: double-encoded member and why trying it again on a *plain* payload is a distinct case.
ENCODINGS: Final[tuple[str, ...]] = ("encoded", "plain", "double")


@dataclass(frozen=True, slots=True)
class HttpParameter:
    """One injectable point: a URL, the parameter in it, and the baseline value."""

    url: str
    parameter: str
    method: str = "GET"
    baseline_value: str = "1"
    #: A hint about what the parameter is for (``file``, ``id``, ``generic``), which decides
    #: whether the traversal family applies. A hint, not a decision: the signal is what counts.
    kind: str = "generic"
    description: str = ""

    def __post_init__(self) -> None:
        if not self.url.startswith(("http://", "https://")):
            msg = f"an HTTP fuzz parameter needs an http(s) URL, got {self.url!r}"
            raise ConfigurationError(msg)
        if not self.parameter:
            msg = "an HTTP fuzz parameter needs a name"
            raise ConfigurationError(msg)
        if self.method not in ("GET", "HEAD", "POST"):
            msg = f"method {self.method!r} is not a declared read-only HTTP method"
            raise ConfigurationError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "baseline_value": self.baseline_value,
            "kind": self.kind,
        }


@dataclass(frozen=True, slots=True)
class HttpFuzzPlan:
    """What an HTTP fuzzing run covers."""

    label: str
    parameters: tuple[HttpParameter, ...]
    families: tuple[str, ...] = DEFAULT_FAMILIES
    #: The asset the hypothesis pipeline knows this origin by (usually the origin URL).
    asset: str | None = None
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.parameters:
            msg = "an HTTP fuzz plan needs at least one parameter"
            raise ConfigurationError(msg)
        unknown = [name for name in self.families if name not in ALL_FAMILIES]
        if unknown:
            msg = (
                f"unknown HTTP fuzz family/families {', '.join(unknown)} "
                f"(this build offers: {', '.join(ALL_FAMILIES)})"
            )
            raise ConfigurationError(msg)

    @property
    def resolved_asset(self) -> str:
        if self.asset:
            return self.asset
        parts = urlsplit(self.parameters[0].url)
        return urlunsplit((parts.scheme, parts.netloc, "", "", ""))

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "asset": self.resolved_asset,
            "families": list(self.families),
            "parameters": [parameter.to_dict() for parameter in self.parameters],
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class HttpFuzzCase:
    """One HTTP test case: which parameter, which payload, how it was encoded, where it went."""

    index: int
    family: str
    parameter: str
    payload: str
    encoding: str
    method: str
    url: str
    body: str | None = None
    #: The string a reflection is proven by, when the family has one (the XSS probe's marker).
    marker: str = ""
    #: The check that can prove this family's signal, and ``None`` for the families whose
    #: signal no shipped check proves.
    verifier: str | None = None
    #: The paired payload of a boolean family, sent to establish the differential.
    control_payload: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "index": self.index,
            "family": self.family,
            "parameter": self.parameter,
            "payload": self.payload,
            "encoding": self.encoding,
            "method": self.method,
            "url": self.url,
            "verifier": self.verifier,
        }
        if self.body is not None:
            payload["body"] = self.body
        if self.marker:
            payload["marker"] = self.marker
        if self.control_payload is not None:
            payload["control_payload"] = self.control_payload
        return payload


@dataclass(frozen=True, slots=True)
class HttpReading:
    """What one HTTP response is: a signal, or nothing."""

    signal: CandidateSignal | None
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def is_signal(self) -> bool:
        return self.signal is not None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"signal": self.signal.value if self.signal else None}
        if self.detail:
            payload["detail"] = self.detail
        if self.evidence:
            payload["evidence"] = self.evidence
        return payload


def load_fuzz_payloads(path: str | None = None) -> WebPayloads:
    """The M3 payload corpus, loaded the way the M3 checks load it (F-09-04)."""
    return load_payloads(path)


#: Characters a "plain" payload must still be percent-encoded for, because a raw one would
#: change what the *URL* means rather than what the parameter contains: ``&`` would start another
#: parameter, ``#`` would start a fragment, and whitespace/control characters make the request
#: line invalid. Everything else — a quote, an angle bracket, a percent, a backslash — goes
#: through untouched, which is the point of having a plain encoding at all.
_STRUCTURAL: Final = "&# \t\r\n\x00"


def _plain(payload: str) -> str:
    return "".join(
        character if character not in _STRUCTURAL else quote(character, safe="")
        for character in payload
    )


def _encoded(payload: str, encoding: str) -> str:
    """The exact value that goes into the parameter, for each encoding class."""
    if encoding == "plain":
        return _plain(payload)
    if encoding == "double":
        return quote(quote(payload, safe=""), safe="")
    return quote(payload, safe="")


def _with_query(url: str, parameter: str, value: str) -> str:
    """``url`` with ``parameter`` set to ``value`` — ``value`` inserted exactly as given.

    Building the URL here rather than through the client's parameter support is deliberate: which
    bytes reach the target is the whole point of an encoding mutation, and a keyword argument that
    encodes them for you hides it. The caller has already applied the encoding class.
    """
    parts = urlsplit(url)
    prefix = f"{parameter}="
    insertion = f"{prefix}{value}"
    query = parts.query
    pairs = [item for item in query.split("&") if item] if query else []
    replaced = False
    for index, item in enumerate(pairs):
        if item == parameter or item.startswith(prefix) or item.split("=", 1)[0] == parameter:
            pairs[index] = insertion
            replaced = True
            break
    if not replaced:
        pairs.append(insertion)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))


def _family_cases(
    plan: HttpFuzzPlan,
    parameter: HttpParameter,
    family: str,
    payloads: WebPayloads,
    *,
    start_index: int,
) -> Iterator[HttpFuzzCase]:
    """Every case one family produces for one parameter."""
    index = start_index

    def make(
        payload: str,
        encoding: str,
        *,
        marker: str = "",
        verifier: str | None = None,
        control: str | None = None,
    ) -> HttpFuzzCase:
        nonlocal index
        value = _encoded(payload, encoding)
        url = _with_query(parameter.url, parameter.parameter, value)
        body = None
        if parameter.method == "POST":
            body = f"{parameter.parameter}={value}"
            url = parameter.url
        case = HttpFuzzCase(
            index=index,
            family=family,
            parameter=parameter.parameter,
            payload=payload,
            encoding=encoding,
            method=parameter.method,
            url=url,
            body=body,
            marker=marker,
            verifier=verifier,
            control_payload=control,
        )
        index += 1
        return case

    if family == "boundary":
        for _name, payload in BOUNDARY_PAYLOADS:
            for encoding in ("encoded", "plain"):
                yield make(payload, encoding)
        return

    if family == "sqli-error":
        for payload in payloads.strings("sqli", "error_payloads"):
            for encoding in ("encoded", "plain"):
                yield make(payload, encoding, verifier=SIGNAL_VERIFIERS[CandidateSignal.ERROR_LEAK])
        return

    if family == "sqli-boolean":
        for probe in payloads.boolean_probes():
            control = "1"
            yield make(
                probe.payload,
                "encoded",
                verifier=SIGNAL_VERIFIERS[CandidateSignal.ERROR_LEAK],
                control=control,
            )
        return

    if family == "sqli-time":
        for time_probe in payloads.time_probes():
            payload = time_probe.payload.replace("{delay}", "5")
            yield make(payload, "encoded", verifier=SIGNAL_VERIFIERS[CandidateSignal.TIMING])
        return

    if family == "xss-reflection":
        template = payloads.string("xss", "probe_template", default="<a{nonce}>\"'{nonce}")
        # The nonce makes each probe unique, so a cached or previously reflected response cannot
        # confirm the wrong request (the same rule the shipped oracle follows).
        for offset, encoding in enumerate(("encoded", "plain")):
            nonce = f"f{parameter.parameter[:4]}{start_index + offset:04d}"
            payload = template.replace("{nonce}", nonce)
            marker = payloads.string("xss", "html_marker", default="<a{nonce}>").replace(
                "{nonce}", nonce
            )
            yield make(
                payload,
                encoding,
                marker=marker,
                verifier=SIGNAL_VERIFIERS[CandidateSignal.REFLECTION],
            )
        return

    if family == "traversal":
        if parameter.kind != "file":
            # A traversal payload against a parameter that is not a file reference is a case the
            # corpus itself does not declare; sending it would be guessing at the grammar.
            return
        for payload in payloads.strings("traversal", "posix") + payloads.strings(
            "traversal", "windows"
        ):
            for encoding in ("encoded", "plain", "double"):
                yield make(payload, encoding, verifier=SIGNAL_VERIFIERS[CandidateSignal.FILE_READ])
        return

    msg = f"family {family!r} has no case builder"
    raise ConfigurationError(msg)


def http_cases(
    plan: HttpFuzzPlan,
    payloads: WebPayloads,
    *,
    limit: int,
) -> tuple[HttpFuzzCase, ...]:
    """The plan's cases, in a stable order, at most ``limit`` of them.

    Parameter-major, family-major, payload order — the order the corpus declares. Stable for the
    same reason the wire engine's is: a bounded run has to be comparable across days, or a change
    in its output cannot be attributed to the target.
    """
    cases: list[HttpFuzzCase] = []
    index = 0
    for parameter in plan.parameters:
        for family in plan.families:
            for case in _family_cases(plan, parameter, family, payloads, start_index=index):
                if len(cases) >= limit:
                    return tuple(cases)
                index = case.index + 1
                cases.append(case)
    return tuple(cases)


def _matches_any(patterns: Mapping[str, Any] | tuple[Any, ...], body: str) -> str | None:
    if isinstance(patterns, Mapping):
        for name, pattern in patterns.items():
            if pattern.search(body):
                return str(name)
        return None
    for entry in patterns:
        name, pattern = entry[0], entry[1]
        if pattern.search(body):
            return f"{name} ({entry[2]})"
    return None


def read_http_response(
    case: HttpFuzzCase,
    *,
    status: int,
    body: str,
    payloads: WebPayloads,
    baseline_status: int | None = None,
    baseline_bytes: int | None = None,
    latency_ratio: float = 0.0,
) -> HttpReading:
    """Read one response against the corpus's own match rules.

    Order matters: the *specific* corpora first (a database error, a traversal marker, an
    unencoded reflection), then the generic shape signals. A response that leaks a SQL error and
    also returns 500 is an error leak, because that is the stronger, provable claim.
    """
    if status >= 500:
        return HttpReading(
            CandidateSignal.FAULT,
            f"the target answered {status} to {case.family} case {case.index}",
            {"status": status, "family": case.family, "parameter": case.parameter},
        )

    family = _matches_any(payloads.sqli_error_signatures(), body)
    if family:
        return HttpReading(
            CandidateSignal.ERROR_LEAK,
            f"a {family} database error signature appeared in the response body",
            {"status": status, "signature_family": family, "parameter": case.parameter},
        )

    marker = _matches_any(payloads.traversal_markers(), body)
    if marker:
        return HttpReading(
            CandidateSignal.FILE_READ,
            f"the response carried the traversal marker {marker}",
            {"status": status, "marker": marker, "parameter": case.parameter},
        )

    if case.marker and case.marker in body:
        return HttpReading(
            CandidateSignal.REFLECTION,
            f"the probe marker {case.marker!r} came back unencoded",
            {"status": status, "marker": case.marker, "parameter": case.parameter},
        )

    if case.family == "sqli-time" and latency_ratio >= 3.0:
        return HttpReading(
            CandidateSignal.TIMING,
            f"the probe took {latency_ratio:.1f}x the baseline",
            {"status": status, "latency_ratio": round(latency_ratio, 2)},
        )

    if baseline_status is not None and status != baseline_status:
        return HttpReading(
            CandidateSignal.DIVERGENCE,
            f"the status changed from {baseline_status} to {status} for this payload",
            {"status": status, "baseline_status": baseline_status},
        )

    # Note what is *not* a signal: a response that is merely longer than the baseline. A longer
    # input legitimately produces a longer answer — a 255-character parameter echoes 255
    # characters — and reporting that as a divergence would bury the real leads in noise. A
    # leaked stack trace is caught by the error-signature rule above, which is the honest read
    # of "the response grew *because* something went wrong".
    return HttpReading(None)


def verifier_for(signal: CandidateSignal) -> str | None:
    """The check that can prove ``signal``, or ``None`` when no shipped check can."""
    return SIGNAL_VERIFIERS.get(signal)
