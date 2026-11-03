"""DOM-XSS sink detection: the injection trace and its analysis (REQ-DET-015, ch03#3).

The second half of research ch03#3 is the half ``m3.xss-oracle`` records as unimplemented:
a sink that is only reachable **through JavaScript execution**. A server-side reflection
oracle cannot see it — the marker never appears in any response body — so the only way to
detect it is to run the page and watch which sink the marker reaches.

**What is injected, and what is not.** The instrumentation below is the *only* script
ARACHNE puts into a page. It runs before any page script, and it does one thing: it wraps the
documented DOM-XSS sinks so that a call whose argument contains the probe marker is recorded
as ``(sink, value)``. It never injects a payload, an event handler, a ``javascript:`` URL or
anything else that could execute: the *marker itself* is inert (``ar9x`` plus hex — the M3
oracle's stem, which contains no markup and no script), so a finding proves **taint flow from
a source to a dangerous sink**, which is exactly what the requirement asks for ("evidence
identifying the sink and the source"). Wrapping a sink forwards to the original
implementation, so the page still behaves as it would for a real visitor — a crawl that
changed the application's behaviour would measure something else.

**What makes it a DOM-XSS finding rather than a reflection.** Two facts must both hold:
the marker reached a sink inside the browser, *and* the raw server response for that URL does
not contain it. The second fact is what rules out the reflected-XSS false positive: if the
server never sent the marker, the only path it could have taken is a client-side source
(``location.hash`` — which is never sent to the server at all — or ``location.search`` read
by the page's own script) into a sink.

**Hostile pages.** The record array is a page-visible global, so a page *can* fabricate
records: it knows the marker because the marker is in its own URL. That is a false positive
the scanner cannot prevent and does not claim to: the result is a candidate with its evidence
attached, and a page that lies about its own sinks is a triage problem, not a safety problem.
:func:`parse_sink_records` bounds what a page can put into evidence — an unknown sink name is
dropped, only string values are read, the record count and every field length are capped, and
the nonce must appear verbatim.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

__all__ = [
    "DEFAULT_STEM",
    "MAX_RECORDS",
    "MAX_VALUE_CHARS",
    "SINK_RISK",
    "SINK_VOCABULARY",
    "SinkHit",
    "instrument_source",
    "parse_sink_records",
    "sink_artifact",
]

#: The marker stem. Must equal :data:`arachne.modules.m3.support.NONCE_STEM` — the crawler
#: plants ``<stem><hex>`` into the page's own sources, and the instrumentation keys on the
#: stem because it has to be baked into a script that runs *before* the nonce exists
#: (asserted by ``tests/unit/test_browser_dom_xss.py``).
DEFAULT_STEM: Final = "ar9x"

#: How many sink records one page may contribute, and how much of a value is kept. A page
#: that writes an megabyte into ``innerHTML`` must not be able to make the crawl allocate it.
MAX_RECORDS: Final = 32
MAX_VALUE_CHARS: Final = 400

#: The closed sink vocabulary. A record naming anything else is dropped: the evidence a
#: finding carries can only ever name a sink this module knows the risk of.
SINK_VOCABULARY: Final[tuple[str, ...]] = (
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "document.write",
    "document.writeln",
    "createContextualFragment",
    "eval",
    "Function",
    "setTimeout",
    "setInterval",
    "location.assign",
    "location.replace",
    "location.href",
    "setAttribute",
    "srcdoc",
    "script.text",
)

#: Sink -> (why it is dangerous, base confidence). A markup sink executes the value; an
#: ``eval``-family sink treats it as code; a navigation sink is the open-redirect half of the
#: same taint. Confidence is the *oracle's* read, never a severity (ADR-02).
SINK_RISK: Final[dict[str, tuple[str, float]]] = {
    "innerHTML": ("assigns the value as markup, so an element and an event handler in it run", 0.8),
    "outerHTML": ("replaces the element with parsed markup and runs it", 0.8),
    "insertAdjacentHTML": ("parses the value as markup and inserts it next to an element", 0.8),
    "document.write": ("writes the value into the parsing stream as markup", 0.8),
    "document.writeln": ("writes the value into the parsing stream as markup", 0.8),
    "createContextualFragment": ("parses the value as markup and returns live nodes", 0.8),
    "eval": ("compiles and runs the value as script", 0.9),
    "Function": ("compiles the value as a function body", 0.9),
    "setTimeout": ("runs a string argument as script", 0.9),
    "setInterval": ("runs a string argument as script, repeatedly", 0.9),
    "location.assign": ("navigates to the value (script or off-origin URL)", 0.6),
    "location.replace": ("navigates to the value (script or off-origin URL)", 0.6),
    "location.href": ("navigates to the value (script or off-origin URL)", 0.6),
    "setAttribute": ("sets an attribute the value can turn into a URL or a frame document", 0.5),
    "srcdoc": ("makes the value the document of an inline frame", 0.7),
    "script.text": ("sets the text of a script element, which the browser then runs", 0.9),
}

#: The instrumentation. ``__ARACHNE_STEM__`` is substituted by :func:`instrument_source`; the
#: script is otherwise a literal so a reviewer can read exactly what will run in the page.
_INSTRUMENT_TEMPLATE: Final = r"""
(function () {
  if (window.__arachneSinkTrace) { return; }
  var STEM = "__ARACHNE_STEM__";
  var MAX_RECORDS = __ARACHNE_MAX_RECORDS__;
  var MAX_VALUE = __ARACHNE_MAX_VALUE__;
  var sinkRecords = [];
  var routeRecords = [];
  window.__arachneSinkTrace = sinkRecords;
  window.__arachneRouteTrace = routeRecords;

  function note(sink, value) {
    try {
      if (typeof value !== "string" || value.indexOf(STEM) < 0) { return; }
      if (sinkRecords.length >= MAX_RECORDS) { return; }
      sinkRecords.push({
        sink: String(sink),
        value: value.slice(0, MAX_VALUE),
        url: String(window.location.href).slice(0, MAX_VALUE)
      });
    } catch (err) { /* a hook must never break the page */ }
  }

  function noteRoute(url) {
    try {
      if (routeRecords.length >= MAX_RECORDS) { return; }
      routeRecords.push(String(url).slice(0, MAX_VALUE));
    } catch (err) { /* ignore */ }
  }

  function wrapSetter(target, property, sink) {
    try {
      var descriptor = Object.getOwnPropertyDescriptor(target, property);
      if (!descriptor || typeof descriptor.set !== "function") { return; }
      Object.defineProperty(target, property, {
        configurable: true,
        enumerable: descriptor.enumerable,
        get: descriptor.get,
        set: function (value) { note(sink, value); return descriptor.set.call(this, value); }
      });
    } catch (err) { /* a frozen prototype is a page's choice; skip that sink */ }
  }

  function wrapMethod(target, property, sink) {
    try {
      var original = target[property];
      if (typeof original !== "function") { return; }
      target[property] = function () {
        try { if (arguments.length > 0) { note(sink, arguments[0]); } } catch (err) { /* ignore */ }
        return original.apply(this, arguments);
      };
    } catch (err) { /* ignore */ }
  }

  if (window.Element && window.Element.prototype) {
    wrapSetter(window.Element.prototype, "innerHTML", "innerHTML");
    wrapSetter(window.Element.prototype, "outerHTML", "outerHTML");
    wrapMethod(window.Element.prototype, "insertAdjacentHTML", "insertAdjacentHTML");
    wrapMethod(window.Element.prototype, "setAttribute", "setAttribute");
  }
  if (window.Range && window.Range.prototype) {
    wrapMethod(window.Range.prototype, "createContextualFragment", "createContextualFragment");
  }
  if (window.Document && window.Document.prototype) {
    wrapMethod(window.Document.prototype, "write", "document.write");
    wrapMethod(window.Document.prototype, "writeln", "document.writeln");
  }
  if (window.HTMLIFrameElement && window.HTMLIFrameElement.prototype) {
    wrapSetter(window.HTMLIFrameElement.prototype, "srcdoc", "srcdoc");
  }
  if (window.HTMLScriptElement && window.HTMLScriptElement.prototype) {
    wrapSetter(window.HTMLScriptElement.prototype, "text", "script.text");
  }
  try {
    var realEval = window.eval;
    window.eval = function (value) { note("eval", value); return realEval.call(window, value); };
  } catch (err) { /* ignore */ }
  try {
    var RealFunction = window.Function;
    var wrapped = function () {
      try { if (arguments.length > 0) { note("Function", arguments[arguments.length - 1]); } }
      catch (err) { /* ignore */ }
      return RealFunction.apply(this, arguments);
    };
    wrapped.prototype = RealFunction.prototype;
    window.Function = wrapped;
  } catch (err) { /* ignore */ }
  ["setTimeout", "setInterval"].forEach(function (name) {
    try {
      var real = window[name];
      if (typeof real !== "function") { return; }
      window[name] = function () {
        try { if (arguments.length > 0 && typeof arguments[0] === "string") { note(name, arguments[0]); } }
        catch (err) { /* ignore */ }
        return real.apply(this, arguments);
      };
    } catch (err) { /* ignore */ }
  });
  if (window.Location && window.Location.prototype) {
    wrapMethod(window.Location.prototype, "assign", "location.assign");
    wrapMethod(window.Location.prototype, "replace", "location.replace");
    wrapSetter(window.Location.prototype, "href", "location.href");
  }
  if (window.History && window.History.prototype) {
    ["pushState", "replaceState"].forEach(function (name) {
      try {
        var real = window.History.prototype[name];
        if (typeof real !== "function") { return; }
        window.History.prototype[name] = function () {
          try { if (arguments.length > 2) { noteRoute(arguments[2]); } } catch (err) { /* ignore */ }
          return real.apply(this, arguments);
        };
      } catch (err) { /* ignore */ }
    });
  }
})();
"""


def instrument_source(stem: str = DEFAULT_STEM) -> str:
    """The init script, with the marker stem and the bounds substituted in."""
    return (
        _INSTRUMENT_TEMPLATE.replace("__ARACHNE_STEM__", stem)
        .replace("__ARACHNE_MAX_RECORDS__", str(MAX_RECORDS))
        .replace("__ARACHNE_MAX_VALUE__", str(MAX_VALUE_CHARS))
    )


@dataclass(frozen=True, slots=True)
class SinkHit:
    """One sink call whose value carried the marker (the DOM-XSS oracle's read)."""

    sink: str
    value: str
    url: str
    rationale: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "sink": self.sink,
            "value": self.value,
            "url": self.url,
            "rationale": self.rationale,
            "confidence": round(self.confidence, 3),
        }


def parse_sink_records(records: object, *, nonce: str) -> tuple[SinkHit, ...]:
    """The marker-carrying sink records in ``records``, bounded and vocabulary-checked.

    ``records`` is whatever the page handed back, so nothing about it is trusted: a non-list
    contributes nothing, an entry that is not a mapping contributes nothing, an unknown sink
    name is dropped, and the nonce must appear verbatim in the value. The result is capped at
    :data:`MAX_RECORDS`.
    """
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
        return ()
    found: list[SinkHit] = []
    seen: set[tuple[str, str]] = set()
    for raw in records:
        if len(found) >= MAX_RECORDS:
            break
        if not isinstance(raw, Mapping):
            continue
        sink = raw.get("sink")
        value = raw.get("value")
        if not isinstance(sink, str) or not isinstance(value, str):
            continue
        if sink not in SINK_VOCABULARY or not nonce or nonce not in value:
            continue
        key = (sink, value)
        if key in seen:
            continue
        seen.add(key)
        rationale, confidence = SINK_RISK[sink]
        found.append(
            SinkHit(
                sink=sink,
                value=value[:MAX_VALUE_CHARS],
                url=str(raw.get("url") or "")[:MAX_VALUE_CHARS],
                rationale=rationale,
                confidence=confidence,
            )
        )
    return tuple(found)


def sink_artifact(
    hit: SinkHit,
    *,
    source: str,
    marker: str,
    client_side_only: bool,
    route: str | None = None,
) -> dict[str, Any]:
    """The machine-readable artifact a finding carries: the source, the sink, and the proof.

    ``source`` is the DOM source the marker was planted in (``location.hash`` or
    ``location.search``) — known to the crawler, not guessed from the page, because the
    crawler chose it. ``client_side_only`` is the fact that separates this from a reflected
    XSS: the raw server response for the page did not contain the marker, so it cannot have
    arrived through the response body.
    """
    return {
        "dom_sink": hit.sink,
        "dom_source": source,
        "marker": marker,
        "sink_value": hit.value,
        "client_side_only": client_side_only,
        "executed_in_browser": True,
        "route": route or hit.url,
        "rationale": hit.rationale,
    }
