"""Purple-team detection validation (S24, area VALID).

The question this area answers is the enterprise's hardest one: *would our defenses have
seen it?* ARACHNE can already prove an attack is possible (the S15 proof ladder). Purple
mode takes the same safe proof actions and turns them into a **detection test**: replay a
named subset, tagged with the ATT&CK technique it exercises, inside a time window agreed
with the defender, with every emitted artifact carrying the run's visible nonce — then
compare what was emitted against what the defender's SIEM actually reported.

The hard rule, stated once and enforced everywhere below: **these tests are designed to be
SEEN.** No evasion, no stealth, no offensive tooling. Payloads are emitted verbatim, the
ordinary rate limit applies, the window is the authorization boundary, and a test that
cannot be distinguished from an attack is not a test this project runs.

- :mod:`arachne.purple.attack` — the ATT&CK vocabulary, the replayable-action catalogue and
  the telemetry each action emits (``templates/purple/attck-map.yaml``).
- :mod:`arachne.purple.window` — the detection window's three-valued state and the refusal
  that guards it (the single definition of "inside the window").
- :mod:`arachne.purple.sigma` — rule-hit/rule-miss alignment against the M6 hunt library.
- :mod:`arachne.purple.alerts` — the defender's alerts, normalized from webhook, pull or
  export.
- :mod:`arachne.purple.coverage` — control-coverage scoring (per technique, per tactic, gap
  list) and the campaign trend.
- :mod:`arachne.purple.campaign` — the campaign spec, the per-scan capability seam and the
  run loop.
- :mod:`arachne.purple.report` — the defender report: detection gaps joined to the attack
  paths an attacker could walk unseen.

Persistence lives beside the other stores (:mod:`arachne.data.purple_store`); the modules
above that decide *what a window means*, *what counts as seen* and *what telemetry an
action emits* stay free of the data layer, so their decisions are testable as pure
functions.
"""
