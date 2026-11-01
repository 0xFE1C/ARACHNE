# ADR-330 · The research corpus is restored, and reconstructed from the checks

| Field | Value |
|---|---|
| Status | accepted (WP-01) |
| Date | 2026-11-02 |
| Deciders | ARACHNE detection engineering, documentation owner |
| Supersedes | ADR-341 (`Restore the research corpus rather than retire it`, status *Proposed*) |
| Requirements | REQ-DOC-001, REQ-DOC-002, REQ-DOC-003 |

## Context

Every registered check declares a `research_ref` (`ch01#14-16`), validated at class-definition
time by `BaseCheck` against `^ch0[1-6]#\d{1,2}(?:-\d{1,2})?$`. The reference is a *traceability*
claim: it says which numbered method of the detection programme's research corpus the check
implements. `arachne coverage` resolves those references against the corpus and is the G-01
gate ("≥ 90% of research methods mapped to checks").

The corpus directory (`docs/research/`) did not exist in this repository. The consequences were
concrete and mutually reinforcing:

- `arachne coverage` — a **shipped, documented command** — returned `{"total": 0, "mapped": 0}`
  (`docs/operator-guide.md` §7 documents it; `docs/release-notes.md` listed the failure as a
  known limitation).
- 23 tests were skipped by a module-level `skipif`, which is the worst possible shape for a
  gate: the tests that would have caught the drift were the tests that were not running.
- Two shipped documents (`docs/operator-guide.md`, `docs/plugin-developer-guide.md`) document
  the corpus path and the `research_ref` contract as if it worked.

`ADR-341` proposed restoring the corpus but left the decision open, with retirement as the
alternative.

## Decision

**Restore the corpus**, under `docs/research/`, as six chapter files carrying exactly the 175
numbered methods the source tree's references and the tests require
(30 / 30 / 35 / 30 / 25 / 25 for `ch01`…`ch06`).

Retirement (removing the command, the `research_ref` field, its registration-time validation,
and the 23 tests) was rejected: it would delete a validation, a CLI command and a documented
plugin contract — a change in shipped behaviour — to fix a missing-data problem, and it would
leave 152 checks with no traceability to the programme that produced them.

**The prose is reconstructed; the numbering and the counts are not.** The checks, their
`research_ref` values and the per-chapter method counts are original and were never lost. The
method *titles and descriptions* are written from what the citing checks actually do: each
referenced method is named for the technique its check implements, and each unreferenced method
is named for the technique that is conspicuously absent. `docs/research/README.md` states this
plainly, so no reader mistakes the corpus for a recovered source document or cites it as an
external authority.

## Consequences

- **Positive.** The shipped command works (`148/175 (84.6%)`), the 23 skips are gone, and the
  G-01 gate can actually fail. The unreferenced methods are now *named* gaps — 27 of them, each
  with the reason it is absent — which is what makes the coverage number reviewable rather than
  a bare percentage.
- **Positive.** `coverage_matrix.md` is now generated and committed, so the coverage claim in
  `docs/operator-guide.md` §7 is a checked artefact instead of a hand-typed number.
- **Negative.** The corpus is authored content maintained by hand. Mitigated by the numbering
  contract (a method is retired in prose, never by deleting its number) and by the two tests
  that assert the counts and every M1 reference.
- **Negative — accepted.** A corpus member is no longer evidence of independent research. The
  provenance note in `docs/research/README.md` is the mitigation, and it is honest about the
  limit.

## Alternatives rejected

- **Retire the concept.** Deletes a command, a field, a validation and a documented contract to
  work around absent data. Large, behaviour-changing, and it destroys traceability.
- **Leave the corpus absent and delete the tests.** Turns a visible gap into an invisible one
  and keeps a shipped command that does nothing. This is the failure mode the work package
  exists to remove.
- **Commit a fixture corpus under `tests/`.** Satisfies the tests without making the command
  work for an operator, which is the user-visible half of the defect.
- **Generate the corpus from the references.** Would make every referenced method "mapped" by
  construction: a coverage number that cannot fail is not a gate.
