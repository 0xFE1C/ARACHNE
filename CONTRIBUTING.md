# Contributing to ARACHNE

> **Owner:** Documentation owners · **Last verified:** 2026-11-05 · **Review interval:** 180 days

Thank you. This document is the practical entry point. The rules a contribution must satisfy
are **executable** — they are the gates in §3, the safety suites, and the documentation checks
that run on every pull request. A release of ARACHNE ships no separate prose specification, so
nothing here points at one.

---

## 1. Before you start

| If you want to... | Read first |
|---|---|
| Report a vulnerability **in ARACHNE** | [`SECURITY.md`](SECURITY.md) — **not** a public issue |
| Write a check or plugin | [`docs/plugin-developer-guide.md`](docs/plugin-developer-guide.md) |
| Understand what ARACHNE does and why | [`docs/architecture.md`](docs/architecture.md) → [`docs/adr/`](docs/adr/) (the decision record) |
| Know what the current gaps are | [`coverage_matrix.md`](coverage_matrix.md) and [`docs/research/README.md`](docs/research/README.md) |
| Operate ARACHNE | [`docs/operator-guide.md`](docs/operator-guide.md) |
| Run ARACHNE end to end | [`docs/getting-started.md`](docs/getting-started.md) |

**One rule above all others:** ARACHNE is a **defensive** tool. A contribution must not add
exploitation, persistence, credential theft, destructive payloads, evasion, denial of
service, or mass targeting. The proof ladder (L0–L4) is the capability boundary, and the
scope gate, attestations, audit integrity, redaction and the cleanup pass are invariants.
A pull request that weakens one is closed, not debated.

---

## 2. The two kinds of contribution

### 2.1 A detection check (most common)

```
1. Read docs/plugin-developer-guide.md.
2. Read docs/architecture.md — the layer and registry the check joins.
3. Pick a gap named in coverage_matrix.md.
4. Scaffold it: `arachne plugin new-check m3.your-check`
5. Implement `run()`. Add a positive fixture AND a decoy fixture.
6. Run the conformance kit and the full suite.
7. Open a PR.
```

**A check is not mergeable without a decoy fixture.** A family that fires on a healthy target
is worse than a family that misses, and the decoy is what makes the difference visible.

**A check must declare a framework mapping** (REQ-DET-002): at least one of `WSTG-*`,
`API<N>:2023`, `CWE-*`, `ATT&CK-T*`, `LLM*`, `ASI*`. The registry refuses one that does not.

**A check must declare the lowest sufficient proof level.** If a read-only request establishes
the claim, it is L1 — not L2 because L2 "sounds stronger".

### 2.2 Everything else

Bug fixes, interface work, performance, documentation. Read the shipped document closest to
the change — [`docs/architecture.md`](docs/architecture.md) for structure,
[`docs/operator-guide.md`](docs/operator-guide.md) for behaviour — then open a PR. For anything
non-trivial, open an issue first so the design is agreed before you write it.

---

## 3. Code standards

### 3.1 The gates

Every pull request must leave all of these green:

```bash
ruff check .
ruff format --check .
mypy
python -m pytest tests -m "not perf" -q
python -m arachne.tools.credentials_gate .
```

| Gate | Configuration | Notes |
|---|---|---|
| `ruff check` | `pyproject.toml` `[tool.ruff.lint]` — E, W, F, I, N, UP, B, A, C4, DTZ, T10, T20, PIE, PTH, RET, RUF, S, SIM, ASYNC | Repo-wide. Do not add a path exclusion to hide a violation. |
| `ruff format` | `line-length = 100` | Repo-wide. |
| `mypy` | `strict = true`, `files = ["src", "tools"]`, `warn_unreachable` | The product and the development tooling; tests are typed loosely on purpose. |
| `pytest` | `pyproject.toml` `[tool.pytest.ini_options]` | `asyncio_mode = auto`; `--strict-markers`. |

### 3.2 Style that the linter cannot check

- **Match the surrounding code.** Comment density, naming, and idiom are local conventions.
- **Docstrings explain *why*.** The code says what; the docstring says which requirement or
  invariant it serves, with the reference that makes it checkable — a shipped document under
  `docs/` (`docs/architecture.md`, `docs/operator-guide.md`) or the requirement id. A path in
  prose must resolve; `python -m arachne.tools.doccheck .` is the gate.
- **No `print`.** CLI output goes through `typer.echo`; logging through the structured logger.
- **No bare `except`.** Use the typed errors in `src/arachne/core/errors.py`.
- **No new top-level package.** New subsystems go into an existing layer
  (`docs/architecture.md` §"Layers").
- **Respect the dependency direction** (`docs/architecture.md`): a module at layer N
  imports from N-1 or lower, never upward.

### 3.3 Test layers

| Layer | Directory | Use it for |
|---|---|---|
| Unit | `tests/unit/` | Pure logic, in-memory stores, parsers |
| Safety | `tests/test_*_safety.py`, `tests/safety/` | Anything touching scope, proof, audit, credentials, fuzzing |
| Integration | `tests/integration/` | CLI/API end to end against fixtures |
| Lab | `tests/lab/` (fixtures) | Ground-truth servers |
| Parity | `tests/parity/` | Heuristic vs AI equivalence |
| Report QA | `tests/report_qa/` | Golden files per renderer |
| Perf | `tests/perf/` | Throughput, latency, memory |

**Add a safety test whenever you touch a safety surface.** Reviewers look for it first.

**Do not delete a test to make a gate pass.** That is a safety change: the invariants
(`INV-1`...`INV-11`) are reviewed by a human before merge, and removing the test that asserts one
needs the owner's explicit approval recorded against the change.

---

## 4. Definition of Done

A pull request is done when **all seven** hold:

1. Every requirement or claim it makes has passing evidence.
2. `ruff check .` passes.
3. `ruff format --check .` passes.
4. `mypy` strict passes.
5. The full non-perf suite passes, including every safety suite.
6. No invariant (`INV-1`...`INV-11`) is weakened.
7. The living docs are updated where behaviour changed — including the page's
   `last-verified` date, which the docs job checks — and the commit exists.

A PR that satisfies 1–3 but not 4–7 is **not done**, and saying so in the PR is the correct
move — a truthful incomplete PR is worth more than a false complete one.

---

## 5. Commits and pull requests

### 5.1 Commit convention

| Situation | Format |
|---|---|
| A work package from the programme | `WP-<nn>: <imperative summary>` with `Verifies: REQ-…` in the body |
| An ordinary contribution | `<area>: <imperative summary>` — e.g. `m3: add host-header injection check` |
| A documentation fix | `docs: <what>` |

**Never** `fix`, `wip`, `updates`, or a bare `S<n>`. The `S1`–`S30` numbering belongs to the
archived programme and is not continued.

One logical change per commit. A reformat is its own commit with no semantic change.

### 5.2 Pull requests

| Step | Rule |
|---|---|
| Branch | One branch per change: `wp-07-coverage-ledger` or `check-host-header` |
| Title | Matches the commit subject |
| Body | What changed, why, the requirement or issue it serves, and the **commands you ran with their output** |
| Size | One concern per PR. A PR that mixes a refactor with a feature is split. |
| Review | A human reviewer checks: invariants untouched, gates green, evidence present |
| Merge | Squash to one commit on `main` |

**PRs that touch a safety surface** (`core/safety.py`, `core/proof.py`, `core/integrity.py`,
`proof/`, `tests/test_*_safety.py`, `tools/credentials_gate.py`) get an explicit safety
review and are never merged on a green CI alone.

### 5.3 Release notes and the changelog

There is **one** changelog source: [`CHANGELOG.md`](CHANGELOG.md). If your change is
user-visible, it gets an entry there and nowhere else — [`docs/release-notes.md`](docs/release-notes.md)
carries a **generated** index of that file, and `python -m arachne.tools.changelog --check`
fails the docs job when the two disagree. Editing the release notes by hand is how two
documents start telling different stories about one release.

---

## 6. Reporting problems

| Kind | Where |
|---|---|
| Security vulnerability **in ARACHNE** | [`SECURITY.md`](SECURITY.md) — private disclosure, never a public issue |
| A check that reports a false positive | A public issue with the check id, the target shape (redacted), and the evidence the check produced |
| A check that misses a known vulnerability | A public issue with a minimal reproduction |
| A documentation error | A PR. Path and link errors are gated (`python -m arachne.tools.doccheck .`, REQ-DOC-001); a report is a gift. |
| Anything else | A public issue, or a PR if it is small and obvious. |

**Never include a real secret, a real customer hostname, or unredacted evidence in an issue.**
Reproduce against a lab fixture.

---

## 7. Working on the build programme

ARACHNE's own development runs as a work-package programme: a tracker file names the single
package a session may implement, a delivery plan defines each package's requirements and gate,
and a handoff gate checks the result. None of that scaffolding is part of a release — the
product ships `docs/`, not the plan — so it is not described here, and a contributor does not
need it: the gates in §3 are the same either way.

The two gates that *read* the scaffolding live in the repository-root `tools` package, which is
development tooling: it is not in the wheel and not in the sdist (a test asserts both), so it
never reaches a user and the shipped tree never names the scaffolding. With an activated
environment, from the repository root:

```bash
python -m tools.wp_check <pkg>          # verify a completed work package from the repository
python -m tools.preamble_check .        # every prompt block matches the shared preamble
```

`wp_check` prints one line per check and exits non-zero on any failure; its seventh check runs
the §3 gates at the work package's commit in a fresh process, which is why it is slow. Pass
`--no-gates` to skip it. Neither tool is on the import path of any packaged module.

One work package per session. A failing work package is fixed before the next starts. Every
deviation is recorded in the tracker, not in the code.

---

## 8. Licence

By contributing you agree that your contribution is licensed under the project's
[MIT licence](LICENSE). Third-party components remain under their own licences.
