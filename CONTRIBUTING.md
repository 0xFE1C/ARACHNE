# Contributing to ARACHNE

Thank you. This document is the practical entry point. The **normative** rules live in
`.spec/`; this page tells you where to go and what a reviewer will check.

---

## 1. Before you start

| If you want to… | Read first |
|---|---|
| Report a vulnerability **in ARACHNE** | [`SECURITY.md`](SECURITY.md) — **not** a public issue |
| Write a check or plugin | [`docs/plugin-developer-guide.md`](docs/plugin-developer-guide.md) |
| Understand what ARACHNE does and why | [`.spec/01-vision.md`](.spec/01-vision.md) |
| Know what the current gaps are | [`.spec/02-current-state.md`](.spec/02-current-state.md) |
| Operate ARACHNE | [`docs/operator-guide.md`](docs/operator-guide.md) |
| Run / extend the build programme | [`STATE.md`](STATE.md) → [`PROMPT.md`](PROMPT.md) |

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
2. Read .spec/05-detection-program.md §2 — the check authoring standard.
3. Pick a framework item with no owner (.spec/00-research/technique-landscape.md has the gap list).
4. Scaffold it (from WP-12 onward): `arachne plugin new-check m3.your-check`
5. Implement `run()`. Add a positive fixture AND a decoy fixture.
6. Run the conformance kit and the full suite.
7. Open a PR.
```

**A check is not mergeable without a decoy fixture.** That is `FP-1` in
`.spec/05-detection-program.md` §4.2, and it is the rule that keeps a 400-check corpus
trustworthy.

**A check must declare a framework mapping** (`.spec/03-requirements.md` REQ-DET-002): at
least one of `WSTG-*`, `API<N>:2023`, `CWE-*`, `ATT&CK-T*`, `LLM*`, `ASI*`. The registry
refuses one that does not.

**A check must declare the lowest sufficient proof level.** If a read-only request establishes
the claim, it is L1 — not L2 because L2 "sounds stronger".

### 2.2 Everything else

Bug fixes, interface work, performance, documentation. Read the relevant `.spec/` document,
then open a PR. For anything non-trivial, open an issue first so the design is agreed before
you write it.

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
| `mypy` | `strict = true`, `files = ["src"]`, `warn_unreachable` | `src/` only; tests are typed loosely on purpose. |
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

**Do not delete a test to make a gate pass.** That is a safety change and requires owner
approval (`.spec/README.md` §6.4).

---

## 4. Definition of Done

A pull request is done when **all seven** hold (`.spec/08-quality-verification.md` §2.1):

1. Every requirement or claim it makes has passing evidence.
2. `ruff check .` passes.
3. `ruff format --check .` passes.
4. `mypy` strict passes.
5. The full non-perf suite passes, including every safety suite.
6. No invariant (`INV-1`…`INV-11`) is weakened.
7. The living docs are updated where behaviour changed, and the commit exists.

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

There is **one** changelog source (introduced in WP-18). [`docs/release-notes.md`](docs/release-notes.md)
is the operator-facing history; do not create a second, parallel changelog. If your change is
user-visible, it gets an entry in the single source, and the release notes are generated from
it.

---

## 6. Reporting problems

| Kind | Where |
|---|---|
| Security vulnerability **in ARACHNE** | [`SECURITY.md`](SECURITY.md) — private disclosure, never a public issue |
| A check that reports a false positive | A public issue with the check id, the target shape (redacted), and the evidence the check produced |
| A check that misses a known vulnerability | A public issue with a minimal reproduction |
| A documentation error | A PR. Path and link errors are gated (`.spec/03-requirements.md` REQ-DOC-001); a report is a gift. |
| A specification problem | An issue against `.spec/`. It is normative, so a change goes through change control (`.spec/README.md` §6). |

**Never include a real secret, a real customer hostname, or unredacted evidence in an issue.**
Reproduce against a lab fixture.

---

## 7. Working on the build programme

If you are a builder session rather than a human contributor, your entry point is
[`STATE.md`](STATE.md), not this file. In short: read `STATE.md`, take the first `pending`
work package, copy its block from [`PROMPT.md`](PROMPT.md), implement only that, keep the
gates green, fill the handoff, commit once, and **stop**.

One work package per session. A failing work package is fixed before the next starts. Every
deviation is recorded in `STATE.md`.

---

## 8. Licence

By contributing you agree that your contribution is licensed under the project's
[MIT licence](LICENSE). Third-party components remain under their own licences.