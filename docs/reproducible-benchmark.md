# Reproducible public benchmark

> **Owner:** Quality group · **Last verified:** 2026-11-05 · **Review interval:** 180 days

This document describes the published benchmark method required by **REQ-TRUST-010**. The
claim it makes is deliberately narrow, because it is the only one that survives a saturated
benchmark: *here is the corpus, here is the command, here are the raw rows and the
environment — re-run it.* The method universe the corpus is drawn from is
[`docs/research/`](research/README.md), and the measured envelope it feeds is
[`docs/performance.md`](performance.md).

The published artefacts live in [`benchmarks/`](../benchmarks/README.md):

| Artefact | Contents |
|---|---|
| `benchmarks/<suite>/results.json` | The raw result: corpus version, command, environment, timing and one row per suite case. |
| `benchmarks/<suite>/baseline.json` | The same document, used by the regression gate. |
| `benchmarks/README.md` | Per-suite corpus version, command, environment block, raw path, date and rotation status. |

## What is measured

For every case the suite declares, one row records:

- `check_id`, `marker`, `expect` (`tp` = planted, `fp` = hardened trap);
- `matched` — whether a stored candidate of that check carried the marker in its evidence;
- `matched_by` — the stored candidate id(s) that matched, not just a count;
- `elapsed_seconds` — wall-clock seconds from scan start to the first matching candidate, or
  `null` when the store exposed no timestamp;
- `timing_source` — where `elapsed_seconds` came from, or why there is none.

The aggregate `score` is derived from those rows by `measure_with_cases`; it is published
beside them so a reader can recompute it without trusting it.

### Precision and recall

With `tp` true positives, `fp` false positives and `planted` planted cases:

- **precision** = `tp / (tp + fp)` — of everything the suite scored, the fraction that hit a
  planted case. When `tp + fp == 0` precision is reported as **0.0**: there was no positive
  prediction, so precision is undefined rather than perfect.
- **recall** = `tp / planted` — the fraction of planted cases found. When `planted == 0` recall
  is reported as **0.0**. `recall` is the same quantity as the existing `detection` field; both
  names are kept because the gate compares `detection` and this document publishes `recall`.
- **false-positive rate** = `fp / (tp + fp)`, as before, and **0.0** when nothing was scored.

A candidate that matches no case is *unscored*, not a false positive: the suite's ground truth
describes specific paths, and punishing findings outside it would make the FP rate a measure of
the suite's exhaustiveness rather than the scanner's precision. The unscored count is published.

### Time-to-finding

`timing.scan_seconds` is measured around the scan call with a monotonic clock and is always
present. Per-case time-to-finding is the difference between the matching candidate's
`created_at` and the scan record's `started_at`; it is recorded only when both exist. If the
store exposes no candidate timestamp, or the scan start was not recorded, the row carries
`elapsed_seconds: null` and a `timing_source` that says which one was missing. The harness never
invents a per-case number.

## Reproducing a result

1. Check out the repository at the commit that contains the result.
2. Run the suite's command from `benchmarks/README.md`. For the in-repository corpus:

   ```bash
   python -m arachne.tools.benchmark --lab --gate
   ```

3. Compare the deterministic fields with the committed document:

   ```python
   from pathlib import Path
   from arachne.quality.benchmark import (
       BenchmarkResult,
       deterministic_projection,
       load_baseline,
   )

   committed = load_baseline(Path("benchmarks"), "arachne-lab")
   fresh = BenchmarkResult.model_validate_json(Path("tmp/results.json").read_text())
   assert deterministic_projection(fresh) == deterministic_projection(committed)
   ```

`deterministic_projection` keeps the corpus version, every aggregate number and each case's
`(check, marker, expectation, matched)`. It drops `measured_at`, the environment, wall-clock
timing and store-minted candidate ids: those are provenance, and a reproduction on another
machine is allowed to differ in them. `tests/unit/test_benchmark_reproducible.py` runs exactly
this comparison against the committed artefact, including a fresh generation of it.

## Corpus versions and rotation

The corpus version is `<suite>@<suite version>+<digest of the case list>`. The digest covers
every `(check_id, marker, expect)` triple, so editing a case changes the corpus version even if
someone forgets to bump `version`; bump the version anyway, because it is what a human reads.

Fixtures rotate at least annually, and the rotation is recorded in the suite file:

```yaml
# --- rotation (managed by `python -m arachne.tools.benchmark --rotate`) ---
rotated_at: '2026-11-04'
review_by: '2027-11-04'
rotation_history:
  - '2026-11-04: seeded annual rotation policy (REQ-TRUST-010)'
# --- end rotation ---
```

Record a rotation with:

```bash
python -m arachne.tools.benchmark --rotate --suite arachne-lab --rotate-note "what changed"
```

The command stamps `rotated_at` with today, sets `review_by` one year later and appends a
`rotation_history` entry, preserving the suite file's hand-written comments. It measures
nothing. `rotation_problems` fails a suite that has no rotation record, a review window longer
than 365 days, or a `review_by` in the past; the committed suites are checked against a fixed
date (2026-11-05) by `tests/unit/test_benchmark_reproducible.py`, and none is overdue.

## Hosted suites: what is deliberately not published

`owasp-benchmark`, `juice-shop` and `dvwa` are `source: recorded, required: false`. They need a
hosted target (and, for DVWA, a credential), and **no measurement has been taken here**, so no
baseline or `results.json` is committed for them. `verify_recorded` still checks the arithmetic
of any baseline an operator later commits, and refuses to pretend an absent one is a pass. This
is the honest state: absent data is published as absent, not as zero.

When an operator runs one, the same `--write-baseline` path writes a result of the same shape,
and `benchmarks/README.md` should then gain that suite's section under "Suites with a committed
result".
