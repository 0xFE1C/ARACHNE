# Published benchmark results (REQ-TRUST-010)

This directory holds the **committed, reproducible** benchmark record. Every suite that has a
baseline has two files:

| File | What it is |
|---|---|
| `baseline.json` | The document the regression gate reads. Carries the aggregates, the corpus version, the command, the environment, the timing and the raw per-case rows. |
| `results.json` | The same document published under the path the requirement names. Kept beside `baseline.json` so a reader can fetch the raw per-case data without knowing the gate's filename. |

Both files are written by the same `--write-baseline` run, so they are byte-identical; neither
is hand-edited. A third party re-derives the whole document by running the command below on
the same corpus, and compares the deterministic fields with
`arachne.quality.benchmark.deterministic_projection` (see `docs/reproducible-benchmark.md`).

**What "raw per-case" means here.** `cases` holds one object per suite case, in suite order:
the check id, the marker, the expectation (`tp` planted / `fp` trap), whether it matched,
*which* stored candidate ids matched it, and the wall-clock seconds from scan start to the
first matching candidate (or an explicit `timing_source` saying why that number does not
exist). The aggregates in `score` are derivable from these rows; they are published together
so neither has to be trusted on its own.

**Timing honesty.** `timing.scan_seconds` is always measured. Per-case time-to-finding exists
only when the store timestamps candidates and the scan's start was recorded. When it does not,
the rows carry `elapsed_seconds: null` with the reason, never a plausible-looking placeholder.

## Suites with a committed result

### arachne-lab

| | |
|---|---|
| Corpus version | `arachne-lab@1.0+54504f855bf96d59` |
| Result date (UTC) | 2026-11-04T18:24:39Z (measured) |
| Raw result | [`arachne-lab/results.json`](arachne-lab/results.json) |
| Gate baseline | [`arachne-lab/baseline.json`](arachne-lab/baseline.json) |
| Reproduce with | `python -m arachne.tools.benchmark --lab --gate` |
| Fixture rotation | last `2026-11-04`, review by `2027-11-04` |

Measured numbers (from the committed document, not re-typed by hand):

- detection / recall: **15 / 16 = 0.9375** (missed `m3.upload-audit:/upload`)
- precision: **15 / 15 = 1.0** (15 true positives, 0 false positives)
- false-positive rate: **0 / 15 = 0.0**; unscored candidates: 14
- scan wall-clock: **25.342 s**; per-case time-to-finding available for 15/15 matched cases

Environment block recorded with the result:

```json
{
  "python_version": "3.14.9",
  "python_implementation": "CPython",
  "platform": "Linux-7.2.11-arch1-1-x86_64",
  "arachne_version": "0.1.0",
  "source_date_epoch": null
}
```

The lab is the in-repository vulnerable application (`tests/lab/web_lab.py`), so this result is
reproducible offline from a checkout: no hosted target, credential or attestation is needed.

## Suites without a committed result

These suites are `source: recorded` and `required: false`: they need a hosted target, and **no
measurement has been taken and committed here**. There is deliberately no `results.json` and no
`baseline.json` for them — an empty or invented result would be worse than an absent one. The
`--gate` run reports their absence as a note (it does not fail), and `verify_recorded` still
checks the arithmetic of any baseline an operator later commits.

### owasp-benchmark

| | |
|---|---|
| Corpus version | `owasp-benchmark@1.0+e15f7c0148d579c8` |
| Raw result | not committed — the target is hosted and no measurement was taken |
| Reproduce with | see the suite file / `reproduce` below |
| Fixture rotation | last `2026-11-04`, review by `2027-11-04` |

The suite ships a sampled case set and a documented command:

```text
docker run -p 8443:8443 owasp/benchmark:latest
arachne scan --url https://localhost:8443/benchmark/ --attestation ...
python -m arachne.tools.benchmark --suite owasp-benchmark \
  --target https://localhost:8443/benchmark/ --write-baseline
```

Why no baseline is committed: the OWASP Benchmark is a hosted Java target (and the suite is a
sample, not the full corpus, which is scored by the Benchmark's own tooling). Running it needs
an operator, a target and an attestation; publishing a number without that run would be a
fabrication. When an operator does run it, `--write-baseline` writes this directory's two
publication files for that suite, in exactly the same shape as the lab's.

### juice-shop

| | |
|---|---|
| Corpus version | `juice-shop@1.0+0567694bcb100387` |
| Raw result | not committed — hosted target, no measurement taken |
| Reproduce with | `docker run -p 3000:3000 bkimminich/juice-shop`, then `python -m arachne.tools.benchmark --suite juice-shop --target http://localhost:3000/ --write-baseline` after the documented scan |
| Fixture rotation | last `2026-11-04`, review by `2027-11-04` |

### dvwa

| | |
|---|---|
| Corpus version | `dvwa@1.0+142b25e1c18e664e` |
| Raw result | not committed — hosted target, no measurement taken |
| Reproduce with | `docker run -p 8080:80 vulnerables/web-dvwa`, then `python -m arachne.tools.benchmark --suite dvwa --target http://localhost:8080/ --write-baseline` after the documented scan |
| Fixture rotation | last `2026-11-04`, review by `2027-11-04` |

## Annual rotation

The fixture set rotates at least annually. Each suite file records `rotated_at`, `review_by`
(one year later) and the `rotation_history` entries. `rotation_problems` is the gate: it fails
a suite with no record, a window longer than 365 days, or a `review_by` in the past. As of
2026-11-05 no suite is overdue (all review by 2027-11-04).

To record a rotation:

```bash
python -m arachne.tools.benchmark --rotate --suite arachne-lab \
  --rotate-note "replaced three fixtures; added two hardened counterparts"
```

Omit `--suite` to stamp every shipped suite. The command writes a managed block at the end of
the suite YAML, preserving the hand-written explanation above the cases; it does not measure.
After editing cases, bump the suite's `version` as well — the corpus version is
`<suite>@<version>+<digest of the case list>`, so the digest changes on its own but the version
is what a human reads in the result.