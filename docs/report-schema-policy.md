# The report schema policy

> **Owner:** Data group · **Last verified:** 2026-11-05 · **Review interval:** 180 days

Every ARACHNE report carries a `schema_version`, and the schema itself ships as data under
`src/arachne/templates/report/`. This page is the promise behind that number: what may change,
what may go away, how long a consumer has, and how to move an old document forward.

The policy is executable. `src/arachne/report/schema_policy.py` holds the ledger and the
checks, and `python -m arachne.tools.report_schema --check` fails the build when a committed
schema disagrees with it.

---

## 1. Supported versions (bounded)

A consumer may rely on the **five most recent minor versions**, ending at the version the
current build writes. The window is a constant, not an accident of history:

| | |
|---|---|
| Current version | `1.14` |
| Supported window | `1.10`, `1.11`, `1.12`, `1.13`, `1.14` |
| Window size | 5 (`SUPPORTED_VERSION_WINDOW`) |

Older schema files stay in the repository — they are frozen history, and a document can always
be validated against the revision it claims. What ends at the window's edge is the *migration*
promise: `migrate_report` converts a supported version forward and refuses one outside it
with a message naming the window.

## 2. The four rules

**Additive-only within a major.** A `1.x` revision may add a field. It may not remove or
rename one, except through the deprecation path below. `policy_violations()` compares every
revision with the one two minors before it and refuses a vanished field that has no record.

**Two minor versions of notice.** A deprecation record names the field, the version it was
deprecated in, and the version that removes it. `removal_version` must be at least two minor
releases after `deprecated_in`; a record that removes sooner is a violation, not a warning.

**Every revision carries a machine-readable changelog.** Each `report-schema-<version>.json`
declares two JSON-Schema extension keywords:

```json
{
  "x-arachne-changelog": [
    {"version": "1.14", "kind": "added",
     "fields": ["intel.severity_feeds", "intel.warnings",
                "intel.feeds[].severity_contributing"],
     "note": "feed freshness SLA warnings for severity-contributing feeds"}
  ],
  "x-arachne-deprecations": []
}
```

When a field is deprecated, its record is added to `x-arachne-deprecations` in that revision
and every later one, until it is removed:

```json
{"field": "ScopeMethodology.requested_by",
 "deprecated_in": "1.20",
 "removal_version": "1.22",
 "reason": "replaced by the principal block"}
```

The field name is the dotted path the checker uses: a top-level property by its bare name
(`locale`), a definition's property as `<Definition>.<field>`.

**No field disappears without a record.** A revision that removes a field present two minors
earlier and carries no matching record fails `python -m arachne.tools.report_schema --check`,
which is a CI gate.

## 3. Migrating an old document

`src/arachne/report/migrate.py` converts a saved report forward without re-running the scan:

```python
from arachne.report.migrate import migrate_report

newer = migrate_report(document)  # to the current version
newer = migrate_report(document, target_version="1.12")
```

The conversion is deterministic and forward-only:

* declared defaults are filled for every field the target schema added;
* a revision that *strengthened* a requirement writes the documented placeholder — schema
  `1.12` made a finding's verification record required, so a migrated finding with no record
  is marked `unverified` at level `L0` and its severity is lowered to `info`, exactly as the
  report model does for a newly built one;
* nothing is removed, so a downgrade is refused rather than performed.

Two golden documents pin the behaviour — `tests/report_qa/golden/migrate-1.10-to-1.11.*` and
`tests/report_qa/golden/migrate-1.11-to-1.12.*` — and the test validates the input against the
source schema and the output against the target schema before comparing bytes.

## 4. Adding a revision (the procedure)

1. Add the change to `src/arachne/report/model.py` and bump `REPORT_SCHEMA_VERSION`.
2. Add a `SchemaRevision` to `SCHEMA_HISTORY` in `src/arachne/report/schema_policy.py` (the
   changelog and, if this revision deprecates something, the record).
3. Run `python -m arachne.tools.report_schema` to write the new file, then
   `python -m arachne.tools.report_schema --check` to confirm the whole history still holds.
4. Add a migration step in `src/arachne/report/migrate.py` only when the revision needs more
   than schema defaults (the 1.12 placeholder is the example).
5. Re-bless the report goldens when the rendered output changed, and read the diff: it must
   be additive.
