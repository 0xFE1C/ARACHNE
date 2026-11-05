# The research corpus

> **Owner:** Detection group · **Last verified:** 2026-11-05 · **Review interval:** 365 days

| Field | Value |
|---|---|
| Owner | ARACHNE detection engineering |
| Last verified | 2026-11-02 |
| Consumed by | `arachne coverage`, and the `research_ref` on every registered check |

This directory is the **method universe** the detection programme is measured against. Each
chapter file carries a numbered list of techniques (`### N. Title`); `arachne coverage`
parses those headings, greps the `research_ref` values out of `src/arachne/modules`, and
reports which methods have an implementing check and which do not. The generated matrix is
committed at [`coverage_matrix.md`](../../coverage_matrix.md).

**The numbering is the interface.** A `research_ref` (`ch04#7`, `ch01#14-16`) resolves
against these headings and nothing else. Renumbering a method silently re-points every check
that cites it, so a method is retired by marking it not-implemented in prose, never by
deleting its number.

| Chapter | Methods | Mapped | Surface |
|---|---|---|---|
| `ch01` | 30 | 19 | Passive reconnaissance and OSINT (M1) |
| `ch02` | 30 | 28 | Network and service discovery (M2) |
| `ch03` | 35 | 34 | Web application vulnerability testing (M3) |
| `ch04` | 30 | 30 | Exposure and misconfiguration discovery (M4) |
| `ch05` | 25 | 21 | Cloud and supply-chain exposure (M5) |
| `ch06` | 25 | 16 | Correlation, threat detection and adversary emulation (M6) |

The mapping column is generated; run `arachne coverage` for the current figures.

## Provenance (read this before citing a method)

The corpus was reconstructed in WP-01 (see `docs/adr/330-research-corpus-restored.md`).
The checks, their `research_ref` values and the per-chapter method counts are original and
were never lost — they are in the source tree. The **prose** in these files was written from
what the citing checks actually do: each referenced method is named for the technique its
check implements, and each un-referenced method is named for the technique that is
*conspicuously absent* from the tool.

Consequences worth stating plainly:

- A method title is a **description of the check that cites it**, not a quotation from a
  vanished source document. Do not cite this corpus as an external authority.
- Methods with no implementing check are marked "Not implemented" in their prose, with the
  reason. Nine of them are absent because the technique would need a capability ARACHNE
  refuses (remote access, dark-web feeds, cloud control-plane writes); the rest are simply
  not built yet. `ch06#13` is refused on principle.
- The counts (30/30/35/30/25/25) are contractual: `tests/unit/test_coverage.py` asserts them,
  and `tests/unit/test_module_contract.py` asserts every M1 reference resolves.
