# Design note: showing what fixes a CVE

Status: **steps 1-3 implemented.** Plan of record for the fix-action feature.
The `Fix` column, the detail-panel section and the "has a known fix" filter
(steps 4-6) remain to build.

## The ask

Admins need the remediation action, not just the finding. Given a CVE, show
what to update to. The motivating example was: *"the CVE for Android 15 RCE is
fixed if you update to Android 16 security patch March"* — surfaced as a column
or a separate page so the fix action is obvious.

Follow-up decision, recorded verbatim: *"I want it to give the Android version
and monthly patch level to rule out 365 days worth of questions."* Both are
required.

## CORRECTION to the first draft of this note

The first draft claimed **55% of Android CVEs carry an exact fix version from
NVD**. That number was real but measured the wrong thing, and the error was
load-bearing — it put the Android bulletin source last in the order of work, as
a granularity nicety.

The 55% was "share of CVEs *matching an Android CPE query* that carry a
`versionEndExcluding` **for any product**". On those CVEs the fix versions
mostly belong to Microsoft Edge, Adobe Flash and Imagination DDK — not to
Android. Re-measured, asking only for `google:android` bounds:

```
Android-matched CVEs sampled        : 1000   (5 pages, spread across the corpus)
  carrying a google:android CPE     : 1000
  ...with an exact Android fix ver  :    9   (1%)
  ...with inclusive bound only      :   26
  ...with no version bound at all   :  965
```

**NVD publishes essentially no Android fix versions: 9 in 1000.** The nine that
exist are scattered and old (CVE-2011-1823 to 2.3.4, CVE-2022-39912 to 13.0).

Consequence: a `Fix` column fed only from NVD would be blank on virtually every
Android row. That is the same class of failure as the empty-vendor bug fixed in
`fe38f08` — the feature would appear shipped while silently excluding the
platform it was requested for. The bulletin source is therefore not optional
and not last; it is the **only** source of Android fix data.

## Feasibility, measured against the live APIs

### NVD version bounds — good for the general fleet, not for Android

`cve.configurations[].nodes[].cpeMatch[]` can carry three bounds:

| Field | Meaning | Usable as a fix version? |
|---|---|---|
| `versionEndExcluding` | versions **below** this are vulnerable | **Yes** — this value *is* the fix |
| `versionEndIncluding` | versions **up to and including** this are vulnerable | Partially — the fix is "later than X", exact version unstated |
| `versionStartIncluding` | lower bound of the affected range | No, but needed to state the range accurately |

Measured over the last 30 days of modifications:

```
RECENT ALL CVEs   n=200 of 19,386 modified
  exact fix version : 115  (57%)
  inclusive only    :  25
  no bound          :  60
```

Real examples:

```
CVE-2013-0074   microsoft:silverlight        fixed in 5.1.20125.0
CVE-2015-3246   libuser_project:libuser      fixed in 0.56.13-8
CVE-2017-0144   siemens:acuson_sc2000_fw     fixed in 4.0e
CVE-2026-21733  imaginationtech:ddk          fixed in 25.3
```

So **~57% of CVEs generally** can be given an exact "fixed in" version from
data already fetched. That covers the Windows / Linux / networking fleet well
and is worth shipping on its own. Coverage is much worse on the 2009-2012
backfill (23% on the oldest Android-matched page), because the practice of
publishing bounds improved over time.

### Android Security Bulletins — the only Android source

No structured "security patch level" field exists anywhere in NVD or MITRE.
Deriving it from reference URLs was tested and rejected: across a 300-CVE
Android sample, **0 had a bulletin reference URL**. CVE-2024-56193 was an
outlier.

Google's bulletins are HTML with no JSON feed, so this means a scraper. Probed
live, they are far more tractable than that suggests:

```
GET https://source.android.com/docs/security/bulletin
  HTTP 200, 277 KB, 125 month links, 2015-08-01 .. 2025-12-01

GET https://source.android.com/docs/security/bulletin/2025-12-01
  HTTP 200, 304 KB, 13 tables, 106 distinct CVE ids, 103 CVE rows
  row0: ["CVE-2025-22420","A-337775777","EoP","High","13, 14, 15, 16"]
```

125 months x ~40-100 CVEs is roughly **8,000-12,000 CVE-to-patch-level
mappings** — a decade of Android remediation data, none of which NVD has.

The versions come from the row and the patch level from the page's own prose
(**not** from the URL — see finding 1 below, which corrects what this note
originally said). Together they answer the ask exactly:

> CVE-2025-22420 — fixed in Android 13, 14, 15, 16 at security patch level
> 2025-12-05

#### Parse by header, never by column position

Table shape varies across the decade, so positional parsing would silently
mis-assign fields. Measured:

```
2015-08-01  CVE | Bug(s) with AOSP links | Severity | Affected versions      (4 cols)
2018-06-01  CVE | References | Type | Severity | Updated AOSP versions       (5 cols)
2021-03-01  CVE | References | Type | Severity | Updated AOSP versions
2023-09-01  CVE | References | Type | Severity | Updated AOSP versions
2025-03-01  CVE | References | Type | Severity | Updated AOSP versions
2025-12-01  CVE | References | Type | Severity | Updated AOSP versions
```

Three findings that dictate the parser's shape:

1. **The header has been stable since 2018** — identical across 2018, 2021,
   2023 and both 2025 samples. Seven years of stability is a good sign for a
   scraper.
2. **Not every table carries versions.** Each bulletin also contains tables
   headed `... | Severity | Subcomponent` (Qualcomm and other vendor
   components) and, new in 2025-12, `References | Android Launch Version |
   Kernel Launch Version | Minimum Update Version`. Only tables whose header
   has an *AOSP versions* / *Affected versions* column carry the data we want;
   the rest must be skipped, not parsed positionally.
3. **2015 is the outlier**: a 4-column header with no `Type`, and version
   values expressed as ranges (`5.1 and below`) rather than lists. Either
   handle it or declare 2018 the floor — 2018 is defensible, since no fleet
   runs Android 5.

Fragility is the real cost. Guards required:

- Select tables and columns **by header text**, so a new or reordered column
  cannot corrupt existing fields.
- Pin a saved real bulletin page as a test fixture.
- ~~Treat HTTP 200 with zero CVE rows as a layout change.~~ **Wrong as
  written** — two real bulletins list no CVEs at all. Corrected in finding 4.
- ~~Bulletins never change once published, so fetch only unseen months.~~
  **Wrong** — they are revised after publication. Corrected in finding 3.

### CISA KEV — remediation deadline, not a version

KEV carries four fields not currently ingested: `requiredAction`, `dueDate`,
`knownRansomwareCampaignUse`, `notes`.

`requiredAction` is mostly boilerplate — across all 1,695 entries:

```
893x  "Apply updates per vendor instructions."
325x  "Apply mitigations per vendor instructions, follow applicable..."
264x  "Apply mitigations per vendor instructions or discontinue use..."
```

Not a fix version. But `dueDate` and `knownRansomwareCampaignUse` are genuinely
valuable for prioritising *which* fix to apply first, and `notes` often carries
a vendor advisory URL. Worth ingesting regardless of this feature.

## What to build

### Data model

One CVE can affect many products, each with its own affected range and fix
version, so this does not fit a single column.

**Chosen: a `remediations` JSONB column on `vulnerabilities`.**

```json
[
  { "source": "NVD",
    "vendor": "microsoft", "product": "edge",
    "affected_from": null, "affected_to": "93.0.961.38",
    "bound": "exclusive", "fixed_in": "93.0.961.38", "patch_level": null },

  { "source": "Android Bulletin",
    "vendor": "google", "product": "android",
    "fixed_in": "13, 14, 15, 16", "patch_level": "2025-12-01" }
]
```

Rejected the alternative of a `remediations` child table: it would add a join
to the list query, which currently does one table scan per page and already
returns everything the detail panel needs. The chosen shape matches the
existing `source_labels` pattern (jsonb plus a GIN index).

`patch_level` is a **general nullable field** on every entry rather than an
Android-specific column — it generalises to any vendor publishing dated patch
levels (Microsoft's Patch Tuesday, Oracle's quarterly CPUs), and costs nothing
when null.

Add a maintained `has_fix BOOLEAN` so the "what can I action today" filter is
an indexed boolean rather than a jsonb probe.

Also from KEV: `kev_due_date DATE`, `kev_ransomware BOOLEAN`,
`kev_required_action TEXT`.

### Merge semantics

`remediations` is a union keyed on `(source, vendor, product, patch_level)`,
appended in `deduplication.js` alongside the existing reference and CWE unions.
It must NOT be last-writer-wins: the NVD entry and the bulletin entry for one
CVE arrive on different fetch cycles, so a plain overwrite would make each
source erase the other's remediation on every poll.

It also has to be added to `CONFLICT_TARGETS` in `repository.js` so the
conditional-upsert change test covers it — a column absent from that list is
never written on conflict.

### Parsing

Extend `server/src/lib/cpe.js`, already covered by `server/tests/cpe.test.js`.
It currently discards the `version*` fields on each `cpeMatch`; keep them and
emit one remediation per distinct (vendor, product, range).

Note that `describeFromCpe` reaches the CPE list through
`collectCpeCriteria`, which returns only the `criteria` **string** from each
`cpeMatch` and so drops the sibling version fields. That helper must either
return the whole match object or gain a parallel one; its current signature is
asserted by tests and must not silently change meaning.

Deduplicate aggressively. A CVE with 163 CPE entries produces many
near-identical ranges; the panel needs a handful, not 163.

### UI

A separate page is not needed — the expandable detail row added in `2566e2f`
is the natural home.

- **A `Fix` column** showing the primary fix, distinguishing three states
  honestly, because ~40% of rows will have no fix data:
  - `15.0` or `2025-12-01` — a known fix
  - `> 1.5` — only an inclusive upper bound published
  - `—` with a tooltip "no fix version published" — genuinely absent, not
    merely unloaded
- **A Remediation section in the detail panel** listing every
  (product, affected range, fixed in, patch level) tuple, plus the KEV due date
  and ransomware flag.
- **A "has a known fix" filter** — the query an admin actually wants.

## What the bulletin implementation actually found

Steps 1-3 are built. Parsing all 91 supported bulletins broke four assumptions
in the plan above, each of which had looked safe against a smaller sample.
Recording them because they are the reason the parser is shaped as it is.

**1. The patch level is not derivable from the URL, and not always `-05`.**
The plan said the patch level "comes from the URL". It does not: bulletins are
published at slug `YYYY-MM-01` but state their remediation level in prose.
Across 91 months: 87 state `-05`, one states `-01` (2025-11), and three state
`-06` (2019-10, 2021-11, 2023-10). Using the slug would tell an admin sitting
on `2025-12-01` they were covered by the December bulletin when they are not.
The value has to be read and can only be validated to the month.

**2. The wording varies.** 2019-06 says "or higher" where every neighbouring
month says "or later". One bulletin in 91.

**3. Bulletins are not immutable.** The note claimed they "never change once
published". Six of eight sampled carried an `Updated` date, and the December
2025 bulletin was still being revised in March 2026. So "fetch only unseen
months" would freeze stale data; the fetcher stores a revision marker and
re-checks the three newest months every cycle.

**4. A bulletin can legitimately contain zero CVEs.** 2025-07 and 2025-10 list
none. July says so outright: *"There are no Android security patches in the
July 2025 Android Security Bulletin."* The plan's guard -- treat HTTP 200 with
no CVEs as a layout change -- turned that real month into a hard failure. The
guard now discriminates on whether CVE ids appear anywhere in the document: if
none do, zero is the honest answer; if they do but no table parses, the layout
changed. The same discriminator applies to the versions column.

Coverage achieved, measured over all 91 months:

```
months parsed            91/91
CVEs with a patch level  3,728
...also with AOSP versions  1,480  (40%)
bulletins with no CVEs        2
```

The other 60% come from the vendor-component tables (Qualcomm, MediaTek and
others), which state a patch level but no AOSP version. Those are real fixes
and are kept -- discarding them would throw away more than half of every
bulletin. They are not attributed to `google:android`, since they are not
Google's components.

## Order of work

Revised from the first draft: the bulletin source moves from last to second,
because the correction above shows it is the only source that serves the
motivating request.

1. ~~**KEV fields**~~ **DONE.** `dueDate`, `knownRansomwareCampaignUse` (as a
   nullable tri-state, since CISA says 'Known'/'Unknown' and never asserts the
   negative) and `requiredAction`. Also extracts the vendor advisory URL from
   `notes`, present on 906 of 1,695 entries.
2. ~~**The `remediations` column, migration and merge semantics.**~~ **DONE.**
   jsonb, unioned on `(source, vendor, product, patch_level)`, with `has_fix`
   denormalised and partially indexed.
3. ~~**The Android bulletin source.**~~ **DONE.** Index fetch to enumerate
   months, per-month fetch with a revision re-check, header-driven table
   parsing, guarded and fixture-tested. See the findings section above for the
   four assumptions this broke.
4. **NVD version bounds** — keep `version*` in `lib/cpe.js` and emit
   remediation entries from the CPE list.
5. **The `Fix` column and the detail-panel Remediation section.**
6. **The "has a known fix" filter** plus `has_fix` and its index.

## Open decisions

- ~~Is "update to Android 15.0" useful enough?~~ **Answered: both the version
  and the monthly patch level.**
- ~~Where does the patch level live in the schema?~~ **Answered: a general
  nullable `patch_level` on every remediation entry.**
- **How far back should bulletins be ingested?** All 125 months (2015+) is
  ~8-12k mappings and a one-time backfill, but pre-2018 needs the outlier
  parser. Proposal: floor at 2018-06, revisit if anyone runs Android 5.
- **How should a CVE with many affected products present in one column?**
  Primary-plus-count ("15.0 +3 more") is the obvious answer, but it inherits
  the "which product is primary" ambiguity documented in `lib/cpe.js`. For
  Android rows the bulletin entry should win the column regardless of CPE
  frequency — the measured reason being that the frequency heuristic picks
  Adobe or Microsoft on Android-matched CVEs.
- **Should rows with no known fix be visually distinct?** With ~40% lacking
  data, a blank column may read as a bug rather than an absence.
