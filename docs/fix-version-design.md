# Design note: showing what fixes a CVE

Status: **investigated, not implemented.** Prepared for a future session.

## The ask

Admins need the remediation action, not just the finding. Given a CVE, show
what to update to. The motivating example was: *"the CVE for Android 15 RCE is
fixed if you update to Android 16 security patch March"* — surfaced as a column
or a separate page so the fix action is obvious.

## Feasibility, measured against the live APIs

Everything below was measured, not assumed. Numbers are from September 2026.

### NVD version bounds — the primary usable source

NVD's `cve.configurations[].nodes[].cpeMatch[]` entries can carry version
bounds. Three fields matter:

| Field | Meaning | Usable as a fix version? |
|---|---|---|
| `versionEndExcluding` | versions **below** this are vulnerable | **Yes** — this value *is* the fix |
| `versionEndIncluding` | versions **up to and including** this are vulnerable | Partially — the fix is "later than X", exact version unstated |
| `versionStartIncluding` | lower bound of the affected range | No, but needed to state the range accurately |

Coverage on a 200-CVE sample of recently modified CVEs:

```
with any version bound            140/200   70%
with versionEndExcluding (= fix)  115/200   58%
```

Coverage on a 300-CVE Android sample specifically:

```
versionEndExcluding (exact fix)   166/300   55%
only versionEndIncluding           17/300    6%
no version bound at all           117/300   39%
```

So roughly **55–58% of CVEs can be given an exact "fixed in" version** from
data we already fetch. Real examples pulled from the API:

```
CVE-2025-20979   google:android              fixed in 15.0
CVE-2013-0074    microsoft:silverlight       fixed in 5.1.20125.0
CVE-2015-3246    libuser_project:libuser     fixed in 0.56.13-8
CVE-2017-0144    siemens:acuson_sc2000_fw    fixed in 4.0e
```

Note the older CPE entries skew toward `versionEndIncluding`; only 88 of 1,372
cpeMatch entries on a sample of *old* Android CVEs had any bound at all. The
practice improved over time, so coverage is much better for recent CVEs than
for the 2009–2012 backfill.

### CISA KEV — remediation deadline, not a version

KEV carries four fields we do not currently ingest: `requiredAction`,
`dueDate`, `knownRansomwareCampaignUse`, `notes`.

`requiredAction` is mostly boilerplate — across all 1,695 entries:

```
893x  "Apply updates per vendor instructions."
325x  "Apply mitigations per vendor instructions, follow applicable..."
264x  "Apply mitigations per vendor instructions or discontinue use..."
```

So it is not a fix version. But `dueDate` and `knownRansomwareCampaignUse` are
genuinely valuable for prioritising *which* fix to apply first, and `notes`
often carries a vendor advisory URL. Worth ingesting regardless of this
feature.

### DECISION (recorded): both are required

Asked whether "update to Android 15.0" was sufficient, the answer was: give
**both the Android version and the monthly patch level**, to pre-empt the
follow-up questions. So the bulletin source below is **required**, not
optional, and step 5 in the order of work moves up.

### The Android patch-level granularity — needs a new source

This is the gap between what was asked for and what the current sources can
give.

There is **no structured "security patch level" field** anywhere in NVD or
MITRE. What NVD gives for Android is the release version
(`versionEndExcluding: 15.0` → "update to Android 15"), not the monthly patch
level (`2025-03-01`) that Android admins actually track.

One Android CVE (CVE-2024-56193) did carry a reference URL containing a patch
level — `source.android.com/security/bulletin/pixel/2025-05-01` — which looked
like a way to derive it. **It is not viable**: across a 300-CVE Android sample,
**0 had a bulletin reference**. That example was an outlier, and any parser
built on it would produce almost nothing.

Getting true patch-level granularity requires ingesting Google's Android
Security Bulletins as a fourth source. They are HTML with no official JSON
feed, so this means a scraper — but they are far more structured than that
suggests. Probed live:

```
GET https://source.android.com/docs/security/bulletin/2025-03-01
  HTTP 200, 277 KB, 10 <table> elements, 41 distinct CVE ids

  sample row, tags stripped:
  CVE-2024-43093  A-341680936  EoP  High  12, 12L, 13, 14, 15

GET https://source.android.com/docs/security/bulletin
  HTTP 200 - index page listing every monthly patch level
```

That row carries everything needed: the CVE id, Google's internal bug id, the
vulnerability type, the severity, and **the affected Android versions**. The
patch level itself comes from the URL. So for that example the dashboard could
state, exactly as asked:

> CVE-2024-43093 - affects Android 12, 12L, 13, 14, 15 - fixed in the
> 2025-03-01 security patch level

The index page enumerates the monthly bulletins, so discovery does not need
guessing at URLs. Bulletins are published monthly and never change once out,
so this is cheap to poll and trivially cacheable: fetch the index, fetch only
bulletins not already stored.

Fragility is the real cost, and it is worth being honest about it. This is
scraped HTML on a site Google can restructure without notice, so it needs:
a parser that fails loudly rather than silently returning zero rows; a test
against a saved fixture of a real bulletin page; and an alert when a fetch
yields no CVEs from a page that returned HTTP 200, which is the signature of
a layout change rather than an empty month.

## What to build

### Data model

One CVE can affect many products, each with its own affected range and fix
version, so this does not fit a single column. Two options:

**Option A — a `remediations` JSONB column on `vulnerabilities`.**
```json
[
  { "vendor": "google", "product": "android",
    "affected_from": null, "affected_to": "15.0",
    "bound": "exclusive", "fixed_in": "15.0" }
]
```
Simplest, no join, and matches the existing pattern (`source_labels` is already
jsonb with a GIN index). Filtering "has a known fix" is
`remediations @> '[{"fixed_in": ...}]'`-shaped, or a generated boolean column.

**Option B — a `remediations` child table** keyed on `cve_id`.
Normalised, easier to query per product, but adds a join to the list query,
which currently does one table scan per page. Given the list endpoint already
returns everything the detail panel needs, a join would undo that.

**Recommendation: Option A.** It preserves the single-query list read, and the
consumer is a display panel rather than an analytical query.

Also add, from KEV: `kev_due_date DATE`, `kev_ransomware BOOLEAN`,
`kev_required_action TEXT`.

### Parsing

Extend `server/src/lib/cpe.js`, which already parses the CPE list and is
already covered by `server/tests/cpe.test.js`. It currently discards the
`version*` fields on each `cpeMatch`; the work is to keep them and emit one
remediation entry per distinct (vendor, product, range).

Deduplicate aggressively. A CVE with 163 CPE entries will produce many
near-identical ranges, and the panel needs a handful, not 163.

### UI

The ask mentioned "a column or maybe a separate page". A separate page is not
needed — the expandable detail row added in `2566e2f` is the natural home, and
it already renders per-CVE structure.

- **A `Fix` column** in the table showing the primary fix version, chosen the
  same way the primary vendor is chosen. Must distinguish three states
  honestly, because 39–42% of rows will have no fix data:
  - `15.0` — a known fix version
  - `> 1.5` — only an inclusive upper bound is published
  - `—` with a tooltip "no fix version published" — genuinely absent, not
    merely unloaded
- **A Remediation section in the detail panel** listing every
  (product, affected range, fixed in) tuple, plus the KEV due date and
  ransomware flag when present.
- **A filter** for "has a known fix", which is the query an admin actually
  wants: *what can I action today?*

### Order of work

1. Ingest the KEV fields (`dueDate`, `knownRansomwareCampaignUse`,
   `requiredAction`). Small, self-contained, immediately useful for
   prioritisation, and independent of everything else.
2. Keep the `version*` bounds in `lib/cpe.js` and add the `remediations`
   column plus its migration.
3. The `Fix` column and the detail-panel section.
4. The "has a known fix" filter.
5. The Android Security Bulletin source, for patch levels. **Required** per
   the decision above. Fetch the index to enumerate months, fetch each unseen
   bulletin, parse the tables to `(cve_id, patch_level, affected_versions[])`,
   and store it as another remediation entry alongside the CPE-derived ones.
   Guard it: fail loudly on a 200 that yields no CVEs, and pin a saved
   bulletin page as a test fixture.

## Decisions needed before starting

- ~~Is "update to Android 15.0" useful enough?~~ **Answered: both the version
  and the monthly patch level are wanted.** Step 5 is required.
- **Where does the patch level live in the schema?** It is Android-specific, so
  either a nullable `patch_level` on each remediation entry (general, mostly
  empty) or an Android-only field. The former generalises to any vendor that
  publishes dated patch levels, which is worth having.
- **How should a CVE with many affected products present in one column?**
  Primary-plus-count ("15.0 +3 more") is the obvious answer, but it inherits
  the same "which one is primary" ambiguity already documented in `lib/cpe.js`.
- **Should rows with no known fix be visually distinct?** With ~40% lacking
  data, a blank column may read as a bug rather than as an absence.
