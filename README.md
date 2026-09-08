# Patchpoint — Vulnerability Dashboard

A self-hosted security monitoring dashboard that consolidates CVE vulnerability data from multiple government sources into a single, searchable, filterable interface.

## Overview

Patchpoint (patch/vulnerability + point/one-stop) aggregates vulnerabilities from:

- **CISA KEV** (Known Exploited Vulnerabilities Catalog) — CSV feed, with the JSON feed as a fallback
- **NIST NVD** (National Vulnerability Database) — API v2.0, in two sweeps: a `hasKev` pass that scores the whole CISA KEV catalogue, then a rolling modification window
- **MITRE CVE Services** — per-CVE enrichment (MITRE has no bulk listing endpoint, so each cycle enriches a bounded batch of CVEs discovered by the other two sources)

All data is deduplicated by CVE ID, merged into unified records with source labels, and stored in PostgreSQL for querying and filtering.

## Features

- **Multi-source data aggregation** — Fetches from CISA KEV and NVD, then enriches records via MITRE CVE Services
- **Deduplication** — Same CVE from multiple sources merges into one record with source labels
- **Sortable & filterable table** — Sort by CVE ID, severity, CVSS, date, vendor, tech type; filter by severity, source, date range, vendor, technology, and KEV flag
- **Expandable rows** — Click any row (or its ▸ control) for the full description, CVSS vector, product, modified and KEV-added dates, CWE links, and reference links. Several rows can be open at once, and no extra request is made — the list response already carries every field
- **Search** — Case-insensitive substring match across CVE ID, description, vendor, and product
- **Alerting system** — Watchlist for CVE IDs, vendors, and products triggers alerts on new matches
- **Configurable polling** — Automatic fetch every 6 hours (configurable via `POLL_INTERVAL_HOURS`) + manual refresh button
- **Containerized** — Docker Compose stack with PostgreSQL, backend, and nginx-frontend

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React + Vite |
| Backend | Node.js + Express |
| Database | PostgreSQL |
| Containerization | Docker + Docker Compose |

## Quick Start

### Prerequisites

- Docker and Docker Compose installed
- No external API keys required (NVD rate-limited but works without key)

### Run the Stack

```bash
# 1. Set a database password. This is required -- the stack will not start
#    without it, by design.
cp .env.example .env
#    then edit .env and change POSTGRES_PASSWORD

# 2. Start all services (PostgreSQL + Backend + Frontend)
docker compose up

# Or run in detached mode
docker compose up -d
```

The stack will be available at:
- **Dashboard UI:** http://localhost:3000
- **API:** http://localhost:3001

### Configuration

Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTGRES_DB` | `vuln_dashboard` | Database name |
| `POSTGRES_USER` | `vuln_user` | Database user |
| `POSTGRES_PASSWORD` | **required** | Database password. No default — `docker compose up` fails without it |
| `PORT` | `3001` | Backend port |
| `CLIENT_PORT` | `3000` | Frontend port |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated origins allowed to call the API cross-origin |
| `NVD_API_KEY` | (empty) | Optional NVD API key. Without one NVD allows 5 requests/30s; with one, 50 |
| `NVD_LOOKBACK_DAYS` | `30` | How far back each NVD poll looks for modified CVEs (NVD caps this at 120) |
| `NVD_MAX_PAGES` | `5` | Page cap per NVD poll, 2000 records per page |
| `MITRE_ENRICH_LIMIT` | `25` | CVEs enriched via MITRE per cycle |
| `NVD_PLATFORMS` | android, windows 10/11/server 2022, linux kernel, cisco ios | Comma-separated CPE match strings swept in full, so your platforms are covered regardless of the rolling window. Empty disables |
| `NVD_PLATFORM_MAX_PAGES` | `12` | Page cap per platform sweep (2000 records a page) |
| `POLL_INTERVAL_HOURS` | `6` | Automatic fetch interval |

### Severity

CISA KEV publishes no CVSS score, so it asserts no severity — `kev_flag` is what
records exploitation. Severities come from NVD and MITRE, and the KEV sweep runs
every cycle so KEV records are scored rather than left blank. The severity filter
offers the full CVSS vocabulary (CRITICAL / HIGH / MEDIUM / LOW) regardless of
what has been ingested; vendor and technology options are data-derived.

### Platform coverage

The rolling NVD window is a delta feed: it reports what changed recently, not
what exists. Measured against the live API, 9,384 CVEs affect
`cpe:2.3:o:google:android` but only about 97 were modified in the last 30 days
— so a dashboard for a fleet that includes Android devices showed almost none
of them.

`NVD_PLATFORMS` fixes that by sweeping each listed platform in full. The
default list covers Android, Windows 10/11, Windows Server 2022, the Linux
kernel and Cisco IOS. Add your own with CPE names from
[the NVD CPE search](https://nvd.nist.gov/products/cpe/search); adding a
platform costs roughly `ceil(cve_count / 2000)` requests per cycle, paced at
6.5s without an API key and 0.8s with one.

Attribution comes from the CPE list too. NVD publishes no vendor or product
field, so records used to be stored with all three of vendor, product and
technology empty — invisible to every filter and findable only by a
description search. They are now derived from
`cve.configurations[].nodes[].cpeMatch[].criteria`.

Two details worth knowing about how that is derived:

- **Vendor and product are a best guess.** A CVE can list over a hundred CPE
  entries, so the most frequently referenced vendor/product pair wins. That
  heuristic was picked by measurement — it identified the right subject in 3 of
  4 hand-checked CVEs, against 1 of 4 for weighting operating-system entries
  higher, because CPE enumerates every affected *version* and so counts reflect
  catalogue granularity rather than relevance.
- **Technology is derived from the whole CPE list**, not the primary pair, so a
  CVE affecting both Safari and Android is still findable under `mobile`. That
  makes the Technology filter the reliable way to slice by platform, since it
  does not depend on picking one winner. Note that `networking` is checked
  before `mobile` so Cisco's IOS does not collide with Apple's.

### Network exposure

Only the dashboard (`3000`) is published on all interfaces — reaching the UI
from another device is intended. The API is bound to `127.0.0.1` because it has
no authentication, and the **database port is not published at all**: only the
backend needs it and it connects over the compose network. For an interactive
session use `docker compose exec db psql -U vuln_user -d vuln_dashboard`.

Note that Docker publishes ports through its own NAT/forward chains, so a host
firewall that denies inbound traffic does **not** block a published port. That
is why the bindings above matter rather than relying on the firewall.
### Performance notes

- **Compression.** nginx gzips static assets and proxied API responses; the
  server also compresses directly, which covers the API port and the Vite dev
  proxy. A list page goes from ~38 KB to ~5.6 KB, the JS bundle from ~205 KB to
  ~69 KB.
- **Caching.** `/assets/` is content-hashed by Vite, so it is served
  `immutable, max-age=1y`. `index.html` is `no-cache` — its URL is stable while
  its contents change, so it must always revalidate.
- **One scan per page, not two.** The list query carries its own filtered total
  via `COUNT(*) OVER()`. PostgreSQL keeps no cached row count, so the previous
  separate `SELECT COUNT(*)` meant every page view scanned twice.
- **Indexes match the queries.** Composite indexes mirror the emitted
  `ORDER BY` including NULLS placement; trigram GIN indexes back the
  leading-wildcard `ILIKE` search that no btree could serve; a
  `jsonb_path_ops` GIN index backs source filtering.
- **Ascending sorts still sort.** Only the DESC direction is indexed — a
  backward scan of a `DESC NULLS LAST` index yields `ASC NULLS FIRST`, so
  covering both would need two indexes per sortable column, and the write cost
  on a bulk-upserted table outweighs it.
- **Smaller client.** The API client uses the platform `fetch` instead of
  axios, which was the largest non-React dependency: the bundle went from
  204.9 KB to 155.0 KB raw, 68.6 KB to 50.0 KB gzipped (27% off the wire).
- **Filter options are cached.** The vendor and technology dropdown lists are
  `SELECT DISTINCT` over the whole table and were re-run on every page load.
  They are cached in process, invalidated when a fetch cycle stores records
  (the only thing that can change them), with a 5-minute TTL as a backstop.
- **The table is not remounted on every interaction.** It used to be replaced
  by a spinner on each sort, filter and page change, tearing down and
  rebuilding every row and losing scroll position. It now stays mounted and is
  marked `aria-busy` while a reload is in flight; the full-page spinner is
  reserved for the first load, when there is nothing to keep.
- **Unchanged rows are not rewritten.** The upsert carries a
  `WHERE ... IS DISTINCT FROM ...` guard, so a poll of upstream data that has
  not changed writes nothing. Before this, every cycle rewrote every row it
  touched — 1,695 for CISA, up to 10,000 for NVD — each one a new row version,
  WAL, an update to all nine indexes (four of them trigram GIN) and a dead
  tuple for vacuum.
- **Alerts are inserted in batches.** The alert engine matched in JS and then
  issued one INSERT per match: 3,390 round trips for 1,695 vulnerabilities
  against a two-item watchlist. It now batches 500 rows per statement — 9
  statements instead of 3,392, for the same result. Matching stays in JS so
  `matchWatchlistItem` remains the single tested definition of a match.
- **`pg_trgm` is optional.** Creating the extension needs elevated rights; if
  the database role cannot, the schema logs a notice and search falls back to
  sequential scans rather than failing to boot.

### Known limitation: deep pagination

Paging uses `LIMIT/OFFSET`, so PostgreSQL fetches and discards every row
before the offset — page 500 discards 12,475 rows. Keyset pagination would fix
it, but the sort is user-selectable across seven columns with `NULLS LAST`
handling, so a correct keyset predicate would need per-column NULL-aware
comparisons, and the UI navigates strictly with Prev/Next anyway. Given that
filters and search are how you actually locate a CVE, this was left as-is
rather than absorbing that complexity. Narrow with a filter instead of paging
into the tens of thousands.

### API change

`source_labels` is now `jsonb` rather than a JSON string, so
`GET /api/vulnerabilities` returns it as a real array:

```diff
- "source_labels": "[\"CISA KEV\",\"NVD\"]"
+ "source_labels": ["CISA KEV", "NVD"]
```

The bundled client handles both shapes. Existing databases are migrated in
place on boot.

### Theme

Dark by default, with a light theme behind the toggle in the header. The
choice persists in `localStorage` and is applied before first paint, so there
is no flash on reload. The OS `prefers-color-scheme` is deliberately not
consulted — dark is the product default, not a mirror of the desktop — and no
preference is recorded until you actually pick one.

Both palettes are CSS custom properties in
[`client/src/styles.css`](client/src/styles.css): the tokens on bare `:root`
are dark, and `:root[data-theme="light"]` redefines the same names. Rules only
ever reference tokens, never literal colours. Every text and badge pair in both
themes clears WCAG AA contrast (lowest 4.76:1 light, 5.98:1 dark).

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌───────────┐
│   Nginx     │────▶│   Express    │────▶│ PostgreSQL│
│ (Frontend)  │     │   (API)      │     │  (Storage)│
└─────────────┘     └──────┬───────┘     └───────────┘
                           │
            ┌──────────────┼──────────────┐
            ▼              ▼              ▼
       ┌──────────┐  ┌──────────┐  ┌──────────────┐
       │  CISA    │  │   NVD    │  │    MITRE     │
       │   KEV    │  │  API v2  │  │ CVE Services │
       │ CSV/JSON │  │ (window) │  │  (per-CVE)   │
       └──────────┘  └──────────┘  └──────────────┘
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/vulnerabilities` | List vulnerabilities with filters |
| `GET` | `/api/vulnerabilities/:cveId` | Get single vulnerability |
| `GET` | `/api/vulnerabilities/count` | Total vulnerability count |
| `POST` | `/api/fetch` | Trigger manual data fetch |
| `GET` | `/api/fetch/status` | Fetch status |
| `GET` | `/api/sources` | List data sources |
| `GET` | `/api/filter-options` | Get available filter values |
| `GET` | `/api/alerts` | Get alerts |
| `DELETE` | `/api/alerts` | Delete all alerts |
| `GET` | `/api/watchlist` | Get watchlist items |
| `POST` | `/api/watchlist` | Add watchlist item |
| `DELETE` | `/api/watchlist/:id` | Remove watchlist item |

### Query Parameters for `/api/vulnerabilities`

| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1; non-numeric, zero and negative values fall back to 1) |
| `perPage` | int | Items per page (default: 25, maximum 200) |
| `sortBy` | string | Sort column: cve_id, severity, cvss_score, published_date, modified_date, vendor, tech_type. Anything else falls back to published_date |
| `sortOrder` | string | ASC or DESC (default: DESC) |
| `source` | string | Filter by source label |
| `severity` | string | Filter by severity: CRITICAL, HIGH, MEDIUM, LOW |
| `startDate` | string | Filter by start date (YYYY-MM-DD) |
| `endDate` | string | Filter by end date (YYYY-MM-DD) |
| `vendor` | string | Filter by vendor name |
| `techType` | string | Filter by technology type |
| `kevFlag` | string | Filter by KEV flag: true or false |
| `search` | string | Case-insensitive substring match across CVE ID, description, vendor, product |

## How to Verify

1. **Stack starts:** `docker compose up` — verify no errors in logs
2. **UI accessible:** Browse to `http://localhost:3000`
3. **Data from multiple sources:** After first fetch, verify vulnerabilities appear (CISA KEV and NVD)
4. **Refresh button:** Click "Refresh Data" — new data appears in the table
5. **Filters:** Filter by severity (CRITICAL), source (CISA KEV), vendor
6. **Search:** Search for a CVE ID you can see in the table — should narrow to that record
7. **Severity filter:** The dropdown lists all four levels, and each returns rows
8. **Sorting:** Click the CVSS header twice — the arrow flips and the order actually reverses
9. **Count endpoint:** `curl http://localhost:3001/api/vulnerabilities/count` — returns a count, not a 404
10. **Watchlist:** Add a vendor watchlist entry, trigger a fetch, verify an alert appears; trigger a second fetch and verify it is **not** duplicated

## Project Structure

```
patchpoint/
├── server/                 # Backend API
│   ├── src/
│   │   ├── db/            # Database schema, client, migrations
│   │   ├── fetchers/      # Data source fetchers (CISA, NVD, MITRE)
│   │   ├── lib/           # Shared HTTP client, severity classification
│   │   ├── models/        # Repository, deduplication, alert engine, orchestrator
│   │   ├── routes/        # Express API routes
│   │   └── services/      # Polling scheduler
│   └── tests/             # Unit and integration tests
├── client/                # React + Vite frontend
│   └── src/
│       ├── components/    # React components
│       └── api.js         # API client
├── Dockerfile             # Backend Dockerfile (multi-stage)
├── Dockerfile.client      # Frontend Dockerfile (nginx)
├── docker-compose.yml     # Full stack orchestration
├── nginx.conf             # Nginx reverse proxy config
└── .env.example           # Environment variables template
```

## Tests

The suite is hermetic — no network and no database required. Upstream HTTP is
mocked and the repository runs against a recording fake, so `npm test` works
offline and in CI.

```bash
cd server && npm install && npm test
```

```bash
cd server && npm test -- --testPathPattern=repository
```

| Suite | Covers |
|-------|--------|
| `deduplication.test.js` | Merge precedence, severity classification, CVE ID normalization |
| `fetchers.test.js` | Field mapping for each upstream API, rate-limit retry, error paths |
| `repository.test.js` | Batch-scoped upsert, no-blanking guarantees, SQL parameterization |
| `routes.test.js` | Route ordering, query parameter clamping, fetch/alert endpoints |
| `integration.test.js` | Cross-source merge, watchlist matching, SQL keyword guards |

## Planned

- **Remediation / fix version** — showing what to update to, not just the
  finding. Investigated with measured feasibility in
  [`docs/fix-version-design.md`](docs/fix-version-design.md): about 55-58% of
  CVEs can be given an exact "fixed in" version from NVD data we already
  fetch, but Android *security patch level* granularity would need Google's
  bulletins as a new source.

## Non-Goals

- Real-time WebSocket updates (polling is sufficient)
- Integration with SIEM/SOAR tools
- Custom vulnerability scoring or ML-based prioritization
- Multi-tenant user management / authentication
- Export to PDF/CSV

## License

MIT
