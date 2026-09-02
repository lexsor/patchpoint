# Patchpoint — Vulnerability Dashboard

A self-hosted security monitoring dashboard that consolidates CVE vulnerability data from multiple government sources into a single, searchable, filterable interface.

## Overview

Patchpoint (patch/vulnerability + point/one-stop) aggregates vulnerabilities from:

- **CISA KEV** (Known Exploited Vulnerabilities Catalog) — CSV feed, with the JSON feed as a fallback
- **NIST NVD** (National Vulnerability Database) — API v2.0, polled over a rolling modification window
- **MITRE CVE Services** — per-CVE enrichment (MITRE has no bulk listing endpoint, so each cycle enriches a bounded batch of CVEs discovered by the other two sources)

All data is deduplicated by CVE ID, merged into unified records with source labels, and stored in PostgreSQL for querying and filtering.

## Features

- **Multi-source data aggregation** — Fetches from CISA KEV and NVD, then enriches records via MITRE CVE Services
- **Deduplication** — Same CVE from multiple sources merges into one record with source labels
- **Sortable & filterable table** — Sort by CVE ID, severity, CVSS, date, vendor, tech type; filter by severity, source, date range, vendor, technology, and KEV flag
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
# Start all services (PostgreSQL + Backend + Frontend)
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
| `POSTGRES_PASSWORD` | `vuln_password` | Database password |
| `PORT` | `3001` | Backend port |
| `CLIENT_PORT` | `3000` | Frontend port |
| `POSTGRES_PORT` | `5433` | Host port for the database (5433 avoids clashing with a local PostgreSQL) |
| `NVD_API_KEY` | (empty) | Optional NVD API key. Without one NVD allows 5 requests/30s; with one, 50 |
| `NVD_LOOKBACK_DAYS` | `30` | How far back each NVD poll looks for modified CVEs (NVD caps this at 120) |
| `NVD_MAX_PAGES` | `5` | Page cap per NVD poll, 2000 records per page |
| `MITRE_ENRICH_LIMIT` | `25` | CVEs enriched via MITRE per cycle |
| `POLL_INTERVAL_HOURS` | `6` | Automatic fetch interval |

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
7. **Sorting:** Click the CVSS header twice — the arrow flips and the order actually reverses
8. **Count endpoint:** `curl http://localhost:3001/api/vulnerabilities/count` — returns a count, not a 404
9. **Watchlist:** Add a vendor watchlist entry, trigger a fetch, verify an alert appears; trigger a second fetch and verify it is **not** duplicated

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

## Non-Goals

- Real-time WebSocket updates (polling is sufficient)
- Integration with SIEM/SOAR tools
- Custom vulnerability scoring or ML-based prioritization
- Multi-tenant user management / authentication
- Export to PDF/CSV

## License

MIT
