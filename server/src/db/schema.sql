-- Patchpoint Database Schema
-- Idempotent: safe to re-run on every boot.
--
-- NOTE: the CVE reference list is stored in `reference_urls`, NOT `references`.
-- `references` is a reserved keyword in PostgreSQL and cannot be used as an
-- unquoted column name.

-- pg_trgm backs the substring search indexes below. Creating an extension
-- needs elevated rights, so a deployment whose database role cannot do it
-- degrades to sequential scans rather than failing to boot.
DO $$
BEGIN
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
EXCEPTION WHEN insufficient_privilege OR feature_not_supported THEN
    RAISE NOTICE 'pg_trgm unavailable; substring search will not be index-backed';
END $$;

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    severity TEXT,
    cvss_score NUMERIC(3,1),
    cvss_vector TEXT,
    published_date DATE,
    modified_date DATE,
    -- jsonb, not text. The source filter is a containment test, and jsonb is
    -- the only form of it an index can serve. `reference_urls` and `cwes` stay
    -- text because nothing filters on them.
    source_labels JSONB DEFAULT '[]'::jsonb,
    vendor TEXT,
    product TEXT,
    tech_type TEXT,
    kev_flag BOOLEAN DEFAULT FALSE,
    kev_date_added DATE,
    -- CISA's remediation deadline for federal agencies. Useful as a
    -- prioritisation signal for everyone else.
    kev_due_date DATE,
    -- Tri-state, deliberately nullable. CISA publishes the string 'Known' or
    -- 'Unknown' (measured: 354 Known, 1341 Unknown of 1695). TRUE means CISA
    -- has observed ransomware use; NULL means CISA does not know. Mapping
    -- 'Unknown' to FALSE would assert "not used in ransomware", which is a
    -- claim the feed never makes.
    kev_ransomware BOOLEAN,
    kev_required_action TEXT,
    reference_urls TEXT DEFAULT '[]',
    cwes TEXT DEFAULT '[]',
    -- What to upgrade to, per affected product. jsonb because entries are
    -- unioned from several sources and the "has a known fix" filter needs a
    -- containment test an index can serve.
    --
    -- Shape: [{ source, vendor, product, affected_from, affected_to, bound,
    --           fixed_in, patch_level }]
    --
    -- `patch_level` is general rather than Android-specific: any vendor that
    -- publishes dated patch levels (Patch Tuesday, Oracle CPUs) fits the same
    -- field, and it costs nothing when null.
    remediations JSONB DEFAULT '[]'::jsonb,
    -- Denormalised from `remediations` so the filter is an indexed boolean
    -- rather than a jsonb probe on every row. Maintained by the upsert.
    has_fix BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Equality / range filters.
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
-- Ordered access to vendor: the DISTINCT list behind the vendor filter, and
-- `sortBy=vendor`. The trigram index below cannot do either.
CREATE INDEX IF NOT EXISTS idx_vuln_vendor ON vulnerabilities(vendor);
CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(kev_flag);
CREATE INDEX IF NOT EXISTS idx_vuln_tech_type ON vulnerabilities(tech_type);
CREATE INDEX IF NOT EXISTS idx_vuln_updated ON vulnerabilities(updated_at);

-- Sort support. These match the ORDER BY the list query actually emits,
-- including the NULLS placement and the cve_id tiebreak — a single-column
-- index on published_date could not satisfy either, so every page paid for a
-- sort node.
--
-- Only the DESC direction is indexed. A backward scan of a `DESC NULLS LAST`
-- index yields `ASC NULLS FIRST`, which is not what the ASC query asks for, so
-- covering both directions would mean two indexes per sortable column. On a
-- table written in 400-row upserts up to twelve times per fetch cycle that
-- write cost outweighs the benefit; ascending sorts still sort.
CREATE INDEX IF NOT EXISTS idx_vuln_published_desc
    ON vulnerabilities(published_date DESC NULLS LAST, cve_id DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_cvss_desc
    ON vulnerabilities(cvss_score DESC NULLS LAST, cve_id DESC);

-- Source filtering: `source_labels @> '["NVD"]'`. jsonb_path_ops is smaller
-- and faster than the default jsonb_ops when containment is the only operator
-- used, which it is here.
CREATE INDEX IF NOT EXISTS idx_vuln_sources
    ON vulnerabilities USING GIN (source_labels jsonb_path_ops);

-- Substring search. Every text filter in the UI is a leading-wildcard ILIKE,
-- which no btree index can serve; trigram GIN indexes can. Guarded on the
-- extension actually being present.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
        CREATE INDEX IF NOT EXISTS idx_vuln_vendor_trgm
            ON vulnerabilities USING GIN (vendor gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_vuln_product_trgm
            ON vulnerabilities USING GIN (product gin_trgm_ops);
        CREATE INDEX IF NOT EXISTS idx_vuln_cve_id_trgm
            ON vulnerabilities USING GIN (cve_id gin_trgm_ops);
        -- The description index is the largest and the costliest to maintain,
        -- but description is also the field that makes search worth having.
        CREATE INDEX IF NOT EXISTS idx_vuln_description_trgm
            ON vulnerabilities USING GIN (description gin_trgm_ops);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS sources (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT,
    last_fetched TIMESTAMP,
    total_fetched INTEGER DEFAULT 0,
    confidence_level TEXT DEFAULT 'high'
);

CREATE TABLE IF NOT EXISTS watchlist (
    id SERIAL PRIMARY KEY,
    item TEXT NOT NULL,
    item_type TEXT NOT NULL CHECK(item_type IN ('cve_id', 'vendor', 'product')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(item, item_type)
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    cve_id TEXT,
    match_type TEXT,
    match_value TEXT,
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- One alert per (CVE, watchlist match) pair, so a repeated poll cannot
    -- re-raise an alert the user has already seen.
    UNIQUE (cve_id, match_type, match_value)
);

CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

-- Constraints added after the initial release. ALTER TABLE has no
-- IF NOT EXISTS for constraints, so guard on pg_constraint.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sources_name_key') THEN
        ALTER TABLE sources ADD CONSTRAINT sources_name_key UNIQUE (name);
    END IF;

    -- One alert per (CVE, watchlist match) pair, so a repeated poll cannot
    -- re-raise an alert the user has already seen.
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'alerts_match_key') THEN
        ALTER TABLE alerts ADD CONSTRAINT alerts_match_key UNIQUE (cve_id, match_type, match_value);
    END IF;
END $$;

-- Migrate an existing text source_labels column to jsonb.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'vulnerabilities'
          AND column_name = 'source_labels'
          AND data_type <> 'jsonb'
    ) THEN
        -- A single unparseable row would abort the cast, so neutralise those
        -- first. `IS NOT JSON` requires PostgreSQL 16, which is what the
        -- compose file pins.
        UPDATE vulnerabilities SET source_labels = '[]'
        WHERE source_labels IS NULL OR source_labels IS NOT JSON;

        ALTER TABLE vulnerabilities
            ALTER COLUMN source_labels TYPE JSONB USING source_labels::jsonb,
            ALTER COLUMN source_labels SET DEFAULT '[]'::jsonb;

        RAISE NOTICE 'source_labels migrated to jsonb';
    END IF;
END $$;

-- Columns added for the fix-action feature. `CREATE TABLE IF NOT EXISTS` is a
-- no-op against an existing table, so a deployment that already holds data
-- would never receive these without an explicit ALTER. `ADD COLUMN IF NOT
-- EXISTS` is idempotent and, for a nullable column with no default rewrite,
-- takes only a brief ACCESS EXCLUSIVE lock rather than rewriting the table.
ALTER TABLE vulnerabilities
    ADD COLUMN IF NOT EXISTS kev_due_date DATE,
    ADD COLUMN IF NOT EXISTS kev_ransomware BOOLEAN,
    ADD COLUMN IF NOT EXISTS kev_required_action TEXT,
    ADD COLUMN IF NOT EXISTS remediations JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS has_fix BOOLEAN DEFAULT FALSE;

-- Prioritisation: "what is overdue" and "what is exploited by ransomware".
CREATE INDEX IF NOT EXISTS idx_vuln_kev_due ON vulnerabilities(kev_due_date);

-- The "has a known fix" filter. Partial, because the query is only ever
-- `has_fix = TRUE` -- indexing the false rows would roughly double the index
-- for an access path nothing asks for.
CREATE INDEX IF NOT EXISTS idx_vuln_has_fix
    ON vulnerabilities(has_fix) WHERE has_fix;

-- Containment queries against remediation entries, e.g. locating every CVE
-- fixed at a given Android patch level. jsonb_path_ops for the same reason as
-- source_labels: containment is the only operator used.
CREATE INDEX IF NOT EXISTS idx_vuln_remediations
    ON vulnerabilities USING GIN (remediations jsonb_path_ops);

-- Indexes superseded by the composite sort indexes above. Dropping them
-- removes write cost without losing any access path: a range or equality test
-- on published_date or cvss_score is served by the leading column of the
-- corresponding composite.
DROP INDEX IF EXISTS idx_vuln_published;
DROP INDEX IF EXISTS idx_vuln_cvss;
-- NOTE: idx_vuln_vendor is deliberately NOT dropped. A trigram GIN index
-- serves `ILIKE '%x%'` but is an unordered inverted index: it cannot produce
-- sorted output, so it does nothing for `sortBy=vendor` or for the
-- `SELECT DISTINCT vendor ... ORDER BY vendor` that /api/filter-options runs on
-- every page load. The btree and the GIN index are complementary, not
-- redundant.
