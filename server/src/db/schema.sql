-- Patchpoint Database Schema
-- Idempotent: safe to re-run on every boot.
--
-- NOTE: the CVE reference list is stored in `reference_urls`, NOT `references`.
-- `references` is a reserved keyword in PostgreSQL and cannot be used as an
-- unquoted column name.

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    severity TEXT,
    cvss_score NUMERIC(3,1),
    cvss_vector TEXT,
    published_date DATE,
    modified_date DATE,
    source_labels TEXT DEFAULT '[]',
    vendor TEXT,
    product TEXT,
    tech_type TEXT,
    kev_flag BOOLEAN DEFAULT FALSE,
    kev_date_added DATE,
    reference_urls TEXT DEFAULT '[]',
    cwes TEXT DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_date);
CREATE INDEX IF NOT EXISTS idx_vuln_vendor ON vulnerabilities(vendor);
CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(kev_flag);
CREATE INDEX IF NOT EXISTS idx_vuln_tech_type ON vulnerabilities(tech_type);
CREATE INDEX IF NOT EXISTS idx_vuln_cvss ON vulnerabilities(cvss_score);
CREATE INDEX IF NOT EXISTS idx_vuln_updated ON vulnerabilities(updated_at);

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
