-- Vulnerability Dashboard Database Schema
-- Creates tables for vulnerabilities, sources, and watchlists

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id VARCHAR(20) PRIMARY KEY,
    title TEXT,
    description TEXT,
    severity VARCHAR(20),
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
    references TEXT DEFAULT '[]',
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

CREATE TABLE IF NOT EXISTS sources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    url VARCHAR(500),
    last_fetched TIMESTAMP,
    total_fetched INTEGER DEFAULT 0,
    confidence_level VARCHAR(50) DEFAULT 'high'
);

CREATE TABLE IF NOT EXISTS watchlist (
    id SERIAL PRIMARY KEY,
    item VARCHAR(255) NOT NULL,
    item_type VARCHAR(20) NOT NULL CHECK(item_type IN ('cve_id', 'vendor', 'product')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(item, item_type)
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(20),
    match_type VARCHAR(50),
    match_value VARCHAR(255),
    message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
