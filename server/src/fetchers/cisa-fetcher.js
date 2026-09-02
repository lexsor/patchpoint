const papaparse = require('papaparse');
const { httpGetText } = require('../lib/http');

const CSV_URL = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv';
const JSON_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const REQUEST_TIMEOUT_MS = 30000;

/**
 * CISA KEV asserts a CVE is being exploited in the wild but publishes no CVSS
 * score. HIGH is the floor we record; if NVD or MITRE later supplies a real
 * score, the deduplication merge raises the severity to match.
 */
const KEV_ASSUMED_SEVERITY = 'HIGH';

/** Fetch the CISA KEV catalog (CSV feed). */
async function fetchCisaKev() {
    console.log(`[CISA KEV] Fetching ${CSV_URL}`);
    const res = await httpGetText(CSV_URL, { timeoutMs: REQUEST_TIMEOUT_MS });

    if (res.statusCode >= 400) {
        throw new Error(`CISA KEV HTTP ${res.statusCode}`);
    }

    const parsed = papaparse.parse(res.body, { header: true, skipEmptyLines: true });
    const records = (parsed.data || [])
        .map((row) => toRecord({
            cveID: row.cveID,
            vendorProject: row.vendorProject,
            product: row.product,
            vulnerabilityName: row.vulnerabilityName,
            shortDescription: row.shortDescription,
            dateAdded: row.dateAdded,
            cwes: row.cwes,
        }))
        .filter(Boolean);

    console.log(`[CISA KEV] Fetched ${records.length} records`);
    return { records, total: records.length };
}

/** Fetch the CISA KEV catalog (JSON feed). */
async function fetchCisaKevJson() {
    console.log(`[CISA KEV JSON] Fetching ${JSON_URL}`);
    const res = await httpGetText(JSON_URL, {
        headers: { Accept: 'application/json' },
        timeoutMs: REQUEST_TIMEOUT_MS,
    });

    if (res.statusCode >= 400) {
        throw new Error(`CISA KEV JSON HTTP ${res.statusCode}`);
    }

    const parsed = JSON.parse(res.body);
    const records = (parsed.vulnerabilities || []).map(toRecord).filter(Boolean);

    console.log(`[CISA KEV JSON] Fetched ${records.length} records`);
    return { records, total: records.length };
}

/** Shared mapping for both feeds — identical field names, different container. */
function toRecord(item) {
    const cveId = (item.cveID || '').trim();
    if (!cveId) return null;

    const dateAdded = normalizeDate(item.dateAdded);

    return {
        cve_id: cveId,
        vendor: (item.vendorProject || '').trim(),
        product: (item.product || '').trim(),
        title: (item.vulnerabilityName || '').trim(),
        description: (item.shortDescription || '').trim(),
        // dateAdded is when CISA catalogued it, not when the CVE was
        // published. Recording it as published_date would be wrong, and
        // fabricating today's date would be worse — leave it unset and let
        // NVD/MITRE supply the real publish date.
        published_date: null,
        kev_flag: true,
        kev_date_added: dateAdded,
        cwes: parseCwes(item.cwes),
        severity: KEV_ASSUMED_SEVERITY,
    };
}

function normalizeDate(value) {
    if (!value || typeof value !== 'string') return null;
    const datePart = value.trim().split('T')[0];
    return /^\d{4}-\d{2}-\d{2}$/.test(datePart) ? datePart : null;
}

/**
 * Parse CWE entries. The CSV feed gives a comma-separated string; the JSON
 * feed gives an array of strings. Always returns an array — the repository
 * serializes it, so a fetcher must not hand back a pre-stringified value.
 */
function parseCwes(cwes) {
    if (!cwes) return [];

    const candidates = Array.isArray(cwes)
        ? cwes
        : (typeof cwes === 'string' ? cwes.split(',') : []);

    const found = new Set();
    for (const candidate of candidates) {
        const text = typeof candidate === 'string'
            ? candidate
            : (candidate && (candidate.cweId || candidate.cwe)) || '';
        const match = String(text).trim().match(/CWE-\d+/);
        if (match) found.add(match[0]);
    }
    return [...found];
}

module.exports = { fetchCisaKev, fetchCisaKevJson, parseCwes, toRecord };
