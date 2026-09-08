const papaparse = require('papaparse');
const { httpGetText } = require('../lib/http');

const CSV_URL = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv';
const JSON_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const REQUEST_TIMEOUT_MS = 30000;

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
            // Both feeds carry identical column names, verified against the
            // live CSV header and JSON keys. This whitelist exists so a new
            // upstream column cannot silently become a record field, which
            // also means a field added here must be added to the CSV header
            // list or it will be present in JSON mode and absent in CSV mode.
            requiredAction: row.requiredAction,
            dueDate: row.dueDate,
            knownRansomwareCampaignUse: row.knownRansomwareCampaignUse,
            notes: row.notes,
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
        kev_due_date: normalizeDate(item.dueDate),
        kev_ransomware: parseRansomwareUse(item.knownRansomwareCampaignUse),
        kev_required_action: (item.requiredAction || '').trim(),
        // `notes` is prose, but for 906 of 1,695 entries it contains the vendor
        // advisory URL -- which is precisely the fix action an admin needs.
        references: parseNoteUrls(item.notes),
        cwes: parseCwes(item.cwes),
        // CISA KEV publishes no CVSS score, so it asserts no severity. An
        // earlier version stamped every KEV record HIGH; since KEV lands
        // first and is ~1,700 records, that made HIGH the only value in the
        // table and the only option in the severity filter. Exploitation is
        // conveyed by kev_flag; severity is left for NVD/MITRE to supply.
        severity: '',
    };
}

function normalizeDate(value) {
    if (!value || typeof value !== 'string') return null;
    const datePart = value.trim().split('T')[0];
    return /^\d{4}-\d{2}-\d{2}$/.test(datePart) ? datePart : null;
}

/**
 * 'Known' -> true, 'Unknown' -> null, anything else -> null.
 *
 * Deliberately tri-state. CISA says 'Known' or 'Unknown' and never asserts
 * that a vulnerability is NOT used by ransomware, so mapping 'Unknown' to
 * false would invent a reassurance the feed does not give. NULL keeps the
 * distinction between "no ransomware use observed" and "we don't know".
 */
function parseRansomwareUse(value) {
    if (typeof value !== 'string') return null;
    return value.trim().toLowerCase() === 'known' ? true : null;
}

// Hosts stripped from the `notes` URL list.
//
// nvd.nist.gov appears on all 1,695 entries and the detail panel already links
// the NVD record directly, so keeping it would add a duplicate row to every
// KEV reference list. cisa.gov entries are links to the binding operational
// directives quoted in `requiredAction` -- policy boilerplate, not a fix.
const NOTE_URL_NOISE = new Set(['nvd.nist.gov', 'cisa.gov']);

/**
 * Pull vendor advisory URLs out of the free-text `notes` field.
 *
 * Returns an array; the repository serializes it, so this must not hand back
 * a pre-stringified value.
 */
function parseNoteUrls(notes) {
    if (!notes || typeof notes !== 'string') return [];

    // Notes are semicolon-separated prose containing bare URLs. Trailing
    // punctuation is common, so stop at whitespace and the characters that
    // routinely terminate a URL in a sentence.
    const found = notes.match(/https?:\/\/[^\s;,)\]]+/g) || [];
    const kept = new Set();

    for (const raw of found) {
        // A trailing period is sentence punctuation far more often than it is
        // part of a path.
        const url = raw.replace(/[.]+$/, '');
        let host;
        try {
            host = new URL(url).hostname.replace(/^www\./, '').toLowerCase();
        } catch {
            continue;
        }
        if (!NOTE_URL_NOISE.has(host)) kept.add(url);
    }

    return [...kept];
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

module.exports = {
    fetchCisaKev, fetchCisaKevJson, parseCwes, toRecord,
    parseRansomwareUse, parseNoteUrls,
};
