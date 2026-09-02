const { httpGetText, sleep } = require('../lib/http');
const { classifySeverity } = require('../lib/severity');

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RESULTS_PER_PAGE = 2000; // Max allowed by NVD
const MAX_RATE_LIMIT_RETRIES = 3;
const REQUEST_TIMEOUT_MS = 60000;

/**
 * Fetch one page of the NVD CVE API (v2.0).
 *
 * All field names below come from the live v2.0 response shape:
 *   cve.published, cve.lastModified, cve.descriptions[], cve.weaknesses[],
 *   cve.metrics.cvssMetricV40|V31|V30|V2[].{type,cvssData,baseSeverity}
 * An earlier version read `datePublished`, `dateUpdated`, `baseMetricScore`
 * and `cveDataTags`, none of which exist; every record came back with a null
 * score, LOW severity and today's date.
 *
 * @param {object} opts
 * @param {number} opts.startIndex        Offset into the result set.
 * @param {string} [opts.lastModStartDate] ISO-8601. Must be paired with end.
 * @param {string} [opts.lastModEndDate]   ISO-8601. Max 120 days from start.
 * @param {string} [opts.apiKey]          Optional NVD API key.
 */
async function fetchNvd({ startIndex = 0, lastModStartDate, lastModEndDate, apiKey } = {}) {
    const params = new URLSearchParams({
        resultsPerPage: String(RESULTS_PER_PAGE),
        startIndex: String(startIndex),
    });

    // NVD requires both bounds together, or neither.
    if (lastModStartDate && lastModEndDate) {
        params.set('lastModStartDate', lastModStartDate);
        params.set('lastModEndDate', lastModEndDate);
    }

    const url = `${NVD_API_URL}?${params.toString()}`;
    const key = apiKey !== undefined ? apiKey : process.env.NVD_API_KEY || '';

    // The API key travels in a header, never in the query string, so it does
    // not end up in logs.
    const headers = { Accept: 'application/json' };
    if (key) headers.apiKey = key;

    console.log(`[NVD] Fetching startIndex=${startIndex}${lastModStartDate ? ` window=${lastModStartDate}..${lastModEndDate}` : ''}`);

    let attempt = 0;
    for (;;) {
        const res = await httpGetText(url, { headers, timeoutMs: REQUEST_TIMEOUT_MS });

        if (res.statusCode === 429 || res.statusCode === 503) {
            if (attempt >= MAX_RATE_LIMIT_RETRIES) {
                throw new Error(`NVD HTTP ${res.statusCode} after ${attempt} retries`);
            }
            attempt++;
            const retryAfter = parseInt(res.headers['retry-after'], 10);
            const waitMs = (Number.isFinite(retryAfter) ? retryAfter : 30) * 1000;
            console.log(`[NVD] HTTP ${res.statusCode}, retry ${attempt}/${MAX_RATE_LIMIT_RETRIES} in ${waitMs}ms`);
            await sleep(waitMs);
            continue;
        }

        if (res.statusCode >= 400) {
            throw new Error(`NVD HTTP ${res.statusCode}`);
        }

        return parseNvdPage(res.body, startIndex);
    }
}

function parseNvdPage(body, startIndex) {
    const parsed = JSON.parse(body);
    const vulnerabilities = parsed.vulnerabilities || [];
    const records = [];

    for (const entry of vulnerabilities) {
        const cve = entry.cve;
        if (!cve || !cve.id) continue;

        const cvss = extractCvss(cve);

        records.push({
            cve_id: cve.id,
            // NVD publishes no title field; the description carries the detail.
            title: '',
            description: extractDescription(cve),
            severity: cvss.severity || (cvss.score != null ? classifySeverity(cvss.score) : ''),
            cvss_score: cvss.score,
            cvss_vector: cvss.vector || '',
            published_date: toDateOnly(cve.published),
            modified_date: toDateOnly(cve.lastModified),
            vendor: '',
            product: '',
            tech_type: '',
            references: (cve.references || []).map((r) => r.url).filter(Boolean),
            cwes: extractCwes(cve),
        });
    }

    const totalResults = parsed.totalResults || 0;
    const consumed = startIndex + (parsed.resultsPerPage || records.length);
    const isLastPage = records.length === 0 || consumed >= totalResults;

    console.log(`[NVD] startIndex=${startIndex}: ${records.length} records (total available: ${totalResults})`);

    return {
        records,
        total: records.length,
        totalResults,
        startIndex,
        nextStartIndex: consumed,
        isLastPage,
    };
}

/** 'YYYY-MM-DDTHH:mm:ss.sss' -> 'YYYY-MM-DD', or null when absent. */
function toDateOnly(value) {
    if (!value || typeof value !== 'string') return null;
    const datePart = value.split('T')[0];
    return /^\d{4}-\d{2}-\d{2}$/.test(datePart) ? datePart : null;
}

/**
 * Pull the base score, vector and stated severity from NVD's metrics block.
 * Newest CVSS version wins; V2 is included because a large share of older
 * CVEs carry only V2 metrics and would otherwise score as null.
 */
function extractCvss(cve) {
    const metrics = cve.metrics || {};
    const ordered = [
        ...(metrics.cvssMetricV40 || []),
        ...(metrics.cvssMetricV31 || []),
        ...(metrics.cvssMetricV30 || []),
        ...(metrics.cvssMetricV2 || []),
    ];

    // `type` is the field that marks the authoritative metric ('Primary').
    const chosen = ordered.find((m) => m.type === 'Primary') || ordered[0];
    if (!chosen || !chosen.cvssData) {
        return { score: null, severity: '', vector: '' };
    }

    const data = chosen.cvssData;
    const score = data.baseScore != null ? parseFloat(data.baseScore) : null;

    // V3.x/V4.0 put baseSeverity on cvssData; V2 puts it on the metric.
    const stated = data.baseSeverity || chosen.baseSeverity || '';

    return {
        score: Number.isFinite(score) ? score : null,
        severity: stated ? String(stated).toUpperCase() : '',
        vector: data.vectorString || '',
    };
}

function extractDescription(cve) {
    const descs = cve.descriptions || [];
    const english = descs.find((d) => d.lang === 'en' && d.value);
    if (english) return english.value;
    return (descs[0] && descs[0].value) || '';
}

/**
 * CWEs live at cve.weaknesses[].description[].value. A previous version walked
 * configurations[].cpeMatch[].vulnerable[0].cpeIdent.weakRefs, a path that
 * does not exist in the v2.0 schema, so CWEs were always empty.
 */
function extractCwes(cve) {
    const found = new Set();
    for (const weakness of cve.weaknesses || []) {
        for (const desc of weakness.description || []) {
            const value = (desc.value || '').trim();
            if (!value) continue;
            const match = value.match(/CWE-\d+/);
            if (match) found.add(match[0]);
            // NVD also emits placeholders like 'NVD-CWE-noinfo' / 'NVD-CWE-Other';
            // those carry no weakness information, so they are dropped.
        }
    }
    return [...found];
}

module.exports = { fetchNvd, extractCvss, extractCwes, extractDescription, RESULTS_PER_PAGE };
