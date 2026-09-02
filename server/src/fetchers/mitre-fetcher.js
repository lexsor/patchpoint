const { httpGetText } = require('../lib/http');
const { classifySeverity } = require('../lib/severity');

const API_BASE = 'https://cveawg.mitre.org/api/cve';
const REQUEST_TIMEOUT_MS = 30000;

/**
 * Fetch a single CVE record from the MITRE CVE Services API.
 *
 * MITRE has no bulk listing endpoint — records are addressed one CVE at a
 * time — so the orchestrator uses this to *enrich* CVEs already discovered
 * via CISA KEV and NVD. Calling it with no ID is a no-op by design.
 *
 * @param {string} cveId
 */
async function fetchMitreCvew(cveId = '') {
    const id = String(cveId || '').trim().toUpperCase();

    if (!id) {
        console.log('[MITRE CVEW] No CVE ID supplied; MITRE has no bulk listing endpoint');
        return { records: [], total: 0 };
    }

    const url = `${API_BASE}/${encodeURIComponent(id)}`;
    console.log(`[MITRE CVEW] Fetching ${url}`);

    const res = await httpGetText(url, {
        headers: { Accept: 'application/json' },
        timeoutMs: REQUEST_TIMEOUT_MS,
    });

    if (res.statusCode === 404) {
        return { records: [], total: 0 };
    }
    if (res.statusCode >= 400) {
        throw new Error(`MITRE CVEW HTTP ${res.statusCode} for ${id}`);
    }

    const record = parseCveRecord(JSON.parse(res.body));
    if (!record) return { records: [], total: 0 };

    console.log(`[MITRE CVEW] Fetched ${record.cve_id}`);
    return { records: [record], total: 1 };
}

/**
 * Map a CVE Record (JSON 5.x) into the internal record shape.
 * Shape: { cveMetadata: {...}, containers: { cna: {...} } }
 */
function parseCveRecord(payload) {
    const meta = (payload && payload.cveMetadata) || {};
    const cna = (payload && payload.containers && payload.containers.cna) || {};

    const cveId = meta.cveId || payload.id || '';
    if (!cveId) return null;

    const description = pickEnglish(cna.descriptions);
    const cvss = extractCvss(cna.metrics);
    const { vendor, product } = extractAffected(cna.affected);

    return {
        cve_id: cveId,
        title: cna.title || '',
        description,
        severity: cvss.severity || (cvss.score != null ? classifySeverity(cvss.score) : ''),
        cvss_score: cvss.score,
        cvss_vector: cvss.vector,
        published_date: toDateOnly(meta.datePublished),
        modified_date: toDateOnly(meta.dateUpdated),
        vendor,
        product,
        tech_type: classifyTechType([product, vendor, description].join(' ')),
        references: (cna.references || []).map((r) => r.url).filter(Boolean),
        cwes: extractCwes(cna.problemTypes),
    };
}

function pickEnglish(descriptions) {
    for (const d of descriptions || []) {
        if (d && d.value && (d.lang === 'en' || (d.lang || '').startsWith('en'))) return d.value;
    }
    const first = (descriptions || [])[0];
    return (first && first.value) || '';
}

/** Newest CVSS version present wins. */
function extractCvss(metrics) {
    for (const metric of metrics || []) {
        const data = metric && (metric.cvssV4_0 || metric.cvssV3_1 || metric.cvssV3_0 || metric.cvssV2_0);
        if (!data) continue;

        const score = data.baseScore != null ? parseFloat(data.baseScore) : null;
        return {
            score: Number.isFinite(score) ? score : null,
            severity: data.baseSeverity ? String(data.baseSeverity).toUpperCase() : '',
            vector: data.vectorString || '',
        };
    }
    return { score: null, severity: '', vector: '' };
}

function extractCwes(problemTypes) {
    const found = new Set();
    for (const pt of problemTypes || []) {
        for (const d of (pt && pt.descriptions) || []) {
            if (d && d.cweId) {
                found.add(d.cweId);
                continue;
            }
            const match = ((d && d.value) || '').match(/CWE-\d+/);
            if (match) found.add(match[0]);
        }
    }
    return [...found];
}

/**
 * Vendor and product come from the structured `affected` array only.
 * An earlier version regex-scraped noun phrases out of the description
 * ("affects (\w+)"), which fabricated vendor names and polluted the vendor
 * filter with junk. Better to leave the field empty than to invent it.
 */
function extractAffected(affected) {
    for (const entry of affected || []) {
        if (!entry) continue;
        const vendor = entry.vendor && entry.vendor !== 'n/a' ? entry.vendor : '';
        const product = entry.product && entry.product !== 'n/a' ? entry.product : '';
        if (vendor || product) return { vendor, product };
    }
    return { vendor: '', product: '' };
}

const TECH_TYPE_KEYWORDS = {
    networking: ['router', 'switch', 'firewall', 'cisco', 'juniper', 'fortinet', 'vpn'],
    mobile: ['android', 'ios', 'iphone', 'smartphone', 'mobile'],
    os: ['linux', 'windows', 'macos', 'operating system', 'kernel', 'solaris'],
    web: ['apache', 'nginx', 'tomcat', 'wordpress', 'drupal', 'joomla', 'iis', 'http server'],
    database: ['mysql', 'postgresql', 'mongodb', 'oracle database', 'mariadb', 'sql server'],
    browser: ['chrome', 'chromium', 'firefox', 'safari', 'edge', 'webkit'],
    container: ['docker', 'kubernetes', 'containerd', 'k8s', 'openshift'],
};

/**
 * Best-effort technology bucket from product/vendor/description text.
 * Returns '' rather than 'other' when nothing matches, so the Technology
 * filter only ever offers buckets that were actually identified.
 */
function classifyTechType(text) {
    const haystack = String(text || '').toLowerCase();
    if (!haystack.trim()) return '';

    for (const [type, keywords] of Object.entries(TECH_TYPE_KEYWORDS)) {
        if (keywords.some((kw) => haystack.includes(kw))) return type;
    }
    return '';
}

function toDateOnly(value) {
    if (!value || typeof value !== 'string') return null;
    const datePart = value.split('T')[0];
    return /^\d{4}-\d{2}-\d{2}$/.test(datePart) ? datePart : null;
}

module.exports = { fetchMitreCvew, parseCveRecord, classifyTechType };
