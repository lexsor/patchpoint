const https = require('https');

const NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const NVD_API_KEY = process.env.NVD_API_KEY || '';
const RESULTS_PER_PAGE = 2000; // Max allowed by NVD

/**
 * Classify severity based on CVSS score
 */
const classifySeverity = (score) => {
    const s = parseFloat(score);
    if (isNaN(s)) return 'LOW';
    if (s >= 9.0) return 'CRITICAL';
    if (s >= 7.0) return 'HIGH';
    if (s >= 4.0) return 'MEDIUM';
    return 'LOW';
};

async function fetchNvd(page = 1) {
    const params = new URLSearchParams({
        resultsPerPage: RESULTS_PER_PAGE,
        startIndex: ((page - 1) * RESULTS_PER_PAGE).toString(),
    });

    if (NVD_API_KEY) {
        params.set('apiKey', NVD_API_KEY);
    }

    const url = `${NVD_API_URL}?${params.toString()}`;
    console.log(`[NVD] Fetching page ${page}: ${url}`);

    return new Promise((resolve, reject) => {
        const req = https.get(url, {
            headers: {
                'User-Agent': 'VulnerabilityDashboard/1.0',
                'Accept': 'application/json',
            },
        }, (res) => {
            if (res.statusCode >= 400) {
                if (res.statusCode === 429) {
                    // Rate limited - retry with backoff
                    const retryAfter = parseInt(res.headers['retry-after'] || '30') * 1000;
                    console.log(`[NVD] Rate limited. Waiting ${retryAfter}ms`);
                    setTimeout(() => resolve(fetchNvd(page)).bind(null, null, null), retryAfter);
                    return;
                }
                reject(new Error(`NVD HTTP ${res.statusCode}`));
                return;
            }

            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    const results = [];
                    
                    for (const vuln of parsed.vulnerabilities) {
                        const cve = vuln.cve;
                        const cvss = extractCvss(cve);
                        
                        results.push({
                            cve_id: cve.id || '',
                            title: cve.title || '',
                            description: extractDescription(cve),
                            severity: cvss.severity || classifySeverity(parseFloat(cvss.score) || 0),
                            cvss_score: parseFloat(cvss.score) || null,
                            cvss_vector: cvss.vector || '',
                            published_date: cve.datePublished ? cve.datePublished.split('T')[0] : new Date().toISOString().split('T')[0],
                            modified_date: cve.dateUpdated ? cve.dateUpdated.split('T')[0] : new Date().toISOString().split('T')[0],
                            vendor: '',
                            product: '',
                            tech_type: '',
                            references: JSON.stringify((cve.references || []).map(r => r.url)),
                            cwes: JSON.stringify(extractCwes(cve)),
                        });
                    }

                    const totalResults = parsed.totalResults || 0;
                    const isLastPage = (page * RESULTS_PER_PAGE) >= totalResults;

                    console.log(`[NVD] Page ${page}: ${results.length} records (total: ${totalResults})`);
                    resolve({ records: results, total: results.length, isLastPage, totalPages: Math.ceil(totalResults / RESULTS_PER_PAGE) });
                } catch (err) {
                    reject(err);
                }
            });
        });

        req.on('error', reject);
        req.setTimeout(60000, () => { req.destroy(); reject(new Error('NVD timeout')); });
    });
}

/**
 * Extract CVSS score and severity from NVD CVSS metrics
 */
function extractCvss(cve) {
    const metrics = cve.metrics?.cvssMetricV31 || cve.metrics?.cvssMetricV30 || [];
    const primaryMetric = metrics.find(m => m.cveDataTags?.includes('Primary')) || metrics[0];
    
    if (!primaryMetric?.cvssData) {
        return { score: null, severity: null, vector: null };
    }

    const cvss = primaryMetric.cvssData;
    return {
        score: cvss.baseMetricScore,
        severity: cvss.vectorString ? classifySeverity(parseFloat(cvss.baseMetricScore) || 0) : null,
        vector: cvss.vectorString,
    };
}

/**
 * Extract description text from NVD CVE
 */
function extractDescription(cve) {
    const descs = cve.descriptions || [];
    for (const d of descs) {
        if (d.value && d.lang === 'en') return d.value;
    }
    if (descs.length > 0) return descs[0].value || '';
    return '';
}

/**
 * Extract CWE IDs from CVE
 */
function extractCwes(cve) {
    const weakIds = [];
    const configs = cve.configurations || [];
    for (const config of configs) {
        if (config.cpeMatch) {
            for (const cpe of config.cpeMatch) {
                const v2WeakRefs = cpe.vulnerable?.[0]?.cpeIdent?.weakRefs || [];
                weakIds.push(...v2WeakRefs);
            }
        }
    }
    return [...new Set(weakIds)];
}

module.exports = { fetchNvd };
