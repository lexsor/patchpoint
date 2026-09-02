const https = require('https');

/**
 * Fetch MITRE CVEW (CVE Enhancement Workspace) data
 * https://cveawg.mitre.org/api/cve/{cveId}
 * Returns structured CVE data with tags, references, timelines
 * 
 * The MITRE CVEW API requires per-CVE requests. The fetcher receives
 * an optional cveId filter — if provided, fetches that single CVE;
 * otherwise returns empty (MITRE doesn't support bulk listing).
 */

/**
 * Fetch a specific CVE from MITRE CVEW API
 */
async function fetchMitreCvew(cveId = '') {
    if (!cveId) {
        // MITRE doesn't support bulk listing — return placeholder
        console.log('[MITRE CVEW] Skipping bulk fetch (API requires per-CVE requests)');
        return { records: [], total: 0 };
    }
    
    const url = `https://cveawg.mitre.org/api/cve/${cveId}`;
    console.log(`[MITRE CVEW] Fetching: ${url}`);

    return new Promise((resolve, reject) => {
        const req = https.get(url, {
            headers: {
                'User-Agent': 'VulnerabilityDashboard/1.0',
                'Accept': 'application/json',
            },
        }, (res) => {
            if (res.statusCode >= 400) {
                reject(new Error(`MITRE CVEW HTTP ${res.statusCode}`));
                return;
            }

            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    const results = [];

                    // MITRE API returns CPEng format:
                    // { dataType: "CVE_RECORD", cveMetadata, containers: { cna: { ... } } }
                    // or older format with cve_Items array
                    const cveData = parsed;
                    const resultsArr = [cveData];

                    for (const item of resultsArr) {
                        // Try CPEng format first
                        const cveId = item?.cveMetadata?.cveId ||
                                      item?.id ||
                                      item?.CVE_data_meta?.ID || '';

                        if (!cveId) continue;

                        // CPEng: containers.cna.*  |  Old: item.*
                        const cna = item?.containers?.cna || {};
                        const oldFormat = item?.cve || item;

                        // Description from CPEng or old format
                        let description = '';
                        const oldDescs = cna?.descriptions || oldFormat?.descriptions || oldFormat?.description?.description_data || [];
                        for (const d of oldDescs) {
                            if (d.value && (d.lang === 'en' || !d.lang)) {
                                description = d.value;
                                break;
                            }
                        }

                        // CVSS from CPEng (first container, cna metrics) or old format
                        let cvssScore = null;
                        let cvssVector = '';
                        
                        // CPEng format: containers.cna.metrics[].cvssV3_1 or cvssV4_0
                        const cnaMetrics = cna?.metrics || [];
                        for (const m of cnaMetrics) {
                            const v4 = m?.cvssV4_0;
                            const v31 = m?.cvssV3_1;
                            const v30 = m?.cvssV3_0;
                            const v20 = m?.cvssV2_0;
                            const target = v4 || v31 || v30 || v20;
                            if (target) {
                                cvssScore = parseFloat(target?.baseScore);
                                cvssVector = target?.vectorString || '';
                                break;
                            }
                        }
                        
                        // Fallback to old format metrics
                        if (cvssScore == null) {
                            const metrics = oldFormat?.metrics?.cvssMetricV31 || 
                                          oldFormat?.metrics?.cvssMetricV30 || [];
                            const primary = metrics.find(m => m.cveDataTags?.includes('Primary')) || metrics[0];
                            if (primary?.cvssData) {
                                cvssScore = parseFloat(primary.cvssData.baseMetricScore) || null;
                                cvssVector = primary.cvssData.vectorString || '';
                            }
                        }

                        // Title from CPEng
                        const title = cna?.title || oldFormat?.title || cveId;

                        // References
                        const refs = [];
                        const oldRefs = cna?.references || oldFormat?.references || [];
                        for (const ref of oldRefs) {
                            if (ref.url) refs.push(ref.url);
                            else if (ref.name) refs.push(ref.name);
                        }

                        // CWEs from CPEng problemTypes or old format weaknesses
                        const cwes = [];
                        const problemTypes = cna?.problemTypes || oldFormat?.weaknesses || [];
                        for (const pt of problemTypes) {
                            const descs = pt?.descriptions || pt?.description || [];
                            for (const d of descs) {
                                const cweId = d?.cweId || '';
                                if (cweId) cwes.push(cweId);
                                else {
                                    const m = (d?.value || '')?.match(/CWE-\d+/);
                                    if (m) cwes.push(m[0]);
                                }
                            }
                        }

                        // Extract vendor/product from CPEng affected[] 
                        let vendor = '';
                        let product = '';
                        const affectedList = cna?.affected || [];
                        for (const a of affectedList) {
                            if (a?.vendor) vendor = a.vendor;
                            if (a?.product) product = a.product;
                            if (vendor && product) break;
                        }

                        // Timeline from cveMetadata or old format
                        let publishedDate = '';
                        let modifiedDate = '';
                        const metaTime = item?.cveMetadata || item?.time || {};
                        if (metaTime.datePublished) publishedDate = metaTime.datePublished.split('T')[0];
                        if (metaTime.dateUpdated) modifiedDate = metaTime.dateUpdated.split('T')[0];

                        // Tags
                        const tags = [];
                        const meta = item?.cveMetadata || {};
                        if (meta?.state) tags.push(meta.state);

                        results.push({
                            cve_id: cveId,
                            title: title,
                            description: description,
                            severity: cvssScore != null ? classifySeverity(cvssScore) : '',
                            cvss_score: cvssScore,
                            cvss_vector: cvssVector,
                            published_date: publishedDate || new Date().toISOString().split('T')[0],
                            modified_date: modifiedDate || new Date().toISOString().split('T')[0],
                            vendor: vendor || extractVendor(description),
                            product: product || extractProduct(description),
                            tech_type: extractTechType(tags),
                            references: JSON.stringify(refs),
                            cwes: JSON.stringify(cwes),
                            tags: JSON.stringify(tags),
                        });
                    }

                    console.log(`[MITRE CVEW] Fetched ${results.length} records`);
                    resolve({ records: results, total: results.length });
                } catch (err) {
                    console.error(`[MITRE CVEW] Parse error:`, err.message);
                    resolve({ records: [], total: 0 });
                }
            });
        });

        req.on('error', (err) => {
            console.error(`[MITRE CVEW] Network error:`, err.message);
            resolve({ records: [], total: 0 });
        });
        req.setTimeout(60000, () => { req.destroy(); resolve({ records: [], total: 0 }); });
    });
}

function classifySeverity(score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
}

function extractVendor(description) {
    if (!description) return '';
    // Common vendor patterns in vulnerability descriptions
    const patterns = [
        /for (\w+(?: \w+)*)\s+(?:in|on|for)/i,
        /affects (\w+(?: \w+)*)/i,
        /affecting (\w+(?: \w+)*)/i,
    ];
    for (const p of patterns) {
        const m = description.match(p);
        if (m) return m[1];
    }
    return '';
}

function extractProduct(description) {
    if (!description) return '';
    const patterns = [
        /(\w+(?: \w+)*\s+(?:web|server|api|service|application|platform|framework|software))/i,
    ];
    for (const p of patterns) {
        const m = description.match(p);
        if (m) return m[1];
    }
    return '';
}

function extractTechType(tags) {
    if (!tags || tags.length === 0) return '';
    const tagList = Array.isArray(tags) ? tags : JSON.parse(tags);
    const mapping = {
        'networking': ['network', 'router', 'switch', 'firewall', 'cisco'],
        'mobile': ['android', 'ios', 'mobile', 'smartphone'],
        'os': ['linux', 'windows', 'macos', 'operating system', 'kernel'],
        'web': ['apache', 'nginx', 'iis', 'tomcat', 'nginx', 'wordpress', 'drupal', 'web'],
        'database': ['mysql', 'postgresql', 'mongodb', 'oracle', 'sql'],
        'browser': ['chrome', 'firefox', 'safari', 'edge', 'browser'],
        'container': ['docker', 'kubernetes', 'container', 'k8s'],
    };
    const lowerTags = tagList.join(' ').toLowerCase();
    for (const [type, keywords] of Object.entries(mapping)) {
        for (const kw of keywords) {
            if (lowerTags.includes(kw)) return type;
        }
    }
    return 'other';
}

module.exports = { fetchMitreCvew };
