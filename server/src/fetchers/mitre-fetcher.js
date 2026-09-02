const https = require('https');

/**
 * Fetch MITRE CVEW (CVE Enhancement Workspace) data
 * https://cveawg.mitre.org/api/cve/
 * Returns structured CVE data with tags, references, timelines
 */

const MITRE_CVEW_URL = 'https://cveawg.mitre.org/api/cve/';

async function fetchMitreCvew(page = 0, size = 2000) {
    const params = new URLSearchParams({
        cve_id: '', // empty = all CVEs
    });
    
    const url = `${MITRE_CVEW_URL}?${params.toString()}&pageSize=${size}&startIndex=${page * size}`;
    console.log(`[MITRE CVEW] Fetching page ${page}: ${url}`);

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

                    // MITRE CVEW API returns { cve_Items: [...] }
                    const items = parsed.cve_Items || parsed.items || parsed.results || [parsed];
                    
                    for (const item of items) {
                        const cveData = item?.cve || item || {};
                        const cveId = cveData.id || cveData.CVE_data_meta?.ID || '';
                        
                        // Extract description
                        let description = '';
                        const descs = cveData.descriptions || cveData.description?.description_data || [];
                        for (const d of descs) {
                            if (d.value && (d.lang === 'en' || !d.lang)) {
                                description = d.value;
                                break;
                            }
                        }

                        // Extract CVSS
                        let cvssScore = null;
                        let cvssVector = '';
                        const metrics = cveData.metrics?.cvssMetricV31 || cveData.metrics?.cvssMetricV30 || [];
                        const primary = metrics.find(m => m.cveDataTags?.includes('Primary')) || metrics[0];
                        if (primary?.cvssData) {
                            cvssScore = parseFloat(primary.cvssData.baseMetricScore) || null;
                            cvssVector = primary.cvssData.vectorString || '';
                        }

                        // Extract references
                        const refs = [];
                        for (const ref of cveData.references || []) {
                            if (ref.url) refs.push(ref.url);
                        }

                        // Extract CWEs
                        const cwes = [];
                        for (const wfn of cveData.weaknesses || []) {
                            for (const desc of wfn.description || []) {
                                const m = desc.value?.match(/CWE-\d+/);
                                if (m) cwes.push(m[0]);
                            }
                        }

                        // Extract timeline
                        let publishedDate = '';
                        let modifiedDate = '';
                        const timeline = cveData.time || {};
                        if (timeline.created) publishedDate = timeline.created.split('T')[0];
                        if (timeline.updated) modifiedDate = timeline.updated.split('T')[0];

                        // Extract tags
                        const tags = (cveData.tags || []).map(t => String(t)).filter(Boolean);

                        results.push({
                            cve_id: cveId,
                            title: cveData?.CVE_data_meta?.ID || cveId,
                            description: description,
                            severity: cvssScore != null ? classifySeverity(cvssScore) : '',
                            cvss_score: cvssScore,
                            cvss_vector: cvssVector,
                            published_date: publishedDate || new Date().toISOString().split('T')[0],
                            modified_date: modifiedDate || new Date().toISOString().split('T')[0],
                            vendor: extractVendor(description),
                            product: extractProduct(description),
                            tech_type: extractTechType(tags),
                            references: JSON.stringify(refs),
                            cwes: JSON.stringify(cwes),
                            tags: JSON.stringify(tags),
                        });
                    }

                    console.log(`[MITRE CVEW] Page ${page}: ${results.length} records`);
                    resolve({ records: results, total: results.length });
                } catch (err) {
                    console.error(`[MITRE CVEW] Parse error on page ${page}:`, err.message);
                    resolve({ records: [], total: 0 });
                }
            });
        });

        req.on('error', (err) => {
            console.error(`[MITRE CVEW] Network error on page ${page}:`, err.message);
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
