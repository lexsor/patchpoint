const https = require('https');
const http = require('http');
const papaparse = require('papaparse');
const { execSync } = require('child_process');

/**
 * Fetch CISA KEV from CSV source
 * https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
 */
async function fetchCisaKev() {
    const url = 'https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv';
    console.log(`[CISA KEV] Fetching from ${url}`);
    
    return new Promise((resolve, reject) => {
        const transport = url.startsWith('https') ? https : http;
        const req = transport.get(url, { headers: { 'User-Agent': 'VulnerabilityDashboard/1.0' } }, (res) => {
            if (res.statusCode >= 400) {
                reject(new Error(`CISA KEV HTTP ${res.statusCode}`));
                return;
            }
            
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const results = [];
                    const parsed = papaparse.parse(data, { header: true, skipEmptyLines: true });
                    
                    for (const row of parsed.data) {
                        results.push({
                            cve_id: row['cveID'] || '',
                            vendor: row['vendorProject'] || '',
                            product: row['product'] || '',
                            title: row['vulnerabilityName'] || '',
                            description: row['shortDescription'] || '',
                            published_date: row['dateAdded'] || new Date().toISOString().split('T')[0],
                            kev_flag: true,
                            kev_date_added: row['dateAdded'] || null,
                            cwes: parseCwes(row['cwes'] || ''),
                            severity: 'HIGH', // CISA KEV implies known exploitation
                        });
                    }
                    
                    console.log(`[CISA KEV] Fetched ${results.length} records`);
                    resolve({ records: results, total: results.length });
                } catch (err) {
                    reject(err);
                }
            });
        });
        
        req.on('error', reject);
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('CISA KEV timeout')); });
    });
}

/**
 * Fetch CISA KEV from JSON source
 * https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 */
async function fetchCisaKevJson() {
    const url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
    console.log(`[CISA KEV JSON] Fetching from ${url}`);
    
    return new Promise((resolve, reject) => {
        const transport = url.startsWith('https') ? https : http;
        const req = transport.get(url, { headers: { 'User-Agent': 'VulnerabilityDashboard/1.0' } }, (res) => {
            if (res.statusCode >= 400) {
                reject(new Error(`CISA KEV JSON HTTP ${res.statusCode}`));
                return;
            }
            
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    const results = [];
                    
                    for (const item of parsed.vulnerabilities) {
                        results.push({
                            cve_id: item.cveID || '',
                            vendor: item.vendorProject || '',
                            product: item.product || '',
                            title: item.vulnerabilityName || '',
                            description: item.shortDescription || '',
                            published_date: item.dateAdded || new Date().toISOString().split('T')[0],
                            kev_flag: true,
                            kev_date_added: item.dateAdded || null,
                            cwes: parseCwes(item.cwes || ''),
                            severity: 'HIGH',
                        });
                    }
                    
                    console.log(`[CISA KEV JSON] Fetched ${results.length} records`);
                    resolve({ records: results, total: results.length });
                } catch (err) {
                    reject(err);
                }
            });
        });
        
        req.on('error', reject);
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('CISA KEV JSON timeout')); });
    });
}

/**
 * Parse CWE entries — handles both CSV (comma-separated string)
 * and JSON (array of objects with weakRefs or cweId fields)
 */
function parseCwes(cwesStr) {
    if (!cwesStr) return [];
    if (Array.isArray(cwesStr)) {
        return cwesStr.map(c => {
            if (typeof c === 'string' && c.startsWith('CWE-')) return c;
            if (typeof c === 'object' && c) return c.cweId || c.cwe || '';
            return '';
        }).filter(Boolean);
    }
    if (typeof cwesStr !== 'string') return [];
    return cwesStr.split(',').map(c => c.trim()).filter(c => c.startsWith('CWE-'));
}

module.exports = { fetchCisaKev, fetchCisaKevJson };
