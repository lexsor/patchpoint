const { getDb } = require('../db/client');

/**
 * Alert Engine
 * 
 * Checks newly fetched vulnerabilities against user watchlist
 * and generates alerts for matches.
 */

// Check vulnerabilities against watchlist after a fetch
async function run() {
    const db = getDb();
    
    // Get watchlist items
    const watchlistResult = await db.query('SELECT * FROM watchlist');
    const watchlist = watchlistResult.rows;
    
    if (watchlist.length === 0) {
        return [];
    }
    
    // Get recently modified/created vulnerabilities (last 24 hours)
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const vulnResult = await db.query(
        'SELECT * FROM vulnerabilities WHERE updated_at >= $1',
        [since]
    );
    const vulnerabilities = vulnResult.rows;
    
    const alerts = [];
    
    for (const vuln of vulnerabilities) {
        for (const watch of watchlist) {
            let match = false;
            let matchType = '';
            
            if (watch.item_type === 'cve_id') {
                if (vuln.cve_id.toUpperCase() === watch.item.toUpperCase().replace(/\s/g, '')) {
                    match = true;
                    matchType = 'CVE ID matched';
                }
            } else if (watch.item_type === 'vendor') {
                if (vuln.vendor && vuln.vendor.toLowerCase().includes(watch.item.toLowerCase())) {
                    match = true;
                    matchType = 'Vendor match';
                }
            } else if (watch.item_type === 'product') {
                if (vuln.product && vuln.product.toLowerCase().includes(watch.item.toLowerCase())) {
                    match = true;
                    matchType = 'Product match';
                }
            }
            
            if (match) {
                const alert = {
                    cve_id: vuln.cve_id,
                    match_type: matchType,
                    match_value: watch.item,
                    message: `Vulnerability ${vuln.cve_id} matches watchlist item "${watch.item}" (${matchType}) from source(s): ${vuln.source_labels}`,
                };
                alerts.push(alert);
                
                // Store alert in database
                await db.query(
                    'INSERT INTO alerts (cve_id, match_type, match_value, message) VALUES ($1, $2, $3, $4)',
                    [vuln.cve_id, matchType, watch.item, alert.message]
                );
            }
        }
    }
    
    return alerts;
}

// Get all alerts
async function getAlerts(limit = 50) {
    const db = getDb();
    const result = await db.query(
        'SELECT * FROM alerts ORDER BY created_at DESC LIMIT $1',
        [limit]
    );
    return result.rows;
}

// Get unread alert count
async function getAlertCount() {
    const db = getDb();
    const result = await db.query('SELECT COUNT(*) as count FROM alerts');
    return parseInt(result.rows[0].count);
}

// Clear old alerts (keep last 1000)
async function clearAlerts() {
    const db = getDb();
    await db.query('DELETE FROM alerts WHERE id NOT IN (SELECT id FROM alerts ORDER BY created_at DESC LIMIT 1000)');
}

module.exports = { run, getAlerts, getAlertCount, clearAlerts };
