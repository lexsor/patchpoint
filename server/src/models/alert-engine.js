const { getDb } = require('../db/client');

/**
 * Alert Engine
 *
 * Checks recently updated vulnerabilities against the user watchlist and
 * records an alert for each match.
 *
 * Alerts are deduplicated in the database by UNIQUE(cve_id, match_type,
 * match_value), so re-running a fetch cycle cannot re-raise an alert the user
 * has already been shown. `run()` returns only the alerts newly created by
 * this pass.
 */

const RECENT_WINDOW_HOURS = 24;
const MAX_RETAINED_ALERTS = 1000;

async function run() {
    const db = getDb();

    const watchlistResult = await db.query('SELECT * FROM watchlist');
    const watchlist = watchlistResult.rows;

    if (watchlist.length === 0) {
        return [];
    }

    const since = new Date(Date.now() - RECENT_WINDOW_HOURS * 60 * 60 * 1000).toISOString();
    const vulnResult = await db.query(
        'SELECT cve_id, vendor, product, source_labels FROM vulnerabilities WHERE updated_at >= $1',
        [since]
    );

    const created = [];

    for (const vuln of vulnResult.rows) {
        for (const watch of watchlist) {
            const matchType = matchWatchlistItem(vuln, watch);
            if (!matchType) continue;

            const message = `Vulnerability ${vuln.cve_id} matches watchlist item "${watch.item}" `
                + `(${matchType}) from source(s): ${vuln.source_labels}`;

            // DO NOTHING means an existing alert for this pair is left alone
            // and RETURNING yields no row, so `created` holds only new alerts.
            const inserted = await db.query(`
                INSERT INTO alerts (cve_id, match_type, match_value, message)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (cve_id, match_type, match_value) DO NOTHING
                RETURNING *
            `, [vuln.cve_id, matchType, watch.item, message]);

            if (inserted.rows.length > 0) {
                created.push(inserted.rows[0]);
            }
        }
    }

    return created;
}

/**
 * Returns a match-type label, or '' when the vulnerability does not match.
 * Exported so it can be tested directly rather than reimplemented in a test.
 */
function matchWatchlistItem(vuln, watch) {
    const needle = String(watch.item || '').trim();
    if (!needle) return '';

    if (watch.item_type === 'cve_id') {
        const a = String(vuln.cve_id || '').toUpperCase().replace(/\s/g, '');
        const b = needle.toUpperCase().replace(/\s/g, '');
        return a && a === b ? 'CVE ID matched' : '';
    }

    if (watch.item_type === 'vendor') {
        return vuln.vendor && vuln.vendor.toLowerCase().includes(needle.toLowerCase())
            ? 'Vendor match'
            : '';
    }

    if (watch.item_type === 'product') {
        return vuln.product && vuln.product.toLowerCase().includes(needle.toLowerCase())
            ? 'Product match'
            : '';
    }

    return '';
}

async function getAlerts(limit = 50) {
    const result = await getDb().query(
        'SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT $1',
        [limit]
    );
    return result.rows;
}

async function getAlertCount() {
    const result = await getDb().query('SELECT COUNT(*) as count FROM alerts');
    return parseInt(result.rows[0].count, 10);
}

/** Delete every alert. Backs DELETE /api/alerts. */
async function clearAlerts() {
    const result = await getDb().query('DELETE FROM alerts');
    return result.rowCount;
}

/** Trim the alert log to the most recent MAX_RETAINED_ALERTS entries. */
async function pruneAlerts(keep = MAX_RETAINED_ALERTS) {
    const result = await getDb().query(`
        DELETE FROM alerts
        WHERE id NOT IN (
            SELECT id FROM alerts ORDER BY created_at DESC, id DESC LIMIT $1
        )
    `, [keep]);
    return result.rowCount;
}

module.exports = { run, matchWatchlistItem, getAlerts, getAlertCount, clearAlerts, pruneAlerts };
