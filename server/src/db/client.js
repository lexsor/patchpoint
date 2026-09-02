const pg = require('pg');
const fs = require('fs');
const path = require('path');

const { Pool } = pg;

// --- Type parsers -----------------------------------------------------------
// By default node-postgres returns NUMERIC as a string (to preserve arbitrary
// precision) and DATE as a JS Date in the *local* timezone. Both leak bugs into
// consumers: `cvss_score.toFixed()` throws on a string, and a local-midnight
// Date can shift a day when re-serialized as ISO. cvss_score is NUMERIC(3,1)
// and dates are plain calendar dates, so it is safe to narrow both here.
const NUMERIC_OID = 1700;
const DATE_OID = 1082;
if (pg.types && typeof pg.types.setTypeParser === 'function') {
    pg.types.setTypeParser(NUMERIC_OID, (v) => (v === null ? null : parseFloat(v)));
    pg.types.setTypeParser(DATE_OID, (v) => v); // keep the wire format: 'YYYY-MM-DD'
}

const pool = new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: parseInt(process.env.POSTGRES_PORT, 10) || 5432,
    database: process.env.POSTGRES_DB || 'vuln_dashboard',
    user: process.env.POSTGRES_USER || 'vuln_user',
    password: process.env.POSTGRES_PASSWORD || 'vuln_password',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

// An error on an idle pooled client is emitted on the pool itself. Without a
// listener this is an unhandled 'error' event and takes the process down.
pool.on('error', (err) => {
    console.error('[DB] Idle client error:', err.message);
});

function getDb() {
    return pool;
}

async function initDb() {
    const client = await pool.connect();
    try {
        const schemaPath = path.join(__dirname, 'schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf-8');
        await client.query(schema);
        console.log('[DB] Schema initialized');
    } finally {
        client.release();
    }
}

async function closeDb() {
    await pool.end();
}

module.exports = { getDb, initDb, closeDb };
