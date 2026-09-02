const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

// Pool configuration from environment
const pool = new Pool({
    host: process.env.POSTGRES_HOST || 'localhost',
    port: process.env.POSTGRES_PORT || 5432,
    database: process.env.POSTGRES_DB || 'vuln_dashboard',
    user: process.env.POSTGRES_USER || 'vuln_user',
    password: process.env.POSTGRES_PASSWORD || 'vuln_password',
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

let db;

function getDb() {
    if (!db) {
        db = pool;
    }
    return db;
}

async function initDb() {
    const client = await pool.connect();
    try {
        const schemaPath = path.join(__dirname, 'schema.sql');
        const schema = fs.readFileSync(schemaPath, 'utf-8');
        await client.query(schema);
        console.log('Database schema initialized');
    } finally {
        client.release();
    }
}

async function closeDb() {
    await pool.end();
    db = null;
}

module.exports = { getDb, initDb, closeDb };
