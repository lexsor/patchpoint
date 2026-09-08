require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { initDb, closeDb } = require('./db/client');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const watchlistRoutes = require('./routes/watchlist');
const { startPolling, stopPolling } = require('./services/scheduler');
const { corsOptions, crossSiteGuard, securityHeaders } = require('./middleware/security');

const PORT = parseInt(process.env.PORT, 10) || 3001;
// Inside a container this must be 0.0.0.0 for nginx to reach it across the
// compose network; a bare `npm start` on a workstation should not expose the
// unauthenticated API to the LAN, hence the loopback default.
const HOST = process.env.HOST || '127.0.0.1';
const POLL_INTERVAL_HOURS = parseFloat(process.env.POLL_INTERVAL_HOURS) || 6;

const app = express();

app.use(securityHeaders);
app.use(cors(corsOptions()));
app.use(crossSiteGuard);
app.use(express.json({ limit: '64kb' }));

app.use('/api', vulnerabilityRoutes);
app.use('/api/watchlist', watchlistRoutes);

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use((req, res) => {
    res.status(404).json({ error: 'Not found' });
});

// Express needs four parameters to recognise this as an error handler.
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
    console.error('[Server] Unhandled error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
});

async function start() {
    try {
        await initDb();

        const server = app.listen(PORT, HOST, () => {
            console.log(`[Server] Listening on http://${HOST}:${PORT}`);
            startPolling(POLL_INTERVAL_HOURS);
        });

        registerShutdown(server);
    } catch (err) {
        console.error('[Server] Failed to start:', err.message);
        process.exit(1);
    }
}

/**
 * Drain the interval, the HTTP server and the connection pool on shutdown.
 * Without this, `docker compose down` killed the process mid-transaction and
 * left pooled connections for PostgreSQL to time out on its own.
 */
function registerShutdown(server) {
    let shuttingDown = false;

    const shutdown = async (signal) => {
        if (shuttingDown) return;
        shuttingDown = true;
        console.log(`[Server] ${signal} received, shutting down`);

        stopPolling();
        server.close(async () => {
            try {
                await closeDb();
            } catch (err) {
                console.error('[Server] Error closing database pool:', err.message);
            }
            process.exit(0);
        });

        // Do not hang forever on a lingering keep-alive connection.
        setTimeout(() => process.exit(0), 10000).unref();
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
}

start();
