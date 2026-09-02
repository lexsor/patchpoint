require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { initDb } = require('./db/client');
const vulnerabilityRoutes = require('./routes/vulnerabilities');
const watchlistRoutes = require('./routes/watchlist');
const { fetchAllSources } = require('./models/fetcher-orchestrator');

const PORT = process.env.PORT || 3001;
const POLL_INTERVAL = parseInt(process.env.POLL_INTERVAL_HOURS) || 6;

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Routes
app.use('/api', vulnerabilityRoutes);
app.use('/api/watchlist', watchlistRoutes);

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Initialize database and start server
async function start() {
    try {
        await initDb();
        console.log('Database initialized');
        
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
            
            // Start periodic polling
            startPolling();
        });
    } catch (err) {
        console.error('Failed to start server:', err);
        process.exit(1);
    }
}

function startPolling() {
    // Fetch immediately on startup
    fetchAllSources().catch(err => console.error('Initial fetch failed:', err));
    
    // Then poll at interval
    setInterval(() => {
        console.log(`[Scheduler] Polling at ${new Date().toISOString()}`);
        fetchAllSources().catch(err => console.error('Polling failed:', err));
    }, POLL_INTERVAL * 60 * 60 * 1000);
    
    console.log(`[Scheduler] Polling every ${POLL_INTERVAL} hours`);
}

start();
