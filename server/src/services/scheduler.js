/**
 * Scheduler module
 * 
 * Handles periodic fetching of vulnerability data.
 * Configurable via POLL_INTERVAL_HOURS environment variable.
 */

const { fetchAllSources } = require('../models/fetcher-orchestrator');

let pollingInterval = null;

/**
 * Start periodic polling
 * @param {number} intervalHours - Polling interval in hours (default: 6)
 */
function startPolling(intervalHours = 6) {
    if (pollingInterval) {
        stopPolling();
    }
    
    const intervalMs = intervalHours * 60 * 60 * 1000;
    
    // Initial fetch
    fetchAllSources().catch(err => console.error('Initial fetch failed:', err));
    
    // Set up polling interval
    pollingInterval = setInterval(() => {
        console.log(`[Scheduler] Polling at ${new Date().toISOString()}`);
        fetchAllSources().catch(err => console.error('Polling failed:', err));
    }, intervalMs);
    
    console.log(`[Scheduler] Polling started every ${intervalHours} hours`);
}

/**
 * Stop periodic polling
 */
function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
        console.log('[Scheduler] Polling stopped');
    }
}

/**
 * Trigger a manual fetch
 */
async function triggerFetch() {
    try {
        const result = await fetchAllSources();
        return { success: !result.error, results: result };
    } catch (err) {
        return { success: false, error: err.message };
    }
}

module.exports = { startPolling, stopPolling, triggerFetch };
