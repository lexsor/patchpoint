/**
 * Scheduler
 *
 * Owns the periodic fetch timer. This is the only polling implementation —
 * index.js previously carried an inline duplicate of it while this module sat
 * unused, so the two could drift apart.
 */

const { fetchAllSources } = require('../models/fetcher-orchestrator');

let pollingTimer = null;

/**
 * Start periodic polling, running one fetch immediately.
 * @param {number} intervalHours
 */
function startPolling(intervalHours = 6) {
    stopPolling();

    const intervalMs = Math.max(intervalHours, 0.1) * 60 * 60 * 1000;

    fetchAllSources().catch((err) => console.error('[Scheduler] Initial fetch failed:', err.message));

    pollingTimer = setInterval(() => {
        console.log(`[Scheduler] Polling at ${new Date().toISOString()}`);
        fetchAllSources().catch((err) => console.error('[Scheduler] Polling failed:', err.message));
    }, intervalMs);

    console.log(`[Scheduler] Polling every ${intervalHours} hour(s)`);
}

function stopPolling() {
    if (pollingTimer) {
        clearInterval(pollingTimer);
        pollingTimer = null;
        console.log('[Scheduler] Polling stopped');
    }
}

function isPolling() {
    return pollingTimer !== null;
}

module.exports = { startPolling, stopPolling, isPolling };
