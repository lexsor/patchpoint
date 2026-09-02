import axios from 'axios';

// Same-origin by default: in dev Vite proxies /api to the backend, in
// production nginx does. VITE_API_BASE overrides it for a split deployment.
const client = axios.create({
    baseURL: import.meta.env.VITE_API_BASE || '',
    timeout: 30000,
});

// A full fetch cycle walks several upstream APIs and can outlive the default
// timeout, so this one call gets a longer budget.
const FETCH_TIMEOUT_MS = 15 * 60 * 1000;

export async function getVulnerabilities(params = {}) {
    const response = await client.get('/api/vulnerabilities', { params });
    return response.data;
}

export async function getVulnerability(cveId) {
    const response = await client.get(`/api/vulnerabilities/${encodeURIComponent(cveId)}`);
    return response.data;
}

export async function getVulnerabilityCount() {
    const response = await client.get('/api/vulnerabilities/count');
    return response.data;
}

export async function getFilterOptions() {
    const response = await client.get('/api/filter-options');
    return response.data;
}

export async function getSources() {
    const response = await client.get('/api/sources');
    return response.data;
}

export async function triggerFetch() {
    const response = await client.post('/api/fetch', null, { timeout: FETCH_TIMEOUT_MS });
    return response.data;
}

export async function getFetchStatus() {
    const response = await client.get('/api/fetch/status');
    return response.data;
}

export async function getAlerts(limit = 50) {
    const response = await client.get('/api/alerts', { params: { limit } });
    return response.data;
}

export async function clearAlerts() {
    const response = await client.delete('/api/alerts');
    return response.data;
}

export async function getWatchlist() {
    const response = await client.get('/api/watchlist');
    return response.data;
}

export async function addWatchlistItem(item, itemType) {
    const response = await client.post('/api/watchlist', { item, itemType });
    return response.data;
}

export async function removeWatchlistItem(id) {
    const response = await client.delete(`/api/watchlist/${encodeURIComponent(id)}`);
    return response.data;
}
