/**
 * API client.
 *
 * Uses the platform `fetch` rather than a library: there are a dozen simple
 * same-origin JSON calls here, and axios was the single largest non-React
 * dependency in the bundle for that.
 */

// Same-origin: in dev Vite proxies /api to the backend, in production nginx
// does.
//
// VITE_API_BASE can point this at another origin, but note that the CSP in
// nginx-security-headers.conf sets `connect-src 'self'`, which blocks
// cross-origin API calls — widen that directive as well, deliberately, or the
// split deployment will fail at runtime with a CSP violation rather than a
// network error.
const BASE = import.meta.env.VITE_API_BASE || '';

const DEFAULT_TIMEOUT_MS = 30000;
// A full fetch cycle walks several upstream APIs and can outlive the default.
const FETCH_CYCLE_TIMEOUT_MS = 15 * 60 * 1000;

/** Error carrying the HTTP status, so callers can branch on it. */
class ApiError extends Error {
    constructor(message, status, body) {
        super(message);
        this.name = 'ApiError';
        this.status = status;
        this.body = body;
    }
}

function withQuery(path, params) {
    if (!params) return path;

    const search = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
        // Skip empties so an unset filter does not become `?vendor=`.
        if (value === undefined || value === null || value === '') continue;
        search.append(key, String(value));
    }

    const qs = search.toString();
    return qs ? `${path}?${qs}` : path;
}

async function requestJson(path, { method = 'GET', params, body, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
    const options = {
        method,
        headers: { Accept: 'application/json' },
        // AbortSignal.timeout is supported by every browser that runs the
        // rest of this bundle.
        signal: AbortSignal.timeout(timeoutMs),
    };

    if (body !== undefined) {
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify(body);
    }

    let response;
    try {
        response = await fetch(BASE + withQuery(path, params), options);
    } catch (err) {
        // A timeout arrives as an AbortError; everything else is a transport
        // failure. Neither has a status.
        const reason = err.name === 'TimeoutError' || err.name === 'AbortError'
            ? 'Request timed out'
            : 'Network request failed';
        throw new ApiError(reason, 0, null);
    }

    // 204 and other empty bodies must not go through response.json().
    const isJson = (response.headers.get('content-type') || '').includes('application/json');
    const payload = isJson ? await response.json().catch(() => null) : null;

    if (!response.ok) {
        const message = (payload && payload.error) || `Request failed with status ${response.status}`;
        throw new ApiError(message, response.status, payload);
    }

    return payload;
}

export function getVulnerabilities(params = {}) {
    return requestJson('/api/vulnerabilities', { params });
}

export function getVulnerability(cveId) {
    return requestJson(`/api/vulnerabilities/${encodeURIComponent(cveId)}`);
}

export function getVulnerabilityCount() {
    return requestJson('/api/vulnerabilities/count');
}

export function getFilterOptions() {
    return requestJson('/api/filter-options');
}

export function getSources() {
    return requestJson('/api/sources');
}

export function triggerFetch() {
    return requestJson('/api/fetch', { method: 'POST', timeoutMs: FETCH_CYCLE_TIMEOUT_MS });
}

export function getFetchStatus() {
    return requestJson('/api/fetch/status');
}

export function getAlerts(limit = 50) {
    return requestJson('/api/alerts', { params: { limit } });
}

export function clearAlerts() {
    return requestJson('/api/alerts', { method: 'DELETE' });
}

export function getWatchlist() {
    return requestJson('/api/watchlist');
}

export function addWatchlistItem(item, itemType) {
    return requestJson('/api/watchlist', { method: 'POST', body: { item, itemType } });
}

export function removeWatchlistItem(id) {
    return requestJson(`/api/watchlist/${encodeURIComponent(id)}`, { method: 'DELETE' });
}

export { ApiError };
