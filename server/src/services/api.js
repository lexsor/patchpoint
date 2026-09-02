const axios = require('axios');

const API_BASE = process.env.API_BASE || 'http://localhost:3001';

async function getVulnerabilities(params = {}) {
    const response = await axios.get(`${API_BASE}/api/vulnerabilities`, { params });
    return response.data;
}

async function getVulnerabilityById(cveId) {
    const response = await axios.get(`${API_BASE}/api/vulnerabilities/${cveId}`);
    return response.data;
}

async function getVulnerabilityCount() {
    const response = await axios.get(`${API_BASE}/api/vulnerabilities/count`);
    return response.data;
}

async function getSources() {
    const response = await axios.get(`${API_BASE}/api/sources`);
    return response.data;
}

async function getFilterOptions() {
    const response = await axios.get(`${API_BASE}/api/filter-options`);
    return response.data;
}

async function triggerFetch() {
    const response = await axios.post(`${API_BASE}/api/fetch`);
    return response.data;
}

async function getFetchStatus() {
    const response = await axios.get(`${API_BASE}/api/fetch/status`);
    return response.data;
}

async function getAlerts(limit = 50) {
    const response = await axios.get(`${API_BASE}/api/alerts?limit=${limit}`);
    return response.data;
}

async function clearAlerts() {
    const response = await axios.delete(`${API_BASE}/api/alerts`);
    return response.data;
}

async function getWatchlist() {
    const response = await axios.get(`${API_BASE}/api/watchlist`);
    return response.data;
}

async function addWatchlistItem(item, itemType) {
    const response = await axios.post(`${API_BASE}/api/watchlist`, { item, itemType });
    return response.data;
}

async function removeWatchlistItem(id) {
    const response = await axios.delete(`${API_BASE}/api/watchlist/${id}`);
    return response.data;
}

module.exports = {
    getVulnerabilities,
    getVulnerabilityById,
    getVulnerabilityCount,
    getSources,
    getFilterOptions,
    triggerFetch,
    getFetchStatus,
    getAlerts,
    clearAlerts,
    getWatchlist,
    addWatchlistItem,
    removeWatchlistItem,
};
