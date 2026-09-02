import axios from './services/api';

export async function getVulnerabilities(params = {}) {
    const response = await axios.get('/api/vulnerabilities', { params });
    return response.data;
}

export async function getFilterOptions() {
    const response = await axios.get('/api/filter-options');
    return response.data;
}

export async function triggerFetch() {
    const response = await axios.post('/api/fetch');
    return response.data;
}

export async function getAlerts(limit = 50) {
    const response = await axios.get(`/api/alerts?limit=${limit}`);
    return response.data;
}

export async function getVulnerabilityCount() {
    const response = await axios.get('/api/vulnerabilities/count');
    return response.data;
}
