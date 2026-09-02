jest.mock('../src/models/repository');
jest.mock('../src/models/fetcher-orchestrator', () => ({
    fetchAllSources: jest.fn(),
    getFetchStatus: jest.fn(() => ({ isFetching: false })),
    SOURCE_CISA: 'CISA KEV',
    SOURCE_NVD: 'NVD',
    SOURCE_MITRE: 'MITRE CVEW',
}));
jest.mock('../src/models/alert-engine');

const express = require('express');
const request = require('supertest');

const repository = require('../src/models/repository');
const orchestrator = require('../src/models/fetcher-orchestrator');
const alertEngine = require('../src/models/alert-engine');
const vulnerabilityRoutes = require('../src/routes/vulnerabilities');

function makeApp() {
    const app = express();
    app.use(express.json());
    app.use('/api', vulnerabilityRoutes);
    return app;
}

const EMPTY_PAGE = { data: [], pagination: { page: 1, perPage: 25, total: 0, totalPages: 0 } };

beforeEach(() => {
    jest.clearAllMocks();
    repository.queryVulnerabilities.mockResolvedValue(EMPTY_PAGE);
    repository.getCount.mockResolvedValue(42);
    repository.getById.mockResolvedValue(null);
    repository.getSources.mockResolvedValue([]);
    repository.getSeverities.mockResolvedValue(['CRITICAL']);
    repository.getVendors.mockResolvedValue(['Atlassian']);
    repository.getTechTypes.mockResolvedValue(['web']);
    alertEngine.getAlerts.mockResolvedValue([]);
    alertEngine.getAlertCount.mockResolvedValue(0);
    alertEngine.clearAlerts.mockResolvedValue(3);
    orchestrator.getFetchStatus.mockReturnValue({ isFetching: false });
});

describe('route registration order', () => {
    test('GET /api/vulnerabilities/count reaches the count handler', async () => {
        // Registered after /vulnerabilities/:cveId, this returned 404 because
        // Express matched 'count' as a CVE ID.
        const res = await request(makeApp()).get('/api/vulnerabilities/count');

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ count: 42 });
        expect(repository.getCount).toHaveBeenCalled();
        expect(repository.getById).not.toHaveBeenCalled();
    });

    test('GET /api/vulnerabilities/:cveId still resolves a real CVE ID', async () => {
        repository.getById.mockResolvedValue({ cve_id: 'CVE-2024-1234' });

        const res = await request(makeApp()).get('/api/vulnerabilities/CVE-2024-1234');

        expect(res.status).toBe(200);
        expect(res.body.cve_id).toBe('CVE-2024-1234');
    });

    test('GET /api/vulnerabilities/:cveId 404s for an unknown CVE', async () => {
        const res = await request(makeApp()).get('/api/vulnerabilities/CVE-0000-0000');
        expect(res.status).toBe(404);
    });
});

describe('query parameter validation', () => {
    const paramsFor = () => repository.queryVulnerabilities.mock.calls[0][0];

    test('a non-numeric page falls back to 1', async () => {
        await request(makeApp()).get('/api/vulnerabilities?page=abc');
        expect(paramsFor().page).toBe(1);
    });

    test('page=0 and negative pages fall back to 1', async () => {
        await request(makeApp()).get('/api/vulnerabilities?page=0');
        expect(paramsFor().page).toBe(1);

        repository.queryVulnerabilities.mockClear();
        await request(makeApp()).get('/api/vulnerabilities?page=-5');
        expect(paramsFor().page).toBe(1);
    });

    test('perPage is clamped to the maximum', async () => {
        await request(makeApp()).get('/api/vulnerabilities?perPage=1000000');
        expect(paramsFor().perPage).toBe(200);
    });

    test('a repeated parameter does not crash the handler', async () => {
        // `?sortOrder=DESC&sortOrder=ASC` arrives as an array; calling
        // .toUpperCase() on it used to throw and return 500.
        const res = await request(makeApp()).get('/api/vulnerabilities?sortOrder=DESC&sortOrder=ASC');

        expect(res.status).toBe(200);
        expect(typeof paramsFor().sortOrder).toBe('string');
    });

    test('kevFlag accepts only true/false', async () => {
        await request(makeApp()).get('/api/vulnerabilities?kevFlag=true');
        expect(paramsFor().kevFlag).toBe(true);

        repository.queryVulnerabilities.mockClear();
        await request(makeApp()).get('/api/vulnerabilities?kevFlag=maybe');
        expect(paramsFor().kevFlag).toBeUndefined();
    });

    test('blank filters are treated as absent', async () => {
        await request(makeApp()).get('/api/vulnerabilities?vendor=&severity=');
        expect(paramsFor().vendor).toBeUndefined();
        expect(paramsFor().severity).toBeUndefined();
    });

    test('alert limit is clamped', async () => {
        await request(makeApp()).get('/api/alerts?limit=99999');
        expect(alertEngine.getAlerts).toHaveBeenCalledWith(500);
    });
});

describe('POST /api/fetch', () => {
    test('409s while a fetch is already running', async () => {
        orchestrator.getFetchStatus.mockReturnValue({ isFetching: true });

        const res = await request(makeApp()).post('/api/fetch');

        expect(res.status).toBe(409);
        expect(orchestrator.fetchAllSources).not.toHaveBeenCalled();
    });

    test('reports per-source results', async () => {
        orchestrator.fetchAllSources.mockResolvedValue({
            started_at: '2024-06-01T00:00:00.000Z',
            finished_at: '2024-06-01T00:05:00.000Z',
            'CISA KEV': { total: 1200, error: null },
            NVD: { total: 3400, error: null },
            'MITRE CVEW': { total: 25, error: null },
            alerts: 2,
            error: null,
        });

        const res = await request(makeApp()).post('/api/fetch');

        expect(res.status).toBe(200);
        expect(res.body.success).toBe(true);
        expect(res.body.sources['CISA KEV'].total).toBe(1200);
        expect(res.body.alerts).toBe(2);
    });

    test('success is false when any source errored', async () => {
        orchestrator.fetchAllSources.mockResolvedValue({
            started_at: 'x',
            finished_at: 'y',
            'CISA KEV': { total: 1200, error: null },
            NVD: { total: 0, error: 'NVD HTTP 429' },
            'MITRE CVEW': { total: 0, error: null },
            alerts: 0,
            error: null,
        });

        const res = await request(makeApp()).post('/api/fetch');

        expect(res.body.success).toBe(false);
        expect(res.body.sources.NVD.error).toBe('NVD HTTP 429');
    });
});

describe('DELETE /api/alerts', () => {
    test('clears every alert, matching what the endpoint advertises', async () => {
        const res = await request(makeApp()).delete('/api/alerts');

        expect(res.status).toBe(200);
        expect(res.body).toEqual({ success: true, deleted: 3 });
        expect(alertEngine.clearAlerts).toHaveBeenCalled();
    });
});

describe('GET /api/filter-options', () => {
    test('includes the source list so the UI cannot drift from the fetchers', async () => {
        const res = await request(makeApp()).get('/api/filter-options');

        expect(res.status).toBe(200);
        expect(res.body.sources).toEqual(['CISA KEV', 'NVD', 'MITRE CVEW']);
        expect(res.body.severities).toEqual(['CRITICAL']);
    });
});

describe('error handling', () => {
    test('a repository failure becomes a 500, not a hang', async () => {
        repository.queryVulnerabilities.mockRejectedValue(new Error('db down'));

        const res = await request(makeApp()).get('/api/vulnerabilities');

        expect(res.status).toBe(500);
        expect(res.body.error).toBe('Failed to fetch vulnerabilities');
    });
});
