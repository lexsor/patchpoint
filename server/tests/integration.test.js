const request = require('supertest');
const express = require('express');
const cors = require('cors');

// We'll create a minimal app for integration testing
const { getDb, initDb } = require('../src/db/client');

describe('API Integration Test', () => {
    let app;
    
    beforeAll(async () => {
        // Use in-memory SQLite for testing
        process.env.SQLITE_PATH = ':memory:';
        
        // Import fresh
        delete require.cache[require.resolve('../src/db/client')];
        delete require.cache[require.resolve('../src/models/repository')];
        delete require.cache[require.resolve('../src/models/deduplication')];
        
        const { initDb: initDbFn } = require('../src/db/client');
        initDbFn();
        
        const { getDb: getDbFn } = require('../src/db/client');
        const repo = require('../src/models/repository');
        
        app = express();
        app.use(cors());
        app.use(express.json());
        
        // Minimal test routes
        app.get('/api/vulnerabilities', async (req, res) => {
            try {
                const result = await repo.queryVulnerabilities({
                    page: parseInt(req.query.page) || 1,
                    perPage: parseInt(req.query.perPage) || 25,
                    sortBy: req.query.sortBy || 'published_date',
                    sortOrder: req.query.sortOrder || 'DESC',
                    search: req.query.search,
                    severity: req.query.severity,
                    vendor: req.query.vendor,
                });
                res.json(result);
            } catch (err) {
                res.status(500).json({ error: err.message });
            }
        });
        
        app.get('/api/vulnerabilities/count', async (req, res) => {
            const count = await repo.getCount();
            res.json({ count });
        });
    });

    afterAll(async () => {
        const { closeDb } = require('../src/db/client');
        closeDb();
    });

    test('POST seed data, GET fetches it', async () => {
        const db = getDb();
        
        // Seed test data
        await db.query(`
            INSERT INTO vulnerabilities (cve_id, title, description, severity, cvss_score, published_date, source_labels)
            VALUES 
            ('CVE-2024-1234', 'Test CVE 1', 'A test vulnerability', 'HIGH', 7.5, '2024-01-15', '["NVD"]'),
            ('CVE-2024-5678', 'Test CVE 2', 'Another test', 'CRITICAL', 9.1, '2024-02-20', '["CISA KEV"]'),
            ('CVE-2024-9999', 'Test CVE 3', 'Third test', 'MEDIUM', 5.0, '2024-03-10', '["MITRE CVEW"]')
        `);
        
        // Test listing
        const res = await request(app).get('/api/vulnerabilities');
        expect(res.status).toBe(200);
        expect(res.body.data).toBeDefined();
        expect(Array.isArray(res.body.data)).toBe(true);
        expect(res.body.data.length).toBe(3);
        expect(res.body.pagination).toBeDefined();
        expect(res.body.pagination.total).toBe(3);
        
        // Test search
        const searchRes = await request(app).get('/api/vulnerabilities').query({ search: 'CVE-2024-1234' });
        expect(searchRes.status).toBe(200);
        expect(searchRes.body.data.length).toBe(1);
        expect(searchRes.body.data[0].cve_id).toBe('CVE-2024-1234');
        
        // Test severity filter
        const sevRes = await request(app).get('/api/vulnerabilities').query({ severity: 'CRITICAL' });
        expect(sevRes.status).toBe(200);
        expect(sevRes.body.data.length).toBe(1);
        expect(sevRes.body.data[0].severity).toBe('CRITICAL');
        
        // Test count
        const countRes = await request(app).get('/api/vulnerabilities/count');
        expect(countRes.status).toBe(200);
        expect(countRes.body.count).toBe(3);
    });

    test('filters work correctly', async () => {
        const res = await request(app).get('/api/vulnerabilities').query({ 
            severity: 'HIGH',
            sortBy: 'cvss_score',
            sortOrder: 'DESC',
        });
        expect(res.status).toBe(200);
        expect(res.body.pagination.total).toBe(1);
        expect(res.body.data[0].severity).toBe('HIGH');
    });

    test('pagination works correctly', async () => {
        const res = await request(app).get('/api/vulnerabilities').query({ 
            page: 1, 
            perPage: 2,
        });
        expect(res.status).toBe(200);
        expect(res.body.pagination.total).toBe(3);
        expect(res.body.pagination.totalPages).toBe(2);
        expect(res.body.data.length).toBe(2);
        
        const res2 = await request(app).get('/api/vulnerabilities').query({ 
            page: 2, 
            perPage: 2,
        });
        expect(res2.body.data.length).toBe(1);
    });
});
