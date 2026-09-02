const express = require('express');
const router = express.Router();
const repository = require('../../models/repository');
const { fetchAllSources, getFetchStatus } = require('../../models/fetcher-orchestrator');
const { getAlerts, getAlertCount, clearAlerts } = require('../../models/alert-engine');

// GET /api/vulnerabilities - List vulnerabilities with filters
router.get('/vulnerabilities', async (req, res) => {
    try {
        const {
            page = 1,
            perPage = 25,
            sortBy = 'published_date',
            sortOrder = 'DESC',
            source,
            severity,
            startDate,
            endDate,
            vendor,
            techType,
            kevFlag,
            search,
        } = req.query;
        
        const result = await repository.queryVulnerabilities({
            page: parseInt(page),
            perPage: parseInt(perPage),
            sortBy,
            sortOrder,
            source,
            severity,
            startDate,
            endDate,
            vendor,
            techType,
            kevFlag: kevFlag !== undefined ? kevFlag === 'true' : undefined,
            search,
        });
        
        res.json(result);
    } catch (err) {
        console.error('Error fetching vulnerabilities:', err.message);
        res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
    }
});

// GET /api/vulnerabilities/:cveId - Get single vulnerability
router.get('/vulnerabilities/:cveId', async (req, res) => {
    try {
        const db = require('../../db/client').getDb();
        const result = await db.query(
            'SELECT * FROM vulnerabilities WHERE cve_id = $1',
            [req.params.cveId.toUpperCase().replace(/\s/g, '')]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Vulnerability not found' });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch vulnerability' });
    }
});

// GET /api/vulnerabilities/count - Get total count
router.get('/vulnerabilities/count', async (req, res) => {
    try {
        const count = await repository.getCount();
        res.json({ count });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get count' });
    }
});

// GET /api/sources - List all sources
router.get('/sources', async (req, res) => {
    try {
        const sources = await repository.getSources();
        res.json({ sources });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch sources' });
    }
});

// GET /api/filter-options - Get available filter values
router.get('/filter-options', async (req, res) => {
    try {
        const [severities, vendors, techTypes] = await Promise.all([
            repository.getSeverities(),
            repository.getVendors(),
            repository.getTechTypes(),
        ]);
        
        res.json({
            severities,
            vendors,
            techTypes: techTypes.filter(t => t !== ''),
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch filter options' });
    }
});

// POST /api/fetch - Trigger manual fetch
router.post('/fetch', async (req, res) => {
    try {
        const status = getFetchStatus();
        if (status.isFetching) {
            return res.status(409).json({ error: 'Fetch already in progress' });
        }
        
        const result = await fetchAllSources();
        res.json({
            success: !result.error,
            results: {
                cisa_kev: result.cisa_kev ? { total: result.cisa_kev.total || 0, error: result.cisa_kev.error } : null,
                nvd: result.nvd ? { total: result.nvd.total || 0, error: result.nvd.error } : null,
                mitre_cvew: result.mitre_cvew ? { total: result.mitre_cvew.total || 0, error: result.mitre_cvew.error } : null,
            },
            started_at: result.started_at,
            error: result.error,
        });
    } catch (err) {
        console.error('Error triggering fetch:', err.message);
        res.status(500).json({ error: 'Failed to trigger fetch' });
    }
});

// GET /api/fetch/status - Get fetch status
router.get('/fetch/status', async (req, res) => {
    res.json(getFetchStatus());
});

// GET /api/alerts - Get alerts
router.get('/alerts', async (req, res) => {
    try {
        const alerts = await getAlerts(parseInt(req.query.limit) || 50);
        const count = await getAlertCount();
        res.json({ alerts, total: count });
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch alerts' });
    }
});

// DELETE /api/alerts - Clear all alerts
router.delete('/alerts', async (req, res) => {
    try {
        await clearAlerts();
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to clear alerts' });
    }
});

module.exports = router;
