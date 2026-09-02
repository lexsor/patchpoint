const express = require('express');
const router = express.Router();
const repository = require('../models/repository');
const { fetchAllSources, getFetchStatus, SOURCE_CISA, SOURCE_NVD, SOURCE_MITRE } = require('../models/fetcher-orchestrator');
const { getAlerts, getAlertCount, clearAlerts } = require('../models/alert-engine');
const { SEVERITY_LEVELS } = require('../lib/severity');

const DEFAULT_PER_PAGE = 25;
const MAX_PER_PAGE = 200;
const DEFAULT_ALERT_LIMIT = 50;
const MAX_ALERT_LIMIT = 500;

/**
 * Query strings are attacker-controlled and Express hands back a string, an
 * array (`?x=1&x=2`) or undefined. Coerce and clamp before anything reaches
 * SQL: an unvalidated `?page=abc` previously produced `OFFSET NaN` and
 * `?page=0` produced a negative offset.
 */
function toPositiveInt(value, fallback, max) {
    const raw = Array.isArray(value) ? value[0] : value;
    const parsed = parseInt(raw, 10);
    if (!Number.isFinite(parsed) || parsed < 1) return fallback;
    return max ? Math.min(parsed, max) : parsed;
}

function toStringParam(value) {
    const raw = Array.isArray(value) ? value[0] : value;
    return typeof raw === 'string' && raw.trim() !== '' ? raw.trim() : undefined;
}

function toBoolParam(value) {
    const raw = toStringParam(value);
    if (raw === undefined) return undefined;
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    return undefined;
}

// GET /api/vulnerabilities - List vulnerabilities with filters
router.get('/vulnerabilities', async (req, res) => {
    try {
        const result = await repository.queryVulnerabilities({
            page: toPositiveInt(req.query.page, 1),
            perPage: toPositiveInt(req.query.perPage, DEFAULT_PER_PAGE, MAX_PER_PAGE),
            sortBy: toStringParam(req.query.sortBy) || 'published_date',
            sortOrder: toStringParam(req.query.sortOrder) || 'DESC',
            source: toStringParam(req.query.source),
            severity: toStringParam(req.query.severity),
            startDate: toStringParam(req.query.startDate),
            endDate: toStringParam(req.query.endDate),
            vendor: toStringParam(req.query.vendor),
            techType: toStringParam(req.query.techType),
            kevFlag: toBoolParam(req.query.kevFlag),
            search: toStringParam(req.query.search),
        });

        res.json(result);
    } catch (err) {
        console.error('Error fetching vulnerabilities:', err.message);
        res.status(500).json({ error: 'Failed to fetch vulnerabilities' });
    }
});

// GET /api/vulnerabilities/count - Total count.
// MUST stay above /vulnerabilities/:cveId: Express matches in registration
// order, so a `:cveId` route declared first swallows 'count' as an ID.
router.get('/vulnerabilities/count', async (req, res) => {
    try {
        const count = await repository.getCount();
        res.json({ count });
    } catch (err) {
        console.error('Error getting count:', err.message);
        res.status(500).json({ error: 'Failed to get count' });
    }
});

// GET /api/vulnerabilities/:cveId - Get single vulnerability
router.get('/vulnerabilities/:cveId', async (req, res) => {
    try {
        const vulnerability = await repository.getById(req.params.cveId);

        if (!vulnerability) {
            return res.status(404).json({ error: 'Vulnerability not found' });
        }

        res.json(vulnerability);
    } catch (err) {
        console.error('Error fetching vulnerability:', err.message);
        res.status(500).json({ error: 'Failed to fetch vulnerability' });
    }
});

// GET /api/sources - List all sources
router.get('/sources', async (req, res) => {
    try {
        const sources = await repository.getSources();
        res.json({ sources });
    } catch (err) {
        console.error('Error fetching sources:', err.message);
        res.status(500).json({ error: 'Failed to fetch sources' });
    }
});

// GET /api/filter-options - Get available filter values
router.get('/filter-options', async (req, res) => {
    try {
        const [vendors, techTypes] = await Promise.all([
            repository.getVendors(),
            repository.getTechTypes(),
        ]);

        res.json({
            // Severity and source are closed vocabularies, so they are served
            // as constants. Vendor and technology genuinely depend on what has
            // been ingested, so those stay data-derived.
            severities: SEVERITY_LEVELS,
            sources: [SOURCE_CISA, SOURCE_NVD, SOURCE_MITRE],
            vendors,
            techTypes,
        });
    } catch (err) {
        console.error('Error fetching filter options:', err.message);
        res.status(500).json({ error: 'Failed to fetch filter options' });
    }
});

// POST /api/fetch - Trigger manual fetch
router.post('/fetch', async (req, res) => {
    try {
        if (getFetchStatus().isFetching) {
            return res.status(409).json({ error: 'Fetch already in progress' });
        }

        const result = await fetchAllSources();

        if (result.reason === 'already_fetching') {
            return res.status(409).json({ error: 'Fetch already in progress' });
        }

        const sources = {};
        for (const name of [SOURCE_CISA, SOURCE_NVD, SOURCE_MITRE]) {
            sources[name] = result[name] || { total: 0, error: 'not run' };
        }

        // Only a source that actually errored counts against success.
        const failed = Object.values(sources).filter((s) => s.error).length;

        res.json({
            success: !result.error && failed === 0,
            sources,
            alerts: result.alerts,
            started_at: result.started_at,
            finished_at: result.finished_at,
            error: result.error,
        });
    } catch (err) {
        console.error('Error triggering fetch:', err.message);
        res.status(500).json({ error: 'Failed to trigger fetch' });
    }
});

// GET /api/fetch/status - Get fetch status
router.get('/fetch/status', (req, res) => {
    res.json(getFetchStatus());
});

// GET /api/alerts - Get alerts
router.get('/alerts', async (req, res) => {
    try {
        const limit = toPositiveInt(req.query.limit, DEFAULT_ALERT_LIMIT, MAX_ALERT_LIMIT);
        const [alerts, total] = await Promise.all([getAlerts(limit), getAlertCount()]);
        res.json({ alerts, total });
    } catch (err) {
        console.error('Error fetching alerts:', err.message);
        res.status(500).json({ error: 'Failed to fetch alerts' });
    }
});

// DELETE /api/alerts - Clear all alerts
router.delete('/alerts', async (req, res) => {
    try {
        const deleted = await clearAlerts();
        res.json({ success: true, deleted });
    } catch (err) {
        console.error('Error clearing alerts:', err.message);
        res.status(500).json({ error: 'Failed to clear alerts' });
    }
});

module.exports = router;
