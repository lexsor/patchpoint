const express = require('express');
const router = express.Router();
const { getDb } = require('../db/client');

// GET /api/watchlist - Get all watchlist items
router.get('/', async (req, res) => {
    try {
        const db = getDb();
        const result = await db.query('SELECT * FROM watchlist ORDER BY created_at DESC');
        res.json({ items: result.rows });
    } catch (err) {
        console.error('Error fetching watchlist:', err.message);
        res.status(500).json({ error: 'Failed to fetch watchlist' });
    }
});

// POST /api/watchlist - Add watchlist item
router.post('/', async (req, res) => {
    try {
        const { item, itemType } = req.body;
        
        if (!item || !itemType) {
            return res.status(400).json({ error: 'item and itemType are required' });
        }
        
        if (!['cve_id', 'vendor', 'product'].includes(itemType)) {
            return res.status(400).json({ error: 'itemType must be cve_id, vendor, or product' });
        }
        
        const db = getDb();
        const result = await db.query(
            'INSERT INTO watchlist (item, item_type) VALUES ($1, $2) RETURNING *',
            [item, itemType]
        );
        
        res.status(201).json({ item: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') { // duplicate key
            return res.status(409).json({ error: 'Watchlist item already exists' });
        }
        console.error('Error adding watchlist item:', err.message);
        res.status(500).json({ error: 'Failed to add watchlist item' });
    }
});

// DELETE /api/watchlist/:id - Remove watchlist item
router.delete('/:id', async (req, res) => {
    try {
        const db = getDb();
        await db.query('DELETE FROM watchlist WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('Error removing watchlist item:', err.message);
        res.status(500).json({ error: 'Failed to remove watchlist item' });
    }
});

module.exports = router;
