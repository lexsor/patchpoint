const { getDb } = require('../db/client');
const { mergeRecords, classifySeverity } = require('../models/deduplication');

class VulnerabilityRepository {
    // Store vulnerabilities with deduplication
    async storeRecords(records, sourceName) {
        const db = getDb();
        const client = await db.connect();
        
        try {
            await client.query('BEGIN');
            
            // First, get existing records for deduplication
            const result = await client.query('SELECT cve_id, source_labels, cvss_score, severity FROM vulnerabilities');
            const existing = new Map();
            for (const row of result.rows) {
                existing.set(row.cve_id, {
                    source_labels: row.source_labels,
                    cvss_score: row.cvss_score,
                    severity: row.severity,
                });
            }
            
            // Merge using deduplication logic
            const merged = mergeRecords(existing, records, sourceName);
            
            // Upsert each merged record
            for (const [cveId, record] of merged) {
                const sourceLabels = JSON.stringify(record.source_labels || 
                    (existing.has(cveId) ? JSON.parse(existing.get(cveId).source_labels) : [sourceName]));
                
                const cvssScore = record.cvss_score ?? (existing.has(cveId) ? existing.get(cveId).cvss_score : null);
                const severity = record.severity || classifySeverity(cvssScore || 0);
                
                await client.query(`
                    INSERT INTO vulnerabilities (
                        cve_id, title, description, severity, cvss_score, cvss_vector,
                        published_date, modified_date, source_labels, vendor, product,
                        tech_type, kev_flag, kev_date_added, references, cwes
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                    ON CONFLICT (cve_id) DO UPDATE SET
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        severity = EXCLUDED.severity,
                        cvss_score = EXCLUDED.cvss_score,
                        cvss_vector = EXCLUDED.cvss_vector,
                        published_date = EXCLUDED.published_date,
                        modified_date = EXCLUDED.modified_date,
                        source_labels = EXCLUDED.source_labels,
                        vendor = COALESCE(EXCLUDED.vendor, vulnerabilities.vendor),
                        product = COALESCE(EXCLUDED.product, vulnerabilities.product),
                        tech_type = COALESCE(EXCLUDED.tech_type, vulnerabilities.tech_type),
                        kev_flag = vulnerabilities.kev_flag OR EXCLUDED.kev_flag,
                        kev_date_added = COALESCE(EXCLUDED.kev_date_added, vulnerabilities.kev_date_added),
                        references = EXCLUDED.references,
                        cwes = EXCLUDED.cwes,
                        updated_at = CURRENT_TIMESTAMP
                `, [
                    cveId, record.title || '', record.description || '', severity,
                    cvssScore, record.cvss_vector || '',
                    record.published_date || new Date().toISOString().split('T')[0],
                    record.modified_date || new Date().toISOString().split('T')[0],
                    sourceLabels, record.vendor || '', record.product || '',
                    record.tech_type || '', record.kev_flag || false,
                    record.kev_date_added || null,
                    record.references || '[]',
                    record.cwes || '[]'
                ]);
            }
            
            await client.query('COMMIT');
            console.log(`[Repository] Stored ${merged.size} unique CVEs from ${sourceName}`);
            return merged.size;
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    }
    
    // Record source fetch metadata
    async updateSource(name, totalFetched) {
        const db = getDb();
        await db.query(`
            INSERT INTO sources (name, url, last_fetched, total_fetched, confidence_level)
            VALUES ($1, $2, CURRENT_TIMESTAMP, $3, 'high')
            ON CONFLICT (name) DO UPDATE SET
                last_fetched = CURRENT_TIMESTAMP,
                total_fetched = sources.total_fetched + $3
        `, [name, '', totalFetched]);
    }
    
    // Query vulnerabilities with filters
    async queryVulnerabilities({
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
        search
    } = {}) {
        const db = getDb();
        const whereClauses = [];
        const params = [];
        let paramIndex = 1;
        
        if (source) {
            whereClauses.push(`source_labels ILIKE $${paramIndex++}`);
            params.push(`%"${source}"%`);
        }
        if (severity) {
            whereClauses.push(`severity = $${paramIndex++}`);
            params.push(severity);
        }
        if (startDate) {
            whereClauses.push(`published_date >= $${paramIndex++}`);
            params.push(startDate);
        }
        if (endDate) {
            whereClauses.push(`published_date <= $${paramIndex++}`);
            params.push(endDate);
        }
        if (vendor) {
            whereClauses.push(`vendor ILIKE $${paramIndex++}`);
            params.push(`%${vendor}%`);
        }
        if (techType) {
            whereClauses.push(`tech_type = $${paramIndex++}`);
            params.push(techType);
        }
        if (kevFlag !== undefined) {
            whereClauses.push(`kev_flag = $${paramIndex++}`);
            params.push(kevFlag);
        }
        if (search) {
            const searchPattern = `%${search}%`;
            whereClauses.push(`(
                cve_id ILIKE $${paramIndex} OR 
                description ILIKE $${paramIndex} OR 
                vendor ILIKE $${paramIndex} OR 
                product ILIKE $${paramIndex}
            )`);
            params.push(searchPattern);
            paramIndex++;
        }
        
        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
        
        // Validate sort column
        const validSortColumns = ['cve_id', 'severity', 'cvss_score', 'published_date', 'modified_date', 'vendor', 'tech_type'];
        const validOrders = ['ASC', 'DESC'];
        const sortCol = validSortColumns.includes(sortBy) ? sortBy : 'published_date';
        const sortOrd = validOrders.includes(sortOrder.toUpperCase()) ? 'DESC' : 'DESC';
        
        // Get total count
        const countResult = await db.query(`SELECT COUNT(*) as count FROM vulnerabilities ${whereSql}`, params);
        const total = parseInt(countResult.rows[0].count);
        
        // Get paginated results
        const offset = (page - 1) * perPage;
        const dataResult = await db.query(`
            SELECT * FROM vulnerabilities ${whereSql}
            ORDER BY ${sortCol} ${sortOrd}
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `, [...params, perPage, offset]);
        
        return {
            data: dataResult.rows,
            pagination: {
                page,
                perPage,
                total,
                totalPages: Math.ceil(total / perPage)
            }
        };
    }
    
    // Get all unique sources
    async getSources() {
        const db = getDb();
        return (await db.query('SELECT * FROM sources ORDER BY last_fetched DESC')).rows;
    }
    
    // Get all unique severities
    async getSeverities() {
        const db = getDb();
        const result = await db.query('SELECT DISTINCT severity FROM vulnerabilities WHERE severity IS NOT NULL ORDER BY severity');
        return result.rows.map(r => r.severity);
    }
    
    // Get all unique vendors
    async getVendors() {
        const db = getDb();
        const result = await db.query('SELECT DISTINCT vendor FROM vulnerabilities WHERE vendor != \'\''+ ' ORDER BY vendor');
        return result.rows.map(r => r.vendor);
    }
    
    // Get all unique tech types
    async getTechTypes() {
        const db = getDb();
        const result = await db.query('SELECT DISTINCT tech_type FROM vulnerabilities WHERE tech_type != \'\''+ ' ORDER BY tech_type');
        return result.rows.map(r => r.tech_type);
    }
    
    // Get total count of stored vulnerabilities
    async getCount() {
        const db = getDb();
        const result = await db.query('SELECT COUNT(*) as count FROM vulnerabilities');
        return parseInt(result.rows[0].count);
    }
}

module.exports = new VulnerabilityRepository();
