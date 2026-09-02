const { getDb } = require('../db/client');
const { mergeRecords, normalizeCveId } = require('./deduplication');

// Column order used by the upsert. `references` is reserved in PostgreSQL, so
// the reference list lives in `reference_urls` on the DB side and is mapped
// to/from `references` on the JS record shape.
const UPSERT_COLUMNS = [
    'cve_id', 'title', 'description', 'severity', 'cvss_score', 'cvss_vector',
    'published_date', 'modified_date', 'source_labels', 'vendor', 'product',
    'tech_type', 'kev_flag', 'kev_date_added', 'reference_urls', 'cwes',
];

// Rows per INSERT statement. 16 columns x 400 rows = 6400 bind parameters,
// comfortably under PostgreSQL's 65535 parameter limit.
const UPSERT_CHUNK_SIZE = 400;

const SELECT_COLUMNS = UPSERT_COLUMNS.join(', ');

/**
 * Non-empty text from the incoming row wins; otherwise the stored value is
 * kept. Guards against a source that reports a field as '' rather than NULL
 * wiping data another source already supplied.
 */
const keepText = (col) => `${col} = COALESCE(NULLIF(EXCLUDED.${col}, ''), vulnerabilities.${col})`;

function buildUpsertSql(rowCount) {
    const valueRows = [];
    for (let r = 0; r < rowCount; r++) {
        const placeholders = UPSERT_COLUMNS.map((_, c) => `$${r * UPSERT_COLUMNS.length + c + 1}`);
        valueRows.push(`(${placeholders.join(', ')})`);
    }

    return `
        INSERT INTO vulnerabilities (${SELECT_COLUMNS})
        VALUES ${valueRows.join(', ')}
        ON CONFLICT (cve_id) DO UPDATE SET
            ${keepText('title')},
            ${keepText('description')},
            ${keepText('severity')},
            cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
            ${keepText('cvss_vector')},
            published_date = COALESCE(EXCLUDED.published_date, vulnerabilities.published_date),
            modified_date = COALESCE(EXCLUDED.modified_date, vulnerabilities.modified_date),
            source_labels = EXCLUDED.source_labels,
            ${keepText('vendor')},
            ${keepText('product')},
            ${keepText('tech_type')},
            kev_flag = vulnerabilities.kev_flag OR EXCLUDED.kev_flag,
            kev_date_added = COALESCE(EXCLUDED.kev_date_added, vulnerabilities.kev_date_added),
            reference_urls = EXCLUDED.reference_urls,
            cwes = EXCLUDED.cwes,
            updated_at = CURRENT_TIMESTAMP
    `;
}

/** DB row -> the in-memory shape the deduplication merge expects. */
function toMergeShape(row) {
    return {
        cve_id: row.cve_id,
        title: row.title || '',
        description: row.description || '',
        severity: row.severity || '',
        cvss_score: row.cvss_score != null ? parseFloat(row.cvss_score) : null,
        cvss_vector: row.cvss_vector || '',
        published_date: row.published_date || null,
        modified_date: row.modified_date || null,
        source_labels: row.source_labels || '[]',
        vendor: row.vendor || '',
        product: row.product || '',
        tech_type: row.tech_type || '',
        kev_flag: row.kev_flag === true,
        kev_date_added: row.kev_date_added || null,
        references: row.reference_urls || '[]',
        cwes: row.cwes || '[]',
    };
}

/** Merged record -> bind parameters, in UPSERT_COLUMNS order. */
function toBindParams(cveId, record) {
    const score = record.cvss_score;
    return [
        cveId,
        record.title || '',
        record.description || '',
        record.severity || '',
        score != null && !Number.isNaN(score) ? score : null,
        record.cvss_vector || '',
        record.published_date || null,
        record.modified_date || null,
        record.source_labels || '[]',
        record.vendor || '',
        record.product || '',
        record.tech_type || '',
        record.kev_flag === true,
        record.kev_date_added || null,
        record.references || '[]',
        record.cwes || '[]',
    ];
}

class VulnerabilityRepository {
    /**
     * Store a batch of records, merging each against whatever is already
     * stored for the same CVE.
     *
     * Only CVEs present in `records` are read and written. Loading the whole
     * table here (as an earlier version did) made every call rewrite every
     * row, and rows absent from the batch were rewritten from a partial
     * projection - blanking title/description/vendor/product and resetting
     * published_date. Scoping to the batch is what prevents that.
     */
    async storeRecords(records, sourceName) {
        const incoming = (Array.isArray(records) ? records : [records]).filter(Boolean);
        const cveIds = [...new Set(incoming.map((r) => normalizeCveId(r.cve_id)).filter(Boolean))];

        if (cveIds.length === 0) {
            console.log(`[Repository] No usable records from ${sourceName}`);
            return 0;
        }

        const client = await getDb().connect();
        try {
            await client.query('BEGIN');

            const result = await client.query(
                `SELECT ${SELECT_COLUMNS} FROM vulnerabilities WHERE cve_id = ANY($1::text[])`,
                [cveIds]
            );

            const existing = new Map();
            for (const row of result.rows) {
                existing.set(row.cve_id, toMergeShape(row));
            }

            // mergeRecords mutates `existing`; because it was seeded only with
            // rows from this batch, the result is exactly this batch's CVEs.
            const merged = mergeRecords(existing, incoming, sourceName);
            const entries = [...merged.entries()];

            for (let i = 0; i < entries.length; i += UPSERT_CHUNK_SIZE) {
                const chunk = entries.slice(i, i + UPSERT_CHUNK_SIZE);
                const params = chunk.flatMap(([cveId, record]) => toBindParams(cveId, record));
                await client.query(buildUpsertSql(chunk.length), params);
            }

            await client.query('COMMIT');
            console.log(`[Repository] Stored ${merged.size} unique CVEs from ${sourceName}`);
            return merged.size;
        } catch (err) {
            await client.query('ROLLBACK').catch(() => {});
            throw err;
        } finally {
            client.release();
        }
    }

    /** Record source fetch metadata. Requires UNIQUE(name) on sources. */
    async updateSource(name, totalFetched) {
        await getDb().query(`
            INSERT INTO sources (name, url, last_fetched, total_fetched, confidence_level)
            VALUES ($1, $2, CURRENT_TIMESTAMP, $3, 'high')
            ON CONFLICT (name) DO UPDATE SET
                last_fetched = CURRENT_TIMESTAMP,
                total_fetched = sources.total_fetched + $3
        `, [name, '', totalFetched]);
    }

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
        search,
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
            whereClauses.push(`(
                cve_id ILIKE $${paramIndex} OR
                description ILIKE $${paramIndex} OR
                vendor ILIKE $${paramIndex} OR
                product ILIKE $${paramIndex}
            )`);
            params.push(`%${search}%`);
            paramIndex++;
        }

        const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        // Sort column and direction are interpolated, so both must come from a
        // fixed allowlist - never from the raw query string.
        const validSortColumns = ['cve_id', 'severity', 'cvss_score', 'published_date', 'modified_date', 'vendor', 'tech_type'];
        const sortCol = validSortColumns.includes(sortBy) ? sortBy : 'published_date';
        const sortOrd = String(sortOrder).toUpperCase() === 'ASC' ? 'ASC' : 'DESC';

        const countResult = await db.query(`SELECT COUNT(*) as count FROM vulnerabilities ${whereSql}`, params);
        const total = parseInt(countResult.rows[0].count, 10);

        const offset = (page - 1) * perPage;
        const dataResult = await db.query(`
            SELECT ${SELECT_COLUMNS}, created_at, updated_at FROM vulnerabilities ${whereSql}
            ORDER BY ${sortCol} ${sortOrd} NULLS LAST, cve_id ${sortOrd}
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `, [...params, perPage, offset]);

        return {
            data: dataResult.rows,
            pagination: {
                page,
                perPage,
                total,
                totalPages: Math.ceil(total / perPage),
            },
        };
    }

    async getById(cveId) {
        const result = await getDb().query(
            `SELECT ${SELECT_COLUMNS}, created_at, updated_at FROM vulnerabilities WHERE cve_id = $1`,
            [normalizeCveId(cveId)]
        );
        return result.rows[0] || null;
    }

    async getSources() {
        return (await getDb().query('SELECT * FROM sources ORDER BY last_fetched DESC NULLS LAST')).rows;
    }

    async getVendors() {
        const result = await getDb().query(
            "SELECT DISTINCT vendor FROM vulnerabilities WHERE vendor IS NOT NULL AND vendor <> '' ORDER BY vendor"
        );
        return result.rows.map((r) => r.vendor);
    }

    async getTechTypes() {
        const result = await getDb().query(
            "SELECT DISTINCT tech_type FROM vulnerabilities WHERE tech_type IS NOT NULL AND tech_type <> '' ORDER BY tech_type"
        );
        return result.rows.map((r) => r.tech_type);
    }

    async getCount() {
        const result = await getDb().query('SELECT COUNT(*) as count FROM vulnerabilities');
        return parseInt(result.rows[0].count, 10);
    }

    /** CVE IDs not yet enriched by `sourceName`, KEV entries first. */
    async getCveIdsMissingSource(sourceName, limit = 25) {
        const result = await getDb().query(`
            SELECT cve_id FROM vulnerabilities
            WHERE source_labels NOT ILIKE $1
            ORDER BY kev_flag DESC, published_date DESC NULLS LAST
            LIMIT $2
        `, [`%"${sourceName}"%`, limit]);
        return result.rows.map((r) => r.cve_id);
    }
}

module.exports = new VulnerabilityRepository();
