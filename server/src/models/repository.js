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
 * Cached vendor/technology lists for the filter dropdowns.
 *
 * Both are `SELECT DISTINCT ... ORDER BY` over the whole table, and
 * /api/filter-options is called on every page load and after every manual
 * refresh. The values only change when a fetch cycle stores new records, so
 * the orchestrator invalidates this explicitly; the TTL is a safety net in
 * case an invalidation is ever missed.
 */
const FILTER_OPTIONS_TTL_MS = 5 * 60 * 1000;
let filterOptionsCache = null;

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
        // jsonb is parsed by the driver, so this arrives as a real array.
        // The merge helpers accept either shape.
        source_labels: row.source_labels || [],
        vendor: row.vendor || '',
        product: row.product || '',
        tech_type: row.tech_type || '',
        kev_flag: row.kev_flag === true,
        kev_date_added: row.kev_date_added || null,
        references: row.reference_urls || '[]',
        cwes: row.cwes || '[]',
    };
}

/**
 * Always hand jsonb a JSON string.
 *
 * node-postgres serialises a JS array as a PostgreSQL array literal ({a,b}),
 * which jsonb rejects. The merge produces a JSON string, but a row read back
 * from jsonb is an array, so both shapes reach here.
 */
function toJsonText(value) {
    if (typeof value === 'string') return value === '' ? '[]' : value;
    if (Array.isArray(value)) return JSON.stringify(value);
    return '[]';
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
        toJsonText(record.source_labels),
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
            // jsonb containment, which the GIN index on source_labels serves.
            // This was `source_labels ILIKE '%"NVD"%'` — a leading-wildcard
            // match on a text column, unindexable by construction.
            whereClauses.push(`source_labels @> $${paramIndex++}::jsonb`);
            params.push(JSON.stringify([source]));
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
        // cve_id is the primary key, so it already orders uniquely; adding it
        // again as a tiebreak would be a redundant sort key.
        const orderBy = sortCol === 'cve_id'
            ? `cve_id ${sortOrd}`
            : `${sortCol} ${sortOrd} NULLS LAST, cve_id ${sortOrd}`;

        const offset = (page - 1) * perPage;

        // `COUNT(*) OVER()` carries the filtered total on every row, computed
        // after WHERE but before LIMIT. That replaces a separate
        // `SELECT COUNT(*)`, which meant every page view scanned the table
        // twice — PostgreSQL keeps no cached row count, so the count scanned
        // whether or not any filter was applied.
        const dataResult = await db.query(`
            SELECT ${SELECT_COLUMNS}, created_at, updated_at,
                   COUNT(*) OVER() AS total_count
            FROM vulnerabilities ${whereSql}
            ORDER BY ${orderBy}
            LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
        `, [...params, perPage, offset]);

        let total = dataResult.rows.length > 0
            ? parseInt(dataResult.rows[0].total_count, 10)
            : NaN;

        // Fall back to a plain COUNT when the window column is absent or
        // unparseable, not only when the page is empty. Missing it would
        // otherwise surface as NaN totals and NaN page counts in the UI.
        if (!Number.isFinite(total)) {
            // No rows means no window to read the count from. Only reachable
            // when the result set is genuinely empty or the offset is past the
            // end, so the extra query is off the hot path.
            const countResult = await db.query(
                `SELECT COUNT(*) as count FROM vulnerabilities ${whereSql}`,
                params
            );
            total = parseInt(countResult.rows[0].count, 10);
        }

        // total_count is an implementation detail of the count optimisation,
        // not part of the record.
        const data = dataResult.rows.map(({ total_count, ...row }) => row);

        return {
            data,
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

    /**
     * Vendor and technology lists, cached. Returns both together because they
     * share a cache entry and are always requested together.
     */
    async getFilterOptions() {
        if (filterOptionsCache && Date.now() - filterOptionsCache.at < FILTER_OPTIONS_TTL_MS) {
            return filterOptionsCache.value;
        }

        const [vendors, techTypes] = await Promise.all([this.getVendors(), this.getTechTypes()]);
        const value = { vendors, techTypes };
        filterOptionsCache = { at: Date.now(), value };
        return value;
    }

    /** Called after records are stored, since that is what can change them. */
    invalidateFilterOptions() {
        filterOptionsCache = null;
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
            WHERE NOT (source_labels @> $1::jsonb)
            ORDER BY kev_flag DESC, published_date DESC NULLS LAST
            LIMIT $2
        `, [JSON.stringify([sourceName]), limit]);
        return result.rows.map((r) => r.cve_id);
    }
}

module.exports = new VulnerabilityRepository();
