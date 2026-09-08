jest.mock('../src/db/client');

const { getDb } = require('../src/db/client');
const repository = require('../src/models/repository');

const UPSERT_COLUMNS = [
    'cve_id', 'title', 'description', 'severity', 'cvss_score', 'cvss_vector',
    'published_date', 'modified_date', 'source_labels', 'vendor', 'product',
    'tech_type', 'kev_flag', 'kev_date_added', 'reference_urls', 'cwes',
];

/**
 * Stand-in for a pooled client that records every statement and answers the
 * batch SELECT from a fake table, filtered the way the real WHERE clause
 * would filter it.
 */
function fakeDb(tableRows = []) {
    const statements = [];

    const query = jest.fn(async (sql, params = []) => {
        statements.push({ sql, params });

        if (/SELECT .* FROM vulnerabilities WHERE cve_id = ANY/i.test(sql)) {
            const requested = new Set(params[0]);
            return { rows: tableRows.filter((r) => requested.has(r.cve_id)) };
        }
        if (/SELECT COUNT\(\*\)/i.test(sql)) {
            return { rows: [{ count: String(tableRows.length) }] };
        }
        // The paginated list query: carries the filtered total on each row.
        if (/COUNT\(\*\) OVER\(\)/i.test(sql)) {
            return {
                rows: tableRows.map((r) => ({ ...r, total_count: String(tableRows.length) })),
            };
        }
        return { rows: [], rowCount: 0 };
    });

    const client = { query, release: jest.fn() };
    getDb.mockReturnValue({ connect: async () => client, query });

    return {
        statements,
        client,
        selects: () => statements.filter((s) => /^\s*SELECT/i.test(s.sql)),
        upserts: () => statements.filter((s) => /INSERT INTO vulnerabilities/i.test(s.sql)),
    };
}

/** Read a column out of an upsert's flat parameter list, for row `rowIndex`. */
function boundValue(upsert, rowIndex, column) {
    const offset = rowIndex * UPSERT_COLUMNS.length + UPSERT_COLUMNS.indexOf(column);
    return upsert.params[offset];
}

function storedRow(overrides = {}) {
    return {
        cve_id: 'CVE-2024-0001',
        title: 'Stored title',
        description: 'A long stored description that already exists in the table.',
        severity: 'CRITICAL',
        cvss_score: 9.8,
        cvss_vector: 'CVSS:3.1/AV:N',
        published_date: '2024-01-15',
        modified_date: '2024-02-01',
        source_labels: '["CISA KEV"]',
        vendor: 'Atlassian',
        product: 'Jira',
        tech_type: 'web',
        kev_flag: true,
        kev_date_added: '2024-01-20',
        reference_urls: '["https://example.com/a"]',
        cwes: '["CWE-94"]',
        ...overrides,
    };
}

beforeEach(() => {
    jest.clearAllMocks();
});

describe('repository.storeRecords', () => {
    test('reads only the CVEs in the incoming batch', async () => {
        const db = fakeDb([storedRow(), storedRow({ cve_id: 'CVE-2024-0002' })]);

        await repository.storeRecords([{ cve_id: 'CVE-2024-0002' }], 'NVD');

        const select = db.selects()[0];
        expect(select.params[0]).toEqual(['CVE-2024-0002']);
    });

    test('writes only the CVEs in the batch, not the whole table', async () => {
        // The regression: seeding the merge map from a full-table SELECT made
        // every call rewrite every row.
        const db = fakeDb([
            storedRow({ cve_id: 'CVE-2024-0001' }),
            storedRow({ cve_id: 'CVE-2024-0002' }),
            storedRow({ cve_id: 'CVE-2024-0003' }),
        ]);

        const stored = await repository.storeRecords([{ cve_id: 'CVE-2024-0002' }], 'NVD');

        expect(stored).toBe(1);
        const upserts = db.upserts();
        expect(upserts).toHaveLength(1);
        expect(upserts[0].params).toHaveLength(UPSERT_COLUMNS.length);
        expect(boundValue(upserts[0], 0, 'cve_id')).toBe('CVE-2024-0002');
    });

    test('does not blank fields the incoming source omits', async () => {
        // NVD supplies no vendor/product; those must survive from CISA KEV.
        const db = fakeDb([storedRow()]);

        await repository.storeRecords([{
            cve_id: 'CVE-2024-0001',
            vendor: '',
            product: '',
            description: 'short',
        }], 'NVD');

        const upsert = db.upserts()[0];
        expect(boundValue(upsert, 0, 'vendor')).toBe('Atlassian');
        expect(boundValue(upsert, 0, 'product')).toBe('Jira');
        expect(boundValue(upsert, 0, 'title')).toBe('Stored title');
        expect(boundValue(upsert, 0, 'description')).toContain('already exists');
    });

    test('does not reset published_date when the incoming record has none', async () => {
        const db = fakeDb([storedRow()]);

        await repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD');

        expect(boundValue(db.upserts()[0], 0, 'published_date')).toBe('2024-01-15');
    });

    test('accumulates source labels across sources', async () => {
        const db = fakeDb([storedRow()]);

        await repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD');

        const labels = JSON.parse(boundValue(db.upserts()[0], 0, 'source_labels'));
        expect(labels).toEqual(['CISA KEV', 'NVD']);
    });

    test('raises the CVSS score and severity when a source reports higher', async () => {
        const db = fakeDb([storedRow({ cvss_score: 5.0, severity: 'MEDIUM' })]);

        await repository.storeRecords([{ cve_id: 'CVE-2024-0001', cvss_score: 9.1 }], 'NVD');

        const upsert = db.upserts()[0];
        expect(boundValue(upsert, 0, 'cvss_score')).toBe(9.1);
        expect(boundValue(upsert, 0, 'severity')).toBe('CRITICAL');
    });

    test('maps the JS `references` field to the reference_urls column', async () => {
        // `references` is a reserved keyword in PostgreSQL and cannot be a
        // bare column name.
        const db = fakeDb();

        await repository.storeRecords([{
            cve_id: 'CVE-2024-7777',
            references: ['https://example.com/x'],
        }], 'NVD');

        const upsert = db.upserts()[0];
        expect(upsert.sql).toContain('reference_urls');
        expect(upsert.sql).not.toMatch(/[^_"]references/);
        expect(JSON.parse(boundValue(upsert, 0, 'reference_urls'))).toEqual(['https://example.com/x']);
    });

    test('serializes array cwes rather than handing an array to the driver', async () => {
        const db = fakeDb();

        await repository.storeRecords([{ cve_id: 'CVE-2024-8888', cwes: ['CWE-79'] }], 'CISA KEV');

        const value = boundValue(db.upserts()[0], 0, 'cwes');
        expect(typeof value).toBe('string');
        expect(JSON.parse(value)).toEqual(['CWE-79']);
    });

    test('chunks a large batch into multiple statements', async () => {
        const db = fakeDb();
        const records = Array.from({ length: 850 }, (_, i) => ({
            cve_id: `CVE-2024-${String(i).padStart(5, '0')}`,
        }));

        const stored = await repository.storeRecords(records, 'NVD');

        expect(stored).toBe(850);
        // 400 + 400 + 50
        expect(db.upserts()).toHaveLength(3);
        expect(db.upserts()[2].params).toHaveLength(50 * UPSERT_COLUMNS.length);
    });

    test('commits once and releases the client', async () => {
        const db = fakeDb();

        await repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD');

        const sqls = db.statements.map((s) => s.sql);
        expect(sqls).toContain('BEGIN');
        expect(sqls).toContain('COMMIT');
        expect(db.client.release).toHaveBeenCalledTimes(1);
    });

    test('rolls back and releases the client when a write fails', async () => {
        const db = fakeDb();
        db.client.query.mockImplementation(async (sql) => {
            if (/INSERT INTO vulnerabilities/i.test(sql)) throw new Error('write failed');
            if (/SELECT .* WHERE cve_id = ANY/i.test(sql)) return { rows: [] };
            return { rows: [], rowCount: 0 };
        });

        await expect(repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD'))
            .rejects.toThrow('write failed');

        expect(db.client.query).toHaveBeenCalledWith('ROLLBACK');
        expect(db.client.release).toHaveBeenCalledTimes(1);
    });

    test('is a no-op for a batch with no usable CVE IDs', async () => {
        const db = fakeDb();

        const stored = await repository.storeRecords([null, { cve_id: '' }, undefined], 'NVD');

        expect(stored).toBe(0);
        expect(db.statements).toHaveLength(0);
    });

    test('deduplicates repeated CVE IDs inside one batch', async () => {
        const db = fakeDb();

        const stored = await repository.storeRecords([
            { cve_id: 'CVE-2024-0001', cvss_score: 4.0 },
            { cve_id: 'cve-2024-0001', cvss_score: 8.0 },
        ], 'NVD');

        expect(stored).toBe(1);
        expect(boundValue(db.upserts()[0], 0, 'cvss_score')).toBe(8.0);
    });
});

describe('repository.queryVulnerabilities', () => {
    test('honours ASC when asked', async () => {
        const db = fakeDb();

        await repository.queryVulnerabilities({ sortBy: 'cvss_score', sortOrder: 'ASC' });

        const dataQuery = db.statements.find((s) => /ORDER BY/i.test(s.sql));
        expect(dataQuery.sql).toMatch(/ORDER BY cvss_score ASC/);
    });

    test('defaults to DESC for an unrecognised order', async () => {
        const db = fakeDb();

        await repository.queryVulnerabilities({ sortOrder: 'sideways' });

        const dataQuery = db.statements.find((s) => /ORDER BY/i.test(s.sql));
        expect(dataQuery.sql).toMatch(/ORDER BY published_date DESC/);
    });

    test('rejects a sort column outside the allowlist', async () => {
        const db = fakeDb();

        await repository.queryVulnerabilities({ sortBy: 'cve_id; DROP TABLE vulnerabilities' });

        const dataQuery = db.statements.find((s) => /ORDER BY/i.test(s.sql));
        expect(dataQuery.sql).not.toContain('DROP TABLE');
        expect(dataQuery.sql).toMatch(/ORDER BY published_date/);
    });

    test('parameterizes every filter value', async () => {
        const db = fakeDb();

        await repository.queryVulnerabilities({
            severity: "CRITICAL' OR 1=1--",
            search: 'jira',
            vendor: 'Atlassian',
            kevFlag: true,
        });

        const dataQuery = db.statements.find((s) => /ORDER BY/i.test(s.sql));
        expect(dataQuery.sql).not.toContain('1=1');
        expect(dataQuery.params).toContain("CRITICAL' OR 1=1--");
        expect(dataQuery.params).toContain('%jira%');
    });
});


describe('query performance shape', () => {
    test('takes the total from the window function, not a second scan', async () => {
        // Two queries per page view meant two sequential scans, since
        // PostgreSQL keeps no cached row count.
        const db = fakeDb([storedRow(), storedRow({ cve_id: 'CVE-2024-0002' })]);

        const result = await repository.queryVulnerabilities({});

        expect(result.pagination.total).toBe(2);
        const listQueries = db.statements.filter((s) => /COUNT\(\*\) OVER\(\)/i.test(s.sql));
        const countQueries = db.statements.filter((s) => /^\s*SELECT COUNT\(\*\)/i.test(s.sql));
        expect(listQueries).toHaveLength(1);
        expect(countQueries).toHaveLength(0);
    });

    test('does not leak total_count into the returned records', async () => {
        const db = fakeDb([storedRow()]);

        const result = await repository.queryVulnerabilities({});

        expect(result.data[0]).not.toHaveProperty('total_count');
        expect(result.data[0].cve_id).toBe('CVE-2024-0001');
        expect(db.statements.length).toBeGreaterThan(0);
    });

    test('falls back to a count query only when the page is empty', async () => {
        const db = fakeDb([]); // no rows -> no window to read
        const result = await repository.queryVulnerabilities({ page: 500 });

        expect(result.pagination.total).toBe(0);
        expect(db.statements.filter((s) => /^\s*SELECT COUNT\(\*\)/i.test(s.sql))).toHaveLength(1);
    });

    test('falls back to a count query when the window value is unusable', async () => {
        // A driver or backend that does not return the window column would
        // otherwise surface NaN totals and NaN page counts in the UI.
        const db = fakeDb([storedRow()]);
        const realQuery = db.client.query.getMockImplementation();
        db.client.query.mockImplementation(async (sql, params) => {
            const out = await realQuery(sql, params);
            if (/COUNT\(\*\) OVER\(\)/i.test(sql)) {
                return { rows: out.rows.map(({ total_count, ...r }) => r) };
            }
            return out;
        });

        const result = await repository.queryVulnerabilities({});

        expect(result.pagination.total).toBe(1);
        expect(Number.isFinite(result.pagination.totalPages)).toBe(true);
    });

    test('filters sources by jsonb containment so the GIN index applies', async () => {
        const db = fakeDb([storedRow()]);

        await repository.queryVulnerabilities({ source: 'NVD' });

        const q = db.statements.find((s) => /COUNT\(\*\) OVER\(\)/i.test(s.sql));
        expect(q.sql).toMatch(/source_labels @> \$\d+::jsonb/);
        expect(q.sql).not.toMatch(/source_labels ILIKE/);
        expect(q.params).toContain('["NVD"]');
    });

    test('finds enrichment targets by containment negation', async () => {
        const db = fakeDb([]);

        await repository.getCveIdsMissingSource('MITRE CVEW', 10);

        const q = db.statements[0];
        expect(q.sql).toMatch(/NOT \(source_labels @> \$1::jsonb\)/);
        expect(q.params[0]).toBe('["MITRE CVEW"]');
    });

    test('binds source_labels as JSON text even when the merge yields an array', async () => {
        // node-postgres would serialise a JS array as a PostgreSQL array
        // literal ({a,b}), which jsonb rejects. Rows read back from jsonb come
        // in as arrays, so both shapes reach the binder.
        const db = fakeDb([storedRow({ source_labels: ['CISA KEV'] })]);

        await repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD');

        const bound = boundValue(db.upserts()[0], 0, 'source_labels');
        expect(typeof bound).toBe('string');
        expect(JSON.parse(bound)).toEqual(['CISA KEV', 'NVD']);
    });
});


describe('filter option caching', () => {
    test('queries once, then serves from cache', async () => {
        // /api/filter-options is hit on every page load and each of these is a
        // DISTINCT over the whole table.
        const db = fakeDb([storedRow()]);
        repository.invalidateFilterOptions();

        await repository.getFilterOptions();
        const afterFirst = db.statements.filter((s) => /SELECT DISTINCT/i.test(s.sql)).length;
        await repository.getFilterOptions();
        await repository.getFilterOptions();
        const afterThird = db.statements.filter((s) => /SELECT DISTINCT/i.test(s.sql)).length;

        expect(afterFirst).toBe(2); // vendors + techTypes
        expect(afterThird).toBe(2); // no further queries
    });

    test('re-queries after invalidation', async () => {
        const db = fakeDb([storedRow()]);
        repository.invalidateFilterOptions();

        await repository.getFilterOptions();
        repository.invalidateFilterOptions();
        await repository.getFilterOptions();

        expect(db.statements.filter((s) => /SELECT DISTINCT/i.test(s.sql))).toHaveLength(4);
    });
});


describe('write amplification', () => {
    test('the upsert only writes rows that would actually change', async () => {
        // A poll of unchanged upstream data used to rewrite every row it
        // touched: a new row version, WAL, updates to all nine indexes, and a
        // dead tuple, per row, per cycle.
        const db = fakeDb();

        await repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD');

        const sql = db.upserts()[0].sql.replace(/\s+/g, ' ');
        expect(sql).toMatch(/ON CONFLICT \(cve_id\) DO UPDATE SET/);
        expect(sql).toMatch(/WHERE vulnerabilities\./);
        expect((sql.match(/IS DISTINCT FROM/g) || []).length).toBe(15);
    });

    test('updated_at is excluded from the change test', async () => {
        // CURRENT_TIMESTAMP always differs, so including it would make every
        // row look changed and defeat the whole guard.
        const db = fakeDb();
        await repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD');

        const sql = db.upserts()[0].sql.replace(/\s+/g, ' ');
        const where = sql.slice(sql.indexOf(' WHERE '));
        expect(where).not.toMatch(/updated_at/);
        expect(sql).toMatch(/updated_at = CURRENT_TIMESTAMP/);
    });

    test('every comparison operand is parenthesised', async () => {
        // IS DISTINCT FROM binds tighter than OR, so the kev_flag target
        // (`a OR b`) unparenthesised parses as
        // `(kev_flag IS DISTINCT FROM kev_flag) OR EXCLUDED.kev_flag` — always
        // true for a KEV row, so the skip would silently never apply to the
        // one dataset it exists for. Valid SQL, wrong meaning.
        const db = fakeDb();
        await repository.storeRecords([{ cve_id: 'CVE-2024-0001' }], 'NVD');

        const sql = db.upserts()[0].sql.replace(/\s+/g, ' ');
        const where = sql.slice(sql.indexOf(' WHERE '));

        // The kev_flag term must wrap its OR expression.
        expect(where).toMatch(/kev_flag IS DISTINCT FROM \(vulnerabilities\.kev_flag OR EXCLUDED\.kev_flag\)/);
        // And no comparison may be followed directly by a bare identifier.
        expect(where).not.toMatch(/IS DISTINCT FROM [a-zA-Z]/);
    });
});
