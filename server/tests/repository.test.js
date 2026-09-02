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
