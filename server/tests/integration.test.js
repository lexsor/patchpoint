jest.mock('../src/db/client');

const fs = require('fs');
const path = require('path');

const { mergeRecords, classifySeverity } = require('../src/models/deduplication');
const { matchWatchlistItem } = require('../src/models/alert-engine');

describe('Deduplication across sources', () => {
    test('merges one CVE seen by CISA KEV and NVD into a single record', () => {
        const cisaRecords = [{
            cve_id: 'CVE-2024-1234',
            vendor: 'Atlassian',
            product: 'Jira',
            description: 'Remote code execution in Jira',
            kev_flag: true,
            kev_date_added: '2024-06-20',
            cwes: ['CWE-94', 'CWE-502'],
            severity: 'HIGH',
        }];

        const nvdRecords = [{
            cve_id: 'CVE-2024-1234',
            description: 'Jira allows remote code execution via crafted requests',
            published_date: '2024-06-14',
            modified_date: '2024-07-01',
            cvss_score: 9.8,
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            severity: 'CRITICAL',
        }];

        const existing = new Map();
        mergeRecords(existing, cisaRecords, 'CISA KEV');
        mergeRecords(existing, nvdRecords, 'NVD');

        const merged = existing.get('CVE-2024-1234');

        expect(JSON.parse(merged.source_labels)).toEqual(['CISA KEV', 'NVD']);
        expect(merged.cvss_score).toBe(9.8);
        expect(merged.severity).toBe('CRITICAL');
        expect(merged.kev_flag).toBe(true);
        expect(merged.kev_date_added).toBe('2024-06-20');
        expect(merged.description).toContain('crafted requests');
        // CISA supplied vendor/product; NVD supplies neither and must not
        // erase them.
        expect(merged.vendor).toBe('Atlassian');
        expect(merged.product).toBe('Jira');
        // NVD supplied the only real dates.
        expect(merged.published_date).toBe('2024-06-14');
        expect(merged.modified_date).toBe('2024-07-01');
        expect(JSON.parse(merged.cwes)).toEqual(expect.arrayContaining(['CWE-94', 'CWE-502']));
    });

    test('keeps unrelated CVEs independent', () => {
        const existing = new Map();

        mergeRecords(existing, [{ cve_id: 'CVE-2024-1000', kev_flag: true }], 'CISA KEV');
        mergeRecords(existing, [{ cve_id: 'CVE-2024-2000', cvss_score: 5.0 }], 'NVD');
        mergeRecords(existing, [{ cve_id: 'CVE-2024-3000', cvss_score: 7.5 }], 'NVD');
        mergeRecords(existing, [{ cve_id: 'CVE-2024-3000', kev_flag: true, cvss_score: 8.2 }], 'CISA KEV');

        expect(existing.size).toBe(3);

        const cve3 = existing.get('CVE-2024-3000');
        expect(JSON.parse(cve3.source_labels)).toEqual(['NVD', 'CISA KEV']);
        expect(cve3.cvss_score).toBe(8.2);
        expect(cve3.kev_flag).toBe(true);
    });

    test('a lower score from a later source does not downgrade severity', () => {
        const existing = new Map();
        mergeRecords(existing, [{ cve_id: 'CVE-2024-4000', cvss_score: 9.5 }], 'NVD');
        mergeRecords(existing, [{ cve_id: 'CVE-2024-4000', cvss_score: 4.0 }], 'MITRE CVEW');

        const merged = existing.get('CVE-2024-4000');
        expect(merged.cvss_score).toBe(9.5);
        expect(merged.severity).toBe('CRITICAL');
    });

    test('a scoreless record is not labelled LOW', () => {
        const existing = new Map();
        mergeRecords(existing, [{ cve_id: 'CVE-2024-5000' }], 'MITRE CVEW');

        // Deriving severity from an absent score used to classify every such
        // record as LOW, which reads as "assessed and harmless".
        expect(existing.get('CVE-2024-5000').severity).toBe('');
        expect(existing.get('CVE-2024-5000').cvss_score).toBeNull();
    });

    test('classifySeverity boundaries', () => {
        expect(classifySeverity(0)).toBe('LOW');
        expect(classifySeverity(3.9)).toBe('LOW');
        expect(classifySeverity(4.0)).toBe('MEDIUM');
        expect(classifySeverity(6.9)).toBe('MEDIUM');
        expect(classifySeverity(7.0)).toBe('HIGH');
        expect(classifySeverity(8.9)).toBe('HIGH');
        expect(classifySeverity(9.0)).toBe('CRITICAL');
        expect(classifySeverity(10.0)).toBe('CRITICAL');
    });
});

describe('Watchlist matching', () => {
    // These call the alert engine's real matcher. An earlier version of this
    // suite reimplemented the comparison inline, so it asserted that
    // String.includes() works rather than testing the shipped code.

    test('CVE ID match is case-insensitive and whitespace-tolerant', () => {
        expect(matchWatchlistItem(
            { cve_id: 'CVE-2024-1234' },
            { item: 'cve-2024- 1234', item_type: 'cve_id' }
        )).toBe('CVE ID matched');
    });

    test('CVE ID match is exact, not a substring', () => {
        expect(matchWatchlistItem(
            { cve_id: 'CVE-2024-12345' },
            { item: 'CVE-2024-1234', item_type: 'cve_id' }
        )).toBe('');
    });

    test('vendor match is a case-insensitive substring', () => {
        expect(matchWatchlistItem(
            { cve_id: 'CVE-2024-5678', vendor: 'Atlassian' },
            { item: 'atlassian', item_type: 'vendor' }
        )).toBe('Vendor match');
    });

    test('product match is a case-insensitive substring', () => {
        expect(matchWatchlistItem(
            { cve_id: 'CVE-2024-5678', product: 'Jira Cloud' },
            { item: 'jira', item_type: 'product' }
        )).toBe('Product match');
    });

    test('no false positive on an unrelated vendor', () => {
        expect(matchWatchlistItem(
            { cve_id: 'CVE-2024-5678', vendor: 'Google' },
            { item: 'microsoft', item_type: 'vendor' }
        )).toBe('');
    });

    test('missing fields and blank watch items never match', () => {
        expect(matchWatchlistItem({ cve_id: 'CVE-2024-1' }, { item: 'acme', item_type: 'vendor' })).toBe('');
        expect(matchWatchlistItem({ cve_id: 'CVE-2024-1', vendor: 'Acme' }, { item: '   ', item_type: 'vendor' })).toBe('');
        expect(matchWatchlistItem({ cve_id: 'CVE-2024-1' }, { item: 'x', item_type: 'nonsense' })).toBe('');
    });
});

describe('SQL keyword safety', () => {
    const schemaSql = fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'schema.sql'), 'utf8');
    const repositorySrc = fs.readFileSync(path.join(__dirname, '..', 'src', 'models', 'repository.js'), 'utf8');

    // `references` is a reserved keyword in PostgreSQL. Using it as a bare
    // column name is a syntax error, which made schema creation fail and took
    // the whole server down on boot. Guard the regression.
    const BARE_REFERENCES = /(?<![\w"'.])references(?![\w"])/i;

    test('schema.sql declares no bare `references` column', () => {
        expect(schemaSql).toContain('reference_urls');
        expect(BARE_REFERENCES.test(stripSqlComments(schemaSql))).toBe(false);
    });

    test('the repository never emits a bare `references` identifier', () => {
        // Strip comments first: prose in this file legitimately mentions
        // `references` inside backticks, which is not emitted SQL.
        const code = stripJsComments(repositorySrc);
        const sqlTemplates = code.match(/`[^`]*`/g) || [];
        for (const template of sqlTemplates) {
            expect(BARE_REFERENCES.test(template)).toBe(false);
        }
    });

    test('schema.sql constrains sources.name so ON CONFLICT (name) resolves', () => {
        // Without a unique constraint, PostgreSQL rejects the upsert with
        // "no unique or exclusion constraint matching the ON CONFLICT
        // specification", so every updateSource call failed.
        expect(schemaSql).toMatch(/name TEXT NOT NULL UNIQUE/);
        expect(repositorySrc).toContain('ON CONFLICT (name)');
    });

    test('schema.sql constrains alerts so repeated polls cannot duplicate them', () => {
        expect(schemaSql).toMatch(/UNIQUE \(cve_id, match_type, match_value\)/);
    });
});

function stripSqlComments(sql) {
    return sql.replace(/--[^\n]*/g, '');
}

/** Drop JSDoc blocks and // lines so prose is not mistaken for emitted SQL. */
function stripJsComments(src) {
    return src
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/^[ \t]*\/\/[^\n]*$/gm, '');
}
