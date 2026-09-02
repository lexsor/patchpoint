jest.mock('../src/lib/http');

const { httpGetText } = require('../src/lib/http');
const { fetchCisaKev, fetchCisaKevJson, parseCwes } = require('../src/fetchers/cisa-fetcher');
const { fetchNvd } = require('../src/fetchers/nvd-fetcher');
const { fetchMitreCvew } = require('../src/fetchers/mitre-fetcher');

/**
 * These fixtures mirror the field names in the live responses. The whole class
 * of bug they guard against was reading fields that do not exist
 * (`datePublished`, `baseMetricScore`, `cveDataTags`), which silently produced
 * null scores and today's date for every record. Hitting the real APIs, as an
 * earlier version of this suite did, made the tests slow, flaky and offline-
 * hostile without ever asserting the mapping.
 */

const ok = (body, headers = {}) => ({ statusCode: 200, headers, body });

beforeEach(() => {
    httpGetText.mockReset();
});

describe('CISA KEV fetcher', () => {
    const CSV = [
        'cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,cwes',
        'CVE-2024-21675,Atlassian,Jira,Jira RCE,2024-06-20,Remote code execution in Jira,"CWE-94,CWE-502"',
        'CVE-2023-1111,Cisco,IOS,IOS overflow,2023-02-01,Buffer overflow,CWE-120',
    ].join('\n');

    test('maps CSV rows onto the record shape', async () => {
        httpGetText.mockResolvedValue(ok(CSV));

        const result = await fetchCisaKev();

        expect(result.total).toBe(2);
        expect(result.records[0]).toMatchObject({
            cve_id: 'CVE-2024-21675',
            vendor: 'Atlassian',
            product: 'Jira',
            title: 'Jira RCE',
            description: 'Remote code execution in Jira',
            kev_flag: true,
            kev_date_added: '2024-06-20',
        });
        expect(result.records[0].cwes).toEqual(['CWE-94', 'CWE-502']);
    });

    test('asserts no severity of its own', async () => {
        httpGetText.mockResolvedValue(ok(CSV));

        const result = await fetchCisaKev();

        // CISA publishes no CVSS score. Stamping every KEV record HIGH made
        // HIGH the only severity in the table, because KEV lands first and is
        // ~1,700 records; the severity filter then had one option.
        expect(result.records.every(r => r.severity === '')).toBe(true);
    });

    test('does not invent a published_date from the KEV catalogue date', async () => {
        httpGetText.mockResolvedValue(ok(CSV));

        const result = await fetchCisaKev();

        // dateAdded is when CISA listed it, not when the CVE was published.
        expect(result.records[0].published_date).toBeNull();
        expect(result.records[0].kev_date_added).toBe('2024-06-20');
    });

    test('maps the JSON feed identically', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify({
            vulnerabilities: [{
                cveID: 'CVE-2024-21675',
                vendorProject: 'Atlassian',
                product: 'Jira',
                vulnerabilityName: 'Jira RCE',
                shortDescription: 'Remote code execution in Jira',
                dateAdded: '2024-06-20',
                cwes: ['CWE-94'],
            }],
        })));

        const result = await fetchCisaKevJson();

        expect(result.total).toBe(1);
        expect(result.records[0].cve_id).toBe('CVE-2024-21675');
        expect(result.records[0].cwes).toEqual(['CWE-94']);
    });

    test('rejects on an HTTP error', async () => {
        httpGetText.mockResolvedValue({ statusCode: 503, headers: {}, body: '' });
        await expect(fetchCisaKev()).rejects.toThrow('CISA KEV HTTP 503');
    });

    test('skips rows with no CVE ID', async () => {
        httpGetText.mockResolvedValue(ok('cveID,vendorProject\n,Nobody\nCVE-2024-1,Acme'));
        const result = await fetchCisaKev();
        expect(result.records.map(r => r.cve_id)).toEqual(['CVE-2024-1']);
    });

    describe('parseCwes', () => {
        test('accepts a comma-separated string (CSV feed)', () => {
            expect(parseCwes('CWE-79, CWE-89')).toEqual(['CWE-79', 'CWE-89']);
        });

        test('accepts an array (JSON feed)', () => {
            expect(parseCwes(['CWE-79', 'CWE-79'])).toEqual(['CWE-79']);
        });

        test('always returns an array, never a pre-stringified value', () => {
            // Handing the repository a JSON string here made node-postgres
            // serialize it as a Postgres array literal, which then failed to
            // JSON.parse on the way back out.
            expect(Array.isArray(parseCwes('CWE-1'))).toBe(true);
            expect(parseCwes('')).toEqual([]);
            expect(parseCwes(null)).toEqual([]);
            expect(parseCwes('not-a-cwe')).toEqual([]);
        });
    });
});

describe('NVD fetcher', () => {
    const NVD_PAGE = {
        totalResults: 1,
        resultsPerPage: 1,
        vulnerabilities: [{
            cve: {
                id: 'CVE-2024-1234',
                published: '2024-06-14T10:15:00.000',
                lastModified: '2024-07-02T18:30:00.000',
                descriptions: [
                    { lang: 'es', value: 'Descripcion en espanol' },
                    { lang: 'en', value: 'Jira allows remote code execution.' },
                ],
                metrics: {
                    cvssMetricV31: [{
                        type: 'Primary',
                        cvssData: {
                            baseScore: 9.8,
                            baseSeverity: 'CRITICAL',
                            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        },
                    }],
                },
                weaknesses: [
                    { type: 'Primary', description: [{ lang: 'en', value: 'CWE-94' }] },
                    { type: 'Secondary', description: [{ lang: 'en', value: 'NVD-CWE-noinfo' }] },
                ],
                references: [{ url: 'https://example.com/a' }, { url: 'https://example.com/b' }],
            },
        }],
    };

    test('reads the real v2.0 field names', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(NVD_PAGE)));

        const result = await fetchNvd({ startIndex: 0 });
        const record = result.records[0];

        expect(record.cve_id).toBe('CVE-2024-1234');
        expect(record.cvss_score).toBe(9.8);            // cvssData.baseScore
        expect(record.severity).toBe('CRITICAL');       // cvssData.baseSeverity
        expect(record.published_date).toBe('2024-06-14'); // cve.published
        expect(record.modified_date).toBe('2024-07-02'); // cve.lastModified
        expect(record.cvss_vector).toContain('CVSS:3.1');
    });

    test('prefers the English description', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(NVD_PAGE)));
        const result = await fetchNvd({ startIndex: 0 });
        expect(result.records[0].description).toBe('Jira allows remote code execution.');
    });

    test('extracts CWEs from weaknesses and drops NVD placeholders', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(NVD_PAGE)));
        const result = await fetchNvd({ startIndex: 0 });
        expect(result.records[0].cwes).toEqual(['CWE-94']);
    });

    test('falls back to CVSS v2 metrics for older CVEs', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify({
            totalResults: 1,
            resultsPerPage: 1,
            vulnerabilities: [{
                cve: {
                    id: 'CVE-1999-0001',
                    published: '1999-09-29T04:00:00.000',
                    lastModified: '2024-01-01T00:00:00.000',
                    descriptions: [{ lang: 'en', value: 'Old issue.' }],
                    metrics: {
                        cvssMetricV2: [{
                            type: 'Primary',
                            baseSeverity: 'HIGH',
                            cvssData: { baseScore: 10, vectorString: 'AV:N/AC:L/Au:N/C:C/I:C/A:C' },
                        }],
                    },
                },
            }],
        })));

        const result = await fetchNvd({ startIndex: 0 });
        expect(result.records[0].cvss_score).toBe(10);
        expect(result.records[0].severity).toBe('HIGH');
        expect(result.records[0].published_date).toBe('1999-09-29');
    });

    test('leaves dates null rather than defaulting to today', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify({
            totalResults: 1,
            resultsPerPage: 1,
            vulnerabilities: [{ cve: { id: 'CVE-2024-9999', descriptions: [] } }],
        })));

        const result = await fetchNvd({ startIndex: 0 });
        expect(result.records[0].published_date).toBeNull();
        expect(result.records[0].modified_date).toBeNull();
        expect(result.records[0].cvss_score).toBeNull();
        expect(result.records[0].severity).toBe('');
    });

    test('sends the API key as a header, not a query parameter', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(NVD_PAGE)));

        await fetchNvd({ startIndex: 0, apiKey: 'secret-key' });

        const [url, options] = httpGetText.mock.calls[0];
        expect(url).not.toContain('secret-key');
        expect(options.headers.apiKey).toBe('secret-key');
    });

    test('sends the hasKev flag when asked', async () => {
        // One paged hasKev query scores the whole CISA KEV catalogue (~1,700
        // CVEs). Without it those records carry no severity, because CISA
        // publishes no CVSS.
        httpGetText.mockResolvedValue(ok(JSON.stringify(NVD_PAGE)));

        await fetchNvd({ startIndex: 0, hasKev: true });

        const [url] = httpGetText.mock.calls[0];
        expect(url).toContain('hasKev');
    });

    test('omits hasKev by default', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(NVD_PAGE)));

        await fetchNvd({ startIndex: 0 });

        expect(httpGetText.mock.calls[0][0]).not.toContain('hasKev');
    });

    test('passes the modification window through when both bounds are given', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(NVD_PAGE)));

        await fetchNvd({
            startIndex: 0,
            lastModStartDate: '2024-06-01T00:00:00.000Z',
            lastModEndDate: '2024-06-30T00:00:00.000Z',
        });

        const [url] = httpGetText.mock.calls[0];
        expect(url).toContain('lastModStartDate=');
        expect(url).toContain('lastModEndDate=');
    });

    test('retries a 429 and then succeeds', async () => {
        httpGetText
            .mockResolvedValueOnce({ statusCode: 429, headers: { 'retry-after': '0' }, body: '' })
            .mockResolvedValueOnce(ok(JSON.stringify(NVD_PAGE)));

        const result = await fetchNvd({ startIndex: 0 });

        expect(httpGetText).toHaveBeenCalledTimes(2);
        expect(result.records[0].cve_id).toBe('CVE-2024-1234');
    });

    test('gives up on a persistent 429 with a rejection, not a crash', async () => {
        // The previous retry did `resolve(fetchNvd(page)).bind(...)`, which
        // threw a TypeError inside a setTimeout callback and killed the
        // process instead of rejecting.
        httpGetText.mockResolvedValue({ statusCode: 429, headers: { 'retry-after': '0' }, body: '' });

        await expect(fetchNvd({ startIndex: 0 })).rejects.toThrow('NVD HTTP 429');
    });

    test('reports pagination state', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify({
            totalResults: 4000,
            resultsPerPage: 2000,
            vulnerabilities: [{ cve: { id: 'CVE-2024-1', descriptions: [] } }],
        })));

        const result = await fetchNvd({ startIndex: 0 });
        expect(result.isLastPage).toBe(false);
        expect(result.nextStartIndex).toBe(2000);
    });
});

describe('MITRE CVEW fetcher', () => {
    const RECORD = {
        dataType: 'CVE_RECORD',
        cveMetadata: {
            cveId: 'CVE-2024-21646',
            state: 'PUBLISHED',
            datePublished: '2024-01-05T09:00:00.000Z',
            dateUpdated: '2024-02-10T11:00:00.000Z',
        },
        containers: {
            cna: {
                title: 'Heap overflow in Example Server',
                descriptions: [{ lang: 'en', value: 'A heap overflow in Example Web Server.' }],
                affected: [{ vendor: 'Example Corp', product: 'Example nginx Gateway' }],
                metrics: [{ cvssV3_1: { baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N' } }],
                problemTypes: [{ descriptions: [{ cweId: 'CWE-122', value: 'Heap overflow' }] }],
                references: [{ url: 'https://example.com/advisory' }],
            },
        },
    };

    test('returns nothing without a CVE ID and makes no request', async () => {
        const result = await fetchMitreCvew();

        expect(result).toEqual({ records: [], total: 0 });
        expect(httpGetText).not.toHaveBeenCalled();
    });

    test('maps a CVE Record 5.x payload', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(RECORD)));

        const result = await fetchMitreCvew('CVE-2024-21646');
        const record = result.records[0];

        expect(record.cve_id).toBe('CVE-2024-21646');
        expect(record.title).toBe('Heap overflow in Example Server');
        expect(record.cvss_score).toBe(7.5);
        expect(record.severity).toBe('HIGH');
        expect(record.published_date).toBe('2024-01-05');
        expect(record.modified_date).toBe('2024-02-10');
        expect(record.vendor).toBe('Example Corp');
        expect(record.product).toBe('Example nginx Gateway');
        expect(record.cwes).toEqual(['CWE-122']);
        expect(record.references).toEqual(['https://example.com/advisory']);
    });

    test('derives tech_type from product text, not from the record state', async () => {
        httpGetText.mockResolvedValue(ok(JSON.stringify(RECORD)));
        const result = await fetchMitreCvew('CVE-2024-21646');
        expect(result.records[0].tech_type).toBe('web');
    });

    test('leaves vendor empty rather than scraping it from the description', async () => {
        // The old extractVendor() regexed "affects (\w+)" out of free text and
        // fabricated vendor names, which then polluted the vendor filter.
        httpGetText.mockResolvedValue(ok(JSON.stringify({
            cveMetadata: { cveId: 'CVE-2024-5555' },
            containers: {
                cna: {
                    descriptions: [{ lang: 'en', value: 'This issue affects Some Random Phrase in production.' }],
                    affected: [{ vendor: 'n/a', product: 'n/a' }],
                },
            },
        })));

        const result = await fetchMitreCvew('CVE-2024-5555');
        expect(result.records[0].vendor).toBe('');
        expect(result.records[0].product).toBe('');
    });

    test('treats 404 as no data', async () => {
        httpGetText.mockResolvedValue({ statusCode: 404, headers: {}, body: '' });
        await expect(fetchMitreCvew('CVE-0000-0000')).resolves.toEqual({ records: [], total: 0 });
    });

    test('rejects on a server error so the caller can report it', async () => {
        httpGetText.mockResolvedValue({ statusCode: 500, headers: {}, body: '' });
        await expect(fetchMitreCvew('CVE-2024-1')).rejects.toThrow('MITRE CVEW HTTP 500');
    });
});
