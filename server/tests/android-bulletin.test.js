jest.mock('../src/lib/http');

const fs = require('fs');
const path = require('path');

const { httpGetText } = require('../src/lib/http');
const {
    fetchBulletinIndex, fetchAndroidBulletin, parseBulletin, parseVersions,
    supportedMonths, extractPatchLevel, extractRevision, EARLIEST_BULLETIN,
} = require('../src/fetchers/android-bulletin-fetcher');
const { extractTables, cellText, decodeEntities, findColumn } = require('../src/lib/html-table');

/**
 * A verbatim excerpt of the real December 2025 bulletin.
 *
 * Pinned as a fixture because this parser reads scraped HTML on a site Google
 * can restructure without notice. The excerpt keeps one `Updated AOSP
 * versions` table, one `Subcomponent` table, the `Android Launch Version`
 * table and the glossary, so the header-driven table selection is exercised
 * against markup that actually shipped rather than against something written
 * to make the parser pass.
 */
const FIXTURE = fs.readFileSync(
    path.join(__dirname, 'fixtures', 'android-bulletin-2025-12-01.html'),
    'utf8',
);

const ok = (body) => ({ statusCode: 200, headers: {}, body });

beforeEach(() => {
    httpGetText.mockReset();
});

describe('parseBulletin', () => {
    test('takes the patch level from the page text, not the URL slug', () => {
        // The single most important assertion in this file. This bulletin is
        // published at slug 2025-12-01 but states 2025-12-05 as the level that
        // addresses its issues, so reporting the slug would tell an admin
        // sitting on 2025-12-01 they were covered when they are not.
        const out = parseBulletin(FIXTURE, '2025-12-01');

        expect(out.patchLevel).toBe('2025-12-05');
        expect(out.patchLevel).not.toBe(out.slug);
    });

    test('accepts a stated patch level equal to the slug', () => {
        // Which one a bulletin names varies: 2025-12 states -05, but
        // 2025-11 states -01. Requiring them to differ would reject a real
        // bulletin, so only the month is validated.
        const html = FIXTURE.replace('2025-12-05', '2025-12-01');

        expect(parseBulletin(html, '2025-12-01').patchLevel).toBe('2025-12-01');
    });

    test('reads the revision marker, because bulletins are revised after publication', () => {
        const out = parseBulletin(FIXTURE, '2025-12-01');
        expect(out.revision).toBe('March 6, 2026');
    });

    test('extracts CVEs from both the AOSP and the vendor-component tables', () => {
        const out = parseBulletin(FIXTURE, '2025-12-01');

        expect(out.total).toBe(8);
        expect(out.records.map((r) => r.cve_id)).toContain('CVE-2025-22420');
        // From the Subcomponent table, which has no version column.
        expect(out.records.map((r) => r.cve_id)).toContain('CVE-2025-48623');
    });

    test('an AOSP row yields the versions that received the fix', () => {
        const out = parseBulletin(FIXTURE, '2025-12-01');
        const record = out.records.find((r) => r.cve_id === 'CVE-2025-22420');

        expect(record.remediations).toEqual([{
            source: 'Android Bulletin',
            vendor: 'google',
            product: 'android',
            fixed_in: '13, 14, 15, 16',
            patch_level: '2025-12-05',
        }]);
    });

    test('a vendor-component row yields a patch level with no version list', () => {
        // These are real fixes at a real patch level; they just are not
        // expressed as AOSP versions. Dropping them would discard more than
        // half of every bulletin.
        const out = parseBulletin(FIXTURE, '2025-12-01');
        const record = out.records.find((r) => r.cve_id === 'CVE-2025-48623');

        expect(record.remediations[0].patch_level).toBe('2025-12-05');
        expect(record.remediations[0].fixed_in).toBe('');
    });

    test('claims google/android attribution only for the AOSP tables', () => {
        // The vendor-component tables cover Qualcomm, MediaTek and others.
        // Labelling those google:android would be wrong.
        const out = parseBulletin(FIXTURE, '2025-12-01');

        expect(out.records.find((r) => r.cve_id === 'CVE-2025-22420').vendor).toBe('google');
        expect(out.records.find((r) => r.cve_id === 'CVE-2025-48623').vendor).toBe('');
    });

    test('classifies every bulletin CVE as mobile', () => {
        // Whichever component it lives in, a CVE in an Android bulletin is an
        // Android platform issue. This is what makes them findable under the
        // Technology filter, which is the reason Android CVEs were invisible
        // before the CPE work in fe38f08.
        const out = parseBulletin(FIXTURE, '2025-12-01');
        expect(out.records.every((r) => r.tech_type === 'mobile')).toBe(true);
    });

    test('maps bulletin severities onto the app vocabulary', () => {
        const out = parseBulletin(FIXTURE, '2025-12-01');
        const severities = new Set(out.records.map((r) => r.severity));

        expect(severities.has('HIGH')).toBe(true);
        expect(severities.has('CRITICAL')).toBe(true);
        // 'Moderate' is the only bulletin severity whose name differs.
        expect([...severities].every((s) => ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(s))).toBe(true);
    });

    test('carries no description, leaving that to NVD and MITRE', () => {
        const out = parseBulletin(FIXTURE, '2025-12-01');
        expect(out.records.every((r) => r.description === '')).toBe(true);
    });

    describe('layout-change guards', () => {
        // The hard case these guards exist for: an empty result and a broken
        // parser look identical from the outside. The discriminator is whether
        // the page still shows CVE ids we failed to read.
        //
        // This distinction is not hypothetical. 2025-10-01 is a real, current
        // bulletin that lists no CVEs at all, carrying only glossary tables.
        // An earlier version of this parser threw on any empty result and
        // turned that month into a hard failure.

        test('throws when CVEs are visible on the page but no table parses', () => {
            // Tables demoted to divs: the CVE ids are still in the document,
            // so this is a parser failure and must not be reported as zero.
            const html = FIXTURE.replace(/<table/g, '<div').replace(/<\/table>/g, '</div>');

            expect(() => parseBulletin(html, '2025-12-01')).toThrow(/none could be parsed/);
        });

        test('returns no records, without throwing, for a bulletin that lists no CVEs', () => {
            // A month with genuinely nothing to publish. Zero is the honest
            // answer here, not an error.
            const html = FIXTURE
                .replace(/<table[\s\S]*?<\/table>/g, '')
                .replace(/CVE-\d{4}-\d{4,7}/g, '')
                .replace(/Updated AOSP versions/g, '');

            const out = parseBulletin(html, '2025-12-01');

            expect(out.total).toBe(0);
            expect(out.patchLevel).toBe('2025-12-05');
        });

        test('throws when the AOSP versions column is renamed but still referenced', () => {
            // Losing the column would silently downgrade every record to
            // "patch level only" rather than failing.
            const html = FIXTURE.replace(
                '<th scope="col">Updated AOSP versions</th>',
                '<th scope="col">Fixed In Versions</th>',
            );

            expect(() => parseBulletin(html, '2025-12-01')).toThrow(/no\s+table column matched it/);
        });

        test('throws when the patch-level statement is missing', () => {
            const html = FIXTURE.replace(/[Ss]ecurity patch levels of/g, 'Patch info for');

            expect(() => parseBulletin(html, '2025-12-01')).toThrow(/could not find/);
        });

        test('throws when the stated patch level is not in the bulletin month', () => {
            // Guards against the sentence matching some other bulletin's
            // statement, e.g. text quoted from a neighbouring month.
            const html = FIXTURE.replace('2025-12-05', '2024-01-05');

            expect(() => parseBulletin(html, '2025-12-01')).toThrow(/not in the bulletin's month/);
        });
    });
});

describe('extractPatchLevel', () => {
    // Every variant below was found by parsing all 91 supported bulletins.
    // Each one broke an assumption that looked safe on a smaller sample.

    test('accepts the singular and plural wording', () => {
        expect(extractPatchLevel('Security patch levels of 2025-12-05 or later address', '2025-12-01'))
            .toBe('2025-12-05');
        expect(extractPatchLevel('Security patch level of 2025-12-05 or later address', '2025-12-01'))
            .toBe('2025-12-05');
    });

    test('accepts "or higher" as well as "or later"', () => {
        // 2019-06 is the only bulletin of the 91 that says "higher"; every
        // neighbouring month says "later".
        expect(extractPatchLevel('Security patch levels of 2019-06-05 or higher address', '2019-06-01'))
            .toBe('2019-06-05');
    });

    test('accepts any day of the month, not just -01 and -05', () => {
        // 2019-10, 2021-11 and 2023-10 all state -06.
        expect(extractPatchLevel('Security patch levels of 2023-10-06 or later address', '2023-10-01'))
            .toBe('2023-10-06');
    });

    test('rejects a level from a different month', () => {
        expect(() => extractPatchLevel('Security patch levels of 2024-01-05 or later', '2025-12-01'))
            .toThrow(/not in the bulletin's month/);
    });
});

describe('extractRevision', () => {
    test('prefers the updated date over the published date', () => {
        expect(extractRevision('Published December 1, 2025 | Updated March 6, 2026'))
            .toBe('March 6, 2026');
    });

    test('falls back to the published date when never revised', () => {
        expect(extractRevision('Published September 5, 2023')).toBe('September 5, 2023');
    });

    test('returns empty rather than throwing when neither is present', () => {
        // A missing date is not worth failing a fetch over; it only means the
        // month is re-parsed more often than necessary.
        expect(extractRevision('no dates here')).toBe('');
    });
});

describe('parseVersions', () => {
    test('splits a version list', () => {
        expect(parseVersions('13, 14, 15, 16')).toEqual(['13', '14', '15', '16']);
    });

    test('keeps the 12L feature drop, which is not numeric', () => {
        expect(parseVersions('11, 12, 12L, 13')).toEqual(['11', '12', '12L', '13']);
    });

    test('keeps point releases', () => {
        expect(parseVersions('6.0, 6.0.1, 7.1.1')).toEqual(['6.0', '6.0.1', '7.1.1']);
    });

    test('rejects a prose range outright rather than salvaging a number from it', () => {
        // Pre-2018 bulletins wrote ranges like "5.1 and below". Salvaging
        // "5.1" would be actively wrong: "and below" describes the AFFECTED
        // versions, so it would be published as a fix target meaning the
        // opposite of what the page says. Dropping the whole value is right,
        // and these months are below the supported floor anyway.
        expect(parseVersions('5.1 and below')).toEqual([]);
        expect(parseVersions('All')).toEqual([]);
        expect(parseVersions('')).toEqual([]);
        expect(parseVersions(null)).toEqual([]);
    });
});

describe('fetchBulletinIndex', () => {
    test('extracts monthly slugs newest first', async () => {
        httpGetText.mockResolvedValue(ok(`
            <a href="/docs/security/bulletin/2025-10-01">October</a>
            <a href="/docs/security/bulletin/2025-12-01">December</a>
            <a href="/docs/security/bulletin/2025-11-01">November</a>
        `));

        const { months } = await fetchBulletinIndex();

        expect(months).toEqual(['2025-12-01', '2025-11-01', '2025-10-01']);
    });

    test('ignores links that are not monthly bulletin slugs', async () => {
        // The index also links Pixel and Automotive bulletins, whose slugs are
        // dated differently.
        httpGetText.mockResolvedValue(ok(`
            <a href="/docs/security/bulletin/2025-12-01">December</a>
            <a href="/docs/security/bulletin/pixel/2025-12-01">Pixel</a>
            <a href="/docs/security/bulletin/2025-12-05">Not a slug</a>
        `));

        const { months } = await fetchBulletinIndex();

        expect(months).toEqual(['2025-12-01']);
    });

    test('throws when the index lists no bulletins', async () => {
        httpGetText.mockResolvedValue(ok('<html><body>nothing here</body></html>'));

        await expect(fetchBulletinIndex()).rejects.toThrow(/listed no monthly bulletins/);
    });

    test('throws on an HTTP error', async () => {
        httpGetText.mockResolvedValue({ statusCode: 503, headers: {}, body: '' });

        await expect(fetchBulletinIndex()).rejects.toThrow(/index HTTP 503/);
    });

    test('restricts redirects to the documentation host', async () => {
        httpGetText.mockResolvedValue(ok('<a href="/docs/security/bulletin/2025-12-01">x</a>'));

        await fetchBulletinIndex();

        expect(httpGetText).toHaveBeenCalledWith(
            expect.any(String),
            expect.objectContaining({ allowedHosts: ['source.android.com'] }),
        );
    });
});

describe('fetchAndroidBulletin', () => {
    test('fetches and parses a month', async () => {
        httpGetText.mockResolvedValue(ok(FIXTURE));

        const out = await fetchAndroidBulletin('2025-12-01');

        expect(out.patchLevel).toBe('2025-12-05');
        expect(out.total).toBe(8);
    });

    test('rejects a slug that is not a bulletin URL', async () => {
        // The slug is interpolated into a URL, so it must never come from
        // anywhere unvalidated.
        await expect(fetchAndroidBulletin('../../etc/passwd')).rejects.toThrow(/Invalid bulletin slug/);
        await expect(fetchAndroidBulletin('2025-12-05')).rejects.toThrow(/Invalid bulletin slug/);
        expect(httpGetText).not.toHaveBeenCalled();
    });

    test('throws on an HTTP error', async () => {
        httpGetText.mockResolvedValue({ statusCode: 404, headers: {}, body: '' });

        await expect(fetchAndroidBulletin('2025-12-01')).rejects.toThrow(/HTTP 404/);
    });
});

describe('supportedMonths', () => {
    test('drops months below the supported floor', () => {
        // Pre-2018 bulletins use a four-column layout with prose version
        // ranges. Nothing in a current fleet runs Android 5.
        const months = ['2025-12-01', '2018-06-01', '2015-08-01', '2017-01-01'];

        expect(supportedMonths(months)).toEqual(['2025-12-01', '2018-06-01']);
    });

    test('the floor is the first month with the modern layout', () => {
        expect(EARLIEST_BULLETIN).toBe('2018-06-01');
    });
});

describe('html-table', () => {
    test('reads headers and rows, ignoring colgroup and tbody', () => {
        const [table] = extractTables(`
            <table><colgroup><col width="20%"></colgroup><tbody>
              <tr><th>CVE</th><th>Severity</th></tr>
              <tr><td>CVE-2025-1</td><td>High</td></tr>
            </tbody></table>
        `);

        expect(table.headers).toEqual(['CVE', 'Severity']);
        expect(table.rows).toEqual([['CVE-2025-1', 'High']]);
    });

    test('strips tags inside a cell and collapses the padding around it', () => {
        // Bulletin cells wrap content in anchors and pad it with newlines, so
        // a strict CVE pattern only matches after normalisation.
        const [table] = extractTables(
            '<table><tr><th>CVE</th></tr><tr><td>\n  CVE-2025-1\n</td></tr></table>',
        );

        expect(table.rows).toEqual([['CVE-2025-1']]);
    });

    test('treats only the first th row as the header', () => {
        // Glossary sections put th cells mid-table.
        const [table] = extractTables(`
            <table>
              <tr><th>CVE</th></tr>
              <tr><td>CVE-2025-1</td></tr>
              <tr><th>Abbreviation</th></tr>
            </table>
        `);

        expect(table.headers).toEqual(['CVE']);
        expect(table.rows).toEqual([['CVE-2025-1'], ['Abbreviation']]);
    });

    test('returns every table in document order', () => {
        const tables = extractTables('<table><tr><th>A</th></tr></table><table><tr><th>B</th></tr></table>');
        expect(tables.map((t) => t.headers[0])).toEqual(['A', 'B']);
    });

    test('does not treat script or style content as text', () => {
        expect(cellText('<td><script>var x = "CVE-9999-9999";</script>ok</td>')).toBe('ok');
    });

    describe('decodeEntities', () => {
        test('decodes the entities this markup actually uses', () => {
            expect(decodeEntities('a&nbsp;b')).toBe('a b');
            expect(decodeEntities('Google&#39;s')).toBe("Google's");
            expect(decodeEntities('a&amp;b')).toBe('a&b');
            expect(decodeEntities('&#34;quoted&#34;')).toBe('"quoted"');
        });

        test('decodes &amp; last so an escaped entity is not double-decoded', () => {
            expect(decodeEntities('&amp;lt;')).toBe('&lt;');
        });

        test('leaves an unknown entity alone rather than dropping it', () => {
            expect(decodeEntities('&notarealentity;')).toBe('&notarealentity;');
        });
    });

    describe('findColumn', () => {
        test('locates a column by header text', () => {
            const headers = ['CVE', 'References', 'Type', 'Severity', 'Updated AOSP versions'];

            expect(findColumn(headers, /^cve$/i)).toBe(0);
            expect(findColumn(headers, /updated aosp versions?/i)).toBe(4);
        });

        test('returns -1 when the column is absent', () => {
            // Which is how a Subcomponent table is distinguished from an AOSP
            // one. Both have five columns, so position cannot tell them apart.
            expect(findColumn(['CVE', 'References', 'Type', 'Severity', 'Subcomponent'],
                /updated aosp versions?/i)).toBe(-1);
        });
    });
});

describe('selectBulletinTargets', () => {
    // Required separately from the fetcher because the orchestrator module
    // pulls in the repository and the other fetchers.
    const { selectBulletinTargets } = require('../src/models/fetcher-orchestrator');

    const months = Array.from({ length: 40 }, (_, i) => {
        const month = 12 - (i % 12);
        const year = 2025 - Math.floor(i / 12);
        return `${year}-${String(month).padStart(2, '0')}-01`;
    });

    test('re-checks the three newest months even when already stored', () => {
        // Bulletins are revised after publication, so the newest months are
        // the ones worth re-reading. Trusting a stored month forever would
        // mean never picking up the AOSP links added within 48 hours.
        const stored = new Map(months.map((m) => [m, 'rev']));

        const targets = selectBulletinTargets(months, stored);

        expect(targets).toEqual(months.slice(0, 3));
    });

    test('fetches never-seen months newest first', () => {
        // The most recent CVEs matter most, so the archive fills in behind
        // them rather than starting at 2018.
        const targets = selectBulletinTargets(months, new Map());

        expect(targets[0]).toBe(months[0]);
        expect(targets[1]).toBe(months[1]);
    });

    test('caps the work per cycle so a cold start does not pull the whole archive', () => {
        // ~91 supported months at ~300 KB each is 27 MB; backfilling across
        // cycles keeps any single cycle cheap.
        const targets = selectBulletinTargets(months, new Map());

        expect(targets).toHaveLength(12);
    });

    test('does not fetch the same month twice in one cycle', () => {
        // The recheck window and the missing list overlap on a cold start.
        const targets = selectBulletinTargets(months, new Map());

        expect(new Set(targets).size).toBe(targets.length);
    });

    test('combines the recheck window with the oldest gaps', () => {
        // Everything stored except one old month: the three newest are
        // re-checked and the gap is filled.
        const stored = new Map(months.filter((m) => m !== months[20]).map((m) => [m, 'rev']));

        const targets = selectBulletinTargets(months, stored);

        expect(targets.slice(0, 3)).toEqual(months.slice(0, 3));
        expect(targets).toContain(months[20]);
    });

    test('returns nothing to do when everything is stored and nothing is recent', () => {
        expect(selectBulletinTargets([], new Map())).toEqual([]);
    });
});
