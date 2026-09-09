const {
    describeFromCpe, remediationsFromCpe, parseCpe,
    collectCpeCriteria, collectCpeMatches,
} = require('../src/lib/cpe');
const { classifyTechType } = require('../src/lib/tech-type');

/** Build a CVE-shaped object carrying the given CPE criteria strings. */
function cveWithCpes(criteria) {
    return {
        id: 'CVE-2024-0001',
        configurations: [{ nodes: [{ cpeMatch: criteria.map((c) => ({ criteria: c })) }] }],
    };
}

/**
 * Build a CVE-shaped object from whole cpeMatch objects, so the version bound
 * fields NVD publishes alongside `criteria` are present.
 */
function cveWithMatches(matches) {
    return { id: 'CVE-2024-0001', configurations: [{ nodes: [{ cpeMatch: matches }] }] };
}

/** A cpeMatch for one product, with whichever bounds are given. */
function match(product, bounds = {}) {
    return { criteria: `cpe:2.3:a:acme:${product}:*:*:*:*:*:*:*:*`, vulnerable: true, ...bounds };
}

describe('parseCpe', () => {
    test('extracts part, vendor and product from a CPE 2.3 string', () => {
        expect(parseCpe('cpe:2.3:o:google:android:14.0:*:*:*:*:*:*:*')).toEqual({
            part: 'o', vendor: 'google', product: 'android',
        });
    });

    test('humanizes underscores, which CPE uses instead of spaces', () => {
        expect(parseCpe('cpe:2.3:o:linux:linux_kernel:6.1:*:*:*:*:*:*:*').product).toBe('linux kernel');
        expect(parseCpe('cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*').product)
            .toBe('windows server 2022');
    });

    test('treats CPE wildcard and not-applicable markers as absent', () => {
        expect(parseCpe('cpe:2.3:a:*:*:1.0:*:*:*:*:*:*:*')).toBeNull();
        expect(parseCpe('cpe:2.3:a:-:-:1.0:*:*:*:*:*:*:*')).toBeNull();
    });

    test('rejects anything that is not a CPE 2.3 string', () => {
        expect(parseCpe('cpe:2.2:o:google:android')).toBeNull();
        expect(parseCpe('not a cpe')).toBeNull();
        expect(parseCpe('')).toBeNull();
        expect(parseCpe(null)).toBeNull();
    });

    test('does not split on an escaped colon inside a component', () => {
        const parsed = parseCpe('cpe:2.3:a:vendor:some\\:product:1.0:*:*:*:*:*:*:*');
        expect(parsed.vendor).toBe('vendor');
        expect(parsed.product).toBe('some:product');
    });
});

describe('collectCpeCriteria', () => {
    test('gathers criteria across configurations and nodes, deduplicated', () => {
        const cve = {
            configurations: [
                { nodes: [{ cpeMatch: [{ criteria: 'A' }, { criteria: 'B' }] }] },
                { nodes: [{ cpeMatch: [{ criteria: 'B' }, { criteria: 'C' }] }] },
            ],
        };
        expect(collectCpeCriteria(cve)).toEqual(['A', 'B', 'C']);
    });

    test('returns nothing for a CVE with no configurations', () => {
        expect(collectCpeCriteria({})).toEqual([]);
        expect(collectCpeCriteria(null)).toEqual([]);
    });
});

describe('describeFromCpe', () => {
    test('attributes a single-CPE Android CVE to google/android', () => {
        const out = describeFromCpe(cveWithCpes(['cpe:2.3:o:google:android:1.5:*:*:*:*:*:*:*']));
        expect(out).toMatchObject({ vendor: 'google', product: 'android', tech_type: 'mobile' });
    });

    test('picks the most frequently referenced pair, not the first listed', () => {
        // CVE-2010-1807's real shape: Safari listed first, but the CVE is
        // about Safari and Safari dominates the list. Position alone would be
        // arbitrary; frequency is the measured-best heuristic.
        const out = describeFromCpe(cveWithCpes([
            'cpe:2.3:a:apple:safari:4.0:*:*:*:*:*:*:*',
            'cpe:2.3:a:apple:safari:4.1:*:*:*:*:*:*:*',
            'cpe:2.3:a:apple:safari:5.0:*:*:*:*:*:*:*',
            'cpe:2.3:o:google:android:2.1:*:*:*:*:*:*:*',
        ]));
        expect(out.vendor).toBe('apple');
        expect(out.product).toBe('safari');
    });

    test('classifies tech_type from the whole CPE list, not the primary', () => {
        // This is what makes an Android CVE findable even when the primary
        // product is something else. A single vendor column cannot represent a
        // CVE spanning many platforms; tech_type can.
        const out = describeFromCpe(cveWithCpes([
            'cpe:2.3:a:adobe:flash_player:10.0:*:*:*:*:*:*:*',
            'cpe:2.3:a:adobe:flash_player:10.1:*:*:*:*:*:*:*',
            'cpe:2.3:o:google:android:2.2:*:*:*:*:*:*:*',
        ]));
        expect(out.product).toBe('flash player');
        expect(out.tech_type).toBe('mobile');
    });

    test('counts distinct versions of one product as that product', () => {
        const many = Array.from({ length: 40 }, (_, i) => `cpe:2.3:o:linux:linux_kernel:6.${i}:*:*:*:*:*:*:*`);
        const out = describeFromCpe(cveWithCpes([...many, 'cpe:2.3:a:acme:tool:1.0:*:*:*:*:*:*:*']));
        expect(out.vendor).toBe('linux');
        expect(out.product).toBe('linux kernel');
        expect(out.tech_type).toBe('os');
        expect(out.cpe_count).toBe(41);
    });

    test('a vendor or product containing a space cannot collide with another split', () => {
        // The tally key is JSON-encoded, so ["mac os","x"] and ["mac","os x"]
        // stay distinct rather than both becoming "mac os x".
        const out = describeFromCpe(cveWithCpes([
            'cpe:2.3:o:apple:mac_os_x:10.6:*:*:*:*:*:*:*',
            'cpe:2.3:o:apple:mac_os_x:10.7:*:*:*:*:*:*:*',
            'cpe:2.3:o:apple_mac:os_x:10.8:*:*:*:*:*:*:*',
        ]));
        expect(out.vendor).toBe('apple');
        expect(out.product).toBe('mac os x');
    });

    test('returns empty fields when a CVE carries no usable CPE', () => {
        expect(describeFromCpe({})).toEqual({ vendor: '', product: '', tech_type: '', cpe_count: 0 });
        expect(describeFromCpe(cveWithCpes(['garbage']))).toEqual({
            vendor: '', product: '', tech_type: '', cpe_count: 0,
        });
    });
});

describe('collectCpeMatches', () => {
    test('keeps one product listed twice with different ranges', () => {
        // The reason this exists rather than reusing collectCpeCriteria: the
        // criteria string is identical for every branch of a product, so
        // deduplicating on it would keep the first branch and drop the rest.
        const matches = collectCpeMatches(cveWithMatches([
            match('tool', { versionStartIncluding: '7.0', versionEndExcluding: '7.0.73' }),
            match('tool', { versionStartIncluding: '8.0', versionEndExcluding: '8.0.39' }),
        ]));

        expect(matches).toHaveLength(2);
        expect(matches.map((m) => m.versionEndExcluding)).toEqual(['7.0.73', '8.0.39']);
    });

    test('drops a match repeated with identical bounds', () => {
        const matches = collectCpeMatches(cveWithMatches([
            match('tool', { versionEndExcluding: '2.0' }),
            match('tool', { versionEndExcluding: '2.0' }),
        ]));

        expect(matches).toHaveLength(1);
    });

    test('collectCpeCriteria still collapses those to one string', () => {
        // Attribution counts distinct products, so the bound-aware collection
        // must not inflate the vendor/product tally or cpe_count.
        const cve = cveWithMatches([
            match('tool', { versionEndExcluding: '7.0.73' }),
            match('tool', { versionEndExcluding: '8.0.39' }),
        ]);

        expect(collectCpeCriteria(cve)).toHaveLength(1);
        expect(describeFromCpe(cve).cpe_count).toBe(1);
    });
});

describe('remediationsFromCpe', () => {
    test('reads an exclusive upper bound as the fix version', () => {
        // "versions below 7.0.73 are vulnerable" means 7.0.73 IS the fix.
        const [entry] = remediationsFromCpe(cveWithMatches([
            match('tool', { versionStartIncluding: '7.0', versionEndExcluding: '7.0.73' }),
        ]), 'NVD');

        expect(entry).toEqual({
            source: 'NVD',
            vendor: 'acme',
            product: 'tool',
            affected_from: '7.0',
            affected_to: '7.0.73',
            bound: 'exclusive',
            fixed_in: '7.0.73',
            patch_level: null,
        });
    });

    test('an inclusive upper bound names no fix version', () => {
        // "vulnerable up to and including 1.5" says the fix is later than 1.5
        // without saying what it is. Putting 1.5 in fixed_in would tell an
        // admin to install a version that is still vulnerable.
        const [entry] = remediationsFromCpe(cveWithMatches([
            match('tool', { versionEndIncluding: '1.5' }),
        ]), 'NVD');

        expect(entry.bound).toBe('inclusive');
        expect(entry.fixed_in).toBeNull();
        expect(entry.affected_to).toBe('1.5');
    });

    test('prefers the exclusive bound if a match somehow carries both', () => {
        // Never seen in 2,579 sampled matches, but exclusive is the more
        // precise statement, so it wins rather than the order of the fields.
        const [entry] = remediationsFromCpe(cveWithMatches([
            match('tool', { versionEndExcluding: '2.0', versionEndIncluding: '1.9' }),
        ]), 'NVD');

        expect(entry.fixed_in).toBe('2.0');
        expect(entry.bound).toBe('exclusive');
    });

    test('skips matches with no upper bound at all', () => {
        // This is the bulk of a long CPE list: an enumeration of every
        // affected version, carrying no fix information. Emitting entries for
        // them would fill the detail panel with "no fix published" rows and
        // inflate the +N count on the Fix column.
        expect(remediationsFromCpe(cveWithMatches([
            { criteria: 'cpe:2.3:o:google:android:2.1:*:*:*:*:*:*:*' },
            { criteria: 'cpe:2.3:o:google:android:2.2:*:*:*:*:*:*:*' },
            match('tool', { versionStartIncluding: '1.0' }),
        ]), 'NVD')).toEqual([]);
    });

    test('keeps every distinct range for one product', () => {
        // Tomcat's real shape: one fix version per affected branch. Collapsing
        // these would tell someone on 8.0 to install the 7.0 fix.
        const entries = remediationsFromCpe(cveWithMatches([
            match('tool', { versionEndExcluding: '6.0.48' }),
            match('tool', { versionStartIncluding: '7.0.0', versionEndExcluding: '7.0.73' }),
            match('tool', { versionStartIncluding: '8.0', versionEndExcluding: '8.0.39' }),
        ]), 'NVD');

        expect(entries.map((e) => e.fixed_in)).toEqual(['6.0.48', '7.0.73', '8.0.39']);
    });

    test('deduplicates a range repeated across configurations', () => {
        const cve = {
            id: 'CVE-2024-0001',
            configurations: [
                { nodes: [{ cpeMatch: [match('tool', { versionEndExcluding: '2.0' })] }] },
                { nodes: [{ cpeMatch: [match('tool', { versionEndExcluding: '2.0' })] }] },
            ],
        };

        expect(remediationsFromCpe(cve, 'NVD')).toHaveLength(1);
    });

    test('records an exclusive lower bound as the affected start', () => {
        // Two occurrences in 2,579 measured matches. This overstates the range
        // by the boundary version itself; dropping the bound would overstate
        // it by everything below.
        const [entry] = remediationsFromCpe(cveWithMatches([
            match('tool', { versionStartExcluding: '1.0', versionEndExcluding: '2.0' }),
        ]), 'NVD');

        expect(entry.affected_from).toBe('1.0');
    });

    test('puts the product the row names first', () => {
        // The Fix column shows the first entry carrying a fix version, and the
        // Vendor/Product columns show the frequency-primary. If they disagree
        // the row names one product and shows another product's version, which
        // is what CVE-2021-44228 does in document order.
        const cve = cveWithMatches([
            { criteria: 'cpe:2.3:a:siemens:firmware:*:*:*:*:*:*:*:*', versionEndExcluding: '2.7.0' },
            { criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*', versionEndExcluding: '2.15.0' },
            { criteria: 'cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*' },
        ]);

        expect(describeFromCpe(cve).product).toBe('log4j');
        expect(remediationsFromCpe(cve, 'NVD').map((e) => e.fixed_in)).toEqual(['2.15.0', '2.7.0']);
    });

    test('stamps the source it is given on every entry', () => {
        // The merge pairs this against the name storeRecords was called with,
        // so it must be the caller's constant rather than a literal in here.
        const entries = remediationsFromCpe(cveWithMatches([
            match('tool', { versionEndExcluding: '2.0' }),
            match('other', { versionEndExcluding: '3.0' }),
        ]), 'NVD');

        expect(entries.map((e) => e.source)).toEqual(['NVD', 'NVD']);
    });

    test('returns nothing for a CVE with no usable CPE', () => {
        expect(remediationsFromCpe({}, 'NVD')).toEqual([]);
        expect(remediationsFromCpe(null, 'NVD')).toEqual([]);
        expect(remediationsFromCpe(cveWithMatches([
            { criteria: 'garbage', versionEndExcluding: '2.0' },
        ]), 'NVD')).toEqual([]);
    });
});

describe('classifyTechType precedence', () => {
    test('android reads as mobile, not os, despite being an operating system', () => {
        expect(classifyTechType('google android operating system')).toBe('mobile');
    });

    test('cisco ios reads as networking, not os or mobile', () => {
        expect(classifyTechType('cisco ios_xe operating system')).toBe('networking');
    });

    test('recognises the buckets the Technology filter offers', () => {
        expect(classifyTechType('linux linux_kernel')).toBe('os');
        expect(classifyTechType('microsoft windows_10')).toBe('os');
        expect(classifyTechType('google chrome')).toBe('browser');
        expect(classifyTechType('postgresql')).toBe('database');
        expect(classifyTechType('kubernetes')).toBe('container');
        expect(classifyTechType('apache http_server')).toBe('web');
    });

    test('returns empty rather than a catch-all when nothing matches', () => {
        // The filter should only offer buckets that were actually identified.
        expect(classifyTechType('acme frobnicator')).toBe('');
        expect(classifyTechType('')).toBe('');
        expect(classifyTechType(null)).toBe('');
    });
});
