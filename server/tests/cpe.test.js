const { describeFromCpe, parseCpe, collectCpeCriteria } = require('../src/lib/cpe');
const { classifyTechType } = require('../src/lib/tech-type');

/** Build a CVE-shaped object carrying the given CPE criteria strings. */
function cveWithCpes(criteria) {
    return {
        id: 'CVE-2024-0001',
        configurations: [{ nodes: [{ cpeMatch: criteria.map((c) => ({ criteria: c })) }] }],
    };
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
