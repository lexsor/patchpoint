const {
    mergeRecords, classifySeverity, normalizeCveId,
    mergeRemediationLists, hasActionableFix,
} = require('../src/models/deduplication');

describe('Deduplication Module', () => {
    describe('normalizeCveId', () => {
        test('normalizes CVE ID by removing spaces and uppercasing', () => {
            expect(normalizeCveId('cve-2024-21675')).toBe('CVE-2024-21675');
            expect(normalizeCveId('CVE-2024- 21675')).toBe('CVE-2024-21675');
            expect(normalizeCveId('  CVE-2024-1234  ')).toBe('CVE-2024-1234');
        });

        test('handles empty/null input', () => {
            expect(normalizeCveId('')).toBe('');
            expect(normalizeCveId(null)).toBe('');
            expect(normalizeCveId(undefined)).toBe('');
        });
    });

    describe('classifySeverity', () => {
        test('classifies CRITICAL for CVSS >= 9.0', () => {
            expect(classifySeverity(9.0)).toBe('CRITICAL');
            expect(classifySeverity(9.8)).toBe('CRITICAL');
            expect(classifySeverity(10.0)).toBe('CRITICAL');
        });

        test('classifies HIGH for CVSS >= 7.0', () => {
            expect(classifySeverity(7.0)).toBe('HIGH');
            expect(classifySeverity(7.5)).toBe('HIGH');
            expect(classifySeverity(8.9)).toBe('HIGH');
        });

        test('classifies MEDIUM for CVSS >= 4.0', () => {
            expect(classifySeverity(4.0)).toBe('MEDIUM');
            expect(classifySeverity(5.5)).toBe('MEDIUM');
            expect(classifySeverity(6.9)).toBe('MEDIUM');
        });

        test('classifies LOW for CVSS < 4.0', () => {
            expect(classifySeverity(3.9)).toBe('LOW');
            expect(classifySeverity(1.0)).toBe('LOW');
            expect(classifySeverity(0.0)).toBe('LOW');
        });

        test('handles NaN gracefully', () => {
            expect(classifySeverity(NaN)).toBe('LOW');
            expect(classifySeverity(null)).toBe('LOW');
        });
    });

    describe('mergeRecords', () => {
        test('creates a new record when CVE does not exist', () => {
            const map = new Map();
            const records = [{
                cve_id: 'CVE-2024-1234',
                title: 'Test vulnerability',
                description: 'A test description',
                cvss_score: 7.5,
                published_date: '2024-01-15',
            }];

            const result = mergeRecords(map, records, 'NVD');
            
            expect(result.size).toBe(1);
            expect(result.has('CVE-2024-1234')).toBe(true);
            expect(result.get('CVE-2024-1234').title).toBe('Test vulnerability');
            expect(result.get('CVE-2024-1234').source_labels).toBe('["NVD"]');
        });

        test('merges same CVE from multiple sources', () => {
            const map = new Map();
            const record1 = [{
                cve_id: 'CVE-2024-1234',
                title: 'Original title',
                description: 'Original description',
                cvss_score: 7.5,
                vendor: 'Vendor A',
            }];
            
            const record2 = [{
                cve_id: 'CVE-2024-1234',
                title: 'Updated title',
                description: 'More detailed description that is longer than original',
                cvss_score: 9.1,
                vendor: 'Vendor B',
            }];

            mergeRecords(map, record1, 'NVD');
            mergeRecords(map, record2, 'CISA KEV');

            const merged = map.get('CVE-2024-1234');
            
            // Should have both sources
            const sources = JSON.parse(merged.source_labels);
            expect(sources).toContain('NVD');
            expect(sources).toContain('CISA KEV');

            // Should keep higher CVSS
            expect(merged.cvss_score).toBe(9.1);
            expect(merged.severity).toBe('CRITICAL');

            // Should keep longer description
            expect(merged.description).toBe('More detailed description that is longer than original');

            // Should keep non-empty vendor
            expect(merged.vendor).toBe('Vendor A'); // kept original since it's set
        });

        test('KEV flag propagates correctly', () => {
            const map = new Map();
            const normalRecord = [{
                cve_id: 'CVE-2024-5678',
                kev_flag: false,
            }];
            const kevRecord = [{
                cve_id: 'CVE-2024-5678',
                kev_flag: true,
                kev_date_added: '2024-03-01',
            }];

            mergeRecords(map, normalRecord, 'NVD');
            mergeRecords(map, kevRecord, 'CISA KEV');

            expect(map.get('CVE-2024-5678').kev_flag).toBe(true);
        });

        test('collects references from multiple sources', () => {
            const map = new Map();
            const record1 = [{
                cve_id: 'CVE-2024-9999',
                references: JSON.stringify(['http://example.com/ref1']),
                cwes: JSON.stringify(['CWE-79']),
            }];
            const record2 = [{
                cve_id: 'CVE-2024-9999',
                references: JSON.stringify(['http://example.com/ref2', 'http://example.com/ref3']),
                cwes: JSON.stringify(['CWE-79', 'CWE-80']),
            }];

            mergeRecords(map, record1, 'NVD');
            mergeRecords(map, record2, 'MITRE CVEW');

            const refs = JSON.parse(map.get('CVE-2024-9999').references);
            const cwes = JSON.parse(map.get('CVE-2024-9999').cwes);

            expect(refs).toContain('http://example.com/ref1');
            expect(refs).toContain('http://example.com/ref2');
            expect(refs).toContain('http://example.com/ref3');
            expect(cwes).toContain('CWE-79');
            expect(cwes).toContain('CWE-80');
        });

        test('handles array and single record input', () => {
            const map = new Map();
            
            // Single record
            mergeRecords(map, { cve_id: 'CVE-2024-1000' }, 'NVD');
            
            // Array of records
            mergeRecords(map, [
                { cve_id: 'CVE-2024-1001' },
                { cve_id: 'CVE-2024-1002' },
            ], 'CISA');

            expect(map.size).toBe(3);
        });

        test('skips records without CVE ID', () => {
            const map = new Map();
            mergeRecords(map, [{ cve_id: '', vendor: 'test' }], 'NVD');
            mergeRecords(map, [null, undefined], 'NVD');
            
            expect(map.size).toBe(0);
        });
    });
});

describe('remediation merging', () => {
    const nvdEntry = {
        source: 'NVD', vendor: 'google', product: 'android',
        affected_to: '15.0', bound: 'exclusive', fixed_in: '15.0', patch_level: null,
    };
    const bulletinEntry = {
        source: 'Android Bulletin', vendor: 'google', product: 'android',
        fixed_in: '13, 14, 15, 16', patch_level: '2025-12-01',
    };

    describe('mergeRemediationLists', () => {
        test('unions entries from different sources rather than overwriting', () => {
            // The failure this prevents: NVD and the Android bulletin write the
            // same CVE on separate fetch cycles. Last-writer-wins would make
            // each source erase the other's remediation on every poll, so the
            // column would flip between the two forever.
            const merged = mergeRemediationLists([nvdEntry], [bulletinEntry]);

            expect(merged).toHaveLength(2);
            expect(merged.map((e) => e.source).sort()).toEqual(['Android Bulletin', 'NVD']);
        });

        test('replaces an entry from the same source and product', () => {
            // A corrected fix version should supersede the stale one, not
            // accumulate beside it, so fixed_in is not part of the key.
            const corrected = { ...nvdEntry, fixed_in: '15.1', affected_to: '15.1' };
            const merged = mergeRemediationLists([nvdEntry], [corrected]);

            expect(merged).toHaveLength(1);
            expect(merged[0].fixed_in).toBe('15.1');
        });

        test('keeps distinct patch levels for the same product', () => {
            // One CVE is legitimately fixed at several Android patch levels
            // across branches; those are distinct facts, not duplicates.
            const march = { ...bulletinEntry, patch_level: '2025-03-01' };
            const merged = mergeRemediationLists([bulletinEntry], [march]);

            expect(merged).toHaveLength(2);
        });

        test('keeps a products distinct ranges instead of collapsing them', () => {
            // Measured on 1,000 CVEs, 142 of 418 products carry more than one
            // range, each with its own fix version. Keying only on
            // (source, vendor, product) kept one and silently dropped the
            // rest, which would show an admin on Tomcat 8 the Tomcat 7 fix.
            const seven = {
                source: 'NVD', vendor: 'apache', product: 'tomcat',
                affected_from: '7.0.0', affected_to: '7.0.73', bound: 'exclusive',
                fixed_in: '7.0.73', patch_level: null,
            };
            const eight = {
                ...seven, affected_from: '8.0', affected_to: '8.0.39', fixed_in: '8.0.39',
            };

            expect(mergeRemediationLists([], [seven, eight])).toHaveLength(2);
            // Both survive because they arrive in one report. Arriving in
            // separate reports is a different case, handled by the test below:
            // NVD publishes every range for a product at once, so a report
            // naming only 8.0 means 7.0 is no longer affected.
            expect(mergeRemediationLists([], [seven, eight]).map((e) => e.fixed_in))
                .toEqual(['7.0.73', '8.0.39']);
        });

        test('a fresh report replaces the whole group it addresses', () => {
            // NVD republishes every range for a product in one response, so a
            // reanalysis that revises one range and withdraws another is
            // complete on arrival. Unioning entry by entry would leave the
            // withdrawn range behind forever.
            const stored = [
                {
                    source: 'NVD', vendor: 'apache', product: 'tomcat',
                    affected_from: '7.0.0', affected_to: '7.0.73', fixed_in: '7.0.73', patch_level: null,
                },
                {
                    source: 'NVD', vendor: 'apache', product: 'tomcat',
                    affected_from: '8.0', affected_to: '8.0.39', fixed_in: '8.0.39', patch_level: null,
                },
            ];
            const revised = [{
                source: 'NVD', vendor: 'apache', product: 'tomcat',
                affected_from: '7.0.0', affected_to: '7.0.75', fixed_in: '7.0.75', patch_level: null,
            }];

            expect(mergeRemediationLists(stored, revised)).toEqual(revised);
        });

        test('a report about one product leaves another products entries alone', () => {
            const tomcat = {
                source: 'NVD', vendor: 'apache', product: 'tomcat',
                affected_to: '7.0.73', fixed_in: '7.0.73', patch_level: null,
            };
            const struts = {
                source: 'NVD', vendor: 'apache', product: 'struts',
                affected_to: '2.5.13', fixed_in: '2.5.13', patch_level: null,
            };

            const merged = mergeRemediationLists([tomcat], [struts]);
            expect(merged.map((e) => e.product).sort()).toEqual(['struts', 'tomcat']);
        });

        test('is order-independent in what it retains', () => {
            const a = mergeRemediationLists([nvdEntry], [bulletinEntry]).length;
            const b = mergeRemediationLists([bulletinEntry], [nvdEntry]).length;
            expect(a).toBe(b);
        });

        test('ignores non-object entries', () => {
            expect(mergeRemediationLists(['garbage', null], [bulletinEntry])).toEqual([bulletinEntry]);
            expect(mergeRemediationLists([], [])).toEqual([]);
        });
    });

    describe('hasActionableFix', () => {
        test('a named fix version counts', () => {
            expect(hasActionableFix([nvdEntry])).toBe(true);
        });

        test('a patch level counts even with no version', () => {
            expect(hasActionableFix([{ source: 'Android Bulletin', patch_level: '2025-12-01' }])).toBe(true);
        });

        test('an inclusive upper bound alone does not count', () => {
            // "fixed sometime after 1.5" names no version, so there is nothing
            // an admin can action. Counting it would make the "has a known
            // fix" filter return rows with no fix in them.
            expect(hasActionableFix([{
                source: 'NVD', vendor: 'a', product: 'b',
                affected_to: '1.5', bound: 'inclusive', fixed_in: null, patch_level: null,
            }])).toBe(false);
        });

        test('accepts a JSON string as well as an array', () => {
            // A row read back from jsonb arrives as an array; a merged record
            // carries a string. Both reach this function.
            expect(hasActionableFix(JSON.stringify([nvdEntry]))).toBe(true);
            expect(hasActionableFix('[]')).toBe(false);
            expect(hasActionableFix(null)).toBe(false);
        });
    });

    describe('through mergeRecords', () => {
        test('a second source does not drop the first source remediations', () => {
            const map = new Map();
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', remediations: [nvdEntry] }], 'NVD');
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', remediations: [bulletinEntry] }], 'Android Bulletin');

            const merged = JSON.parse(map.get('CVE-2024-0001').remediations);
            expect(merged).toHaveLength(2);
        });

        test('a new record keeps every range the source reported', () => {
            // The createMergedRecord path deduplicates too, so a first sighting
            // of a multi-branch CVE has to survive it intact. Under the old
            // key this stored one of the three.
            const ranges = ['6.0.48', '7.0.73', '8.0.39'].map((fixed) => ({
                source: 'NVD', vendor: 'apache', product: 'tomcat',
                affected_from: fixed.slice(0, 3), affected_to: fixed, fixed_in: fixed, patch_level: null,
            }));
            const map = new Map();
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', remediations: ranges }], 'NVD');

            expect(JSON.parse(map.get('CVE-2024-0001').remediations)).toHaveLength(3);
        });

        test('a later bulletin month does not delete an earlier patch level', () => {
            // Bulletins report one month per fetch cycle, so replacement has to
            // be scoped by patch level. Scoping it to the source alone would
            // make each month wipe the last.
            const march = { ...bulletinEntry, patch_level: '2025-03-05', fixed_in: '13, 14, 15' };
            const map = new Map();
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', remediations: [march] }], 'Android Bulletin');
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', remediations: [bulletinEntry] }], 'Android Bulletin');

            const merged = JSON.parse(map.get('CVE-2024-0001').remediations);
            expect(merged.map((e) => e.patch_level).sort()).toEqual(['2025-03-05', '2025-12-01']);
        });

        test('a source that supplies no remediations does not wipe them', () => {
            // MITRE enrichment runs after NVD and carries no remediation data.
            const map = new Map();
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', remediations: [nvdEntry] }], 'NVD');
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', description: 'fuller text' }], 'MITRE CVEW');

            expect(JSON.parse(map.get('CVE-2024-0001').remediations)).toHaveLength(1);
        });

        test('a positive ransomware finding survives a later Unknown', () => {
            const map = new Map();
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', kev_flag: true, kev_ransomware: true }], 'CISA KEV');
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', kev_flag: true, kev_ransomware: null }], 'CISA KEV');

            expect(map.get('CVE-2024-0001').kev_ransomware).toBe(true);
        });

        test('ransomware stays null when no source reports Known', () => {
            const map = new Map();
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', kev_flag: true, kev_ransomware: null }], 'CISA KEV');

            expect(map.get('CVE-2024-0001').kev_ransomware).toBeNull();
        });

        test('carries the KEV due date and required action', () => {
            const map = new Map();
            mergeRecords(map, [{
                cve_id: 'CVE-2024-0001', kev_flag: true,
                kev_due_date: '2024-07-11',
                kev_required_action: 'Apply updates per vendor instructions.',
            }], 'CISA KEV');

            const record = map.get('CVE-2024-0001');
            expect(record.kev_due_date).toBe('2024-07-11');
            expect(record.kev_required_action).toBe('Apply updates per vendor instructions.');
        });

        test('a non-KEV source does not clear KEV remediation fields', () => {
            const map = new Map();
            mergeRecords(map, [{
                cve_id: 'CVE-2024-0001', kev_flag: true, kev_due_date: '2024-07-11',
            }], 'CISA KEV');
            mergeRecords(map, [{ cve_id: 'CVE-2024-0001', cvss_score: 9.1 }], 'NVD');

            expect(map.get('CVE-2024-0001').kev_due_date).toBe('2024-07-11');
        });
    });
});
