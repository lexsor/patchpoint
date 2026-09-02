const { mergeRecords, classifySeverity, normalizeCveId } = require('../src/models/deduplication');

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
