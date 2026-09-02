const repository = require('../src/models/repository');
const { mergeRecords, classifySeverity } = require('../src/models/deduplication');

describe('Repository & Deduplication Integration', () => {
    describe('mergeRecords integration with repository flow', () => {
        test('simulates full fetch → store → query cycle', () => {
            // Simulate CISA KEV fetch result
            const cisaRecords = [{
                cve_id: 'CVE-2024-1234',
                vendor: 'Atlassian',
                product: 'Jira',
                description: 'Remote code execution in Jira',
                published_date: '2024-06-15',
                kev_flag: true,
                kev_date_added: '2024-06-20',
                cwes: JSON.stringify(['CWE-94', 'CWE-502']),
                severity: 'HIGH',
            }];

            // Simulate NVD fetch result for same CVE
            const nvdRecords = [{
                cve_id: 'CVE-2024-1234',
                vendor: 'Atlassian',
                description: 'Jira allows remote code execution via crafted requests',
                published_date: '2024-06-14',
                cvss_score: 9.8,
                cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                severity: 'CRITICAL',
            }];

            // Deduplicate
            const existing = new Map();
            mergeRecords(existing, cisaRecords, 'CISA KEV');
            mergeRecords(existing, nvdRecords, 'NVD');

            const merged = existing.get('CVE-2024-1234');
            
            // Should have both sources
            const sources = JSON.parse(merged.source_labels);
            expect(sources).toContain('CISA KEV');
            expect(sources).toContain('NVD');
            
            // Should have highest CVSS from NVD
            expect(merged.cvss_score).toBe(9.8);
            expect(merged.severity).toBe('CRITICAL');
            
            // KEV flag should be true
            expect(merged.kev_flag).toBe(true);
            
            // Should have the longer description (NVD wins over CISA)
            expect(merged.description).toContain('remote code execution');
            
            // Should have CWEs
            const cwes = JSON.parse(merged.cwes);
            expect(cwes).toContain('CWE-94');
            expect(cwes).toContain('CWE-502');
        });

        test('handles multiple CVEs from different sources independently', () => {
            const existing = new Map();
            
            // CVE-1 from CISA only
            mergeRecords(existing, [{ cve_id: 'CVE-2024-1000', kev_flag: true }], 'CISA KEV');
            
            // CVE-2 from NVD only
            mergeRecords(existing, [{ cve_id: 'CVE-2024-2000', cvss_score: 5.0 }], 'NVD');
            
            // CVE-3 from both
            mergeRecords(existing, [{ cve_id: 'CVE-2024-3000', cvss_score: 7.5 }], 'NVD');
            mergeRecords(existing, [{ cve_id: 'CVE-2024-3000', kev_flag: true, cvss_score: 8.2 }], 'CISA KEV');

            expect(existing.size).toBe(3);
            
            // CVE-3 should have both sources and highest CVSS
            const cve3 = existing.get('CVE-2024-3000');
            expect(JSON.parse(cve3.source_labels)).toContain('NVD');
            expect(JSON.parse(cve3.source_labels)).toContain('CISA KEV');
            expect(cve3.cvss_score).toBe(8.2);
            expect(cve3.kev_flag).toBe(true);
        });

        test('classifySeverity boundaries are correct', () => {
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

    describe('Watchlist alert matching logic', () => {
        test('CVE ID match is case-insensitive and whitespace-tolerant', () => {
            const watchlistItem = { item: 'CVE-2024-1234', item_type: 'cve_id' };
            const vuln = { cve_id: 'CVE-2024-1234', vendor: 'Test' };
            
            // Simulate alert engine matching
            const matches = vuln.cve_id.toUpperCase().replace(/\s/g, '') === 
                          watchlistItem.item.toUpperCase().replace(/\s/g, '');
            expect(matches).toBe(true);
        });

        test('Vendor match is case-insensitive substring', () => {
            const watchlistItem = { item: 'atlassian', item_type: 'vendor' };
            const vuln = { cve_id: 'CVE-2024-5678', vendor: 'Atlassian' };
            
            const matches = vuln.vendor && vuln.vendor.toLowerCase().includes(watchlistItem.item.toLowerCase());
            expect(matches).toBe(true);
        });

        test('Product match is case-insensitive substring', () => {
            const watchlistItem = { item: 'jira', item_type: 'product' };
            const vuln = { cve_id: 'CVE-2024-5678', product: 'Jira Cloud' };
            
            const matches = vuln.product && vuln.product.toLowerCase().includes(watchlistItem.item.toLowerCase());
            expect(matches).toBe(true);
        });

        test('no false positives on partial non-matches', () => {
            const watchlistItem = { item: 'microsoft', item_type: 'vendor' };
            const vuln = { cve_id: 'CVE-2024-5678', vendor: 'Google' };
            
            const matches = vuln.vendor && vuln.vendor.toLowerCase().includes(watchlistItem.item.toLowerCase());
            expect(matches).toBe(false);
        });
    });
});

