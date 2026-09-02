const request = require('supertest');
const express = require('express');
const { fetchCisaKev, fetchCisaKevJson } = require('../src/fetchers/cisa-fetcher');
const { fetchNvd } = require('../src/fetchers/nvd-fetcher');
const { fetchMitreCvew } = require('../src/fetchers/mitre-fetcher');

// Mock the fetchers for API testing
describe('Data Source Fetchers', () => {
    describe('CISA KEV CSV Fetcher', () => {
        test('fetchCisaKev fetches real data from CISA', async () => {
            const result = await fetchCisaKev();
            expect(result.records).toBeDefined();
            expect(Array.isArray(result.records)).toBe(true);
            expect(result.records.length).toBeGreaterThan(0);
            
            // Verify record structure
            const firstRecord = result.records[0];
            expect(firstRecord.cve_id).toBeDefined();
            expect(firstRecord.kev_flag).toBe(true);
            expect(firstRecord.vendor).toBeDefined();
        }, 30000);
    });

    describe('CISA KEV JSON Fetcher', () => {
        test('fetchCisaKevJson fetches real data from CISA', async () => {
            const result = await fetchCisaKevJson();
            expect(result.records).toBeDefined();
            expect(Array.isArray(result.records)).toBe(true);
            expect(result.records.length).toBeGreaterThan(0);
            
            const firstRecord = result.records[0];
            expect(firstRecord.cve_id).toBeDefined();
            expect(firstRecord.kev_flag).toBe(true);
        }, 30000);
    });

    describe('NVD Fetcher', () => {
        test('fetchNvd fetches data from NVD API', async () => {
            const result = await fetchNvd(1);
            expect(result.records).toBeDefined();
            expect(Array.isArray(result.records)).toBe(true);
            // NVD has thousands of CVEs, page 1 should have some
            expect(result.total).toBeGreaterThan(0);
            expect(result.isLastPage).toBeDefined();
            
            // Verify record structure
            const firstRecord = result.records[0];
            expect(firstRecord.cve_id).toMatch(/CVE-\d{4}-\d+/);
        }, 60000);
    });

    describe('MITRE CVEW Fetcher', () => {
        test('fetchMitreCvew fetches data from MITRE API', async () => {
            const result = await fetchMitreCvew(0);
            expect(result.records).toBeDefined();
            expect(Array.isArray(result.records)).toBe(true);
            
            // MITRE API may have rate limits, but should return structured data
            if (result.records.length > 0) {
                const firstRecord = result.records[0];
                expect(firstRecord.cve_id).toBeDefined();
            }
        }, 60000);
    });
});
