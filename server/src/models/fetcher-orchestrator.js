const { fetchCisaKev, fetchCisaKevJson } = require('../fetchers/cisa-fetcher');
const { fetchNvd } = require('../fetchers/nvd-fetcher');
const { fetchMitreCvew } = require('../fetchers/mitre-fetcher');
const repository = require('../models/repository');
const alertEngine = require('./alert-engine');

/**
 * Fetcher Orchestrator
 * 
 * Orchestrates fetching from all data sources and stores results with deduplication.
 * Supports both scheduled polling and manual trigger via API.
 */

let isFetching = false;

async function fetchAllSources() {
    if (isFetching) {
        console.log('[Fetcher] Fetch already in progress, skipping');
        return { success: false, reason: 'already_fetching' };
    }
    
    isFetching = true;
    const results = {
        cisa_kev: null,
        cisa_kev_json: null,
        nvd: null,
        mitre_cvew: null,
        error: null,
        started_at: new Date().toISOString(),
    };
    
    try {
        console.log('[Fetcher] Starting full fetch cycle');
        
        // Fetch CISA KEV (CSV)
        try {
            results.cisa_kev = await fetchCisaKev();
            await repository.storeRecords(results.cisa_kev.records, 'CISA KEV');
            await repository.updateSource('CISA KEV', results.cisa_kev.total);
            console.log(`[Fetcher] CISA KEV complete: ${results.cisa_kev.total} records`);
        } catch (err) {
            console.error('[Fetcher] CISA KEV error:', err.message);
            results.cisa_kev = { error: err.message };
        }
        
        // Fetch CISA KEV (JSON) - can skip if CSV succeeded
        if (results.cisa_kev && results.cisa_kev.total > 0) {
            try {
                results.cisa_kev_json = await fetchCisaKevJson();
                await repository.storeRecords(results.cisa_kev_json.records, 'CISA KEV JSON');
                await repository.updateSource('CISA KEV JSON', results.cisa_kev_json.total);
                console.log(`[Fetcher] CISA KEV JSON complete: ${results.cisa_kev_json.total} records`);
            } catch (err) {
                console.error('[Fetcher] CISA KEV JSON error:', err.message);
                results.cisa_kev_json = { error: err.message };
            }
        } else {
            // Try JSON if CSV failed
            try {
                results.cisa_kev_json = await fetchCisaKevJson();
                await repository.storeRecords(results.cisa_kev_json.records, 'CISA KEV');
                await repository.updateSource('CISA KEV', results.cisa_kev_json.total);
                console.log(`[Fetcher] CISA KEV JSON (fallback): ${results.cisa_kev_json.total} records`);
            } catch (err) {
                console.error('[Fetcher] CISA KEV JSON error:', err.message);
                results.cisa_kev_json = { error: err.message };
            }
        }
        
        // Fetch NVD
        try {
            let totalNvd = 0;
            let page = 1;
            let isLastPage = false;
            
            do {
                const nvdResult = await fetchNvd(page);
                await repository.storeRecords(nvdResult.records, 'NVD');
                totalNvd += nvdResult.total;
                isLastPage = nvdResult.isLastPage;
                page++;
                
                // Rate limit awareness: NVD allows 5 req/30s without key
                if (!isLastPage && page < 5) {
                    await new Promise(resolve => setTimeout(resolve, 30000));
                }
            } while (!isLastPage && page <= 5);
            
            results.nvd = { total: totalNvd };
            await repository.updateSource('NVD', totalNvd);
            console.log(`[Fetcher] NVD complete: ${totalNvd} records`);
        } catch (err) {
            console.error('[Fetcher] NVD error:', err.message);
            results.nvd = { error: err.message };
        }
        
        // Fetch MITRE CVEW
        try {
            results.mitre_cvew = await fetchMitreCvew(0);
            await repository.storeRecords(results.mitre_cvew.records, 'MITRE CVEW');
            await repository.updateSource('MITRE CVEW', results.mitre_cvew.total);
            console.log(`[Fetcher] MITRE CVEW complete: ${results.mitre_cvew.total} records`);
        } catch (err) {
            console.error('[Fetcher] MITRE CVEW error:', err.message);
            results.mitre_cvew = { error: err.message };
        }
        
        // Run alert engine after fetch
        try {
            const alerts = await alertEngine.run();
            console.log(`[Fetcher] Generated ${alerts.length} alerts`);
        } catch (err) {
            console.error('[Fetcher] Alert engine error:', err.message);
        }
        
        console.log(`[Fetcher] Full fetch cycle complete`);
        return results;
        
    } catch (err) {
        results.error = err.message;
        console.error('[Fetcher] Fetch error:', err.message);
        return results;
    } finally {
        isFetching = false;
    }
}

function getFetchStatus() {
    return { isFetching };
}

module.exports = { fetchAllSources, getFetchStatus };
