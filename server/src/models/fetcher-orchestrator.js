const { fetchCisaKev, fetchCisaKevJson } = require('../fetchers/cisa-fetcher');
const { fetchNvd } = require('../fetchers/nvd-fetcher');
const { fetchMitreCvew } = require('../fetchers/mitre-fetcher');
const { sleep } = require('../lib/http');
const repository = require('./repository');
const alertEngine = require('./alert-engine');

/**
 * Fetcher Orchestrator
 *
 * Runs one fetch cycle across all sources and stores the results with
 * deduplication. Each source is isolated: one failing source does not stop
 * the others, and its error is reported per-source rather than aborting.
 */

const SOURCE_CISA = 'CISA KEV';
const SOURCE_NVD = 'NVD';
const SOURCE_MITRE = 'MITRE CVEW';

// NVD publishes 5 requests / 30s without an API key and 50 / 30s with one.
// Stay under both with a little headroom.
const NVD_DELAY_NO_KEY_MS = 6500;
const NVD_DELAY_WITH_KEY_MS = 800;

const intFromEnv = (name, fallback) => {
    const parsed = parseInt(process.env[name], 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

let isFetching = false;
let lastCompletedAt = null;
let lastResult = null;

async function fetchAllSources() {
    if (isFetching) {
        console.log('[Fetcher] Fetch already in progress, skipping');
        return { success: false, reason: 'already_fetching', started_at: null };
    }

    isFetching = true;
    const startedAt = new Date().toISOString();
    const results = {
        started_at: startedAt,
        finished_at: null,
        [SOURCE_CISA]: null,
        [SOURCE_NVD]: null,
        [SOURCE_MITRE]: null,
        alerts: 0,
        error: null,
    };

    try {
        console.log('[Fetcher] Starting full fetch cycle');

        results[SOURCE_CISA] = await runSource(SOURCE_CISA, fetchCisaSource);
        results[SOURCE_NVD] = await runSource(SOURCE_NVD, fetchNvdSource);
        results[SOURCE_MITRE] = await runSource(SOURCE_MITRE, fetchMitreSource);

        try {
            const alerts = await alertEngine.run();
            results.alerts = alerts.length;
            console.log(`[Fetcher] Generated ${alerts.length} new alerts`);
        } catch (err) {
            console.error('[Fetcher] Alert engine error:', err.message);
        }

        console.log('[Fetcher] Full fetch cycle complete');
    } catch (err) {
        // Only an unexpected failure outside the per-source guards lands here.
        results.error = err.message;
        console.error('[Fetcher] Fetch error:', err.message);
    } finally {
        results.finished_at = new Date().toISOString();
        lastCompletedAt = results.finished_at;
        lastResult = results;
        isFetching = false;
    }

    return results;
}

/**
 * Run one source, recording its outcome. Metadata bookkeeping is kept
 * separate from the fetch itself so a failed `updateSource` cannot make a
 * successful fetch look like a failure.
 */
async function runSource(name, fn) {
    try {
        const outcome = await fn();
        console.log(`[Fetcher] ${name} complete: ${outcome.stored} stored from ${outcome.fetched} fetched`);

        try {
            await repository.updateSource(name, outcome.stored);
        } catch (err) {
            console.error(`[Fetcher] ${name} metadata update failed:`, err.message);
        }

        return { total: outcome.stored, fetched: outcome.fetched, error: null, ...outcome.extra };
    } catch (err) {
        console.error(`[Fetcher] ${name} error:`, err.message);
        return { total: 0, fetched: 0, error: err.message };
    }
}

/**
 * CISA KEV. The CSV and JSON feeds are the same catalog in two formats, so
 * JSON is a fallback rather than a second source — labelling it separately
 * made one dataset appear twice under two source names.
 */
async function fetchCisaSource() {
    let result;
    try {
        result = await fetchCisaKev();
    } catch (err) {
        console.warn(`[Fetcher] CISA KEV CSV failed (${err.message}); trying JSON feed`);
        result = await fetchCisaKevJson();
    }

    const stored = await repository.storeRecords(result.records, SOURCE_CISA);
    return { fetched: result.total, stored };
}

/**
 * Page through an NVD query, storing each page as it arrives.
 *
 * @param {object} query   Extra fetchNvd options (window bounds, hasKev).
 * @param {number} maxPages
 * @param {number} delayMs Spacing between requests, to respect rate limits.
 * @param {string} label   For the truncation warning.
 */
async function pageThroughNvd(query, { maxPages, delayMs, label }) {
    let startIndex = 0;
    let fetched = 0;
    let stored = 0;
    let pages = 0;
    let truncated = false;

    for (;;) {
        const page = await fetchNvd({ ...query, startIndex });

        fetched += page.total;
        if (page.records.length > 0) {
            stored += await repository.storeRecords(page.records, SOURCE_NVD);
        }

        pages++;
        startIndex = page.nextStartIndex;

        if (page.isLastPage) break;

        if (pages >= maxPages) {
            truncated = true;
            console.warn(
                `[Fetcher] NVD ${label} stopped at the ${maxPages}-page cap with ${page.totalResults} records `
                + 'available. Raise NVD_MAX_PAGES or set NVD_API_KEY to ingest the rest.'
            );
            break;
        }

        await sleep(delayMs);
    }

    return { fetched, stored, pages, truncated };
}

/**
 * NVD, in two sweeps.
 *
 * 1. `hasKev` — every CVE in the CISA KEV catalogue (~1,700, so one page
 *    covers it). CISA publishes no CVSS score, so without this pass the KEV
 *    records that dominate the table carry no severity at all and the
 *    severity filter has nothing real to filter on.
 * 2. A rolling modification window, for everything that changed recently.
 *    The original implementation paged by index from 0 every cycle, so it
 *    re-read the same first 10,000 CVEs (of ~385,000) forever and never saw
 *    an update. NVD caps the window at 120 days.
 */
async function fetchNvdSource() {
    const lookbackDays = Math.min(intFromEnv('NVD_LOOKBACK_DAYS', 30), 120);
    const maxPages = intFromEnv('NVD_MAX_PAGES', 5);
    const apiKey = process.env.NVD_API_KEY || '';
    const delayMs = apiKey ? NVD_DELAY_WITH_KEY_MS : NVD_DELAY_NO_KEY_MS;

    const kev = await pageThroughNvd({ hasKev: true, apiKey }, { maxPages, delayMs, label: 'KEV sweep' });
    console.log(`[Fetcher] NVD KEV sweep: ${kev.stored} scored from ${kev.fetched} fetched`);

    await sleep(delayMs);

    const end = new Date();
    const start = new Date(end.getTime() - lookbackDays * 24 * 60 * 60 * 1000);
    const recent = await pageThroughNvd({
        lastModStartDate: start.toISOString(),
        lastModEndDate: end.toISOString(),
        apiKey,
    }, { maxPages, delayMs, label: `${lookbackDays}-day window` });

    return {
        fetched: kev.fetched + recent.fetched,
        stored: kev.stored + recent.stored,
        extra: {
            kev: { fetched: kev.fetched, stored: kev.stored, truncated: kev.truncated },
            recent: { fetched: recent.fetched, stored: recent.stored, truncated: recent.truncated },
            truncated: kev.truncated || recent.truncated,
        },
    };
}

/**
 * MITRE CVE Services, used as an enrichment pass.
 *
 * There is no bulk endpoint, so this takes CVEs already discovered by CISA or
 * NVD that carry no MITRE label yet and requests them one at a time, bounded
 * by MITRE_ENRICH_LIMIT. The previous code called fetchMitreCvew(0) — `0` is
 * falsy, so the source was a permanent no-op despite being advertised.
 */
async function fetchMitreSource() {
    const limit = intFromEnv('MITRE_ENRICH_LIMIT', 25);
    const cveIds = await repository.getCveIdsMissingSource(SOURCE_MITRE, limit);

    if (cveIds.length === 0) {
        console.log('[Fetcher] MITRE CVEW: nothing left to enrich');
        return { fetched: 0, stored: 0, extra: { enriched: 0 } };
    }

    console.log(`[Fetcher] MITRE CVEW: enriching ${cveIds.length} CVE(s)`);

    const records = [];
    let failures = 0;

    for (const cveId of cveIds) {
        try {
            const result = await fetchMitreCvew(cveId);
            records.push(...result.records);
        } catch (err) {
            failures++;
            console.warn(`[Fetcher] MITRE CVEW ${cveId} failed: ${err.message}`);
        }
    }

    const stored = records.length > 0 ? await repository.storeRecords(records, SOURCE_MITRE) : 0;
    return { fetched: records.length, stored, extra: { enriched: records.length, failures } };
}

function getFetchStatus() {
    return {
        isFetching,
        lastCompletedAt,
        lastResult,
    };
}

module.exports = { fetchAllSources, getFetchStatus, SOURCE_CISA, SOURCE_NVD, SOURCE_MITRE };
