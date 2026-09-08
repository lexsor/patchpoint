const { fetchCisaKev, fetchCisaKevJson } = require('../fetchers/cisa-fetcher');
const { fetchNvd } = require('../fetchers/nvd-fetcher');
const { fetchMitreCvew } = require('../fetchers/mitre-fetcher');
const {
    fetchBulletinIndex, fetchAndroidBulletin, supportedMonths,
    SOURCE_NAME: SOURCE_ANDROID,
} = require('../fetchers/android-bulletin-fetcher');
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

// MITRE has no documented public rate limit, but the enrichment pass issues
// one request per CVE and previously fired them back to back. Space them out.
const MITRE_DELAY_MS = 250;

// Android bulletins are ~300 KB documentation pages on a Google property with
// no published rate limit. Spacing them out is politeness rather than a
// requirement.
const BULLETIN_DELAY_MS = 500;

// Bulletins per cycle. There are ~91 supported months, so a cold start
// backfills across successive cycles rather than pulling 27 MB in one pass.
// Never-seen months are taken newest-first, so the most useful data lands on
// the first cycle and the archive fills in behind it.
const BULLETIN_MAX_PER_CYCLE = 12;

// How many recent months to re-check every cycle regardless of being stored.
// Bulletins are revised after publication -- AOSP links are added within 48
// hours, and later corrections do happen -- so the newest months are the ones
// worth re-reading. Older months are left alone unless never seen.
const BULLETIN_RECHECK_MONTHS = 3;

/**
 * Platforms to guarantee coverage for, as CPE match strings.
 *
 * The rolling modification window is not enough on its own. Measured against
 * the live API: 9,384 CVEs affect google:android, but only 97 of them were
 * modified in the last 30 days -- and that window itself holds 19,271 CVEs
 * against a 10,000-record page cap, so even those 97 are not guaranteed to
 * land. A dashboard for a fleet that includes Android devices therefore showed
 * almost no Android CVEs.
 *
 * Each entry is swept in full, so the platforms an operator actually runs are
 * covered regardless of when NVD last touched the record.
 */
const DEFAULT_NVD_PLATFORMS = [
    'cpe:2.3:o:google:android',
    'cpe:2.3:o:microsoft:windows_10',
    'cpe:2.3:o:microsoft:windows_11',
    'cpe:2.3:o:microsoft:windows_server_2022',
    'cpe:2.3:o:linux:linux_kernel',
    'cpe:2.3:o:cisco:ios',
];

const listFromEnv = (name, fallback) => {
    const raw = process.env[name];
    if (raw === undefined) return fallback;
    return raw.split(',').map((s) => s.trim()).filter(Boolean);
};

const intFromEnv = (name, fallback) => {
    const parsed = parseInt(process.env[name], 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

/**
 * Reduce an internal error to something safe to return over the API.
 *
 * `GET /api/fetch/status` and `POST /api/fetch` are unauthenticated, and the
 * raw message leaks more than it should: a JSON.parse failure embeds the first
 * bytes of the upstream response, and a socket error embeds the address and
 * port it failed to reach ("connect ECONNREFUSED 10.0.0.5:8080"). That turns
 * any future request-forgery bug into a readable one. The full message still
 * goes to the server log.
 */
function publicError(err) {
    const message = String((err && err.message) || 'unknown error');

    // An upstream HTTP status is genuinely useful to an operator and leaks
    // nothing, so keep just that shape.
    const status = /HTTP ([0-9]{3})/.exec(message);
    if (status) return `upstream returned HTTP ${status[1]}`;
    if (/timed out|ETIMEDOUT/i.test(message)) return 'upstream request timed out';
    if (/Refusing (insecure|cross-host) redirect/i.test(message)) return 'upstream redirect refused';
    if (/redirects/i.test(message)) return 'too many upstream redirects';
    if (/ENOTFOUND|EAI_AGAIN/i.test(message)) return 'upstream host could not be resolved';
    if (/ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|socket hang up/i.test(message)) {
        return 'upstream connection failed';
    }
    if (/JSON|Unexpected token|not valid JSON/i.test(message)) return 'upstream returned malformed data';
    return 'fetch failed';
}

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
        [SOURCE_ANDROID]: null,
        alerts: 0,
        error: null,
    };

    try {
        console.log('[Fetcher] Starting full fetch cycle');

        results[SOURCE_CISA] = await runSource(SOURCE_CISA, fetchCisaSource);
        results[SOURCE_NVD] = await runSource(SOURCE_NVD, fetchNvdSource);
        results[SOURCE_MITRE] = await runSource(SOURCE_MITRE, fetchMitreSource);
        // Runs after NVD so the CVEs it enriches usually already exist. It
        // works either way -- a bulletin CVE absent from NVD is inserted
        // rather than skipped -- but ordering it here keeps the merge doing
        // fills rather than creating half-populated rows.
        results[SOURCE_ANDROID] = await runSource(SOURCE_ANDROID, fetchAndroidBulletinSource);

        // New records can introduce new vendors or technology types, so drop
        // the cached dropdown lists before anything reads them again.
        repository.invalidateFilterOptions();

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
        results.error = publicError(err);
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
        // Full detail to the log, a sanitised summary to the API.
        console.error(`[Fetcher] ${name} error:`, err.message);
        return { total: 0, fetched: 0, error: publicError(err) };
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
    // Platform sweeps are historical backfills rather than deltas, so they get
    // their own, higher cap. Measured volumes at 2,000 records per page:
    // android 9,384 (5 pages), windows_10 4,063 (3), windows_11 598 (1),
    // windows_server_2022 3,391 (2), linux_kernel 20,398 (11), cisco:ios 615
    // (1). 12 covers all of them, including the kernel, which an 8-page cap
    // would have silently truncated.
    const platformMaxPages = intFromEnv('NVD_PLATFORM_MAX_PAGES', 12);
    const apiKey = process.env.NVD_API_KEY || '';
    const delayMs = apiKey ? NVD_DELAY_WITH_KEY_MS : NVD_DELAY_NO_KEY_MS;

    const kev = await pageThroughNvd({ hasKev: true, apiKey }, { maxPages, delayMs, label: 'KEV sweep' });
    console.log(`[Fetcher] NVD KEV sweep: ${kev.stored} scored from ${kev.fetched} fetched`);

    await sleep(delayMs);

    // Platform sweeps. Without these, coverage of a given platform depends on
    // NVD having touched the record inside the rolling window, which for
    // Android meant 97 of 9,384.
    const platforms = listFromEnv('NVD_PLATFORMS', DEFAULT_NVD_PLATFORMS);
    const platformResults = [];

    for (const platform of platforms) {
        const result = await pageThroughNvd(
            { virtualMatchString: platform, apiKey },
            { maxPages: platformMaxPages, delayMs, label: `platform ${platform}` }
        );
        platformResults.push({ platform, ...result });
        console.log(`[Fetcher] NVD platform ${platform}: ${result.stored} stored from ${result.fetched} fetched`);
        await sleep(delayMs);
    }

    const end = new Date();
    const start = new Date(end.getTime() - lookbackDays * 24 * 60 * 60 * 1000);
    const recent = await pageThroughNvd({
        lastModStartDate: start.toISOString(),
        lastModEndDate: end.toISOString(),
        apiKey,
    }, { maxPages, delayMs, label: `${lookbackDays}-day window` });

    const platformFetched = platformResults.reduce((n, r) => n + r.fetched, 0);
    const platformStored = platformResults.reduce((n, r) => n + r.stored, 0);

    return {
        fetched: kev.fetched + recent.fetched + platformFetched,
        stored: kev.stored + recent.stored + platformStored,
        extra: {
            kev: { fetched: kev.fetched, stored: kev.stored, truncated: kev.truncated },
            recent: { fetched: recent.fetched, stored: recent.stored, truncated: recent.truncated },
            platforms: platformResults.map((r) => ({
                platform: r.platform, fetched: r.fetched, stored: r.stored, truncated: r.truncated,
            })),
            truncated: kev.truncated || recent.truncated || platformResults.some((r) => r.truncated),
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

    for (const [index, cveId] of cveIds.entries()) {
        if (index > 0) await sleep(MITRE_DELAY_MS);

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

/**
 * Decide which bulletins to fetch this cycle.
 *
 * Two reasons to fetch a month: it has never been ingested, or it is recent
 * enough that a revision is plausible. Recent months come first because a
 * revision to last month matters more than backfilling 2019.
 *
 * @param {string[]} months  Supported slugs, newest first.
 * @param {Map<string,string>} stored  slug -> stored revision.
 */
function selectBulletinTargets(months, stored) {
    const recheck = months.slice(0, BULLETIN_RECHECK_MONTHS);
    const missing = months.filter((slug) => !stored.has(slug));

    const targets = [];
    for (const slug of [...recheck, ...missing]) {
        if (!targets.includes(slug)) targets.push(slug);
        if (targets.length >= BULLETIN_MAX_PER_CYCLE) break;
    }
    return targets;
}

/**
 * Android Security Bulletins.
 *
 * The only source of Android fix versions and monthly security patch levels;
 * NVD publishes an Android version bound for roughly 1% of Android CVEs.
 */
async function fetchAndroidBulletinSource() {
    const { months } = await fetchBulletinIndex();
    const supported = supportedMonths(months);
    const stored = await repository.getStoredBulletins();
    const targets = selectBulletinTargets(supported, stored);

    console.log(
        `[Android Bulletin] ${supported.length} supported months, `
        + `${stored.size} already stored; fetching ${targets.length} this cycle`,
    );

    let fetched = 0;
    let storedCount = 0;
    let unchanged = 0;
    const failures = [];

    for (const [index, slug] of targets.entries()) {
        if (index > 0) await sleep(BULLETIN_DELAY_MS);

        try {
            const bulletin = await fetchAndroidBulletin(slug);
            fetched += bulletin.total;

            // A month whose revision marker is unchanged holds the same rows
            // we already stored, so the upsert would be pure write for no
            // change. The conditional upsert would elide it anyway; skipping
            // avoids building the statement at all.
            if (stored.get(slug) === bulletin.revision) {
                unchanged += 1;
                continue;
            }

            storedCount += await repository.storeRecords(bulletin.records, SOURCE_ANDROID);
            await repository.recordBulletin({
                slug,
                patchLevel: bulletin.patchLevel,
                revision: bulletin.revision,
                cveCount: bulletin.total,
            });
        } catch (err) {
            // One odd month must not block the rest, but a systemic layout
            // change must not be absorbed silently either -- see below.
            console.error(`[Android Bulletin] ${slug} failed:`, err.message);
            failures.push(slug);
        }
    }

    // Every attempted month failing is a layout change, not bad luck. The
    // parser already refuses to return an empty result for a single page; this
    // is the same guard at the level of the whole source, so the API reports
    // an error instead of a quiet success with nothing stored.
    if (targets.length > 0 && failures.length === targets.length) {
        throw new Error(
            `All ${targets.length} Android bulletin fetches failed `
            + `(${failures.join(', ')}); the bulletin format has probably changed`,
        );
    }

    return {
        fetched,
        stored: storedCount,
        extra: {
            months_fetched: targets.length,
            months_unchanged: unchanged,
            months_stored: stored.size,
            months_supported: supported.length,
            failures: failures.length,
        },
    };
}

function getFetchStatus() {
    return {
        isFetching,
        lastCompletedAt,
        lastResult,
    };
}

module.exports = {
    fetchAllSources,
    getFetchStatus,
    publicError,
    selectBulletinTargets,
    SOURCE_CISA,
    SOURCE_NVD,
    SOURCE_MITRE,
    SOURCE_ANDROID,
};
