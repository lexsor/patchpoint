/**
 * Android Security Bulletin fetcher.
 *
 * Why this source exists: NVD publishes almost no Android fix versions. Across
 * 1,000 Android CVEs, 9 carried a `versionEndExcluding` for `google:android`
 * and 965 carried no version bound at all. A fix column fed only from NVD
 * would therefore be blank on virtually every Android row. Google's monthly
 * bulletins are the only source that says what to update to, and the only
 * source of the monthly security patch level Android admins actually track.
 *
 * These are HTML pages with no JSON feed, so this is a scraper, and it is
 * written to fail loudly rather than to return nothing: a silent zero would
 * look exactly like a quiet month.
 */

const { httpGetText } = require('../lib/http');
const { extractTables, cellText, findColumn } = require('../lib/html-table');

const SOURCE_NAME = 'Android Bulletin';
const BULLETIN_HOST = 'source.android.com';
const INDEX_URL = `https://${BULLETIN_HOST}/docs/security/bulletin`;
const REQUEST_TIMEOUT_MS = 30000;

// Bulletins before 2018-06 use a different table shape: four columns, no
// `Type`, and version values written as prose ranges ("5.1 and below") rather
// than as a list. Nothing in a current fleet runs Android 5, so the floor is
// set here rather than carrying a second parser for it.
const EARLIEST_BULLETIN = '2018-06-01';

// Bulletin slugs are always the first of the month.
const SLUG_PATTERN = /^\d{4}-\d{2}-01$/;

// Bulletin severities map onto the app's vocabulary. 'Moderate' is the only
// one that differs by name.
const SEVERITY_MAP = {
    critical: 'CRITICAL', high: 'HIGH', moderate: 'MEDIUM', medium: 'MEDIUM', low: 'LOW',
};

const httpOptions = {
    timeoutMs: REQUEST_TIMEOUT_MS,
    // Redirects may not leave the documentation host. Without this a
    // redirect could carry the request somewhere unrelated and the parser
    // would then be reading an attacker-influenced page.
    allowedHosts: [BULLETIN_HOST],
};

/**
 * Fetch the bulletin index and return every monthly slug it lists.
 *
 * The index enumerates the months, so discovery never has to guess a URL.
 *
 * @returns {Promise<{months: string[]}>} Slugs newest-first, e.g. '2025-12-01'.
 */
async function fetchBulletinIndex() {
    console.log(`[Android Bulletin] Fetching index ${INDEX_URL}`);
    const res = await httpGetText(INDEX_URL, httpOptions);

    if (res.statusCode >= 400) {
        throw new Error(`Android Bulletin index HTTP ${res.statusCode}`);
    }

    const found = new Set();
    for (const match of res.body.matchAll(/\/docs\/security\/bulletin\/(\d{4}-\d{2}-\d{2})/g)) {
        if (SLUG_PATTERN.test(match[1])) found.add(match[1]);
    }

    const months = [...found].sort().reverse();

    // An index that parses to nothing means the page moved or was
    // restructured, not that Google stopped publishing bulletins.
    if (months.length === 0) {
        throw new Error(
            'Android Bulletin index returned HTTP 200 but listed no monthly bulletins; '
            + 'the index layout has probably changed',
        );
    }

    console.log(`[Android Bulletin] Index lists ${months.length} bulletins (${months[months.length - 1]} .. ${months[0]})`);
    return { months };
}

/** Slugs at or after the supported floor. */
function supportedMonths(months) {
    return months.filter((slug) => slug >= EARLIEST_BULLETIN);
}

/**
 * Fetch and parse one monthly bulletin.
 *
 * @param {string} slug e.g. '2025-12-01'
 */
async function fetchAndroidBulletin(slug) {
    if (!SLUG_PATTERN.test(slug)) {
        throw new Error(`Invalid bulletin slug: ${slug}`);
    }

    const url = `${INDEX_URL}/${slug}`;
    console.log(`[Android Bulletin] Fetching ${url}`);
    const res = await httpGetText(url, httpOptions);

    if (res.statusCode >= 400) {
        throw new Error(`Android Bulletin ${slug} HTTP ${res.statusCode}`);
    }

    const parsed = parseBulletin(res.body, slug);
    console.log(
        `[Android Bulletin] ${slug}: ${parsed.records.length} CVEs, `
        + `patch level ${parsed.patchLevel}, revision ${parsed.revision}`,
    );
    return parsed;
}

/**
 * The authoritative patch level that fixes a bulletin's issues.
 *
 * NOT derived from the URL. Bulletins are published at slug `YYYY-MM-01` but
 * state their remediation level in the page text:
 *
 *   "Security patch levels of 2025-12-05 or later address all of these issues."
 *
 * Android publishes two levels per month: `-01` covers the AOSP framework and
 * system issues, `-05` additionally covers vendor and kernel components. Which
 * one a bulletin names VARIES -- 2025-12 states `-05` while 2025-11 states
 * `-01` -- so the value has to be read rather than assumed. An earlier version
 * of this comment claimed it was always `-05`, which held for the eight
 * bulletins first sampled and broke on the ninth.
 *
 * Only the stated level is guaranteed to address everything a bulletin lists,
 * which is why the slug is not usable: for a `-05` month it would tell an
 * admin sitting on `YYYY-MM-01` that they were covered when they are not.
 */
function extractPatchLevel(text, slug) {
    // "or later" and "or higher" both occur -- 2019-06 uses "higher" where
    // every neighbouring month uses "later". The day component varies too:
    // most bulletins state -05, some -01, and 2019-10 / 2021-11 / 2023-10
    // state -06. Nothing about this sentence is safe to hard-code beyond the
    // date's shape.
    const stated = text.match(
        /security patch levels? of\s+(\d{4}-\d{2}-\d{2})\s+or (?:later|higher)/i,
    );

    if (!stated) {
        throw new Error(
            `Android Bulletin ${slug}: could not find the "security patch levels of X or later" `
            + 'statement; the page layout has probably changed',
        );
    }

    const level = stated[1];

    // The stated level must belong to the same month as the bulletin. If it
    // does not, the sentence matched something other than this bulletin's own
    // remediation statement and the value cannot be trusted.
    if (level.slice(0, 7) !== slug.slice(0, 7)) {
        throw new Error(
            `Android Bulletin ${slug}: stated patch level ${level} is not in the bulletin's month`,
        );
    }

    return level;
}

/**
 * The bulletin's revision marker, used to decide whether a stored month needs
 * re-parsing.
 *
 * Bulletins are NOT immutable once published: AOSP links are added within 48
 * hours, and revisions land much later than that -- the December 2025
 * bulletin was still being updated in March 2026. Six of eight sampled
 * bulletins carried an `Updated` date.
 */
function extractRevision(text) {
    const updated = text.match(/Updated\s+([A-Z][a-z]+ \d{1,2}, \d{4})/);
    if (updated) return updated[1];
    const published = text.match(/Published\s+([A-Z][a-z]+ \d{1,2}, \d{4})/);
    return published ? published[1] : '';
}

/**
 * Parse a bulletin page into records.
 *
 * Exported so the fixture test can exercise it without network access.
 *
 * @param {string} html Raw bulletin page.
 * @param {string} slug e.g. '2025-12-01'
 */
function parseBulletin(html, slug) {
    const plainText = cellText(html);
    const patchLevel = extractPatchLevel(plainText, slug);
    const revision = extractRevision(plainText);

    const tables = extractTables(html);
    const byCve = new Map();
    let versionTables = 0;

    for (const table of tables) {
        // Column lookup is by header, never by position: within one bulletin
        // some tables end in `Updated AOSP versions` and others in
        // `Subcomponent`, so index 4 means different things in each.
        const cveCol = findColumn(table.headers, /^cve$/i);
        if (cveCol === -1) continue;

        const versionCol = findColumn(table.headers, /(updated aosp|affected) versions?/i);
        const severityCol = findColumn(table.headers, /^severity$/i);
        if (versionCol !== -1) versionTables += 1;

        for (const cells of table.rows) {
            const cveId = (cells[cveCol] || '').match(/CVE-\d{4}-\d{4,7}/);
            if (!cveId) continue;

            const versions = versionCol !== -1 ? parseVersions(cells[versionCol]) : [];
            const severity = severityCol !== -1
                ? SEVERITY_MAP[(cells[severityCol] || '').trim().toLowerCase()] || ''
                : '';

            // A CVE can appear in more than one table of the same bulletin.
            // Prefer the entry that carries version information.
            const existing = byCve.get(cveId[0]);
            if (existing && existing.versions.length >= versions.length) continue;

            byCve.set(cveId[0], { versions, severity, fromAospTable: versionCol !== -1 });
        }
    }

    // Distinguish "this month really has nothing" from "we failed to read it".
    //
    // Both look like zero records, and the difference cannot be inferred from
    // the table count: 2025-10-01 is a real, current bulletin that lists no
    // CVEs at all, carrying only the glossary tables, while a restructured
    // page would also yield nothing. The discriminator is whether the raw
    // document mentions any CVE id anywhere. If it does not, there was
    // nothing to extract and zero is the honest answer; if it does, we are
    // looking at content we can see but no longer parse.
    //
    // An earlier version threw on any empty result, which turned that real
    // October bulletin into a hard failure.
    const cveIdsInDocument = new Set(String(html).match(/CVE-\d{4}-\d{4,7}/g) || []);

    if (byCve.size === 0 && cveIdsInDocument.size > 0) {
        throw new Error(
            `Android Bulletin ${slug}: ${cveIdsInDocument.size} CVE ids appear in the page `
            + `but none could be parsed from its ${tables.length} tables; `
            + 'the page layout has probably changed',
        );
    }

    // Same discriminator for the versions column. A month whose page never
    // mentions AOSP versions genuinely has no such table (2025-10-01 again);
    // one that mentions it but where no column matched means the header
    // changed, which would silently downgrade every record to
    // "patch level only".
    const mentionsAospVersions = /updated aosp versions?/i.test(html);
    if (versionTables === 0 && mentionsAospVersions) {
        throw new Error(
            `Android Bulletin ${slug}: the page mentions "Updated AOSP versions" but no `
            + 'table column matched it; the table layout has probably changed',
        );
    }

    if (byCve.size === 0) {
        console.log(`[Android Bulletin] ${slug}: no CVEs listed in this bulletin`);
    }

    const records = [...byCve.entries()].map(([cveId, info]) => toRecord(cveId, info, patchLevel));

    return { records, total: records.length, patchLevel, revision, slug };
}

/**
 * '13, 14, 15, 16' -> ['13', '14', '15', '16'].
 *
 * Values are Android release versions, including the '12L' feature drop, so
 * they are not all numeric.
 */
function parseVersions(cell) {
    return String(cell || '')
        .split(',')
        .map((part) => part.trim())
        .filter((part) => /^\d+(\.\d+)*L?$/i.test(part));
}

function toRecord(cveId, info, patchLevel) {
    const { versions, severity, fromAospTable } = info;

    return {
        cve_id: cveId,
        // Bulletins carry no CVE description; NVD and MITRE supply that.
        description: '',
        // The bulletin states a severity even when NVD has not scored the CVE
        // yet. The merge only fills an empty severity, so this cannot lower a
        // score-derived one.
        severity,
        // Attribution is claimed only for the AOSP tables. The vendor-
        // component tables in the same bulletin cover Qualcomm, MediaTek and
        // others, and labelling those `google:android` would be wrong.
        vendor: fromAospTable ? 'google' : '',
        product: fromAospTable ? 'android' : '',
        // Every CVE in an Android bulletin is an Android platform issue,
        // whichever component it lives in. This is what makes them findable
        // under the Technology filter.
        tech_type: 'mobile',
        remediations: [{
            source: SOURCE_NAME,
            vendor: 'google',
            product: 'android',
            // The versions that received the fix -- i.e. what to update to.
            // Empty for a vendor-component CVE, where the bulletin states a
            // patch level but no AOSP version.
            fixed_in: versions.join(', '),
            patch_level: patchLevel,
        }],
    };
}

module.exports = {
    fetchBulletinIndex,
    fetchAndroidBulletin,
    parseBulletin,
    parseVersions,
    supportedMonths,
    extractPatchLevel,
    extractRevision,
    SOURCE_NAME,
    INDEX_URL,
    EARLIEST_BULLETIN,
};
