/**
 * CPE 2.3 parsing.
 *
 * NVD exposes no `vendor` or `product` field. The only machine-readable
 * attribution it publishes is the CPE strings under
 * `cve.configurations[].nodes[].cpeMatch[].criteria`, which the fetcher used
 * to ignore entirely — so every NVD record was stored with empty vendor,
 * product and tech_type, and none of them could be found by anything except a
 * description search.
 *
 * Format (13 colon-separated components):
 *   cpe:2.3:part:vendor:product:version:update:edition:language:
 *          sw_edition:target_sw:target_hw:other
 * part is `a` (application), `o` (operating system) or `h` (hardware).
 */

const { classifyTechType } = require('./tech-type');

const PART = 2;
const VENDOR = 3;
const PRODUCT = 4;

/** A CPE component may escape a literal colon as `\:`; split without splitting those. */
function splitCpe(cpe) {
    return String(cpe).split(/(?<!\\):/);
}

/** `linux_kernel` -> `linux kernel`, and drop CPE's wildcard/NA markers. */
function humanize(value) {
    if (!value || value === '*' || value === '-') return '';
    return value.replace(/\\(.)/g, '$1').replace(/_/g, ' ').trim();
}

/**
 * Parse one CPE string.
 * @returns {{part: string, vendor: string, product: string}|null}
 */
function parseCpe(cpe) {
    const parts = splitCpe(cpe);
    if (parts.length < 5 || parts[0] !== 'cpe' || parts[1] !== '2.3') return null;

    const vendor = humanize(parts[VENDOR]);
    const product = humanize(parts[PRODUCT]);
    if (!vendor && !product) return null;

    return { part: parts[PART], vendor, product };
}

/**
 * Every distinct cpeMatch object on a CVE, in document order.
 *
 * `collectCpeCriteria` returns only the criteria string, which is all the
 * vendor/product attribution needs. NVD publishes the version bounds as
 * SIBLING fields on the same match object, so anything deriving a fix version
 * needs the whole match rather than the string.
 *
 * Identity here is the criteria plus all four bound fields, not the criteria
 * alone: the same product string legitimately appears more than once with
 * different ranges (apache:tomcat carries one match per affected branch), and
 * deduplicating on the string would keep only the first branch.
 */
function collectCpeMatches(cve) {
    const found = [];
    const seen = new Set();

    for (const config of (cve && cve.configurations) || []) {
        for (const node of config.nodes || []) {
            for (const match of node.cpeMatch || []) {
                if (!match || !match.criteria) continue;
                const key = JSON.stringify([
                    match.criteria,
                    match.versionStartIncluding || null,
                    match.versionStartExcluding || null,
                    match.versionEndExcluding || null,
                    match.versionEndIncluding || null,
                ]);
                if (seen.has(key)) continue;
                seen.add(key);
                found.push(match);
            }
        }
    }

    return found;
}

/** Every distinct CPE criteria string on a CVE, in document order. */
function collectCpeCriteria(cve) {
    const found = [];
    const seen = new Set();

    for (const match of collectCpeMatches(cve)) {
        if (seen.has(match.criteria)) continue;
        seen.add(match.criteria);
        found.push(match.criteria);
    }

    return found;
}

/**
 * The most frequently referenced (vendor, product) pair in a parsed CPE list.
 *
 * Shared by `describeFromCpe`, which shows it in the Vendor and Product
 * columns, and by `remediationsFromCpe`, which sorts that product's fix
 * versions to the front. Both must agree on who the primary is, or a row
 * would name one product and show another product's fix version.
 *
 * @returns {{vendor: string, product: string, score: number}|null}
 */
function primaryPair(parsed) {
    const tally = new Map();

    for (const entry of parsed) {
        // JSON so a vendor or product containing a space cannot collide
        // with a different split of the same characters.
        const key = JSON.stringify([entry.vendor, entry.product]);
        const current = tally.get(key) || { ...entry, score: 0 };
        current.score += 1;
        tally.set(key, current);
    }

    let primary = null;
    for (const candidate of tally.values()) {
        if (!primary || candidate.score > primary.score) primary = candidate;
    }

    return primary;
}

/**
 * Derive vendor, product and technology bucket for a CVE from its CPE list.
 *
 * Choosing the primary vendor/product needs care: a CVE can carry well over a
 * hundred CPE entries and the first is not necessarily the relevant one.
 * CVE-2010-1807 matches an Android query but lists `apple:safari` first, so
 * taking entry zero would attribute a Safari issue by position alone.
 *
 * The rule is the most frequently referenced vendor/product pair. That was
 * chosen by measurement, not argument — three heuristics were run against four
 * CVEs with known subjects:
 *
 *   CVE            truth          os-weighted        raw-frequency
 *   CVE-2009-1754  Android        android      ok    android      ok
 *   CVE-2010-1807  Safari/WebKit  android      no    safari       ok
 *   CVE-2010-2884  Adobe Flash    acrobat      no    acrobat      no
 *   CVE-2010-3636  Adobe Flash    mac os x     no    flash player ok
 *
 * Raw frequency scored 3/4 against 1/4 for weighting operating-system entries
 * higher, and its single miss still identifies the right vendor. Weighting the
 * OS looked reasonable but is wrong in practice: CPE enumerates every affected
 * *version*, so the count reflects catalogue granularity rather than what the
 * vulnerability is actually in.
 *
 * tech_type is deliberately derived from the WHOLE list rather than the
 * primary. A CVE affecting both Safari and Android should still be findable
 * under `mobile`, and the Technology filter is the reliable way to slice by
 * platform precisely because it does not depend on picking one winner. A
 * single vendor column cannot represent a CVE spanning 163 CPEs; tech_type can.
 */
function describeFromCpe(cve) {
    const criteria = collectCpeCriteria(cve);
    if (criteria.length === 0) {
        return { vendor: '', product: '', tech_type: '', cpe_count: 0 };
    }

    const parsed = criteria.map(parseCpe).filter(Boolean);
    if (parsed.length === 0) {
        return { vendor: '', product: '', tech_type: '', cpe_count: 0 };
    }

    const primary = primaryPair(parsed);

    // Classify across every product and vendor mentioned, not just the primary.
    const haystack = parsed.map((p) => `${p.vendor} ${p.product}`).join(' ');
    const osHint = parsed.some((p) => p.part === 'o') ? ' operating system' : '';

    return {
        vendor: primary.vendor,
        product: primary.product,
        tech_type: classifyTechType(haystack + osHint),
        cpe_count: parsed.length,
    };
}

/**
 * Derive remediation entries from a CVE's CPE version bounds.
 *
 * NVD publishes no "fixed in" field, but `cpeMatch` carries the bounds of the
 * affected range, and the exclusive upper bound IS the fix version: if
 * versions below 7.0.73 are vulnerable then 7.0.73 is what to update to.
 * Measured over 1,000 CVEs modified in the last 30 days, 115 of 200 sampled
 * (57%) carry at least one exclusive bound. Coverage is far worse on the
 * oldest CVEs -- 5 in 800 sampled from the start of the corpus -- because the
 * practice of publishing bounds postdates them.
 *
 * Mapping:
 *   versionEndExcluding  -> `fixed_in`, plus `affected_to` with bound
 *                           'exclusive'. An actionable fix.
 *   versionEndIncluding  -> `affected_to` with bound 'inclusive' and no
 *                           `fixed_in`. States "the fix is later than X"
 *                           without naming it, which the UI renders as `> X`
 *                           and `hasActionableFix` deliberately excludes.
 *   versionStartIncluding / versionStartExcluding -> `affected_from`.
 *
 * A match with no END bound is skipped. A lower bound alone carries no fix
 * information at all, so an entry built from one would show as "no fix
 * published" while still inflating the `+N` count on the Fix column.
 *
 * The two end bounds are mutually exclusive in practice (0 of 2,579 bounded
 * matches sampled carried both); if both ever appear, the exclusive one wins
 * because it is the more precise statement.
 *
 * `versionStartExcluding` is recorded as `affected_from` even though that
 * field reads as inclusive, overstating the affected range by the one version
 * at the boundary. It appeared twice in 2,579 matches, no consumer renders
 * `affected_from`, and the alternative -- dropping the bound -- would overstate
 * the range by everything below it.
 *
 * On deduplication: the design note called for deduplicating "hard", on the
 * grounds that a CVE with 163 CPE entries yields many near-identical ranges.
 * Measured, that is wrong -- deduplicating (vendor, product, range) over the
 * same 2,579 matches kept 99% of them. The volume in a long CPE list is
 * unbounded exact-version enumeration (`android:2.1`, `android:2.2`, ...),
 * which this function skips outright for having no end bound. Distinct ranges
 * that survive are distinct fixes: 142 of 418 products sampled carried more
 * than one, and collapsing them would leave an admin on Tomcat 8 reading the
 * fix for Tomcat 7. Entries per CVE after this: p50=0, p90=9, p99=17, and 101
 * at the maximum (CVE-2021-44228, which names 101 genuinely different
 * products). They are not capped -- a cap would hide a real fix for whichever
 * product fell outside it.
 *
 * @param {object} cve      A CVE object from the NVD v2.0 API.
 * @param {string} source   Source label to stamp on each entry. Must match the
 *                          name `storeRecords` is called with, since the merge
 *                          in deduplication.js pairs them up.
 */
function remediationsFromCpe(cve, source) {
    const primary = primaryPair(collectCpeCriteria(cve).map(parseCpe).filter(Boolean));
    const entries = [];
    const seen = new Set();

    for (const match of collectCpeMatches(cve)) {
        const end = match.versionEndExcluding || match.versionEndIncluding;
        if (!end) continue;

        const parsed = parseCpe(match.criteria);
        if (!parsed) continue;

        const exclusive = Boolean(match.versionEndExcluding);
        const entry = {
            source,
            vendor: parsed.vendor,
            product: parsed.product,
            affected_from: match.versionStartIncluding || match.versionStartExcluding || null,
            affected_to: end,
            bound: exclusive ? 'exclusive' : 'inclusive',
            fixed_in: exclusive ? end : null,
            // No vendor in NVD's data publishes a dated patch level; the field
            // exists for sources that do, such as the Android bulletins.
            patch_level: null,
        };

        const key = JSON.stringify([
            entry.vendor, entry.product, entry.affected_from, entry.affected_to, entry.bound,
        ]);
        if (seen.has(key)) continue;
        seen.add(key);
        entries.push(entry);
    }

    if (!primary) return entries;

    // Show the fix for the product the row names. The Vendor and Product
    // columns hold the frequency-primary, and on 8 of 263 measured CVEs the
    // first fix version in document order belongs to something else entirely
    // -- CVE-2021-44228's row reads `cisco / webex meetings server` while its
    // first bounded match is a Siemens firmware. Sorting is stable, so within
    // each group the document order NVD published is preserved.
    const isPrimary = (e) => e.vendor === primary.vendor && e.product === primary.product;
    return [...entries.filter(isPrimary), ...entries.filter((e) => !isPrimary(e))];
}

module.exports = {
    describeFromCpe, remediationsFromCpe, parseCpe,
    collectCpeCriteria, collectCpeMatches, splitCpe, humanize,
};
