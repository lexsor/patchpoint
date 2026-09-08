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

/** Every distinct CPE criteria string on a CVE, in document order. */
function collectCpeCriteria(cve) {
    const found = [];
    const seen = new Set();

    for (const config of (cve && cve.configurations) || []) {
        for (const node of config.nodes || []) {
            for (const match of node.cpeMatch || []) {
                const criteria = match && match.criteria;
                if (criteria && !seen.has(criteria)) {
                    seen.add(criteria);
                    found.push(criteria);
                }
            }
        }
    }

    return found;
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

module.exports = { describeFromCpe, parseCpe, collectCpeCriteria, splitCpe, humanize };
