/**
 * Deduplication module for vulnerability records.
 *
 * Deduplication strategy:
 * - Key: CVE ID (e.g., "CVE-2024-21675")
 * - When the same CVE is found from multiple sources, merge into one record
 * - Source labels are accumulated as a JSON array
 * - The highest CVSS score wins for severity scoring
 * - The longest description wins
 * - KEV flag takes precedence (true if any source marks it)
 *
 * `mergeRecords` mutates and returns the map it is given, so callers must seed
 * it with ONLY the rows they intend to write back. See repository.storeRecords.
 */

const { classifySeverity } = require('../lib/severity');

const mergeRecords = (existing, newRecords, sourceName) => {
    const records = Array.isArray(newRecords) ? newRecords : [newRecords];

    for (const record of records) {
        if (!record) continue;
        const cveId = normalizeCveId(record.cve_id);
        if (!cveId) continue;

        if (existing.has(cveId)) {
            // Merge: keep highest severity, accumulate sources
            mergeInto(existing.get(cveId), record, sourceName);
        } else {
            // New record: create a merged copy
            existing.set(cveId, createMergedRecord(record, sourceName));
        }
    }

    return existing;
};

const mergeInto = (existing, incoming, sourceName) => {
    // Accumulate source labels
    const sources = normalizeSources(existing.source_labels);
    if (!sources.includes(sourceName)) {
        sources.push(sourceName);
        existing.source_labels = JSON.stringify(sources);
    }

    // Keep the higher CVSS score
    if (incoming.cvss_score != null) {
        const existingScore = existing.cvss_score != null ? existing.cvss_score : 0;
        if (parseFloat(incoming.cvss_score) > parseFloat(existingScore)) {
            existing.cvss_score = parseFloat(incoming.cvss_score);
            existing.cvss_vector = incoming.cvss_vector || existing.cvss_vector;
            existing.severity = classifySeverity(existing.cvss_score);
        }
    }

    // A record with no score at all should still get a severity if a source
    // states one directly (CISA KEV asserts HIGH without publishing a score).
    if (!existing.severity && incoming.severity) {
        existing.severity = incoming.severity;
    }

    // Prefer a real title over none
    if (!existing.title && incoming.title) existing.title = incoming.title;

    // Keep the earliest published date
    if (incoming.published_date && (!existing.published_date || incoming.published_date < existing.published_date)) {
        existing.published_date = incoming.published_date;
    }

    // Keep the latest modified date
    if (incoming.modified_date && (!existing.modified_date || incoming.modified_date > existing.modified_date)) {
        existing.modified_date = incoming.modified_date;
    }

    // Prefer the more detailed description
    if (incoming.description && (!existing.description || incoming.description.length > existing.description.length)) {
        existing.description = incoming.description;
    }

    // KEV flag: true if any source marks it
    if (incoming.kev_flag) {
        existing.kev_flag = true;
        if (incoming.kev_date_added && (!existing.kev_date_added || incoming.kev_date_added > existing.kev_date_added)) {
            existing.kev_date_added = incoming.kev_date_added;
        }
        if (incoming.kev_due_date) existing.kev_due_date = incoming.kev_due_date;
        // Tri-state: only a positive 'Known' overwrites. `null` means CISA
        // does not know, and must never overwrite an established true.
        if (incoming.kev_ransomware === true) existing.kev_ransomware = true;
        if (incoming.kev_required_action) existing.kev_required_action = incoming.kev_required_action;
    }

    // Union references and CWEs
    const allRefs = new Set([...normalizeList(existing.references), ...normalizeList(incoming.references)]);
    existing.references = JSON.stringify([...allRefs]);

    const allCwes = new Set([...normalizeList(existing.cwes), ...normalizeList(incoming.cwes)]);
    existing.cwes = JSON.stringify([...allCwes]);

    // Union remediations rather than overwrite them. NVD supplies CPE-derived
    // fix versions and the Android bulletin supplies patch levels, on separate
    // fetch cycles; last-writer-wins would make each source erase the other's
    // remediation on every poll.
    existing.remediations = JSON.stringify(mergeRemediationLists(
        normalizeList(existing.remediations),
        normalizeList(incoming.remediations),
    ));

    // Keep non-empty vendor/product/tech_type
    if (!existing.vendor && incoming.vendor) existing.vendor = incoming.vendor;
    if (!existing.product && incoming.product) existing.product = incoming.product;
    if (!existing.tech_type && incoming.tech_type) existing.tech_type = incoming.tech_type;
};

/**
 * Identity of a remediation entry: which source said it, about which product,
 * at which patch level.
 *
 * `patch_level` is part of the key because one CVE is legitimately fixed at
 * several Android patch levels across branches, and those are distinct facts
 * rather than duplicates. `fixed_in` is deliberately NOT part of the key, so
 * a corrected fix version from the same source replaces the stale one instead
 * of accumulating beside it.
 */
const remediationKey = (entry) => JSON.stringify([
    entry.source || '', entry.vendor || '', entry.product || '', entry.patch_level || '',
]);

/**
 * Union two remediation lists, later entries winning on key collision.
 *
 * Entries are objects, so a Set cannot deduplicate them by value.
 */
const mergeRemediationLists = (existingList, incomingList) => {
    const byKey = new Map();
    for (const entry of [...existingList, ...incomingList]) {
        if (!entry || typeof entry !== 'object') continue;
        byKey.set(remediationKey(entry), entry);
    }
    return [...byKey.values()];
};

/**
 * Does this remediation list contain an actionable fix?
 *
 * An entry with only an inclusive upper bound says "fixed sometime after X"
 * without naming a version, which is not something an admin can action, so it
 * does not count. Backs the `has_fix` column and the "has a known fix" filter.
 */
const hasActionableFix = (remediations) => normalizeList(remediations)
    .some((entry) => entry && typeof entry === 'object'
        && (Boolean(entry.fixed_in) || Boolean(entry.patch_level)));

const createMergedRecord = (record, sourceName) => {
    const score = record.cvss_score != null && record.cvss_score !== ''
        ? parseFloat(record.cvss_score)
        : null;

    return {
        cve_id: normalizeCveId(record.cve_id),
        title: record.title || '',
        description: record.description || '',
        // Only derive a severity when there is a score to derive it from.
        // Defaulting a scoreless record to LOW (via classifySeverity(0)) is
        // actively misleading — leave it empty and let a later source fill it.
        severity: record.severity || (score != null ? classifySeverity(score) : ''),
        cvss_score: Number.isNaN(score) ? null : score,
        cvss_vector: record.cvss_vector || '',
        // Never fabricate a date. An unknown publish date must stay NULL so it
        // cannot pollute date filters or date sorting.
        published_date: record.published_date || null,
        modified_date: record.modified_date || null,
        source_labels: JSON.stringify([sourceName]),
        vendor: record.vendor || '',
        product: record.product || '',
        tech_type: record.tech_type || '',
        kev_flag: record.kev_flag || false,
        kev_date_added: record.kev_date_added || null,
        kev_due_date: record.kev_due_date || null,
        // `|| null` would turn a legitimate false into null; the field is
        // tri-state, so an explicit undefined check is required.
        kev_ransomware: record.kev_ransomware === undefined ? null : record.kev_ransomware,
        kev_required_action: record.kev_required_action || '',
        references: JSON.stringify(normalizeList(record.references)),
        cwes: JSON.stringify(normalizeList(record.cwes)),
        remediations: JSON.stringify(mergeRemediationLists([], normalizeList(record.remediations))),
    };
};

const normalizeCveId = (cveId) => {
    if (!cveId) return '';
    return String(cveId).trim().toUpperCase().replace(/\s+/g, '');
};

const normalizeSources = (sourceLabels) => {
    if (Array.isArray(sourceLabels)) return [...sourceLabels];
    try {
        const arr = JSON.parse(sourceLabels);
        return Array.isArray(arr) ? arr : [];
    } catch {
        return sourceLabels ? [sourceLabels] : [];
    }
};

/**
 * Coerce a reference/CWE field to an array. Sources are inconsistent: some
 * hand back a real array, others a JSON string. Accept both so a fetcher
 * cannot silently destroy the field by picking the wrong one.
 */
const normalizeList = (value) => {
    if (Array.isArray(value)) return value.filter(Boolean);
    if (typeof value !== 'string' || value === '') return [];
    try {
        const arr = JSON.parse(value);
        return Array.isArray(arr) ? arr.filter(Boolean) : [];
    } catch {
        return [];
    }
};

module.exports = {
    mergeRecords, classifySeverity, normalizeCveId, normalizeList,
    mergeRemediationLists, hasActionableFix, remediationKey,
};
