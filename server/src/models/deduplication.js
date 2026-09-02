/**
 * Deduplication module for vulnerability records.
 * 
 * Deduplication strategy:
 * - Key: CVE ID (e.g., "CVE-2024-21675")
 * - When the same CVE is found from multiple sources, merge into one record
 * - Source labels are accumulated as a JSON array
 * - The highest CVSS score wins for severity scoring
 * - Descriptions are concatenated with source attribution
 * - KEV flag takes precedence (true if any source marks it)
 */

const mergeRecords = (existing, newRecords, sourceName) => {
    const records = Array.isArray(newRecords) ? newRecords : [newRecords];
    
    for (const record of records) {
        if (!record) continue;
        const cveId = normalizeCveId(record.cve_id);
        if (!cveId) continue;

        if (existing.has(cveId)) {
            // Merge: keep highest severity, accumulate sources
            const merged = existing.get(cveId);
            mergeInto(merged, record, sourceName);
        } else {
            // New record: create a merged copy
            const merged = createMergedRecord(record, sourceName);
            existing.set(cveId, merged);
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
            existing.cvss_score = incoming.cvss_score;
            existing.cvss_vector = incoming.cvss_vector || existing.cvss_vector;
            existing.severity = classifySeverity(parseFloat(incoming.cvss_score));
        }
    }

    // Keep the earliest published date
    if (incoming.published_date && (!existing.published_date || incoming.published_date < existing.published_date)) {
        existing.published_date = incoming.published_date;
    }

    // Keep the latest modified date
    if (incoming.modified_date && (!existing.modified_date || incoming.modified_date > existing.modified_date)) {
        existing.modified_date = incoming.modified_date;
    }

    // Prefer non-empty descriptions, merge them
    if (incoming.description && (!existing.description || incoming.description.length > existing.description.length)) {
        existing.description = incoming.description;
    }

    // KEV flag: true if any source marks it
    if (incoming.kev_flag) {
        existing.kev_flag = true;
        if (incoming.kev_date_added && (!existing.kev_date_added || incoming.kev_date_added > existing.kev_date_added)) {
            existing.kev_date_added = incoming.kev_date_added;
        }
    }

    // Collect references and CWEs
    const allRefs = new Set([...normalizeRefs(existing.references), ...normalizeRefs(incoming.references)]);
    existing.references = JSON.stringify([...allRefs]);

    const allCwes = new Set([...normalizeCwes(existing.cwes), ...normalizeCwes(incoming.cwes)]);
    existing.cwes = JSON.stringify([...allCwes]);

    // Keep non-empty vendor/product
    if (!existing.vendor && incoming.vendor) existing.vendor = incoming.vendor;
    if (!existing.product && incoming.product) existing.product = incoming.product;
    if (!existing.tech_type && incoming.tech_type) existing.tech_type = incoming.tech_type;
};

const createMergedRecord = (record, sourceName) => ({
    cve_id: normalizeCveId(record.cve_id),
    title: record.title || '',
    description: record.description || '',
    severity: record.severity || classifySeverity(parseFloat(record.cvss_score) || 0),
    cvss_score: record.cvss_score != null ? parseFloat(record.cvss_score) : null,
    cvss_vector: record.cvss_vector || '',
    published_date: record.published_date || new Date().toISOString().split('T')[0],
    modified_date: record.modified_date || new Date().toISOString().split('T')[0],
    source_labels: JSON.stringify([sourceName]),
    vendor: record.vendor || '',
    product: record.product || '',
    tech_type: record.tech_type || '',
    kev_flag: record.kev_flag || false,
    kev_date_added: record.kev_date_added || null,
    references: record.references || '[]',
    cwes: record.cwes || '[]',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
});

// Severity classification based on CVSS v3/v4
const classifySeverity = (score) => {
    const s = parseFloat(score);
    if (isNaN(s)) return 'LOW';
    if (s >= 9.0) return 'CRITICAL';
    if (s >= 7.0) return 'HIGH';
    if (s >= 4.0) return 'MEDIUM';
    return 'LOW';
};

const normalizeCveId = (cveId) => {
    if (!cveId) return '';
    return cveId.trim().toUpperCase().replace(/\s+/g, '');
};

const normalizeSources = (sourceLabels) => {
    try {
        const arr = JSON.parse(sourceLabels);
        return Array.isArray(arr) ? arr : [];
    } catch {
        return [sourceLabels];
    }
};

const normalizeRefs = (refsStr) => {
    try {
        const arr = JSON.parse(refsStr);
        return Array.isArray(arr) ? arr : [];
    } catch {
        return [];
    }
};

const normalizeCwes = (cwesStr) => {
    try {
        const arr = JSON.parse(cwesStr);
        return Array.isArray(arr) ? arr : [];
    } catch {
        return [];
    }
};

module.exports = { mergeRecords, classifySeverity, normalizeCveId };
