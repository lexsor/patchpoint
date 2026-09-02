/**
 * The complete severity vocabulary, most severe first.
 *
 * This is a closed set defined by the CVSS rating scale, so the UI filter is
 * built from it rather than from `SELECT DISTINCT severity`. Deriving the
 * options from stored data meant the dropdown only ever offered whatever had
 * been ingested so far — in practice just HIGH, because CISA KEV stamped every
 * record HIGH and lands first.
 */
const SEVERITY_LEVELS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

/**
 * CVSS severity classification (CVSS v3.x / v4.0 qualitative rating scale).
 * Single source of truth — fetchers and the deduplication merge all use this.
 */
const classifySeverity = (score) => {
    const s = parseFloat(score);
    if (isNaN(s)) return 'LOW';
    if (s >= 9.0) return 'CRITICAL';
    if (s >= 7.0) return 'HIGH';
    if (s >= 4.0) return 'MEDIUM';
    return 'LOW';
};

module.exports = { classifySeverity, SEVERITY_LEVELS };
