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

module.exports = { classifySeverity };
