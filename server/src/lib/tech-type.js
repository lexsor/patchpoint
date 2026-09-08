/**
 * Technology-type classification.
 *
 * Shared so the CPE-derived path (NVD) and the free-text path (MITRE) agree on
 * the vocabulary. The buckets are what the Technology filter offers, so they
 * only mean something if both producers use the same list.
 */

const TECH_TYPE_KEYWORDS = {
    mobile: [
        'android', 'ios', 'iphone_os', 'ipados', 'smartphone', 'mobile',
        'harmonyos', 'tizen', 'watchos', 'wear_os',
    ],
    networking: [
        'router', 'switch', 'firewall', 'cisco', 'juniper', 'fortinet', 'fortios',
        'pan-os', 'panos', 'vpn', 'ios_xe', 'nx-os', 'sonicwall', 'mikrotik',
        'asa', 'big-ip',
    ],
    os: [
        'linux_kernel', 'linux', 'windows', 'macos', 'mac_os', 'operating system',
        'kernel', 'solaris', 'freebsd', 'debian', 'ubuntu', 'rhel',
        'enterprise_linux', 'aix', 'esxi',
    ],
    browser: ['chrome', 'chromium', 'firefox', 'safari', 'edge', 'webkit', 'browser'],
    database: [
        'mysql', 'postgresql', 'mongodb', 'mariadb', 'sql_server', 'oracle_database',
        'redis', 'elasticsearch', 'sqlite',
    ],
    container: ['docker', 'kubernetes', 'containerd', 'k8s', 'openshift', 'podman'],
    web: [
        'apache', 'nginx', 'tomcat', 'wordpress', 'drupal', 'joomla', 'iis',
        'http_server', 'jenkins', 'confluence', 'jira',
    ],
};

// Order matters, and networking must precede mobile.
//
// Cisco's router OS is called IOS, so `cisco ios` collides with Apple's iOS.
// Checking networking first lets the vendor break the tie: `cisco ios` matches
// on `cisco` and lands in networking, while a bare `apple ios` has no
// networking keyword and falls through to mobile. Without this ordering every
// Cisco IOS advisory was filed under mobile.
const PRECEDENCE = ['networking', 'mobile', 'browser', 'database', 'container', 'web', 'os'];

// Keywords match on word boundaries, not as bare substrings. `ios` as a
// substring also matches inside `radios`, and `asa` inside `database`.
// CPE writes multi-word names with underscores (`iphone_os`) but the parser
// humanizes them to spaces before classification, so both sides are normalised
// to spaces. Without this every multi-word keyword in the lists above was
// unreachable: `iphone_os` never matched `apple iphone os`, and
// `oracle_database` never matched `oracle database`.
const normalize = (text) => String(text).toLowerCase().replace(/_/g, ' ');

const boundaryCache = new Map();
function matches(haystackNormalized, rawKeyword) {
    const keyword = normalize(rawKeyword);
    const haystack = haystackNormalized;
    let pattern = boundaryCache.get(keyword);
    if (!pattern) {
        // Keywords are literals, so neutralise any regex metacharacter.
        const escaped = keyword.replace(/[^a-z0-9_ -]/gi, (ch) => `\\${ch}`);
        // `-` and `_` are word characters for our purposes, so the guards are
        // written explicitly rather than with \b: `pan-os` must still match
        // inside `pan-os 10.1`, while `ios` must not match inside `radios`.
        pattern = new RegExp(`(^|[^a-z0-9])${escaped}($|[^a-z0-9])`, 'i');
        boundaryCache.set(keyword, pattern);
    }
    return pattern.test(haystack);
}

/**
 * Classify a technology bucket from arbitrary text (product names, vendor
 * names, a description). Returns '' when nothing matches, never a catch-all —
 * the filter should only offer buckets that were actually identified.
 */
function classifyTechType(text) {
    const haystack = normalize(text || '');
    if (!haystack.trim()) return '';

    for (const type of PRECEDENCE) {
        if (TECH_TYPE_KEYWORDS[type].some((kw) => matches(haystack, kw))) return type;
    }
    return '';
}

module.exports = { classifyTechType, TECH_TYPE_KEYWORDS, PRECEDENCE };
