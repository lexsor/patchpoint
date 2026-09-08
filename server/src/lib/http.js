const https = require('https');
const http = require('http');
const zlib = require('zlib');

const DEFAULT_TIMEOUT_MS = 60000;
const MAX_REDIRECTS = 5;

/**
 * Is `candidate` the same site as `origin`, comparing registrable domain?
 *
 * Crude last-two-labels comparison, which is all that is needed for the three
 * fixed government feeds: it permits www.cisa.gov -> cisa.gov and CDN
 * subdomains, while refusing a hop to an unrelated host.
 */
function isSameSite(candidate, origin) {
    const a = String(candidate).toLowerCase();
    const b = String(origin).toLowerCase();
    if (a === b) return true;

    // An IP literal has no registrable domain, so only exact equality counts.
    // Comparing "last two labels" of an address would be meaningless.
    const isIpish = (host) => /^[0-9.]+$/.test(host) || host.includes(':');
    if (isIpish(a) || isIpish(b)) return false;

    const tail = (host) => host.split('.').slice(-2).join('.');
    return tail(a) === tail(b);
}

/**
 * May this redirect be followed?
 *
 * Two independent rules, both required:
 *  - No protocol downgrade. A chain that started on https must stay on https;
 *    anything other than http/https is refused outright.
 *  - No host change, except to an explicitly allowlisted host. The redirect
 *    target is chosen by the remote server, so it is untrusted input — this is
 *    what stops a hijacked feed pointing the fetch at an internal address.
 *
 * Exported for testing: the decision matrix is worth asserting directly
 * rather than only through a live socket.
 */
function isRedirectAllowed(next, { chainOrigin, originProtocol, allowedHosts = null }) {
    const url = next instanceof URL ? next : new URL(next);

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return { allowed: false, reason: `unsupported scheme ${url.protocol}` };
    }
    if (originProtocol === 'https:' && url.protocol !== 'https:') {
        return { allowed: false, reason: `insecure redirect to ${url.protocol}//${url.hostname}` };
    }

    const sameSite = isSameSite(url.hostname, chainOrigin);
    if (!sameSite && !(Array.isArray(allowedHosts) && allowedHosts.includes(url.hostname))) {
        return { allowed: false, reason: `cross-host redirect to ${url.hostname}` };
    }

    // Caller headers (which may carry an API key) travel only within the site
    // the chain started on.
    return { allowed: true, forwardHeaders: sameSite };
}

/**
 * GET a URL and return its body as text.
 *
 * Wraps the three things every fetcher previously got wrong on its own:
 *  - `res.setEncoding('utf8')`, so a multi-byte character split across two
 *    chunks is not corrupted by string concatenation.
 *  - 3xx redirects. Treating only `statusCode >= 400` as failure meant a
 *    redirect fell through to the parser with an empty or HTML body.
 *  - gzip/deflate/brotli response bodies.
 *
 * @returns {Promise<{ statusCode: number, headers: object, body: string }>}
 */
function httpGetText(url, {
    headers = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
    redirectsLeft = MAX_REDIRECTS,
    allowedHosts = null,
    originHost = null,
    originProtocol = null,
} = {}) {
    return new Promise((resolve, reject) => {
        const target = new URL(url);
        // Remember where the chain started so every hop is judged against the
        // original host rather than against the previous redirect.
        const chainOrigin = originHost || target.hostname;
        const chainProtocol = originProtocol || target.protocol;
        const transport = target.protocol === 'https:' ? https : http;

        const req = transport.get(target, {
            headers: {
                'User-Agent': 'Patchpoint/1.0',
                'Accept-Encoding': 'gzip, deflate, br',
                ...headers,
            },
        }, (res) => {
            const { statusCode } = res;

            // Follow redirects rather than parsing the redirect body.
            if (statusCode >= 300 && statusCode < 400 && res.headers.location) {
                res.resume(); // drain so the socket can be reused
                if (redirectsLeft <= 0) {
                    reject(new Error(`Too many redirects for ${url}`));
                    return;
                }

                const next = new URL(res.headers.location, target);
                const verdict = isRedirectAllowed(next, {
                    chainOrigin,
                    originProtocol: chainProtocol,
                    allowedHosts,
                });

                if (!verdict.allowed) {
                    reject(new Error(`Refusing ${verdict.reason}`));
                    return;
                }

                httpGetText(next.toString(), {
                    headers: verdict.forwardHeaders ? headers : {},
                    timeoutMs,
                    redirectsLeft: redirectsLeft - 1,
                    allowedHosts,
                    originHost: chainOrigin,
                    originProtocol: chainProtocol,
                }).then(resolve, reject);
                return;
            }

            let stream = res;
            const encoding = (res.headers['content-encoding'] || '').toLowerCase();
            if (encoding === 'gzip') stream = res.pipe(zlib.createGunzip());
            else if (encoding === 'deflate') stream = res.pipe(zlib.createInflate());
            else if (encoding === 'br') stream = res.pipe(zlib.createBrotliDecompress());

            stream.setEncoding('utf8');
            let body = '';
            stream.on('data', (chunk) => { body += chunk; });
            stream.on('end', () => resolve({ statusCode, headers: res.headers, body }));
            stream.on('error', reject);
        });

        req.on('error', reject);
        req.setTimeout(timeoutMs, () => {
            req.destroy(new Error(`Request timed out after ${timeoutMs}ms: ${url}`));
        });
    });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

module.exports = { httpGetText, sleep, isRedirectAllowed, isSameSite };
