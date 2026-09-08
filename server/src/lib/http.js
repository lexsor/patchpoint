const https = require('https');
const http = require('http');
const zlib = require('zlib');

const DEFAULT_TIMEOUT_MS = 60000;
const MAX_REDIRECTS = 5;

/**
 * May this redirect be followed, and may the caller's headers travel with it?
 *
 * Three rules, all required:
 *  - Scheme must be http or https.
 *  - No protocol downgrade: a chain that started on https stays on https.
 *  - The host must be EXACTLY the host the chain started on, or explicitly
 *    allowlisted by the caller.
 *
 * The host rule used to compare registrable domains (the last two labels),
 * which had two problems. It let a redirect to any `*.nist.gov` host count as
 * same-site and therefore receive the caller's headers -- including the NVD
 * API key -- so one subdomain takeover under that zone would have collected
 * it. And "last two labels" is wrong for multi-part public suffixes, where
 * `foo.co.uk` and `bar.co.uk` would have compared equal. Exact matching has
 * neither problem and costs nothing: none of the three feeds redirects at all
 * (measured), so there is no legitimate hop to accommodate.
 *
 * `allowedHosts` is the deliberate escape hatch. Failing closed is only
 * operationally acceptable if there is a way to open it: if a feed ever starts
 * redirecting to a CDN, the refusal names the host and an operator can add it
 * explicitly rather than the fetcher silently following.
 *
 * Exported for testing: the decision matrix is worth asserting directly
 * rather than only through a live socket.
 */
function isRedirectAllowed(next, { chainOrigin, originProtocol, allowedHosts = null }) {
    const url = next instanceof URL ? next : new URL(next);
    const host = url.hostname.toLowerCase();
    const origin = String(chainOrigin).toLowerCase();

    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        return { allowed: false, reason: `unsupported scheme ${url.protocol}` };
    }
    if (originProtocol === 'https:' && url.protocol !== 'https:') {
        return { allowed: false, reason: `insecure redirect to ${url.protocol}//${host}` };
    }

    const sameHost = host === origin;
    const allowlisted = Array.isArray(allowedHosts)
        && allowedHosts.some((h) => String(h).toLowerCase() === host);

    if (!sameHost && !allowlisted) {
        return { allowed: false, reason: `cross-host redirect to ${host}` };
    }

    // Request headers may carry a secret (the NVD API key), so they travel
    // only back to the exact host that was originally addressed. An
    // allowlisted hop is still a different operator and gets nothing.
    return { allowed: true, forwardHeaders: sameHost };
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

module.exports = { httpGetText, sleep, isRedirectAllowed };
