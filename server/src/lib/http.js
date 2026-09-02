const https = require('https');
const http = require('http');
const zlib = require('zlib');

const DEFAULT_TIMEOUT_MS = 60000;
const MAX_REDIRECTS = 5;

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
function httpGetText(url, { headers = {}, timeoutMs = DEFAULT_TIMEOUT_MS, redirectsLeft = MAX_REDIRECTS } = {}) {
    return new Promise((resolve, reject) => {
        const target = new URL(url);
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
                const next = new URL(res.headers.location, target).toString();
                httpGetText(next, { headers, timeoutMs, redirectsLeft: redirectsLeft - 1 })
                    .then(resolve, reject);
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

module.exports = { httpGetText, sleep };
