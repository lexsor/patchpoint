const express = require('express');
const cors = require('cors');
const http = require('http');
const request = require('supertest');

const { corsOptions, crossSiteGuard, securityHeaders, allowedOrigins } = require('../src/middleware/security');
const { publicError } = require('../src/models/fetcher-orchestrator');
const { httpGetText, isRedirectAllowed } = require('../src/lib/http');

/**
 * Builds the same middleware stack index.js installs, so the policy is tested
 * as it is actually composed rather than in isolation.
 */
function makeApp(env = {}) {
    const app = express();
    app.use(securityHeaders);
    app.use(cors(corsOptions(env)));
    app.use(crossSiteGuard);
    app.use(express.json());
    app.get('/api/thing', (req, res) => res.json({ ok: true }));
    app.post('/api/thing', (req, res) => res.json({ created: true }));
    app.delete('/api/thing', (req, res) => res.json({ deleted: true }));
    return app;
}

describe('CORS policy', () => {
    // A bare cors() sets Access-Control-Allow-Origin: * unconditionally, which
    // let any site read this unauthenticated API's whole dataset.
    test('does not emit a wildcard origin', async () => {
        const res = await request(makeApp()).get('/api/thing').set('Origin', 'https://evil.example');
        expect(res.headers['access-control-allow-origin']).not.toBe('*');
    });

    test('rejects an unlisted origin by sending no CORS headers', async () => {
        const res = await request(makeApp()).get('/api/thing').set('Origin', 'https://evil.example');
        // The request still executes server-side; what matters is that the
        // browser is not told it may read the response.
        expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });

    test('allows the configured client origin', async () => {
        const res = await request(makeApp({ ALLOWED_ORIGINS: 'https://patchpoint.internal' }))
            .get('/api/thing')
            .set('Origin', 'https://patchpoint.internal');
        expect(res.headers['access-control-allow-origin']).toBe('https://patchpoint.internal');
    });

    test('allows requests with no Origin header (curl, healthchecks)', async () => {
        const res = await request(makeApp()).get('/api/thing');
        expect(res.status).toBe(200);
    });

    test('refuses to answer a cross-origin DELETE preflight', async () => {
        const res = await request(makeApp())
            .options('/api/thing')
            .set('Origin', 'https://evil.example')
            .set('Access-Control-Request-Method', 'DELETE');
        expect(res.headers['access-control-allow-origin']).toBeUndefined();
    });

    test('does not reflect arbitrary requested headers back', async () => {
        // Header reflection is what let a cross-origin JSON POST preflight
        // succeed against the old configuration.
        const res = await request(makeApp())
            .options('/api/thing')
            .set('Origin', 'https://evil.example')
            .set('Access-Control-Request-Method', 'POST')
            .set('Access-Control-Request-Headers', 'content-type,x-anything');
        expect(res.headers['access-control-allow-headers']).toBeUndefined();
    });

    test('defaults to the local client origins when unconfigured', () => {
        expect(allowedOrigins({})).toEqual(['http://localhost:3000', 'http://127.0.0.1:3000']);
        expect(allowedOrigins({ ALLOWED_ORIGINS: 'https://a.test, https://b.test' }))
            .toEqual(['https://a.test', 'https://b.test']);
    });
});

describe('cross-site request guard', () => {
    // POST /api/fetch reads no request body, which makes it a CORS "simple
    // request" reachable from a plain <form> with no preflight. Tightening
    // CORS alone does not close it, hence this guard.
    test('blocks a cross-site POST', async () => {
        const res = await request(makeApp()).post('/api/thing').set('Sec-Fetch-Site', 'cross-site');
        expect(res.status).toBe(403);
        expect(res.body.error).toMatch(/cross-site/i);
    });

    test('blocks a cross-site DELETE', async () => {
        const res = await request(makeApp()).delete('/api/thing').set('Sec-Fetch-Site', 'cross-site');
        expect(res.status).toBe(403);
    });

    test('blocks a same-site-but-cross-origin POST', async () => {
        const res = await request(makeApp()).post('/api/thing').set('Sec-Fetch-Site', 'same-site');
        expect(res.status).toBe(403);
    });

    test('allows a same-origin POST', async () => {
        const res = await request(makeApp()).post('/api/thing').set('Sec-Fetch-Site', 'same-origin');
        expect(res.status).toBe(200);
    });

    test('allows a direct navigation/typed request', async () => {
        const res = await request(makeApp()).post('/api/thing').set('Sec-Fetch-Site', 'none');
        expect(res.status).toBe(200);
    });

    test('allows clients that send neither header (curl, scripts)', async () => {
        const res = await request(makeApp()).post('/api/thing');
        expect(res.status).toBe(200);
    });

    test('falls back to Origin when Sec-Fetch-Site is absent', async () => {
        // Safari <= 16.3 and Firefox < 90 send no Sec-Fetch-Site, so without
        // this fallback the guard failed open on exactly those browsers and a
        // cross-origin form POST to /api/fetch went through.
        const res = await request(makeApp()).post('/api/thing').set('Origin', 'https://evil.example');
        expect(res.status).toBe(403);
    });

    test('allows an allowlisted Origin when Sec-Fetch-Site is absent', async () => {
        const res = await request(makeApp()).post('/api/thing').set('Origin', 'http://localhost:3000');
        expect(res.status).toBe(200);
    });

    test('prefers Sec-Fetch-Site over Origin when both are present', async () => {
        // Sec-Fetch-Site cannot be forged by page script, so it wins.
        const res = await request(makeApp())
            .post('/api/thing')
            .set('Sec-Fetch-Site', 'same-origin')
            .set('Origin', 'https://evil.example');
        expect(res.status).toBe(200);
    });

    test('never blocks reads', async () => {
        const res = await request(makeApp()).get('/api/thing').set('Sec-Fetch-Site', 'cross-site');
        expect(res.status).toBe(200);
    });
});

describe('security headers', () => {
    test('are present on API responses', async () => {
        const res = await request(makeApp()).get('/api/thing');
        expect(res.headers['x-content-type-options']).toBe('nosniff');
        expect(res.headers['x-frame-options']).toBe('DENY');
        expect(res.headers['referrer-policy']).toBe('no-referrer');
        expect(res.headers['content-security-policy']).toContain("default-src 'none'");
        expect(res.headers['content-security-policy']).toContain("frame-ancestors 'none'");
    });
});

describe('upstream error sanitisation', () => {
    // The raw message reaches unauthenticated callers via POST /api/fetch and
    // GET /api/fetch/status. A JSON.parse failure embeds the start of the
    // upstream body; a socket error embeds the address it could not reach.
    test('keeps the upstream HTTP status, which is useful and leaks nothing', () => {
        expect(publicError({ message: 'NVD HTTP 429' })).toBe('upstream returned HTTP 429');
        expect(publicError({ message: 'MITRE CVEW HTTP 500 for CVE-2024-1' })).toBe('upstream returned HTTP 500');
    });

    test('strips internal addresses and ports', () => {
        const out = publicError({ message: 'connect ECONNREFUSED 10.0.0.5:8080' });
        expect(out).toBe('upstream connection failed');
        expect(out).not.toMatch(/10\.0\.0\.5|8080/);
    });

    test('strips response-body fragments from parse failures', () => {
        const out = publicError({ message: 'Unexpected token \'a\', "ami-launch-index" is not valid JSON' });
        expect(out).toBe('upstream returned malformed data');
        expect(out).not.toMatch(/ami-launch/);
    });

    test('strips internal hostnames from resolution failures', () => {
        const out = publicError({ message: 'getaddrinfo ENOTFOUND internal.corp' });
        expect(out).toBe('upstream host could not be resolved');
        expect(out).not.toMatch(/internal\.corp/);
    });

    test('falls back to a generic message for anything unrecognised', () => {
        expect(publicError({ message: 'surprise /etc/passwd detail' })).toBe('fetch failed');
        expect(publicError({})).toBe('fetch failed');
        expect(publicError(null)).toBe('fetch failed');
    });
});

describe('redirect handling in httpGetText', () => {
    let server;
    let base;
    let receivedHeaders;

    beforeAll((done) => {
        receivedHeaders = [];
        server = http.createServer((req, res) => {
            receivedHeaders.push({ url: req.url, headers: req.headers });

            if (req.url === '/downgrade') {
                res.writeHead(302, { Location: 'http://127.0.0.1:1/nowhere' });
                return res.end();
            }
            if (req.url === '/metadata') {
                res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
                return res.end();
            }
            if (req.url === '/other-host') {
                res.writeHead(302, { Location: 'https://attacker.example/collect' });
                return res.end();
            }
            if (req.url === '/loop') {
                res.writeHead(302, { Location: '/loop' });
                return res.end();
            }
            if (req.url === '/same-host') {
                res.writeHead(302, { Location: '/landed' });
                return res.end();
            }
            res.writeHead(200, { 'Content-Type': 'text/plain' });
            return res.end('landed');
        });
        server.listen(0, '127.0.0.1', () => {
            base = `http://127.0.0.1:${server.address().port}`;
            done();
        });
    });

    afterAll((done) => { server.close(() => done()); });

    beforeEach(() => { receivedHeaders = []; });

    // The scheme and host rules are asserted directly against the decision
    // function: an https origin cannot be reproduced over a local socket
    // without certificates, and the matrix is the part worth pinning.
    describe('decision matrix', () => {
        const from = (proto, host) => ({ chainOrigin: host, originProtocol: proto });

        test('allows a same-host https hop and forwards headers', () => {
            const v = isRedirectAllowed('https://www.cisa.gov/x', from('https:', 'www.cisa.gov'));
            expect(v.allowed).toBe(true);
            expect(v.forwardHeaders).toBe(true);
        });

        test('refuses a sibling subdomain, and never forwards headers off-host', () => {
            // This used to be allowed by a registrable-domain comparison, and
            // with it went the caller's headers -- so a redirect to any
            // *.nist.gov host would have received the NVD API key. One
            // subdomain takeover in that zone was enough to collect it.
            const v = isRedirectAllowed('https://evil.nist.gov/x', from('https:', 'services.nvd.nist.gov'));
            expect(v.allowed).toBe(false);
            expect(v.reason).toMatch(/cross-host/i);
        });

        test('refuses the parent domain', () => {
            expect(isRedirectAllowed('https://nist.gov/x', from('https:', 'services.nvd.nist.gov')).allowed).toBe(false);
        });

        test('is not fooled by a multi-part public suffix', () => {
            // "last two labels" made foo.co.uk and bar.co.uk the same site.
            expect(isRedirectAllowed('https://bar.co.uk/x', from('https:', 'foo.co.uk')).allowed).toBe(false);
        });

        test('matches the host case-insensitively', () => {
            expect(isRedirectAllowed('https://WWW.CISA.GOV/x', from('https:', 'www.cisa.gov')).allowed).toBe(true);
        });

        test('refuses an https to http downgrade', () => {
            const v = isRedirectAllowed('http://www.cisa.gov/x', from('https:', 'www.cisa.gov'));
            expect(v.allowed).toBe(false);
            expect(v.reason).toMatch(/insecure redirect/i);
        });

        test('refuses an unrelated host', () => {
            const v = isRedirectAllowed('https://attacker.example/collect', from('https:', 'www.cisa.gov'));
            expect(v.allowed).toBe(false);
            expect(v.reason).toMatch(/cross-host/i);
        });

        test('refuses link-local metadata over either scheme', () => {
            expect(isRedirectAllowed('http://169.254.169.254/latest/', from('https:', 'www.cisa.gov')).allowed).toBe(false);
            expect(isRedirectAllowed('https://169.254.169.254/latest/', from('https:', 'www.cisa.gov')).allowed).toBe(false);
        });

        test('refuses a non-http scheme', () => {
            const v = isRedirectAllowed('file:///etc/passwd', from('https:', 'www.cisa.gov'));
            expect(v.allowed).toBe(false);
            expect(v.reason).toMatch(/unsupported scheme/i);
        });

        test('permits an explicitly allowlisted host but drops headers', () => {
            const v = isRedirectAllowed('https://cdn.example/x', {
                chainOrigin: 'www.cisa.gov', originProtocol: 'https:', allowedHosts: ['cdn.example'],
            });
            expect(v.allowed).toBe(true);
            expect(v.forwardHeaders).toBe(false);
        });

        test('treats IP literals like any other host: exact match only', () => {
            expect(isRedirectAllowed('http://127.0.0.1:9/x', from('http:', '127.0.0.1')).allowed).toBe(true);
            expect(isRedirectAllowed('http://10.0.0.2/x', from('http:', '10.0.0.1')).allowed).toBe(false);
            expect(isRedirectAllowed('http://169.254.169.254/x', from('http:', '127.0.0.1')).allowed).toBe(false);
        });
    });

    test('refuses a cross-host redirect over a real socket', async () => {
        await expect(httpGetText(`${base}/other-host`, { timeoutMs: 5000 }))
            .rejects.toThrow(/cross-host redirect/i);
    });

    test('still follows a same-host relative redirect', async () => {
        const res = await httpGetText(`${base}/same-host`, { timeoutMs: 5000 });
        expect(res.statusCode).toBe(200);
        expect(res.body).toBe('landed');
    });

    test('forwards caller headers on a same-host hop', async () => {
        await httpGetText(`${base}/same-host`, { timeoutMs: 5000, headers: { apiKey: 'secret-key' } });
        const landed = receivedHeaders.find((r) => r.url === '/landed');
        expect(landed.headers.apikey).toBe('secret-key');
    });

    test('bounds the redirect chain', async () => {
        await expect(httpGetText(`${base}/loop`, { timeoutMs: 5000 }))
            .rejects.toThrow(/too many redirects/i);
    });

    test('a plain request is unaffected', async () => {
        const res = await httpGetText(`${base}/landed`, { timeoutMs: 5000 });
        expect(res.statusCode).toBe(200);
        expect(res.body).toBe('landed');
    });
});
