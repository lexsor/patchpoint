/**
 * Request-level security middleware.
 *
 * Extracted from index.js so the policy is unit-testable rather than only
 * observable by booting the whole server.
 */

const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000'];

/** Origins permitted to make cross-origin API calls. */
function allowedOrigins(env = process.env) {
    const configured = (env.ALLOWED_ORIGINS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);

    return configured.length > 0 ? configured : DEFAULT_ALLOWED_ORIGINS;
}

/**
 * Options for the `cors` package.
 *
 * A bare `cors()` sets `Access-Control-Allow-Origin: *` unconditionally and
 * reflects whatever `Access-Control-Request-Headers` the caller asks for. On an
 * API with no authentication that let any web page the operator visited read
 * the whole dataset and then call the destructive endpoints — DELETE
 * /api/alerts wipes the alert history irrecoverably, since regeneration only
 * looks back 24 hours.
 *
 * Rejecting an origin means calling back with `false`, which makes the `cors`
 * package emit no CORS headers and fall through — so the preflight is not
 * answered and the browser refuses the real request.
 */
function corsOptions(env = process.env) {
    const allowed = allowedOrigins(env);

    return {
        origin(origin, callback) {
            // No Origin header: same-origin navigation, curl, or a server-side
            // client. Nothing to decide, and blocking these would break the
            // documented `curl localhost:3001/...` checks.
            if (!origin) return callback(null, true);
            return callback(null, allowed.includes(origin) ? origin : false);
        },
        methods: ['GET', 'HEAD', 'POST', 'DELETE'],
        credentials: false,
        maxAge: 600,
    };
}

/**
 * Reject cross-site state-changing requests.
 *
 * A tightened CORS policy alone does not cover this. `POST /api/fetch` reads
 * no request body, which makes it a CORS "simple request" — a plain
 * `<form method="POST">` on any site reaches it without a preflight, so no
 * origin check is ever consulted. `Sec-Fetch-Site` is set by the browser and
 * cannot be spoofed by page script, so it is the reliable signal here.
 *
 * Non-browser clients (curl, scripts, the container healthcheck) send no
 * Sec-Fetch-Site header and are unaffected; this closes browser-driven CSRF
 * without breaking automation.
 */
function crossSiteGuard(req, res, next) {
    if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
        return next();
    }

    const site = req.get('Sec-Fetch-Site');
    if (site && site !== 'same-origin' && site !== 'none') {
        return res.status(403).json({ error: 'Cross-site request rejected' });
    }

    return next();
}

/**
 * Response headers that limit what a served page is allowed to do.
 *
 * nginx serves the built client in production, but the API can be reached
 * directly, so these are set here too rather than only in nginx.conf.
 */
function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    // The API only ever returns JSON, so nothing needs to load or execute.
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    return next();
}

module.exports = { corsOptions, crossSiteGuard, securityHeaders, allowedOrigins, DEFAULT_ALLOWED_ORIGINS };
