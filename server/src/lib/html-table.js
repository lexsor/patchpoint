/**
 * Minimal HTML table extraction.
 *
 * Written rather than pulling in cheerio because the only consumer is the
 * Android Security Bulletin parser, and that markup is narrow and known:
 * measured across bulletins from 2015 to 2025 there are no nested tables, no
 * `rowspan`, no `colspan` and no `<thead>` -- just `<table><tbody><tr>` with
 * `<th>` on the header row and `<td>` on the rest. A general-purpose parser
 * would be a large dependency for a job with those guarantees.
 *
 * That said, the guarantees are the reason this is safe, so the bulletin
 * fetcher validates its own assumptions (see `parseBulletin`) instead of
 * trusting cell positions.
 */

const NAMED_ENTITIES = {
    nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'",
    ldquo: '“', rdquo: '”', lsquo: '‘', rsquo: '’',
    ndash: '–', mdash: '—', hellip: '…',
};

/** Decode the entities that actually appear in this markup. */
function decodeEntities(text) {
    return String(text)
        .replace(/&#x([0-9a-f]+);/gi, (_, hex) => safeCodePoint(parseInt(hex, 16)))
        .replace(/&#(\d+);/g, (_, dec) => safeCodePoint(parseInt(dec, 10)))
        // `&amp;` is decoded last so `&amp;lt;` yields the literal `&lt;`
        // rather than being double-decoded into `<`.
        .replace(/&([a-z]+);/gi, (match, name) => {
            const key = name.toLowerCase();
            return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, key)
                ? NAMED_ENTITIES[key]
                : match;
        });
}

function safeCodePoint(code) {
    if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return '';
    try {
        return String.fromCodePoint(code);
    } catch {
        return '';
    }
}

/**
 * Cell markup -> plain text.
 *
 * Bulletin cells routinely wrap their content in an anchor and pad it with
 * newlines, so the CVE id in `<td>\n  CVE-2025-22420\n</td>` only matches a
 * strict pattern after collapsing whitespace.
 */
function cellText(html) {
    return decodeEntities(
        String(html)
            // Drop anything scripted or styled before stripping tags, so its
            // body does not become visible text.
            .replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ')
            // A <br> is a space, not a word join.
            .replace(/<br\s*\/?>/gi, ' ')
            .replace(/<[^>]*>/g, ' '),
    ).replace(/\s+/g, ' ').trim();
}

/**
 * Extract every table in the document.
 *
 * @returns {Array<{headers: string[], rows: string[][]}>} Tables in document
 *   order. `headers` is empty for a table with no `<th>` row.
 */
function extractTables(html) {
    const source = String(html || '');
    const tables = [];

    for (const [tableHtml] of source.matchAll(/<table\b[^>]*>([\s\S]*?)<\/table>/gi)) {
        const rows = [];
        let headers = [];

        for (const [rowHtml] of tableHtml.matchAll(/<tr\b[^>]*>([\s\S]*?)<\/tr>/gi)) {
            const cells = [...rowHtml.matchAll(/<(t[dh])\b[^>]*>([\s\S]*?)<\/\1>/gi)]
                .map((match) => cellText(match[2]));

            if (cells.length === 0) continue;

            // The first row that carries any <th> is the header. Later <th>
            // cells appear mid-table in the glossary sections, so "has a th"
            // alone cannot decide this.
            const isHeaderRow = /<th\b/i.test(rowHtml);
            if (isHeaderRow && headers.length === 0) {
                headers = cells;
            } else {
                rows.push(cells);
            }
        }

        tables.push({ headers, rows });
    }

    return tables;
}

/**
 * Index of the first header matching `pattern`, or -1.
 *
 * Column lookup is by header text rather than position because the bulletin
 * layout is not positionally stable: the 2015 tables have four columns and no
 * `Type`, later ones have five, and within a single 2025 bulletin some tables
 * end in `Updated AOSP versions` while others end in `Subcomponent`.
 */
function findColumn(headers, pattern) {
    return headers.findIndex((header) => pattern.test(header));
}

module.exports = { extractTables, cellText, decodeEntities, findColumn };
