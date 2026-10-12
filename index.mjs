/**
 * BookOrbit Libgen Indexer Plugin
 *
 * Implements search and download resolution targeting the libgen.li / libgen.bz
 * mirror family for ebook search and download resolution. Adheres strictly to
 * BookOrbit PLUGIN_API_VERSION = 1 contract as a dependency-free ECMAScript module.
 */

/**
 * Source-inspected host contract (not an executable upstream integration test).
 * Pin: https://github.com/bookorbit/bookorbit/commit/c19f728ba4f2894b14048b1f6ef402bc5e5635a3
 * packages/plugin-api/src/index.ts declares PluginReleaseFile.headers and a
 * PluginRequestInit WITHOUT signal. plugin-host.ts ignores init.signal and
 * imposes its own 25-second request ceiling plus the caller's deadline.
 * DirectDownloadService forwards sanitized headers and checks stream byte counts,
 * but does not perform format-aware structural validation or an atomic temp-file
 * rename. Production payload-validation acceptance remains unresolved; see README.md.
 */
const HOST_CONTRACT = {
  targetHost: 'BookOrbit',
  targetVersion: '1.0.0',
  upstreamRepo: 'https://github.com/bookorbit/bookorbit',
  upstreamCommit: 'c19f728ba4f2894b14048b1f6ef402bc5e5635a3',
  upstreamPr: 'https://github.com/bookorbit/bookorbit/pull/1696',
  apiVersion: 1,
  interfaces: [
    'IndexerPlugin',
    'CandidateRelease',
    'PluginFetch',
    'ResolvedFile',
    'PluginReleaseFile',
    'DirectDownloadService',
    'HostDownloader',
    'PluginHost',
    'PluginReleaseCandidate',
    'PluginRequestInit',
  ],
  supportsRequestSignal: false,
  payloadValidationVerified: false,
};

const DEFAULT_MAX_ATTEMPTS = 3;
const MIN_ATTEMPTS = 1;
const MAX_ATTEMPTS = 10;
const DEFAULT_MIRROR_TIMEOUT_MS = 8000;
const MD5_REGEX = /^[a-f0-9]{32}$/i;

const BROWSER_HEADERS = {
  'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36',
  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'Accept-Language': 'en-US,en;q=0.9',
  'Cookie': 'covers=on',
};

const PREFERRED_EXTENSIONS = new Set(['epub', 'mobi', 'pdf', 'azw3', 'cbz']);

const LANGUAGE_BY_NAME = {
  arabic: 'ar', bulgarian: 'bg', catalan: 'ca', chinese: 'zh',
  czech: 'cs', danish: 'da', dutch: 'nl', english: 'en',
  esperanto: 'eo', finnish: 'fi', french: 'fr', german: 'de',
  greek: 'el', hebrew: 'he', hungarian: 'hu', italian: 'it',
  japanese: 'ja', latin: 'la', norwegian: 'no', polish: 'pl',
  portuguese: 'pt', romanian: 'ro', russian: 'ru', serbian: 'sr',
  spanish: 'es', swedish: 'sv', tagalog: 'tl', technical: undefined,
  turkish: 'tr', ukrainian: 'uk',
};

const SIZE_UNITS = {
  b: 1,
  kb: 1024,
  mb: 1024 ** 2,
  gb: 1024 ** 3,
  tb: 1024 ** 4,
};

const ENTITY_REGEX = /&(?:amp|quot|apos|lt|gt|nbsp|#(\d+)|#x([0-9a-f]+));/gi;
const NAMED_ENTITIES = { amp: '&', quot: '"', apos: "'", lt: '<', gt: '>', nbsp: ' ' };

/**
 * Host error creation helper: uses host.fail if available, else creates Error with code.
 */
function fail(host, code, message) {
  if (typeof host?.fail === 'function') {
    return host.fail(code, message);
  }
  const err = new Error(message);
  err.code = code;
  return err;
}

/**
 * Resolves mirror URLs from primary and fallback configuration.
 * Canonicalizes to origin and enforces attempt bounds.
 */
function allMirrors(config) {
  const primaryRaw = (config?.baseUrl || '').trim();
  const fallbacksRaw = (config?.settings?.fallbackMirrors || '')
    .split(',')
    .map(m => m.trim())
    .filter(Boolean);

  const origins = [];
  for (const raw of [primaryRaw, ...fallbacksRaw]) {
    if (!raw) continue;
    try {
      const u = new URL(raw);
      if (u.protocol === 'http:' || u.protocol === 'https:') {
        const canonical = u.origin;
        if (!origins.includes(canonical)) {
          origins.push(canonical);
        }
      }
    } catch {
      // Skip malformed mirror strings
    }
  }

  if (origins.length === 0) {
    throw new Error('No valid HTTP/HTTPS mirrors configured for Library Genesis plugin');
  }

  const rawMax = Number(config?.settings?.maxMirrorAttempts);
  const maxAttempts = Number.isFinite(rawMax)
    ? Math.max(MIN_ATTEMPTS, Math.min(MAX_ATTEMPTS, Math.floor(rawMax)))
    : DEFAULT_MAX_ATTEMPTS;

  return origins.slice(0, maxAttempts);
}

/**
 * Sanitizes URLs down to origin + pathname for safe logging and error diagnostics.
 */
function sanitizeUrlForLogging(urlStr) {
  try {
    const u = new URL(urlStr);
    return `${u.origin}${u.pathname}`;
  } catch {
    return 'invalid-url';
  }
}

/**
 * Redacts full URLs inside error messages to origin/pathname, stripping queries & credentials.
 */
function sanitizeErrorDiagnostics(err) {
  if (!err) return 'unknown error';
  const rawMsg = err instanceof Error ? err.message : String(err);
  return rawMsg.replace(/https?:\/\/[^\s"'<>]+/gi, match => {
    const trailingPunctMatch = match.match(/[:.,;]+$/);
    const trailingPunct = trailingPunctMatch ? trailingPunctMatch[0] : '';
    const cleanMatch = trailingPunct ? match.slice(0, -trailingPunct.length) : match;
    return `${sanitizeUrlForLogging(cleanMatch)}${trailingPunct}`;
  });
}

/**
 * Verifies that a URL object uses strictly http: or https: scheme.
 */
function isHttpOrHttps(urlObj) {
  return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
}

/**
 * Validates that urlStr is a valid HTTP(S) URL string; throws if invalid.
 */
function validateHttpUrl(urlStr) {
  const parsed = new URL(urlStr);
  if (!isHttpOrHttps(parsed)) {
    throw new Error(`Invalid protocol ${parsed.protocol}: must be http or https`);
  }
  return parsed.toString();
}

/**
 * Validates that urlStr is a valid HTTP(S) URL string, returning fallback if invalid.
 */
function validateHttpUrlString(urlStr, fallback) {
  try {
    const u = new URL(urlStr);
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.toString();
  } catch {}
  return fallback;
}

/**
 * Validates that urlStr is an HTTP(S) URL targeting targetMd5 without conflicting identities.
 * Rejects duplicate md5 parameters, conflicting query/path hashes, and unsupported schemes.
 */
function isSafeTargetWithMatchingMd5(urlStr, targetMd5) {
  if (!targetMd5 || !MD5_REGEX.test(targetMd5)) return false;
  const normalizedTarget = targetMd5.toLowerCase();

  let u;
  try {
    u = new URL(urlStr);
  } catch {
    return false;
  }

  // 1. Strict protocol validation
  if (!isHttpOrHttps(u)) return false;

  // 2. Query parameter validation: reject duplicate or conflicting 'md5' parameters
  const md5Params = u.searchParams.getAll('md5');
  if (md5Params.length > 1) {
    return false; // Reject multiple/duplicate md5 parameters
  }
  if (md5Params.length === 1) {
    if (md5Params[0].trim().toLowerCase() !== normalizedTarget) {
      return false; // Conflicting query MD5
    }
  }

  // 3. Path segment validation: check recognized endpoints
  const segments = u.pathname.split('/').filter(Boolean);
  let pathHasHash = false;
  for (const seg of segments) {
    const segBase = seg.replace(/\.[a-z0-9]+$/i, '');
    if (MD5_REGEX.test(segBase)) {
      pathHasHash = true;
      if (segBase.toLowerCase() !== normalizedTarget) {
        return false; // Conflicting path MD5
      }
    } else if (/^[a-f0-9]{32,}/i.test(segBase) || (/^[a-f0-9]{28,40}$/i.test(segBase) && /(?:main|book|ads)/i.test(u.pathname))) {
      return false; // Malformed or conflicting identifier in recognized endpoint
    }
  }

  // If both query and path lacked an MD5, it does not positively identify targetMd5
  if (md5Params.length === 0 && !pathHasHash) {
    return false;
  }

  return true;
}

/**
 * Checks whether a URL contains conflicting or duplicate MD5 parameters or path segments.
 * Used to reject redirected URLs that point to different books or tampered parameters.
 */
function hasConflictingOrDuplicateMd5(urlStr, targetMd5) {
  if (!targetMd5 || !MD5_REGEX.test(targetMd5)) return true;
  const normalizedTarget = targetMd5.toLowerCase();
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    return true; // Malformed URL is unsafe
  }
  if (!isHttpOrHttps(u)) return true;

  // 1. Check query parameters: reject duplicate md5 params or conflicting md5
  const md5Params = u.searchParams.getAll('md5');
  if (md5Params.length > 1) return true;
  if (md5Params.length === 1) {
    const p = md5Params[0].trim().toLowerCase();
    if (p !== normalizedTarget) return true;
  }

  // 2. Check path segments: reject if any segment is a conflicting or malformed MD5
  const segments = u.pathname.split('/').filter(Boolean);
  for (const seg of segments) {
    const segBase = seg.replace(/\.[a-z0-9]+$/i, '');
    if (MD5_REGEX.test(segBase)) {
      if (segBase.toLowerCase() !== normalizedTarget) return true;
    } else if (/^[a-f0-9]{32,}/i.test(segBase) || (/^[a-f0-9]{28,40}$/i.test(segBase) && /(?:main|book|ads)/i.test(u.pathname))) {
      if (segBase.toLowerCase() !== normalizedTarget) return true;
    }
  }

  return false;
}

/** Best-effort release of a response that is no longer needed, including late fetches. */
function discardResponse(response) {
  try {
    if (response?.body && !response.bodyUsed) {
      Promise.resolve(response.body.cancel()).catch(() => {});
    }
  } catch {
    // A host may expose a locked body; its own request ceiling still applies.
  }
}

/**
 * Bounds plugin waiting, not the host socket. The pinned API ignores init.signal.
 * Race both fetching and reading against one attempt deadline, observe late
 * rejections, and discard late responses without accepting them as candidates.
 */
function createBoundedRequestSignal(callerSignal, timeoutMs = DEFAULT_MIRROR_TIMEOUT_MS) {
  const controller = new AbortController();
  let timeoutId = null;
  let isLocalTimeout = false;

  if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
    timeoutId = setTimeout(() => {
      isLocalTimeout = true;
      const error = new Error(`Mirror wait timed out after ${timeoutMs}ms`);
      error.name = 'TimeoutError';
      controller.abort(error);
    }, timeoutMs);
  }

  const onCallerAbort = () => {
    if (timeoutId) clearTimeout(timeoutId);
    controller.abort(callerSignal?.reason || new Error('Host deadline aborted'));
  };
  if (callerSignal) {
    if (callerSignal.aborted) onCallerAbort();
    else callerSignal.addEventListener('abort', onCallerAbort, { once: true });
  }

  function run(operation) {
    return new Promise((resolve, reject) => {
      const signal = controller.signal;
      if (signal.aborted) {
        reject(signal.reason);
        return;
      }
      let settled = false;
      const onAbort = () => {
        settled = true;
        signal.removeEventListener('abort', onAbort);
        reject(signal.reason);
      };
      signal.addEventListener('abort', onAbort, { once: true });
      Promise.resolve().then(() => {
        if (signal.aborted) throw signal.reason;
        return operation();
      }).then(value => {
        signal.removeEventListener('abort', onAbort);
        if (settled) {
          discardResponse(value);
          return;
        }
        settled = true;
        resolve(value);
      }, error => {
        signal.removeEventListener('abort', onAbort);
        if (!settled) {
          settled = true;
          reject(error);
        }
      });
    });
  }

  const cleanup = () => {
    if (timeoutId) clearTimeout(timeoutId);
    callerSignal?.removeEventListener('abort', onCallerAbort);
  };
  return {
    signal: controller.signal,
    isCallerAborted: () => Boolean(callerSignal?.aborted),
    isLocalTimeout: () => isLocalTimeout,
    run,
    cleanup,
  };
}

/**
 * Extracts a strictly bounded 32-character hex MD5 from row cells and links.
 * Enforces identifier boundaries:
 * - Captures complete identifier tokens to prevent prefix truncation (e.g. md5=<valid-hash>g is rejected).
 * - Rejects conflicting complete identities across cells (e.g. title hash A + mirror hash B).
 * Returns the verified 32-character hex MD5 if all identifiers agree, or null if malformed or conflicting.
 */
function extractRowMd5(cellCombinedHtml, responseUrl) {
  if (!cellCombinedHtml) return null;
  const hrefRegex = /href=["']([^"']+)["']/gi;
  let match;
  const foundHashes = new Set();
  let sawMalformed = false;

  // 1. Structured URL parsing from href attributes
  while ((match = hrefRegex.exec(cellCombinedHtml)) !== null) {
    const rawHref = decodeHtmlEntities(match[1].trim());
    try {
      const u = new URL(rawHref, responseUrl || 'https://libgen.bz');
      const md5Params = u.searchParams.getAll('md5');
      for (const p of md5Params) {
        const val = p.trim();
        if (!val) continue;
        if (MD5_REGEX.test(val)) {
          foundHashes.add(val.toLowerCase());
        } else {
          // Any non-empty md5 parameter that is not exactly 32-hex is malformed
          sawMalformed = true;
        }
      }
      for (const seg of u.pathname.split('/').filter(Boolean)) {
        const segBase = seg.replace(/\.[a-z0-9]+$/i, '');
        if (MD5_REGEX.test(segBase)) {
          foundHashes.add(segBase.toLowerCase());
        } else if (/^[a-f0-9]{32,}/i.test(segBase) || (/^[a-f0-9]{28,40}$/i.test(segBase) && /(?:main|book|ads)/i.test(u.pathname))) {
          sawMalformed = true;
        }
      }
    } catch {}
  }

  // 2. Complete-token pattern scanning for raw strings/attributes (prevents prefix truncation)
  // Query parameter: ?md5=... or &md5=...
  const queryTokenRegex = /[?&]md5=([^&"'#\s<>]+)/gi;
  let qMatch;
  while ((qMatch = queryTokenRegex.exec(cellCombinedHtml)) !== null) {
    const token = qMatch[1].trim();
    if (!token) continue;
    if (MD5_REGEX.test(token)) {
      foundHashes.add(token.toLowerCase());
    } else {
      sawMalformed = true;
    }
  }

  // Path token: /main/<token> or /book/<token>
  const pathTokenRegex = /\/(?:main|book)\/([^&"'#\s<>\/?]+)/gi;
  let pMatch;
  while ((pMatch = pathTokenRegex.exec(cellCombinedHtml)) !== null) {
    const rawToken = pMatch[1].trim();
    const token = rawToken.replace(/\.[a-z0-9]+$/i, '');
    if (!token || token === 'index' || token === 'search') continue;
    if (MD5_REGEX.test(token)) {
      foundHashes.add(token.toLowerCase());
    } else if (/^[a-f0-9]{32,}/i.test(token) || /^[a-f0-9]{28,40}$/i.test(token) || /^[a-z0-9_-]{8,}$/i.test(token)) {
      sawMalformed = true;
    }
  }

  // Reject row if malformed identifier was detected, or if multiple conflicting hashes exist, or if 0 hashes
  if (sawMalformed || foundHashes.size !== 1) {
    return null;
  }

  return [...foundHashes][0];
}

/**
 * Clamps search limit between 1 and 100, default 25.
 */
function clampLimit(rawLimit) {
  const num = Number(rawLimit);
  if (!Number.isFinite(num) || num < 1) return 25;
  return Math.min(100, Math.floor(num));
}

/**
 * Builds the search URL targeting /index.php on baseUrl with standard columns, objects, and topics.
 */
function buildSearchUrl(baseUrl, searchText, limit = 25) {
  const url = new URL('/index.php', baseUrl);
  const params = new URLSearchParams();

  params.set('req', searchText);

  // Columns: title (t), author (a), series (s), year (y), publisher (p), isbn (i)
  for (const col of ['t', 'a', 's', 'y', 'p', 'i']) {
    params.append('columns[]', col);
  }

  // Objects: files (f), editions (e), series (s), authors (a), publishers (p), works (w)
  for (const obj of ['f', 'e', 's', 'a', 'p', 'w']) {
    params.append('objects[]', obj);
  }

  // Topics: l = libgen (non-fiction), f = fiction
  params.append('topics[]', 'l');
  params.append('topics[]', 'f');

  params.set('res', String(clampLimit(limit)));
  params.set('filesuns', 'all');

  url.search = params.toString();
  return url.toString();
}

/**
 * Maps human-readable language strings to ISO 639-1 two-letter codes.
 */
function normalizeLanguage(langText) {
  if (!langText) return undefined;
  return LANGUAGE_BY_NAME[langText.trim().toLowerCase()] || undefined;
}

/**
 * Decodes numeric (decimal, hex) and named HTML entities.
 */
function decodeHtmlEntities(text) {
  if (!text) return '';
  return text.replace(ENTITY_REGEX, (match, dec, hex) => {
    if (dec) {
      const code = parseInt(dec, 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    }
    if (hex) {
      const code = parseInt(hex, 16);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    }
    const name = match.slice(1, -1).toLowerCase();
    return NAMED_ENTITIES[name] ?? match;
  });
}

/**
 * Strips HTML tags from input string.
 */
function stripTags(html) {
  if (!html) return '';
  return html.replace(/<[^>]*>/g, '');
}

/**
 * Parses file size string supporting b, kb, mb, gb, tb and comma/dot number formats.
 */
function parseSize(raw) {
  if (!raw) return null;
  const trimmed = raw.trim();

  // Strictly match: <number> <unit> without trailing garbage
  const match = /^([0-9.,]+)\s*(bytes?|[kmgt]?b)$/i.exec(trimmed);
  if (!match) return null;

  let numStr = match[1];
  const unitRaw = match[2].toLowerCase();

  let unit = unitRaw;
  if (unit === 'bytes' || unit === 'byte') unit = 'b';
  else if (!unit.endsWith('b')) unit += 'b';

  // Normalize decimal comma vs thousands separator
  if (numStr.includes(',') && numStr.includes('.')) {
    if (numStr.indexOf(',') < numStr.indexOf('.')) {
      numStr = numStr.replace(/,/g, ''); // 1,024.50 -> 1024.50
    } else {
      numStr = numStr.replace(/\./g, '').replace(',', '.'); // 1.024,50 -> 1024.50
    }
  } else if (numStr.includes(',')) {
    const parts = numStr.split(',');
    if (parts.length === 2 && parts[1].length === 3 && parts[0].length >= 1) {
      numStr = parts.join(''); // 1,000 -> 1000
    } else if (parts.length === 2) {
      numStr = parts.join('.'); // 1,5 -> 1.5
    } else {
      return null;
    }
  }

  // Ensure entire remaining string is a valid finite positive number
  if (!/^\d+(?:\.\d+)?$/.test(numStr)) return null;

  const value = Number(numStr);
  if (!Number.isFinite(value) || value < 0) return null;

  const multiplier = SIZE_UNITS[unit];
  return multiplier ? Math.round(value * multiplier) : null;
}

/**
 * Sanitizes book name for safe local filename representation.
 */
function sanitizeName(name) {
  if (!name) return 'download';
  const normalized = name.normalize('NFC');
  const cleaned = normalized.replace(/[^\p{L}\p{N}\s._-]/gu, ' ').trim();
  const collapsed = cleaned.replace(/\s+/g, ' ');
  if (!/[\p{L}\p{N}]/u.test(collapsed)) return 'download';
  return collapsed.slice(0, 120).trim() || 'download';
}

/**
 * Parses <table id="tablelibgen"> HTML table from search response.
 * Detects data-row presence independently of cell extraction success.
 */
function parseSearchResults(html, responseUrl) {
  const tableMatch = /<table\b[^>]*\bid=["']tablelibgen["'][^>]*>([\s\S]*?)<\/table>/i.exec(html);
  if (!tableMatch) {
    return { items: [], tableFound: false, dataRowCount: 0, rejectedCount: 0 };
  }

  const tableBody = tableMatch[1];
  const rowChunks = tableBody.split(/<\/tr>/i);
  const items = [];
  let dataRowCount = 0;
  let rejectedCount = 0;

  for (const rowChunk of rowChunks) {
    // 1. Independent data-row presence check
    if (!/<td\b/i.test(rowChunk)) continue;
    dataRowCount++;

    // 2. Extract matching <td>...</td> pairs and first-cell opening attributes
    const tdMatches = [];
    const tdOpenTags = [];
    const tdRegex = /<td\b([^>]*)>([\s\S]*?)<\/td>/gi;
    let tdMatch;
    while ((tdMatch = tdRegex.exec(rowChunk)) !== null) {
      tdOpenTags.push(tdMatch[1]);
      tdMatches.push(tdMatch[2]);
    }

    if (tdMatches.length === 0) {
      // Row had <td starts but no complete pairs (malformed markup)
      rejectedCount++;
      continue;
    }

    // 3. Dynamic cover offset detection: inspect ONLY the first cell's tag and content
    const hasCover = /<img\b[^>]*src=["']?[^"'>]*covers\//i.test(tdMatches[0]) ||
                     /\bclass=["']?[^"'>]*\bcover\b/i.test(tdOpenTags[0]);
    const offset = hasCover ? 1 : 0;

    if (tdMatches.length < 9 + offset) {
      rejectedCount++;
      continue;
    }

    const titleCell = tdMatches[0 + offset];
    const authorCell = tdMatches[1 + offset];
    const langCell = tdMatches[4 + offset];
    const sizeCell = tdMatches[6 + offset];
    const extCell = tdMatches[7 + offset];
    const mirrorsCell = tdMatches[8 + offset];

    const title = decodeHtmlEntities(stripTags(titleCell)).trim();
    const author = decodeHtmlEntities(stripTags(authorCell)).trim();
    const rawLang = stripTags(langCell).trim();
    const language = normalizeLanguage(rawLang);
    const format = stripTags(extCell).trim().toLowerCase();
    const sizeBytes = parseSize(stripTags(sizeCell).trim());

    // Extract validated 32-hex MD5 with strict identifier boundary enforcement
    const md5 = extractRowMd5(titleCell + mirrorsCell, responseUrl);

    if (!title || !md5 || !format) {
      rejectedCount++;
      continue;
    }

    // Extract landing link using exact MD5 identity matching
    let landingUrl = null;
    const hrefRegex = /href=["']([^"']+)["']/gi;
    let match;
    while ((match = hrefRegex.exec(mirrorsCell + titleCell)) !== null) {
      const rawHref = decodeHtmlEntities(match[1].trim());
      try {
        const resolved = new URL(rawHref, responseUrl);
        if (isSafeTargetWithMatchingMd5(resolved.href, md5)) {
          landingUrl = resolved.toString();
          break;
        }
      } catch {
        // Skip invalid URLs
      }
    }

    items.push({
      title,
      author: author || undefined,
      format,
      sizeBytes,
      language,
      md5,
      landingUrl,
    });
  }

  return { items, tableFound: true, dataRowCount, rejectedCount };
}

/**
 * Constructs a candidate release object conforming to BookOrbit PLUGIN_API_VERSION = 1.
 */
function toRelease(item, mirrorBase) {
  const downloadUrl = item.landingUrl || `${mirrorBase}/ads.php?md5=${item.md5}`;

  return {
    guid: item.md5,
    title: item.title,
    bookTitle: item.title,
    downloadUrl,
    sizeBytes: item.sizeBytes,
    seeders: null,
    leechers: null,
    format: item.format,
    ...(item.language ? { language: item.language } : {}),
    ...(item.author ? { author: item.author } : {}),
    freeleech: true,
    primaryFileCount: 1,
  };
}

/**
 * Evaluates whether Content-Type indicates binary ebook stream.
 */
function isBinaryEbookContentType(contentType) {
  if (!contentType || contentType.includes('text/html') || contentType.includes('text/plain') || contentType.includes('application/json')) {
    return false;
  }
  const ebookTypes = [
    'application/epub+zip',
    'application/pdf',
    'application/x-mobipocket-ebook',
    'application/octet-stream',
  ];
  return ebookTypes.some(k => contentType.includes(k));
}

/**
 * Extracts the exact "GET" direct link from the mirror landing page, verifying MD5 identity.
 */
function extractGetLink(html, baseUrl, targetMd5) {
  const aRegex = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = aRegex.exec(html)) !== null) {
    const attrs = match[1];
    const text = stripTags(match[2]).trim().toUpperCase();

    // Must be strictly "GET" anchor text
    if (text !== 'GET') continue;

    const hrefMatch = /href=["']([^"']+)["']/i.exec(attrs);
    if (!hrefMatch) continue;

    const rawHref = decodeHtmlEntities(hrefMatch[1].trim());
    let fullUrl;
    try {
      fullUrl = new URL(rawHref, baseUrl);
    } catch {
      continue;
    }

    // Must be HTTP or HTTPS
    if (!isHttpOrHttps(fullUrl)) continue;

    // Check query parameters: reject if any MD5 conflicts or duplicates exist
    const md5Params = fullUrl.searchParams.getAll('md5');
    if (md5Params.length > 1) continue;
    if (md5Params.length === 1 && md5Params[0].toLowerCase() !== targetMd5.toLowerCase()) {
      continue; // Conflicting query MD5
    }

    // Check path segments: reject if any 32-hex segment conflicts
    const segments = fullUrl.pathname.split('/').filter(Boolean);
    let pathConflict = false;
    for (const seg of segments) {
      const segBase = seg.replace(/\.[a-z0-9]+$/i, '');
      if (MD5_REGEX.test(segBase) && segBase.toLowerCase() !== targetMd5.toLowerCase()) {
        pathConflict = true;
        break;
      }
    }
    if (pathConflict) continue;

    // If pointing to get.php, ensure target MD5 is attached if missing
    if (fullUrl.pathname.endsWith('/get.php') || fullUrl.pathname.endsWith('get.php')) {
      if (!fullUrl.searchParams.has('md5')) {
        fullUrl.searchParams.set('md5', targetMd5);
      }
      return fullUrl.toString();
    }

    // Direct storage/mirror link obtained from validated landing page
    return fullUrl.toString();
  }

  return null;
}

/**
 * Executes book search across mirrors with fallback failover.
 */
async function search(query, config, host, signal) {
  const mirrors = allMirrors(config);
  const searchText = typeof host?.buildSearchText === 'function'
    ? host.buildSearchText(query)
    : (query?.searchText || query?.title || (typeof query === 'string' ? query : ''));
  if (!searchText) return [];

  const limit = clampLimit(query?.limit ?? 25);
  const mirrorOutcomes = [];
  let sawEmptyOrUnsupportedMirror = false;
  let terminalCancellation = null;

  const mirrorTimeoutSetting = Number(config?.settings?.timeoutMs);
  const perMirrorTimeout = Number.isFinite(mirrorTimeoutSetting) && mirrorTimeoutSetting > 0
    ? mirrorTimeoutSetting
    : DEFAULT_MIRROR_TIMEOUT_MS;

  for (const mirror of mirrors) {
    if (signal?.aborted) {
      terminalCancellation = new Error('Host deadline aborted');
      break;
    }

    const bounded = createBoundedRequestSignal(signal, perMirrorTimeout);
    let response;

    try {
      const searchUrl = buildSearchUrl(mirror, searchText, limit);
      response = await bounded.run(() => host.fetch(searchUrl, {
        headers: BROWSER_HEADERS,
      }));

      if (!response.ok) {
        mirrorOutcomes.push({
          mirror,
          kind: response.status === 429 ? 'throttled' : (response.status === 504 ? 'timeout' : 'http_error'),
          status: response.status,
        });
        continue;
      }

      const responseUrl = validateHttpUrlString(response.url, searchUrl);
      const html = await bounded.run(() => response.text());

      // Scoped empty-catalog detection: strictly within identified results containers
      const paginatorMatch = /<div\b[^>]*id=["']paginator["'][^>]*>([\s\S]*?)<\/div>/i.exec(html);
      const isPositivelyIdentifiedEmpty = paginatorMatch && /no books found|nothing found|0 files found/i.test(paginatorMatch[1]);

      const { items, tableFound, dataRowCount, rejectedCount } = parseSearchResults(html, responseUrl);

      // Case 1: Unrecognized page structure (no table and no empty container)
      if (!tableFound && !isPositivelyIdentifiedEmpty) {
        mirrorOutcomes.push({ mirror, kind: 'unrecognized', detail: 'Missing tablelibgen and results container' });
        continue;
      }

      // Case 2: Table found, but all data rows failed parsing -> parser regression!
      if (tableFound && dataRowCount > 0 && items.length === 0) {
        mirrorOutcomes.push({ mirror, kind: 'parser_error', detail: `Rejected ${rejectedCount}/${dataRowCount} rows` });
        continue;
      }

      // Case 3: Valid rows parsed -> takes precedence over paginator text!
      if (items.length > 0) {
        const releases = items
          .filter(item => PREFERRED_EXTENSIONS.has(item.format))
          .slice(0, limit)
          .map(item => toRelease(item, mirror));

        if (releases.length > 0) {
          return releases; // Success!
        }

        // Valid items present, but none in preferred formats
        sawEmptyOrUnsupportedMirror = true;
        continue;
      }

      // Case 4: Verified empty catalog on this mirror (0 data rows or recognized empty marker)
      if (isPositivelyIdentifiedEmpty || (tableFound && dataRowCount === 0)) {
        sawEmptyOrUnsupportedMirror = true;
        continue;
      }
    } catch (err) {
      // 1. Caller deadline cancellation (terminal)
      if (signal?.aborted || (bounded.isCallerAborted() && !bounded.isLocalTimeout())) {
        terminalCancellation = err;
        break;
      }

      // 2. Request-local socket timeout or AbortError (retryable across mirrors)
      const isTimeout = bounded.isLocalTimeout() ||
                        err?.name === 'TimeoutError' ||
                        (err?.name === 'AbortError' && !signal?.aborted);

      if (isTimeout) {
        mirrorOutcomes.push({
          mirror,
          kind: 'timeout',
          detail: `Mirror attempt timed out (${perMirrorTimeout}ms)`,
        });
        continue;
      }

      mirrorOutcomes.push({ mirror, kind: 'transport_error', detail: sanitizeErrorDiagnostics(err) });
    } finally {
      bounded.cleanup();
      discardResponse(response);
    }
  }

  // The host adapter races search against its caller deadline; never try another mirror after cancellation.
  if (signal?.aborted || terminalCancellation) {
    return [];
  }

  // If at least one responsive mirror verified an empty catalog or unsupported-only candidates
  if (sawEmptyOrUnsupportedMirror) {
    return [];
  }

  // Synthesize structured diagnostics
  const allThrottled = mirrorOutcomes.length > 0 && mirrorOutcomes.every(o => o.kind === 'throttled');
  if (allThrottled) {
    throw fail(host, 'throttled', 'All Libgen mirrors returned 429 Throttled');
  }

  const allTimedOut = mirrorOutcomes.length > 0 && mirrorOutcomes.every(o => o.kind === 'timeout');
  if (allTimedOut) {
    throw fail(host, 'timeout', 'All Libgen mirrors timed out');
  }

  const summary = mirrorOutcomes.map(o => `${o.mirror}: ${o.kind}${o.status ? ` (${o.status})` : ''}${o.detail ? ` (${o.detail})` : ''}`).join('; ');
  throw fail(host, 'unreachable', `Libgen search failed across all mirrors: ${summary || 'unknown error'}`);
}

/**
 * Resolves a release into a downloadable file object with headers, filename, and format.
 */
async function resolveFile(release, config, host, signal) {
  const mirrors = allMirrors(config);
  const md5 = (release?.guid || '').trim().toLowerCase();

  // 1. Strict MD5 validation
  if (!MD5_REGEX.test(md5)) {
    throw fail(host, 'error', `Invalid release GUID "${release?.guid}": must be 32-character hex MD5`);
  }

  // 2. Reconstruct candidate targets: validate scheme and exact MD5 identity before adding
  const targets = [];
  if (release?.downloadUrl && isSafeTargetWithMatchingMd5(release.downloadUrl, md5)) {
    targets.push(release.downloadUrl);
  }

  for (const m of mirrors) {
    const fallbackUrl = `${m}/ads.php?md5=${encodeURIComponent(md5)}`;
    if (!targets.includes(fallbackUrl)) targets.push(fallbackUrl);
  }

  const targetErrors = [];
  const targetTimeoutSetting = Number(config?.settings?.timeoutMs);
  const perTargetTimeout = Number.isFinite(targetTimeoutSetting) && targetTimeoutSetting > 0
    ? targetTimeoutSetting
    : DEFAULT_MIRROR_TIMEOUT_MS;

  for (const targetUrl of targets) {
    if (signal?.aborted) {
      throw new Error('Host deadline aborted');
    }

    const bounded = createBoundedRequestSignal(signal, perTargetTimeout);
    let response;

    try {
      response = await bounded.run(() => host.fetch(targetUrl, {
        headers: BROWSER_HEADERS,
      }));

      if (!response.ok) {
        targetErrors.push(`${sanitizeUrlForLogging(targetUrl)}: HTTP ${response.status}`);
        continue;
      }

      const responseUrl = validateHttpUrlString(response.url, targetUrl);

      // Validate redirected URL identity: reject if response URL carries conflicting or duplicate MD5
      if (hasConflictingOrDuplicateMd5(responseUrl, md5)) {
        targetErrors.push(
          `${sanitizeUrlForLogging(targetUrl)}: Redirected to conflicting identity ${sanitizeUrlForLogging(responseUrl)} for MD5 ${md5}`
        );
        continue;
      }

      const contentType = (response.headers?.get?.('content-type') || '').toLowerCase();

      // 3. Binary-response classification (heuristic)
      if (isBinaryEbookContentType(contentType)) {
        return {
          url: validateHttpUrl(responseUrl),
          headers: BROWSER_HEADERS, // Provided for host downloader
          fileName: `${sanitizeName(release.bookTitle || release.title)}.${release.format}`,
          sizeBytes: release.sizeBytes,
          format: release.format,
        };
      }

      // 4. Parse HTML landing page for exact GET download link
      const html = await bounded.run(() => response.text());
      const directUrl = extractGetLink(html, responseUrl, md5);

      if (directUrl) {
        return {
          url: validateHttpUrl(directUrl),
          headers: BROWSER_HEADERS, // Provided for host downloader
          fileName: `${sanitizeName(release.bookTitle || release.title)}.${release.format}`,
          sizeBytes: release.sizeBytes,
          format: release.format,
        };
      }

      targetErrors.push(`${sanitizeUrlForLogging(targetUrl)}: No valid GET link matching MD5 ${md5}`);
    } catch (err) {
      if (signal?.aborted || (bounded.isCallerAborted() && !bounded.isLocalTimeout())) {
        throw err; // Propagate caller cancellation immediately
      }
      const isTimeout = bounded.isLocalTimeout() ||
                        err?.name === 'TimeoutError' ||
                        (err?.name === 'AbortError' && !signal?.aborted);
      if (isTimeout) {
        targetErrors.push(`${sanitizeUrlForLogging(targetUrl)}: Request timed out (${perTargetTimeout}ms)`);
        continue;
      }
      targetErrors.push(`${sanitizeUrlForLogging(targetUrl)}: ${sanitizeErrorDiagnostics(err)}`);
    } finally {
      bounded.cleanup();
      discardResponse(response);
    }
  }

  throw fail(host, 'error', `Could not resolve download for "${release?.title}": ${targetErrors.join('; ')}`);
}

/**
 * Tests connection to configured mirror by querying the test endpoint.
 */
async function test(config, host) {
  try {
    const primary = (config?.baseUrl || '').trim();
    if (!primary) {
      return { success: false, error: 'No Base URL configured' };
    }
    validateHttpUrl(primary);

    const searchUrl = buildSearchUrl(primary, 'test', 5);
    const response = await host.fetch(searchUrl, { headers: BROWSER_HEADERS });

    if (!response.ok) {
      return { success: false, error: `Primary mirror returned HTTP ${response.status}` };
    }

    const html = await response.text();
    const hasTable = /<table\b[^>]*\bid=["']tablelibgen["']/i.test(html);
    const hasSearchForm = /<form\b[^>]*action=["'][^"']*index\.php["'][^>]*>[\s\S]*?<input\b[^>]*name=["']req["']/i.test(html);

    if (!hasTable && !hasSearchForm) {
      return {
        success: false,
        error: 'Mirror responded, but is not a recognized libgen.li search page (missing tablelibgen and search form controls)',
      };
    }

    return { success: true, indexerName: 'Library Genesis (libgen.li / libgen.bz)' };
  } catch (error) {
    return { success: false, error: sanitizeErrorDiagnostics(error) };
  }
}

const plugin = {
  apiVersion: 1,
  version: '0.1.0',
  type: 'libgen',
  label: 'Library Genesis (libgen.li / libgen.bz)',
  requiresCredential: false,
  credentialKind: null,
  mediaKinds: ['ebook'],
  usesCategories: false,
  seedsBack: false,
  defaultBaseUrl: 'https://libgen.bz',
  baseUrlHint: 'Must be a libgen.li / libgen.bz family mirror (e.g. https://libgen.bz, https://libgen.li, https://libgen.la). Note: libgen.rs/is mirrors use an incompatible layout and are not supported.',
  settingsFields: [
    {
      key: 'fallbackMirrors',
      type: 'string',
      label: 'Fallback mirrors (comma-separated)',
      hint: 'Additional libgen.li-compatible mirrors tried in order if primary fails or returns no usable candidates.',
      default: 'https://libgen.li, https://libgen.la, https://libgen.gl',
    },
    {
      key: 'timeoutMs',
      type: 'number',
      label: 'Mirror wait timeout (milliseconds)',
      hint: 'Bounds plugin waiting per mirror, not the host socket. Default 8000 ms.',
      default: DEFAULT_MIRROR_TIMEOUT_MS,
    },
    {
      key: 'maxMirrorAttempts',
      type: 'number',
      label: 'Maximum mirror attempts',
      hint: 'Maximum number of mirrors to try per search (clamped between 1 and 10).',
      default: 3,
    },
  ],

  search,
  test,
  resolveFile,
};

export default plugin;

export {
  allMirrors,
  sanitizeUrlForLogging,
  sanitizeErrorDiagnostics,
  isHttpOrHttps,
  isSafeTargetWithMatchingMd5,
  validateHttpUrl,
  validateHttpUrlString,
  BROWSER_HEADERS,
  PREFERRED_EXTENSIONS,
  clampLimit,
  buildSearchUrl,
  LANGUAGE_BY_NAME,
  normalizeLanguage,
  decodeHtmlEntities,
  stripTags,
  parseSize,
  sanitizeName,
  parseSearchResults,
  toRelease,
  extractGetLink,
  isBinaryEbookContentType,
  search,
  test,
  resolveFile,
  HOST_CONTRACT,
  DEFAULT_MIRROR_TIMEOUT_MS,
  hasConflictingOrDuplicateMd5,
  createBoundedRequestSignal,
  extractRowMd5,
};

export const _internal = {
  allMirrors,
  sanitizeUrlForLogging,
  sanitizeErrorDiagnostics,
  isHttpOrHttps,
  isSafeTargetWithMatchingMd5,
  validateHttpUrl,
  validateHttpUrlString,
  BROWSER_HEADERS,
  PREFERRED_EXTENSIONS,
  clampLimit,
  buildSearchUrl,
  LANGUAGE_BY_NAME,
  normalizeLanguage,
  decodeHtmlEntities,
  stripTags,
  parseSize,
  sanitizeName,
  parseSearchResults,
  toRelease,
  extractGetLink,
  isBinaryEbookContentType,
  search,
  test,
  resolveFile,
  HOST_CONTRACT,
  DEFAULT_MIRROR_TIMEOUT_MS,
  hasConflictingOrDuplicateMd5,
  createBoundedRequestSignal,
  extractRowMd5,
};
