/**
 * Verification Suite for BookOrbit Libgen Indexer Plugin
 *
 * Standalone offline test suite validating plugins/libgen/index.mjs against
 * BookOrbit PLUGIN_API_VERSION = 1 contract, multi-mirror failover taxonomy,
 * parser integrity, MD5 identity hardening, and download resolution.
 *
 * Run with: node plugins/libgen/verify.mjs
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import plugin, * as namedExports from './index.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURES_DIR = path.join(__dirname, 'fixtures');

// Extract helper functions from named exports or plugin._internal
const helpers = { ...plugin._internal, ...namedExports };
const {
  parseSize,
  sanitizeName,
  sanitizeUrlForLogging,
  sanitizeErrorDiagnostics,
  isSafeTargetWithMatchingMd5,
  normalizeLanguage,
  parseSearchResults,
  extractGetLink,
  allMirrors,
  buildSearchUrl,
  toRelease,
  isBinaryEbookContentType,
  validateHttpUrl,
  clampLimit,
  BROWSER_HEADERS,
  HOST_CONTRACT,
  DEFAULT_MIRROR_TIMEOUT_MS,
  hasConflictingOrDuplicateMd5,
  createBoundedRequestSignal,
  extractRowMd5,
  WIRE_PAGE_SIZE,
  DEFAULT_MAX_PAGES,
  DEFAULT_SEARCH_BUDGET_MS,
  MIN_SEARCH_BUDGET_MS,
  MAX_SEARCH_BUDGET_MS,
  MIN_PAGE_BUDGET_MS,
  ISO_639_2_TO_1,
  normalizeLanguageSubtag,
  languagesAgree,
  validateIsbn,
  classifyQueryInputs,
  SearchBudgetTracker,
} = helpers;

// Verify that critical helper functions were exported
for (const [name, fn] of Object.entries({
  parseSize,
  sanitizeName,
  sanitizeUrlForLogging,
  sanitizeErrorDiagnostics,
  isSafeTargetWithMatchingMd5,
  normalizeLanguage,
  hasConflictingOrDuplicateMd5,
  createBoundedRequestSignal,
  extractRowMd5,
})) {
  if (typeof fn !== 'function') {
    throw new Error(`Critical helper function "${name}" is not exported from index.mjs`);
  }
}

if (!HOST_CONTRACT || typeof HOST_CONTRACT !== 'object') {
  throw new Error('Critical constant HOST_CONTRACT is not exported from index.mjs');
}

// ---------------------------------------------------------------------------
// Mini Test Harness
// ---------------------------------------------------------------------------

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;
const failures = [];

async function test(name, fn) {
  totalTests++;
  try {
    await fn();
    passedTests++;
    console.log(`  ✓ ${name}`);
  } catch (err) {
    failedTests++;
    failures.push({ name, error: err });
    console.error(`  ✗ ${name}`);
    console.error(`    ${err?.message || err}`);
    if (err?.stack) {
      const relevantStack = err.stack.split('\n').slice(1, 3).join('\n');
      console.error(`    ${relevantStack.trim()}`);
    }
  }
}

function suite(name) {
  console.log(`\n=== ${name} ===`);
}

// ---------------------------------------------------------------------------
// Mock Host Implementation
// ---------------------------------------------------------------------------

export function createMockHost(options = {}) {
  const callHistory = [];
  const cannedResponses = new Map();
  const routeHandlers = [];

  if (options.routes) {
    for (const r of options.routes) {
      routeHandlers.push(r);
    }
  }

  if (options.responses) {
    for (const [k, v] of Object.entries(options.responses)) {
      cannedResponses.set(k, v);
    }
  }

  function createResponse(spec, reqUrl) {
    if (!spec) {
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        url: reqUrl,
        headers: {
          get(name) {
            return name.toLowerCase() === 'content-type' ? 'text/html; charset=utf-8' : null;
          },
        },
        text: async () => '',
        json: async () => ({}),
      };
    }

    if (typeof spec.text === 'function') {
      return spec;
    }

    const status = spec.status ?? (spec.ok === false ? 500 : 200);
    const ok = spec.ok !== undefined ? spec.ok : (status >= 200 && status < 300);
    const statusText = spec.statusText || (ok ? 'OK' : 'Error');
    const respUrl = spec.url || reqUrl;

    const rawHeaders = spec.headers || {};
    const headersMap = new Map();
    if (rawHeaders instanceof Map) {
      for (const [k, v] of rawHeaders.entries()) headersMap.set(k.toLowerCase(), v);
    } else if (typeof rawHeaders.forEach === 'function') {
      rawHeaders.forEach((v, k) => headersMap.set(k.toLowerCase(), v));
    } else {
      for (const [k, v] of Object.entries(rawHeaders)) {
        headersMap.set(k.toLowerCase(), v);
      }
    }
    if (!headersMap.has('content-type')) {
      headersMap.set('content-type', 'text/html; charset=utf-8');
    }

    const headersObj = {
      get(name) {
        return headersMap.get(name.toLowerCase()) || null;
      },
      has(name) {
        return headersMap.has(name.toLowerCase());
      },
      entries() {
        return headersMap.entries();
      },
    };

    let rawBuffer = null;
    let bodyStr = '';
    if (Buffer.isBuffer(spec.buffer)) {
      rawBuffer = spec.buffer;
      bodyStr = rawBuffer.toString('utf-8');
    } else if (spec.fixture) {
      const fixturePath = path.isAbsolute(spec.fixture)
        ? spec.fixture
        : path.join(FIXTURES_DIR, spec.fixture);
      rawBuffer = fs.readFileSync(fixturePath);
      bodyStr = rawBuffer.toString('utf-8');
    } else if (spec.body !== undefined) {
      bodyStr = typeof spec.body === 'string' ? spec.body : JSON.stringify(spec.body);
      rawBuffer = Buffer.from(bodyStr);
    } else if (spec.html !== undefined) {
      bodyStr = spec.html;
      rawBuffer = Buffer.from(bodyStr);
    } else if (spec.text !== undefined && typeof spec.text === 'string') {
      bodyStr = spec.text;
      rawBuffer = Buffer.from(bodyStr);
    } else {
      rawBuffer = Buffer.alloc(0);
    }

    if (!headersMap.has('content-length') && rawBuffer) {
      headersMap.set('content-length', String(rawBuffer.length));
    }

    return {
      ok,
      status,
      statusText,
      url: respUrl,
      headers: headersObj,
      text: async () => bodyStr,
      json: async () => JSON.parse(bodyStr),
      buffer: async () => rawBuffer,
      arrayBuffer: async () => rawBuffer.buffer.slice(rawBuffer.byteOffset, rawBuffer.byteOffset + rawBuffer.byteLength),
    };
  }

  const host = {
    calls: callHistory,
    callHistory,
    lastCall() {
      return callHistory[callHistory.length - 1];
    },
    resetHistory() {
      callHistory.length = 0;
    },
    setResponse(urlOrPattern, resp) {
      cannedResponses.set(urlOrPattern, resp);
    },
    addRoute(pattern, handler) {
      routeHandlers.push({ pattern, handler });
    },
    async fetch(url, fetchOptions = {}) {
      const urlStr = String(url);
      const callRecord = {
        url: urlStr,
        options: fetchOptions,
        headers: fetchOptions.headers || {},
        signal: fetchOptions.signal,
        timestamp: Date.now(),
      };
      callHistory.push(callRecord);

      if (fetchOptions.signal?.aborted) {
        const abortErr = new Error('The operation was aborted');
        abortErr.name = 'AbortError';
        throw abortErr;
      }

      for (const route of routeHandlers) {
        let matches = false;
        if (typeof route.pattern === 'function') {
          matches = route.pattern(urlStr, fetchOptions);
        } else if (route.pattern instanceof RegExp) {
          matches = route.pattern.test(urlStr);
        } else if (typeof route.pattern === 'string') {
          matches = urlStr.includes(route.pattern);
        }
        if (matches) {
          const res = typeof route.handler === 'function' ? await route.handler(urlStr, fetchOptions) : route.handler;
          if (res instanceof Error) throw res;
          return createResponse(res, urlStr);
        }
      }

      if (cannedResponses.has(urlStr)) {
        const res = cannedResponses.get(urlStr);
        if (res instanceof Error) throw res;
        return createResponse(res, urlStr);
      }

      for (const [key, res] of cannedResponses.entries()) {
        if (key instanceof RegExp && key.test(urlStr)) {
          if (res instanceof Error) throw res;
          return createResponse(res, urlStr);
        }
        if (typeof key === 'string' && urlStr.includes(key)) {
          if (res instanceof Error) throw res;
          return createResponse(res, urlStr);
        }
      }

      if (options.defaultHandler) {
        const res = await options.defaultHandler(urlStr, fetchOptions);
        return createResponse(res, urlStr);
      }

      return createResponse({ status: 404, ok: false, text: 'Not Found' }, urlStr);
    },

    fail(kind, message) {
      const err = new Error(message);
      err.kind = kind;
      err.code = kind;
      err.name = 'HostFailError';
      return err;
    },

    buildSearchText(query) {
      if (!query) return '';
      if (typeof query === 'string') return query.trim();
      const parts = [];
      if (query.title) parts.push(query.title.trim());
      if (query.author) parts.push(query.author.trim());
      return parts.join(' ').trim();
    },
  };

  return host;
}

// ---------------------------------------------------------------------------
// Zero-Dependency Binary Format Generators & Host Downloader Simulation
// ---------------------------------------------------------------------------

function crc32(buf) {
  let crc = ~0;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (~crc) >>> 0;
}

export function createSimpleZipBuffer(entries) {
  const localHeaders = [];
  const centralHeaders = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const dataBuf = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content, 'utf8');
    const entryCrc = crc32(dataBuf);

    // Local Header (30 bytes + nameBuf.length + dataBuf.length)
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); // local signature
    lh.writeUInt16LE(20, 4); // version needed
    lh.writeUInt16LE(0, 6); // flags
    lh.writeUInt16LE(0, 8); // compression = stored
    lh.writeUInt16LE(0, 10); // mod time
    lh.writeUInt16LE(0, 12); // mod date
    lh.writeUInt32LE(entryCrc, 14); // crc32
    lh.writeUInt32LE(dataBuf.length, 18); // compressed size
    lh.writeUInt32LE(dataBuf.length, 22); // uncompressed size
    lh.writeUInt16LE(nameBuf.length, 26); // name length
    lh.writeUInt16LE(0, 28); // extra length

    localHeaders.push(lh, nameBuf, dataBuf);

    // Central Directory Header (46 bytes + nameBuf.length)
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); // cd signature
    cd.writeUInt16LE(20, 4); // version made by
    cd.writeUInt16LE(20, 6); // version needed
    cd.writeUInt16LE(0, 8); // flags
    cd.writeUInt16LE(0, 10); // compression = stored
    cd.writeUInt16LE(0, 12); // mod time
    cd.writeUInt16LE(0, 14); // mod date
    cd.writeUInt32LE(entryCrc, 16); // crc32
    cd.writeUInt32LE(dataBuf.length, 20); // compressed size
    cd.writeUInt32LE(dataBuf.length, 24); // uncompressed size
    cd.writeUInt16LE(nameBuf.length, 28); // name length
    cd.writeUInt16LE(0, 30); // extra length
    cd.writeUInt16LE(0, 32); // comment length
    cd.writeUInt16LE(0, 34); // disk num
    cd.writeUInt16LE(0, 36); // internal attr
    cd.writeUInt32LE(0, 38); // external attr
    cd.writeUInt32LE(offset, 42); // local header offset

    centralHeaders.push(cd, nameBuf);

    offset += 30 + nameBuf.length + dataBuf.length;
  }

  const cdOffset = offset;
  let cdSize = 0;
  for (const b of centralHeaders) cdSize += b.length;

  // End of Central Directory (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // eocd signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // disk start
  eocd.writeUInt16LE(entries.length, 8); // entries on disk
  eocd.writeUInt16LE(entries.length, 10); // total entries
  eocd.writeUInt32LE(cdSize, 12); // size of CD
  eocd.writeUInt32LE(cdOffset, 16); // offset of CD
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localHeaders, ...centralHeaders, eocd]);
}

export function createValidEpubBuffer() {
  return createSimpleZipBuffer([
    { name: 'mimetype', content: 'application/epub+zip' },
    {
      name: 'META-INF/container.xml',
      content:
        '<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>',
    },
    {
      name: 'OEBPS/content.opf',
      content:
        '<?xml version="1.0"?><package version="3.0" xmlns="http://www.idpf.org/2007/opf" unique-identifier="pub-id"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Test Book</dc:title></metadata></package>',
    },
  ]);
}

export function createValidPdfBuffer() {
  return Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n115\n%%EOF\n',
    'ascii'
  );
}

export function createValidMobiBuffer() {
  const buf = Buffer.alloc(256);
  buf.write('Test Book MOBI Header Title', 0, 'ascii');
  buf.write('BOOKMOBI', 60, 'ascii');
  return buf;
}

export function createValidCbzBuffer() {
  return createSimpleZipBuffer([
    { name: 'page_01.jpg', content: Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00]) },
    { name: 'page_02.png', content: Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  ]);
}

/** Simulation-only signature checks: NOT format integrity or upstream verification. */
export function validatePayloadStructure(format, buffer) {
  if (!buffer || buffer.length === 0) {
    throw new Error('MockDownloader: Empty file payload');
  }

  const fmt = (format || '').toLowerCase();
  switch (fmt) {
    case 'epub': {
      if (buffer.length < 4 || buffer.readUInt32LE(0) !== 0x04034b50) {
        throw new Error('MockDownloader: Invalid EPUB magic header (not a ZIP archive)');
      }
      const raw = buffer.toString('binary');
      if (!raw.includes('mimetype') || !raw.includes('application/epub+zip')) {
        throw new Error('MockDownloader: Invalid EPUB structure: missing mimetype application/epub+zip');
      }
      if (!raw.includes('META-INF/container.xml')) {
        throw new Error('MockDownloader: Invalid EPUB structure: missing META-INF/container.xml');
      }
      break;
    }
    case 'pdf': {
      const header = buffer.subarray(0, 5).toString('ascii');
      if (header !== '%PDF-') {
        throw new Error('MockDownloader: Invalid PDF magic header (does not start with %PDF-)');
      }
      const trailer = buffer.subarray(Math.max(0, buffer.length - 1024)).toString('ascii');
      if (!trailer.includes('%%EOF')) {
        throw new Error('MockDownloader: Invalid PDF structure: missing %%EOF trailer');
      }
      break;
    }
    case 'mobi':
    case 'azw3': {
      const raw = buffer.toString('binary');
      if (!raw.includes('BOOKMOBI') && !raw.includes('Mobipocket')) {
        throw new Error('MockDownloader: Invalid MOBI structure: missing BOOKMOBI header signature');
      }
      break;
    }
    case 'cbz': {
      if (buffer.length < 4 || buffer.readUInt32LE(0) !== 0x04034b50) {
        throw new Error('MockDownloader: Invalid CBZ magic header (not a ZIP archive)');
      }
      const raw = buffer.toString('binary');
      const hasImages = /\.(?:jpe?g|png|webp|gif)/i.test(raw);
      if (!hasImages) {
        throw new Error('MockDownloader: Invalid CBZ structure: no image entries found');
      }
      break;
    }
    default:
      if (buffer.length < 16) {
        throw new Error(`MockDownloader: Payload too small for format ${format}`);
      }
  }
}

const RESERVED_HOST_HEADERS = new Set(['host', 'content-length', 'transfer-encoding', 'connection', 'range', 'if-range']);

/** Invented test downloader; it does not execute BookOrbit and cannot close a release gate. */
export function createMockHostDownloader({ bookdropDir, tempDir, host }) {
  if (!fs.existsSync(bookdropDir)) fs.mkdirSync(bookdropDir, { recursive: true });
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  async function downloadAndPublish(resolvedFile) {
    // Simulation of selected header rules; not an upstream contract test.
    if (!resolvedFile || typeof resolvedFile !== 'object') {
      throw new Error('MockDownloader: Invalid resolvedFile object');
    }
    if (!resolvedFile.url || !resolvedFile.fileName) {
      throw new Error('MockDownloader: resolvedFile must contain url and fileName');
    }
    if (!resolvedFile.headers || !resolvedFile.headers['User-Agent']) {
      throw new Error('MockDownloader: Missing forwarded User-Agent header in resolvedFile');
    }

    const sanitizedHeaders = {
      'Accept': '*/*',
    };

    for (const [key, val] of Object.entries(resolvedFile.headers)) {
      if (/[\r\n\0]/.test(key) || /[\r\n\0]/.test(String(val))) {
        throw new Error(`MockDownloader: Forbidden CR/LF/NUL character in header "${key}"`);
      }
      if (RESERVED_HOST_HEADERS.has(key.toLowerCase())) {
        // DirectDownloadService strips/filters transport-reserved headers
        continue;
      }
      sanitizedHeaders[key] = val;
    }

    // 2. Fetch using host and sanitized forwarded headers
    const response = await host.fetch(resolvedFile.url, {
      headers: sanitizedHeaders,
    });

    if (!response.ok) {
      throw new Error(`MockDownloader: HTTP transfer failed with status ${response.status}`);
    }

    // 3. Stage writes to atomic temporary sibling file (*.tmp)
    const tmpFilePath = path.join(tempDir, `${resolvedFile.fileName}.tmp`);
    const finalFilePath = path.join(bookdropDir, resolvedFile.fileName);

    let rawBuffer;
    if (typeof response.buffer === 'function') {
      rawBuffer = await response.buffer();
    } else if (typeof response.arrayBuffer === 'function') {
      const ab = await response.arrayBuffer();
      rawBuffer = Buffer.from(ab);
    } else {
      const text = await response.text();
      rawBuffer = Buffer.from(text);
    }

    fs.writeFileSync(tmpFilePath, rawBuffer);

    try {
      // 4. Transport completeness verification
      const contentLengthHeader = response.headers?.get?.('content-length');
      if (contentLengthHeader !== null && contentLengthHeader !== undefined) {
        const expectedBytes = parseInt(contentLengthHeader, 10);
        if (Number.isFinite(expectedBytes) && rawBuffer.length !== expectedBytes) {
          throw new Error(
            `MockDownloader: Transport incomplete: expected ${expectedBytes} bytes, received ${rawBuffer.length} bytes`
          );
        }
      }

      // 5. Anti-bot HTML interstitial rejection (even under application/octet-stream)
      const probeHead = rawBuffer.subarray(0, 1024).toString('utf-8');
      if (/<!DOCTYPE html|<html\b|<head\b|<div\b[^>]*class=["'](?:error|challenge|cf-)/i.test(probeHead)) {
        throw new Error('MockDownloader: Anti-bot HTML interstitial detected in payload');
      }

      // 6. Format-aware payload validation
      const format = (resolvedFile.format || path.extname(resolvedFile.fileName).replace('.', '')).toLowerCase();
      validatePayloadStructure(format, rawBuffer);

      // 7. Atomic commitment to watched bookdrop only after structural validation passes
      fs.renameSync(tmpFilePath, finalFilePath);
      return { success: true, filePath: finalFilePath, sizeBytes: rawBuffer.length };
    } catch (err) {
      // Clean up temporary staging file on failure
      if (fs.existsSync(tmpFilePath)) {
        try { fs.unlinkSync(tmpFilePath); } catch {}
      }
      throw err;
    }
  }

  return { downloadAndPublish };
}

// ---------------------------------------------------------------------------
// Test Suites
// ---------------------------------------------------------------------------

async function runAllTests() {
  const startTime = Date.now();
  console.log('Starting BookOrbit Libgen Plugin Verification Suite...');

  // =========================================================================
  // 0. Source-inspection metadata only; not upstream execution or release acceptance.
  // =========================================================================
  suite('0. Source-Inspected Host Metadata (payload release gate unresolved)');

  await test('HOST_CONTRACT records pinned source and unverified payload acceptance', () => {
    assert.equal(HOST_CONTRACT.targetHost, 'BookOrbit');
    assert.equal(HOST_CONTRACT.supportsRequestSignal, false);
    assert.equal(HOST_CONTRACT.payloadValidationVerified, false);
    assert.equal(HOST_CONTRACT.apiVersion, 1);
    assert.equal(HOST_CONTRACT.upstreamRepo, 'https://github.com/bookorbit/bookorbit');
    assert.equal(HOST_CONTRACT.upstreamCommit, 'c19f728ba4f2894b14048b1f6ef402bc5e5635a3');
    assert.equal(HOST_CONTRACT.upstreamPr, 'https://github.com/bookorbit/bookorbit/pull/1696');
    assert(HOST_CONTRACT.interfaces.includes('IndexerPlugin'));
    assert(HOST_CONTRACT.interfaces.includes('PluginReleaseCandidate'));
    assert(HOST_CONTRACT.interfaces.includes('PluginHost'));
    assert(HOST_CONTRACT.interfaces.includes('PluginRequestInit'));
    assert(HOST_CONTRACT.interfaces.includes('PluginReleaseFile'));
  });

  await test('plugin exports adhere to HOST_CONTRACT and PLUGIN_API_VERSION = 1', () => {
    assert.equal(plugin.apiVersion, 1);
    assert.equal(typeof plugin.search, 'function');
    assert.equal(typeof plugin.test, 'function');
    assert.equal(typeof plugin.resolveFile, 'function');
    assert.equal(typeof plugin.version, 'string');
    assert.equal(typeof plugin.label, 'string');
    assert(Array.isArray(plugin.mediaKinds));
    assert(Array.isArray(plugin.settingsFields));
    assert.equal(plugin.defaultBaseUrl, 'https://libgen.bz');
  });

  // =========================================================================
  // 1. Unit Tests for Helpers
  // =========================================================================
  suite('1. Unit Tests for Helpers');

  await test('parseSize: standard units (b, kb, mb, gb, tb, bytes)', () => {
    assert.equal(parseSize('100 B'), 100);
    assert.equal(parseSize('100 bytes'), 100);
    assert.equal(parseSize('100 byte'), 100);
    assert.equal(parseSize('1024 b'), 1024);
    assert.equal(parseSize('1 KB'), 1024);
    assert.equal(parseSize('10 KB'), 10240);
    assert.equal(parseSize('1.5 MB'), 1572864);
    assert.equal(parseSize('2 GB'), 2147483648);
    assert.equal(parseSize('1 TB'), 1099511627776);
  });

  await test('parseSize: decimal comma vs decimal dot & European formats', () => {
    assert.equal(parseSize('1,5 MB'), 1572864);
    assert.equal(parseSize('1.5 MB'), 1572864);
    assert.equal(parseSize('1,024.50 KB'), 1049088);
    assert.equal(parseSize('1.024,50 KB'), 1049088);
    assert.equal(parseSize('1,000 KB'), 1024000);
    assert.equal(parseSize('2,5 GB'), 2684354560);
  });

  await test('stripTags: preserves malformed markup and handles unmatched tags in linear time', () => {
    assert.equal(namedExports.stripTags('before<b>bold</b>after<unclosed'), 'beforeboldafter<unclosed');
    assert.equal(namedExports.stripTags('a<<nested>b'), 'ab');
    // Isolate the adversarial input so a regex regression cannot hang the suite.
    const child = spawnSync(process.execPath, ['--input-type=module', '-e',
      `import { stripTags } from ${JSON.stringify(new URL('./index.mjs', import.meta.url).href)};
       const input = '<'.repeat(512 * 1024);
       if (stripTags(input) !== input) process.exit(1);`], { timeout: 5000 });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 0, child.stderr?.toString());
  });

  await test('HTML limit: buffered UTF-8 and declared oversized responses are rejected', async () => {
    const { readBoundedHtml, MAX_HTML_BYTES } = namedExports;
    assert.equal(await readBoundedHtml({ text: async () => 'x'.repeat(MAX_HTML_BYTES) }), 'x'.repeat(MAX_HTML_BYTES));
    await assert.rejects(readBoundedHtml({ text: async () => 'x'.repeat(MAX_HTML_BYTES + 1) }), /512 KiB/);
    await assert.rejects(readBoundedHtml({ text: async () => 'é'.repeat(MAX_HTML_BYTES / 2 + 1) }), /512 KiB/);
    await assert.rejects(readBoundedHtml({
      headers: { get: () => String(MAX_HTML_BYTES + 1) },
      text: async () => { throw new Error('Must reject before reading'); },
    }), /512 KiB/);
  });

  await test('HTML limit: oversized streams are cancelled even with a false Content-Length', async () => {
    let cancelled = false;
    let reads = 0;
    const body = new ReadableStream({
      pull(controller) {
        reads++;
        controller.enqueue(new Uint8Array(64 * 1024));
      },
      cancel() { cancelled = true; },
    }, { highWaterMark: 0 });
    await assert.rejects(namedExports.readBoundedHtml({ body, headers: { get: () => '1' } }), /512 KiB/);
    assert.equal(cancelled, true);
    assert.equal(reads, 9);
    assert.equal(body.locked, false);
  });

  await test('HTML limit: streaming decoder preserves split multibyte characters', async () => {
    const bytes = new TextEncoder().encode('café');
    const body = new ReadableStream({ start(controller) {
      controller.enqueue(bytes.slice(0, 4));
      controller.enqueue(bytes.slice(4));
      controller.close();
    } });
    assert.equal(await namedExports.readBoundedHtml({ body }), 'café');
    assert.equal(body.locked, false);
  });

  await test('HTML limit: search, resolution, and connection test reject oversized pages', async () => {
    const host = createMockHost({ defaultHandler: () => ({
      status: 200, text: 'x'.repeat(namedExports.MAX_HTML_BYTES + 1),
      headers: { 'content-type': 'text/html' },
    }) });
    const config = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: '' } };
    await assert.rejects(plugin.search({ title: 'Book' }, config, host), /512 KiB/);
    await assert.rejects(plugin.resolveFile({ guid: 'a'.repeat(32), title: 'Book', format: 'epub' }, config, host), /512 KiB/);
    const result = await plugin.test(config, host);
    assert.equal(result.success, false);
    assert.match(result.error, /512 KiB/);
  });

  await test('parseSize: invalid values, trailing garbage, negatives & infinite return null', () => {
    assert.equal(parseSize(null), null);
    assert.equal(parseSize(undefined), null);
    assert.equal(parseSize(''), null);
    assert.equal(parseSize('   '), null);
    assert.equal(parseSize('invalid'), null);
    assert.equal(parseSize('15'), null);
    assert.equal(parseSize('foo MB'), null);
    assert.equal(parseSize('15 MB extra'), null);
    assert.equal(parseSize('15 MB (approx)'), null);
    assert.equal(parseSize('-5 MB'), null);
    assert.equal(parseSize('Infinity MB'), null);
    assert.equal(parseSize('-Infinity MB'), null);
    assert.equal(parseSize('NaN MB'), null);
    assert.equal(parseSize('1.2.3 MB'), null);
    assert.equal(parseSize('1,2,3 MB'), null);
  });

  await test('sanitizeName: Unicode NFC normalization', () => {
    const decomposed = 'Cafe\u0301'; // 'e' + combining acute accent
    const composed = 'Café';
    assert.equal(sanitizeName(decomposed), composed);
  });

  await test('sanitizeName: special characters, space collapsing & trimming', () => {
    assert.equal(sanitizeName('Dune / Messiah: Part * 1?'), 'Dune Messiah Part 1');
    assert.equal(sanitizeName('   The    Hobbit   '), 'The Hobbit');
    assert.equal(sanitizeName('Book [2024] (Special-Edition) v1.0'), 'Book 2024 Special-Edition v1.0');
  });

  await test('sanitizeName: max 120 chars length clamping', () => {
    const longName = 'A'.repeat(150);
    const result = sanitizeName(longName);
    assert.equal(result.length, 120);
    assert.equal(result, 'A'.repeat(120));
  });

  await test('sanitizeName: fallback to "download"', () => {
    assert.equal(sanitizeName(''), 'download');
    assert.equal(sanitizeName('   '), 'download');
    assert.equal(sanitizeName(null), 'download');
    assert.equal(sanitizeName(undefined), 'download');
    assert.equal(sanitizeName('!@#$%^&*()=+{}|[]:;"<>?/~`'), 'download');
  });

  await test('sanitizeUrlForLogging: strips query parameters and user credentials', () => {
    assert.equal(
      sanitizeUrlForLogging('https://libgen.li/ads.php?md5=0123456789abcdef0123456789abcdef&key=XYZ123'),
      'https://libgen.li/ads.php'
    );
    assert.equal(
      sanitizeUrlForLogging('https://admin:secret@libgen.bz/index.php?req=dune'),
      'https://libgen.bz/index.php'
    );
    assert.equal(sanitizeUrlForLogging('invalid-url-string'), 'invalid-url');
  });

  await test('sanitizeErrorDiagnostics: redacts full URLs and credentials inside error messages', () => {
    const rawError = new Error(
      'Failed fetch at https://user:pass@libgen.li/get.php?md5=0123456789abcdef0123456789abcdef - socket reset'
    );
    const sanitized = sanitizeErrorDiagnostics(rawError);
    assert.equal(sanitized, 'Failed fetch at https://libgen.li/get.php - socket reset');
    assert(!sanitized.includes('user:pass'));
    assert(!sanitized.includes('md5='));

    assert.equal(sanitizeErrorDiagnostics(null), 'unknown error');
    assert.equal(sanitizeErrorDiagnostics('Plain string error'), 'Plain string error');
  });

  await test('isSafeTargetWithMatchingMd5: strict protocol checks', () => {
    const target = '0123456789abcdef0123456789abcdef';
    assert.equal(isSafeTargetWithMatchingMd5(`ftp://libgen.li/ads.php?md5=${target}`, target), false);
    assert.equal(isSafeTargetWithMatchingMd5(`file:///etc/passwd?md5=${target}`, target), false);
    assert.equal(isSafeTargetWithMatchingMd5(`javascript:alert(1)?md5=${target}`, target), false);
    assert.equal(isSafeTargetWithMatchingMd5(`data:text/html,...?md5=${target}`, target), false);
  });

  await test('isSafeTargetWithMatchingMd5: query param duplicate and conflict rejection', () => {
    const target = '0123456789abcdef0123456789abcdef';
    const conflicting = 'fedcba9876543210fedcba9876543210';

    // Duplicate query params rejected
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/ads.php?md5=${target}&md5=${target}`, target),
      false
    );
    // Conflicting query md5 rejected
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/ads.php?md5=${conflicting}`, target),
      false
    );
  });

  await test('isSafeTargetWithMatchingMd5: path segment conflict rejection and valid acceptances', () => {
    const target = '0123456789abcdef0123456789abcdef';
    const conflicting = 'fedcba9876543210fedcba9876543210';

    // Conflicting path md5 rejected
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/main/${conflicting}`, target),
      false
    );
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/main/${conflicting}?md5=${target}`, target),
      false
    );

    // Valid MD5 in query or path accepted
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/ads.php?md5=${target}`, target),
      true
    );
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/main/${target}`, target),
      true
    );
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/book/${target}`, target),
      true
    );
    assert.equal(
      isSafeTargetWithMatchingMd5(`http://libgen.bz/get.php?md5=${target}&key=XYZ`, target),
      true
    );
    // Case-insensitive hash accepted
    assert.equal(
      isSafeTargetWithMatchingMd5(`https://libgen.li/ads.php?md5=${target.toUpperCase()}`, target),
      true
    );

    // Missing MD5 entirely rejected
    assert.equal(isSafeTargetWithMatchingMd5('https://libgen.li/ads.php', target), false);
    assert.equal(isSafeTargetWithMatchingMd5('https://libgen.li/main/books', target), false);
    // Invalid target MD5 rejected
    assert.equal(isSafeTargetWithMatchingMd5(`https://libgen.li/ads.php?md5=${target}`, 'not-an-md5'), false);
  });

  await test('normalizeLanguage: ISO 639-1 mapping and undefined for unknown', () => {
    assert.equal(normalizeLanguage('english'), 'en');
    assert.equal(normalizeLanguage('English'), 'en');
    assert.equal(normalizeLanguage('RUSSIAN'), 'ru');
    assert.equal(normalizeLanguage('Spanish'), 'es');
    assert.equal(normalizeLanguage('French'), 'fr');
    assert.equal(normalizeLanguage('German'), 'de');
    assert.equal(normalizeLanguage('Italian'), 'it');
    assert.equal(normalizeLanguage('Chinese'), 'zh');
    assert.equal(normalizeLanguage('Japanese'), 'ja');

    assert.equal(normalizeLanguage('technical'), undefined);
    assert.equal(normalizeLanguage('klingon'), undefined);
    assert.equal(normalizeLanguage(''), undefined);
    assert.equal(normalizeLanguage(null), undefined);
  });

  await test('allMirrors: parsing, deduplication, attempt clamping, and error handling', () => {
    // Basic deduplication and trailing slashes
    const cfg1 = {
      baseUrl: 'https://libgen.bz/',
      settings: {
        fallbackMirrors: 'https://libgen.bz, https://libgen.li, http://libgen.la',
        maxMirrorAttempts: 5,
      },
    };
    assert.deepEqual(allMirrors(cfg1), ['https://libgen.bz', 'https://libgen.li', 'http://libgen.la']);

    // Clamps maxMirrorAttempts between 1 and 10
    const cfg2 = {
      baseUrl: 'https://libgen.bz',
      settings: {
        fallbackMirrors: 'https://libgen.li, https://libgen.la, https://libgen.gl',
        maxMirrorAttempts: 2,
      },
    };
    assert.deepEqual(allMirrors(cfg2), ['https://libgen.bz', 'https://libgen.li']);

    // Skips malformed URLs
    const cfg3 = {
      baseUrl: 'not-a-url',
      settings: { fallbackMirrors: 'ftp://unsupported.org, https://libgen.li' },
    };
    assert.deepEqual(allMirrors(cfg3), ['https://libgen.li']);

    // Throws if no valid mirrors
    assert.throws(
      () => allMirrors({ baseUrl: 'invalid', settings: { fallbackMirrors: 'ftp://bad' } }),
      /No valid HTTP\/HTTPS mirrors configured/
    );
  });

  await test('clampLimit & buildSearchUrl: verifies parameter structure', () => {
    assert.equal(clampLimit(undefined), 25);
    assert.equal(clampLimit(0), 25);
    assert.equal(clampLimit(-10), 25);
    assert.equal(clampLimit(10), 10);
    assert.equal(clampLimit(250), 100);

    const urlStr = buildSearchUrl('https://libgen.bz', 'Dune Frank Herbert', 15);
    const u = new URL(urlStr);
    assert.equal(u.origin, 'https://libgen.bz');
    assert.equal(u.pathname, '/index.php');
    assert.equal(u.searchParams.get('req'), 'Dune Frank Herbert');
    assert.equal(u.searchParams.get('res'), '15');
    assert.equal(u.searchParams.get('filesuns'), 'all');

    const columns = u.searchParams.getAll('columns[]');
    assert.deepEqual(columns, ['t', 'a', 's', 'y', 'p', 'i']);

    const objects = u.searchParams.getAll('objects[]');
    assert.deepEqual(objects, ['f', 'e', 's', 'a', 'p', 'w']);

    const topics = u.searchParams.getAll('topics[]');
    assert.deepEqual(topics, ['l', 'f']);
  });

  await test('extractGetLink: verifies anchor text, protocol and MD5 parameters', () => {
    const targetMd5 = '0123456789abcdef0123456789abcdef';
    const baseUrl = 'https://libgen.bz/ads.php';

    // Must have strictly "GET" anchor text
    const htmlNonGet = `<a href="get.php?md5=${targetMd5}">DOWNLOAD</a>`;
    assert.equal(extractGetLink(htmlNonGet, baseUrl, targetMd5), null);

    // Rejects non-HTTP schemes
    const htmlFtp = `<a href="ftp://dl.libgen.bz/${targetMd5}.epub">GET</a>`;
    assert.equal(extractGetLink(htmlFtp, baseUrl, targetMd5), null);

    // Rejects conflicting query MD5
    const htmlConflict = `<a href="get.php?md5=fedcba9876543210fedcba9876543210">GET</a>`;
    assert.equal(extractGetLink(htmlConflict, baseUrl, targetMd5), null);

    // Appends target MD5 to get.php if missing
    const htmlKey = `<a href="get.php?key=ABC">GET</a>`;
    const resKey = extractGetLink(htmlKey, baseUrl, targetMd5);
    assert(resKey.includes(`md5=${targetMd5}`));
    assert(resKey.includes('key=ABC'));

    // Accepts direct CDN link
    const htmlDirect = `<a href="https://dl.libgen.bz/file.epub">GET</a>`;
    assert.equal(extractGetLink(htmlDirect, baseUrl, targetMd5), 'https://dl.libgen.bz/file.epub');
  });

  await test('hasConflictingOrDuplicateMd5: detects conflicts in query and path, rejects duplicates', () => {
    const target = '0123456789abcdef0123456789abcdef';
    const other = 'fedcba9876543210fedcba9876543210';

    // Matching query and path
    assert.equal(hasConflictingOrDuplicateMd5(`https://libgen.li/ads.php?md5=${target}`, target), false);
    assert.equal(hasConflictingOrDuplicateMd5(`https://dl.libgen.bz/main/${target}.epub`, target), false);
    assert.equal(hasConflictingOrDuplicateMd5('https://dl.libgen.bz/main/other-name.epub', target), false);

    // Conflicting query parameter
    assert.equal(hasConflictingOrDuplicateMd5(`https://libgen.li/ads.php?md5=${other}`, target), true);
    // Duplicate query parameters
    assert.equal(hasConflictingOrDuplicateMd5(`https://libgen.li/ads.php?md5=${target}&md5=${other}`, target), true);
    assert.equal(hasConflictingOrDuplicateMd5(`https://libgen.li/ads.php?md5=${target}&md5=${target}`, target), true);

    // Conflicting path segment
    assert.equal(hasConflictingOrDuplicateMd5(`https://libgen.li/main/${other}`, target), true);
    assert.equal(hasConflictingOrDuplicateMd5(`https://libgen.li/main/${other}.epub`, target), true);

    // Malformed URLs
    assert.equal(hasConflictingOrDuplicateMd5('invalid-url', target), true);
    assert.equal(hasConflictingOrDuplicateMd5('ftp://libgen.li/file.epub', target), true);
    assert.equal(hasConflictingOrDuplicateMd5(`https://libgen.li/ads.php?md5=${target}`, 'not-valid-md5'), true);
  });

  await test('extractRowMd5: strict identifier boundaries (P2: rejects 33-hex hashes without truncation)', () => {
    const validMd5 = '0123456789abcdef0123456789abcdef';
    const invalid33Hex = '0123456789abcdef0123456789abcdef0';
    const baseUrl = 'https://libgen.bz/index.php';

    // 1. Valid 32-hex hash in query param
    const htmlValidQuery = `<td><a href="/book/index.php?md5=${validMd5}">Hyperion</a></td>`;
    assert.equal(extractRowMd5(htmlValidQuery, baseUrl), validMd5);

    // 2. Valid 32-hex hash in path
    const htmlValidPath = `<td><a href="/main/${validMd5}">Direct</a></td>`;
    assert.equal(extractRowMd5(htmlValidPath, baseUrl), validMd5);

    // 3. P2 Defect: 33-hex hash MUST NOT be truncated to 32 characters; it must be rejected!
    const html33Query = `<td><a href="/book/index.php?md5=${invalid33Hex}">Malformed Book</a></td>`;
    assert.equal(extractRowMd5(html33Query, baseUrl), null);

    const html33Path = `<td><a href="/main/${invalid33Hex}">Malformed Direct</a></td>`;
    assert.equal(extractRowMd5(html33Path, baseUrl), null);

    // 4. P2 Defect: md5=<valid-hash>g (no prefix truncation) must be rejected
    const htmlValidPlusG = `<td><a href="/book/index.php?md5=${validMd5}g">Malformed Suffix G</a></td>`;
    assert.equal(extractRowMd5(htmlValidPlusG, baseUrl), null);

    // 5. P2 Defect: Conflicting complete identities (title hash A + mirror hash B) must be rejected
    const otherValidMd5 = 'fedcba9876543210fedcba9876543210';
    const htmlConflicting = `<td><a href="/book/index.php?md5=${validMd5}">Book Title</a></td><td><a href="/main/${otherValidMd5}">Mirror</a></td>`;
    assert.equal(extractRowMd5(htmlConflicting, baseUrl), null);

    // 6. Multiple identical valid hashes are accepted
    const htmlDuplicateSame = `<td><a href="/book/index.php?md5=${validMd5}">Book Title</a></td><td><a href="/main/${validMd5}">Mirror</a></td>`;
    assert.equal(extractRowMd5(htmlDuplicateSame, baseUrl), validMd5);

    // 7. Non-hex characters rejected
    const htmlNonHex = `<td><a href="/book/index.php?md5=0123456789abcdef0123456789abcdeg">Invalid Hex</a></td>`;
    assert.equal(extractRowMd5(htmlNonHex, baseUrl), null);

    // 8. Short hashes rejected
    const htmlShort = `<td><a href="/book/index.php?md5=0123456789abcdef">Short Hash</a></td>`;
    assert.equal(extractRowMd5(htmlShort, baseUrl), null);
  });

  await test('createBoundedRequestSignal: distinguishes local timeout from caller cancellation', async () => {
    // Case 1: Caller cancellation
    const callerController = new AbortController();
    const bounded1 = createBoundedRequestSignal(callerController.signal, 5000);
    assert.equal(bounded1.isLocalTimeout(), false);
    assert.equal(bounded1.isCallerAborted(), false);
    callerController.abort();
    assert.equal(bounded1.isCallerAborted(), true);
    assert.equal(bounded1.isLocalTimeout(), false);
    assert.equal(bounded1.signal.aborted, true);
    bounded1.cleanup();

    // Case 2: Request-local timeout fires while caller has NOT aborted
    const bounded2 = createBoundedRequestSignal(undefined, 20);
    assert.equal(bounded2.signal.aborted, false);
    await new Promise((r) => setTimeout(r, 40));
    assert.equal(bounded2.signal.aborted, true);
    assert.equal(bounded2.isLocalTimeout(), true);
    assert.equal(bounded2.isCallerAborted(), false);
    bounded2.cleanup();
  });

  // =========================================================================
  // 1b. Unit Tests for Two-Pass Pagination & Budget Utilities
  // =========================================================================
  suite('1b. Unit Tests for Two-Pass Pagination & Budget Utilities');

  await test('validateIsbn: syntax, modulo-11 ISBN-10, and alternating modulo-10 ISBN-13', () => {
    // Valid ISBN-10 with numeric check digit
    assert.deepEqual(validateIsbn('0-306-40615-2'), { valid: true, clean: '0306406152', type: 'isbn10' });
    // Valid ISBN-10 with check digit 'X'
    assert.deepEqual(validateIsbn('0-8044-2957-X'), { valid: true, clean: '080442957X', type: 'isbn10' });
    assert.deepEqual(validateIsbn('080442957x'), { valid: true, clean: '080442957X', type: 'isbn10' });
    // Invalid ISBN-10 check digit
    assert.deepEqual(validateIsbn('0-306-40615-3'), { valid: false, clean: '', type: null });

    // Valid ISBN-13 (prefix 978)
    assert.deepEqual(validateIsbn('978-0-306-40615-7'), { valid: true, clean: '9780306406157', type: 'isbn13' });
    // Valid ISBN-13 (prefix 979)
    assert.deepEqual(validateIsbn('979-10-90636-07-1'), { valid: true, clean: '9791090636071', type: 'isbn13' });
    // Invalid ISBN-13 check digit
    assert.deepEqual(validateIsbn('978-0-306-40615-8'), { valid: false, clean: '', type: null });

    // Non-string / null / empty / malformed
    assert.deepEqual(validateIsbn(null), { valid: false, clean: '', type: null });
    assert.deepEqual(validateIsbn(''), { valid: false, clean: '', type: null });
    assert.deepEqual(validateIsbn('12345'), { valid: false, clean: '', type: null });
    assert.deepEqual(validateIsbn('978-invalid-isbn'), { valid: false, clean: '', type: null });
  });

  await test('classifyQueryInputs: bare ISBN vs host echo vs hybrid vs text-only', () => {
    // Bare ISBN-10 string
    const bare10 = classifyQueryInputs('0-306-40615-2', null);
    assert.equal(bare10.isIsbnOnly, true);
    assert.equal(bare10.hasMeaningfulText, false);
    assert.equal(bare10.searchText, '');
    assert.equal(bare10.isbnVal.clean, '0306406152');

    // Bare ISBN-13 string
    const bare13 = classifyQueryInputs('9780306406157', null);
    assert.equal(bare13.isIsbnOnly, true);
    assert.equal(bare13.hasMeaningfulText, false);
    assert.equal(bare13.searchText, '');

    // Host-echoed ISBN matching candidate text
    const hostEcho = classifyQueryInputs(
      { isbn13: '9780306406157' },
      { buildSearchText: () => '978-0-306-40615-7' }
    );
    assert.equal(hostEcho.isIsbnOnly, true);
    assert.equal(hostEcho.hasMeaningfulText, false);
    assert.equal(hostEcho.searchText, '');

    // Hybrid query: valid ISBN with genuine title text
    const hybrid = classifyQueryInputs(
      { isbn13: '9780306406157', title: 'Dune' },
      { buildSearchText: () => 'Dune' }
    );
    assert.equal(hybrid.isIsbnOnly, false);
    assert.equal(hybrid.hasMeaningfulText, true);
    assert.equal(hybrid.searchText, 'Dune');

    // Text-only query
    const textOnly = classifyQueryInputs('Dune Frank Herbert', null);
    assert.equal(textOnly.isbnVal.valid, false);
    assert.equal(textOnly.isIsbnOnly, false);
    assert.equal(textOnly.hasMeaningfulText, true);
    assert.equal(textOnly.searchText, 'Dune Frank Herbert');

    // Empty query
    const empty = classifyQueryInputs('', null);
    assert.equal(empty.isIsbnOnly, false);
    assert.equal(empty.hasMeaningfulText, false);
  });

  await test('buildSearchUrl: wire page size, options object, column selection, and page param', () => {
    const base = 'https://libgen.bz';
    // Legacy numeric limit (res=15, full columns & objects, no page)
    const u1 = new URL(buildSearchUrl(base, 'dune', 15));
    assert.equal(u1.searchParams.get('res'), '15');
    assert.deepEqual(u1.searchParams.getAll('columns[]'), ['t', 'a', 's', 'y', 'p', 'i']);
    assert.deepEqual(u1.searchParams.getAll('objects[]'), ['f', 'e', 's', 'a', 'p', 'w']);
    assert.equal(u1.searchParams.has('page'), false);

    // Default limit uses WIRE_PAGE_SIZE = 25
    const uDefault = new URL(buildSearchUrl(base, 'dune'));
    assert.equal(uDefault.searchParams.get('res'), '25');

    // Options with columns=['i'] (ISBN targeted pass) defaults objects to ['f']
    const uIsbn = new URL(buildSearchUrl(base, '9780306406157', { columns: ['i'] }));
    assert.deepEqual(uIsbn.searchParams.getAll('columns[]'), ['i']);
    assert.deepEqual(uIsbn.searchParams.getAll('objects[]'), ['f']);
    assert.equal(uIsbn.searchParams.get('res'), '25');

    // Options with page=1 omits page parameter
    const uPage1 = new URL(buildSearchUrl(base, 'dune', { page: 1 }));
    assert.equal(uPage1.searchParams.has('page'), false);

    // Options with page=3 sets page parameter
    const uPage3 = new URL(buildSearchUrl(base, 'dune', { columns: ['t', 'a'], page: 3 }));
    assert.deepEqual(uPage3.searchParams.getAll('columns[]'), ['t', 'a']);
    assert.equal(uPage3.searchParams.get('page'), '3');
  });

  await test('languagesAgree & normalizeLanguageSubtag: 2-letter, 3-letter, dialects, and mismatches', () => {
    // Exact 2-letter matches
    assert.equal(languagesAgree('en', 'en'), true);
    assert.equal(languagesAgree('es', 'es'), true);

    // 3-letter to 2-letter mapping via ISO_639_2_TO_1
    assert.equal(normalizeLanguageSubtag('eng'), 'en');
    assert.equal(normalizeLanguageSubtag('fre'), 'fr');
    assert.equal(normalizeLanguageSubtag('spa'), 'es');
    assert.equal(languagesAgree('eng', 'en'), true);
    assert.equal(languagesAgree('en', 'eng'), true);

    // Subtag dialects
    assert.equal(normalizeLanguageSubtag('en-US'), 'en');
    assert.equal(normalizeLanguageSubtag('pt_BR'), 'pt');
    assert.equal(languagesAgree('en-US', 'en'), true);

    // Permissive missing metadata
    assert.equal(languagesAgree(undefined, 'en'), true);
    assert.equal(languagesAgree('en', undefined), true);
    assert.equal(languagesAgree(null, null), true);

    // Rejection of language mismatches
    assert.equal(languagesAgree('en', 'es'), false);
    assert.equal(languagesAgree('de', 'fr'), false);
  });

  await test('SearchBudgetTracker: deterministic clock injection, bounds clamping, and page prediction', () => {
    // Clamping bounds
    const lowTracker = new SearchBudgetTracker(500);
    assert.equal(lowTracker.budgetMs, 1000);
    const highTracker = new SearchBudgetTracker(25000);
    assert.equal(highTracker.budgetMs, 18000);
    const defaultTracker = new SearchBudgetTracker();
    assert.equal(defaultTracker.budgetMs, 15000);

    // Mock clock injection
    let mockTime = 10000;
    const tracker = new SearchBudgetTracker(5000, null, () => mockTime);
    assert.equal(tracker.remainingMs(), 5000);
    assert.equal(tracker.isExhausted(), false);
    assert.equal(tracker.canAffordNextPage(), true);

    // Advance clock by 3000ms
    mockTime += 3000;
    assert.equal(tracker.remainingMs(), 2000);
    assert.equal(tracker.isExhausted(), false);

    // Record page duration of 2200ms -> slowestPageMs = 2200
    tracker.recordPageDuration(2200);
    assert.equal(tracker.slowestPageMs, 2200);
    // Remaining is 2000 < slowestPageMs (2200) -> canAffordNextPage() returns false
    assert.equal(tracker.canAffordNextPage(), false);

    // Prediction against MIN_PAGE_BUDGET_MS: remaining <= MIN_PAGE_BUDGET_MS cannot afford next page
    assert.equal(MIN_PAGE_BUDGET_MS, 500);
    let minClock = 0;
    const minTracker = new SearchBudgetTracker(1000, null, () => minClock);
    assert.equal(minTracker.canAffordNextPage(), true);
    minClock = 500; // remaining is 500 <= MIN_PAGE_BUDGET_MS (500)
    assert.equal(minTracker.remainingMs(), 500);
    assert.equal(minTracker.canAffordNextPage(), false);

    // Clock reaches budget
    mockTime += 2000;
    assert.equal(tracker.remainingMs(), 0);
    assert.equal(tracker.isExhausted(), true);
    assert.equal(tracker.canAffordNextPage(), false);

    // Host signal abort sets remainingMs to 0
    const controller = new AbortController();
    const abortTracker = new SearchBudgetTracker(10000, controller.signal);
    assert.equal(abortTracker.canAffordNextPage(), true);
    controller.abort();
    assert.equal(abortTracker.remainingMs(), 0);
    assert.equal(abortTracker.isExhausted(), true);
    assert.equal(abortTracker.canAffordNextPage(), false);
  });

  // =========================================================================
  // 2. Fixture-driven Search Tests
  // =========================================================================
  suite('2. Fixture-driven Search Tests');

  const defaultCfg = {
    baseUrl: 'https://libgen.bz',
    settings: {
      fallbackMirrors: 'https://libgen.li, https://libgen.la',
      maxMirrorAttempts: 3,
    },
  };

  await test('Fixture: search-covers-on.html (with thumbnail images, offset = 1)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-covers-on.html', status: 200, url: 'https://libgen.bz/index.php' },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);

    const r0 = releases[0];
    assert.equal(r0.title, 'Dune');
    assert.equal(r0.author, 'Frank Herbert');
    assert.equal(r0.format, 'epub');
    assert.equal(r0.language, 'en');
    assert.equal(r0.sizeBytes, 1258291); // 1.2 MB
    assert.equal(r0.guid, '0123456789abcdef0123456789abcdef');
    assert.equal(r0.downloadUrl, 'https://libgen.bz/ads.php?md5=0123456789abcdef0123456789abcdef');

    const r1 = releases[1];
    assert.equal(r1.title, 'Dune Messiah');
    assert.equal(r1.author, 'Frank Herbert');
    assert.equal(r1.format, 'mobi');
    assert.equal(r1.language, 'en');
    assert.equal(r1.sizeBytes, 870400); // 850 KB
    assert.equal(r1.guid, 'abcdef0123456789abcdef0123456789');
  });

  await test('Fixture: search-covers-off.html (without thumbnail column, offset = 0)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-covers-off.html', status: 200, url: 'https://libgen.bz/index.php' },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Children of Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(releases[0].title, 'Children of Dune');
    assert.equal(releases[0].author, 'Frank Herbert');
    assert.equal(releases[0].format, 'epub');
    assert.equal(releases[0].sizeBytes, 1258291); // 1.2 MB in search-covers-off.html
    assert.equal(releases[0].guid, '11111111111111111111111111111111');
  });

  await test('Fixture: search-relative-links.html (resolves relative links against response URL)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-relative-links.html', status: 200, url: 'https://libgen.bz/index.php?req=dune' },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Heretics of Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(releases[0].title, 'Heretics of Dune');
    assert.equal(releases[0].guid, '22222222222222222222222222222222');
    assert.equal(releases[0].downloadUrl, 'https://libgen.bz/ads.php?md5=22222222222222222222222222222222');
    assert.equal(releases[1].title, 'Chapterhouse: Dune');
    assert.equal(releases[1].guid, '22222222222222222222222222222223');
    assert.equal(releases[1].downloadUrl, 'https://libgen.bz/ads.php?md5=22222222222222222222222222222223');
  });

  await test('Fixture: search-non-english.html (validates language mapping ru, es, fr)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-non-english.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 3);
    assert.equal(releases[0].language, 'ru');
    assert.equal(releases[1].language, 'es');
    assert.equal(releases[2].language, 'fr');
  });

  await test('Fixture: unsupported formats are terminal without mirror failover', async () => {
    const mockHost = createMockHost({
      routes: [
        { pattern: 'https://libgen.bz', handler: { fixture: 'search-unsupported-formats.html', status: 200 } },
        { pattern: 'https://libgen.li', handler: { status: 500, ok: false } },
      ],
    });
    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.deepEqual(releases, []);
    assert.equal(mockHost.calls.length, 1);
  });

  await test('Fixture: search-parser-rejection.html (fails over to next mirror, does NOT return [] on single broken mirror)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-parser-rejection.html', status: 200 },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(releases[0].title, 'Dune');
    assert.equal(mockHost.calls.length, 2);

    // If only one mirror configured and it has parser rejection -> throws 'parser_error', NOT []!
    const singleMirrorCfg = { baseUrl: 'https://libgen.bz' };
    const singleHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-parser-rejection.html', status: 200 },
        },
      ],
    });

    await assert.rejects(
      async () => await plugin.search({ title: 'Dune' }, singleMirrorCfg, singleHost),
      (err) => err?.kind === 'parser_error'
    );
  });

  await test('Fixture: search-unclosed-td.html (data-row detection catches unclosed tds, records parser error, fails over)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-unclosed-td.html', status: 200 },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(mockHost.calls.length, 2);
  });

  await test('Fixture: search-empty-marker-outside.html (ignores "nothing found" in footer when table has items)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-empty-marker-outside.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 1);
    assert.equal(releases[0].title, 'Dune');
    assert.equal(releases[0].guid, '88888888888888888888888888888888');
  });

  await test('Fixture: search-conflicting-evidence.html (parsed rows take precedence over paginator "no books found")', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-conflicting-evidence.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 1);
    assert.equal(releases[0].title, 'Dune (Special Edition)');
    assert.equal(releases[0].guid, '99999999999999999999999999999999');
  });

  await test('Fixture: empty-search.html (verified empty catalog returns [] when mirrors are checked)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'empty-search.html', status: 200 },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'empty-search.html', status: 200 },
        },
        {
          pattern: 'https://libgen.la',
          handler: { fixture: 'empty-search.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'NonexistentBook12345' }, defaultCfg, mockHost);
    assert.deepEqual(releases, []);
  });

  await test('Fixture: challenge-page.html (unrecognized page triggers failover to next mirror)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'challenge-page.html', status: 200 },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(mockHost.calls.length, 2);
  });

  await test('Fixture: captured-libgen-bz-search.html (realistic libgen.bz HTML search results parsing)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'captured-libgen-bz-search.html', status: 200, url: 'https://libgen.bz/index.php?req=Hyperion' },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Hyperion' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);

    const r0 = releases[0];
    assert.equal(r0.title, 'Hyperion (Hyperion Cantos)');
    assert.equal(r0.bookTitle, 'Hyperion (Hyperion Cantos)');
    assert.equal(r0.author, 'Dan Simmons');
    assert.equal(r0.format, 'epub');
    assert.equal(r0.language, 'en');
    assert.equal(r0.sizeBytes, 1887437); // Math.round(1.8 * 1024 * 1024)
    assert.equal(r0.guid, 'c1111111111111111111111111111111');
    assert.equal(r0.downloadUrl, 'https://libgen.bz/ads.php?md5=c1111111111111111111111111111111');

    const r1 = releases[1];
    assert.equal(r1.title, 'The Fall of Hyperion');
    assert.equal(r1.author, 'Dan Simmons');
    assert.equal(r1.format, 'pdf');
    assert.equal(r1.guid, 'c2222222222222222222222222222222');
  });

  await test('parseSearchResults: row with 33-hex hash is rejected and does not produce release candidate (P2)', () => {
    // Cover cell with class="cover" and img src ensuring correct 10-column alignment (offset = 1)
    const htmlWith33Hex = `
      <table id="tablelibgen">
        <tbody>
          <tr>
            <td class="cover"><img src="/covers/c0123456789abcdef0123456789abcdef.jpg" alt="cover"></td>
            <td><a href="/book/index.php?md5=0123456789abcdef0123456789abcdef0">Malformed 33-hex Book</a></td>
            <td>Dan Simmons</td>
            <td>Spectra</td>
            <td>1989</td>
            <td>English</td>
            <td>482</td>
            <td>1.8 MB</td>
            <td>epub</td>
            <td><a href="ads.php?md5=0123456789abcdef0123456789abcdef0">[1]</a></td>
          </tr>
        </tbody>
      </table>
    `;
    const { items, tableFound, rejectedCount, dataRowCount } = parseSearchResults(
      htmlWith33Hex,
      'https://libgen.bz/index.php'
    );
    assert.equal(tableFound, true);
    assert.equal(dataRowCount, 1);
    assert.equal(rejectedCount, 1, 'Row with 33-hex hash must be rejected due to MD5 boundary failure');
    assert.equal(items.length, 0, 'Must NOT create candidate from malformed 33-hex row');
  });

  await test('parseSearchResults: row with md5=<valid-hash>g is rejected and produces no candidate (P2)', () => {
    const validMd5 = '0123456789abcdef0123456789abcdef';
    const htmlWithTrailingG = `
      <table id="tablelibgen">
        <tbody>
          <tr>
            <td class="cover"><img src="/covers/c0123456789abcdef0123456789abcdef.jpg" alt="cover"></td>
            <td><a href="/book/index.php?md5=${validMd5}g">Book With Trailing G</a></td>
            <td>Author Name</td>
            <td>Publisher</td>
            <td>2020</td>
            <td>English</td>
            <td>350</td>
            <td>2.0 MB</td>
            <td>epub</td>
            <td><a href="ads.php?md5=${validMd5}g">[1]</a></td>
          </tr>
        </tbody>
      </table>
    `;
    const { items, tableFound, rejectedCount, dataRowCount } = parseSearchResults(
      htmlWithTrailingG,
      'https://libgen.bz/index.php'
    );
    assert.equal(tableFound, true);
    assert.equal(dataRowCount, 1);
    assert.equal(rejectedCount, 1, 'Row with <valid-hash>g must be rejected without prefix truncation');
    assert.equal(items.length, 0, 'Must NOT create candidate with truncated GUID from <hash>g');
  });

  await test('parseSearchResults: row with title hash A and mirror hash B is rejected (P2)', () => {
    const hashA = '0123456789abcdef0123456789abcdef';
    const hashB = 'fedcba9876543210fedcba9876543210';
    const htmlWithConflictingHashes = `
      <table id="tablelibgen">
        <tbody>
          <tr>
            <td class="cover"><img src="/covers/c0123456789abcdef0123456789abcdef.jpg" alt="cover"></td>
            <td><a href="/book/index.php?md5=${hashA}">Book Title A</a></td>
            <td>Author Name</td>
            <td>Publisher</td>
            <td>2020</td>
            <td>English</td>
            <td>350</td>
            <td>2.0 MB</td>
            <td>epub</td>
            <td><a href="ads.php?md5=${hashB}">[1]</a></td>
          </tr>
        </tbody>
      </table>
    `;
    const { items, tableFound, rejectedCount, dataRowCount } = parseSearchResults(
      htmlWithConflictingHashes,
      'https://libgen.bz/index.php'
    );
    assert.equal(tableFound, true);
    assert.equal(dataRowCount, 1);
    assert.equal(rejectedCount, 1, 'Row with conflicting title hash A and mirror hash B must be rejected');
    assert.equal(items.length, 0, 'Must NOT create candidate downloading B when title declares A');
  });

  // =========================================================================
  // 2b. Multi-Page Pagination & Two-Pass Orchestration Tests
  // =========================================================================
  suite('2b. Multi-Page Pagination & Two-Pass Orchestration Tests');

  function makeLibgenPageHtml(rows, paginatorHtml = '') {
    const trs = rows.map(r => `
      <tr>
        <td class="cover"><img src="/covers/c_${r.md5}.jpg" alt="cover"></td>
        <td><a href="/book/index.php?md5=${r.md5}">${r.title}</a></td>
        <td>${r.author || 'Author'}</td>
        <td>Publisher</td>
        <td>2020</td>
        <td>${r.language || 'English'}</td>
        <td>300</td>
        <td>${r.size || '1.0 MB'}</td>
        <td>${r.format || 'epub'}</td>
        <td><a href="ads.php?md5=${r.md5}">[1]</a></td>
      </tr>
    `).join('\n');
    return `<table id="tablelibgen"><tbody>${trs}</tbody></table>${paginatorHtml}`;
  }

  await test('Pagination: Unrecognized HTML failover across mirrors', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { text: '<html><body>Cloudflare Challenge</body></html>', status: 200 },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });
    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(mockHost.calls.length, 2);
  });

  await test('Pagination: Precedence of valid items over contradictory empty text across pages', async () => {
    // Page 1 has 25 Russian rows with contradictory "no books found" in paginator
    const page1Rows = Array.from({ length: 25 }, (_, i) => ({
      md5: `111111111111111111111111111111${String(i).padStart(2, '0')}`,
      title: `Russian Title ${i}`,
      language: 'Russian',
      format: 'epub',
    }));
    const page1Html = makeLibgenPageHtml(page1Rows, '<div id="paginator">no books found</div>');

    // Page 2 has 3 English rows
    const page2Rows = [
      { md5: '22222222222222222222222222222201', title: 'English Title 1', language: 'English', format: 'epub' },
      { md5: '22222222222222222222222222222202', title: 'English Title 2', language: 'English', format: 'epub' },
      { md5: '22222222222222222222222222222203', title: 'English Title 3', language: 'English', format: 'epub' },
    ];
    const page2Html = makeLibgenPageHtml(page2Rows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('page=2'),
          handler: { text: page2Html, status: 200 },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { text: page1Html, status: 200 },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { maxPages: 4 } };
    const releases = await plugin.search({ title: 'Dune', language: 'en' }, cfg, mockHost);
    assert.equal(releases.length, 3);
    assert.equal(releases[0].title, 'English Title 1');
    assert.equal(mockHost.calls.length, 2);
  });

  await test('Pagination: Full page without paginator markup continues walking', async () => {
    const page1Rows = Array.from({ length: 25 }, (_, i) => ({
      md5: `333333333333333333333333333333${String(i).padStart(2, '0')}`,
      title: `Page 1 Book ${i}`,
      language: 'English',
      format: 'epub',
    }));
    const page1Html = makeLibgenPageHtml(page1Rows); // completely no paginator markup

    const page2Rows = [
      { md5: '44444444444444444444444444444401', title: 'Page 2 Book 1', language: 'English', format: 'epub' },
    ];
    const page2Html = makeLibgenPageHtml(page2Rows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('page=2'),
          handler: { text: page2Html, status: 200 },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { text: page1Html, status: 200 },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { maxPages: 2 } };
    const releases = await plugin.search({ title: 'Dune', limit: 30 }, cfg, mockHost);
    assert.equal(releases.length, 26);
    assert.equal(mockHost.calls.length, 2);
  });

  await test('Budget: completed empty and filtered searches do not need another page budget', async () => {
    for (const fixture of ['empty-search.html', 'search-unsupported-formats.html']) {
      for (const elapsed of [8000, 15000]) {
        let now = 0;
        const host = createMockHost({
          defaultHandler: () => {
            now = elapsed;
            return { fixture, status: 200 };
          },
        });
        const cfg = {
          baseUrl: 'https://libgen.bz',
          settings: { fallbackMirrors: '', maxPages: 1, searchBudgetMs: 15000 },
          _nowFn: () => now,
        };
        assert.deepEqual(await plugin.search({ title: 'Dune' }, cfg, host), []);
        assert.equal(host.calls.length, 1);
      }
    }
  });

  await test('Budget: preemption before a required mirror retry throws timeout', async () => {
    let now = 0;
    const host = createMockHost({ defaultHandler: () => {
      now = 15000;
      return { status: 500, ok: false };
    } });
    const cfg = {
      baseUrl: 'https://libgen.bz',
      settings: { fallbackMirrors: 'https://libgen.li', searchBudgetMs: 15000 },
      _nowFn: () => now,
    };
    await assert.rejects(plugin.search({ title: 'Dune' }, cfg, host), err => err?.kind === 'timeout');
    assert.equal(host.calls.length, 1);
  });

  await test('Two-Pass: empty ISBN pass is not retried after text failure', async () => {
    const host = createMockHost({ defaultHandler: url => {
      const parsed = new URL(url);
      const isbn = parsed.searchParams.getAll('columns[]').includes('i');
      if (parsed.hostname === 'libgen.bz') {
        return isbn
          ? { fixture: 'empty-search.html', status: 200 }
          : { status: 500, ok: false };
      }
      assert.equal(isbn, false, 'Completed ISBN pass must not run on the fallback');
      return { fixture: 'search-covers-on.html', status: 200 };
    } });
    const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li' } };
    const releases = await plugin.search({ isbn13: '9780306406157', title: 'Dune', limit: 10 }, cfg, host);
    assert.equal(releases.length, 2);
    assert.equal(host.calls.length, 3);
  });

  await test('Error Classification: all parser failures retain parser_error, mixed failures remain unreachable', async () => {
    for (const mixed of [false, true]) {
      const host = createMockHost({ defaultHandler: url => {
        if (mixed && new URL(url).hostname === 'libgen.li') return { status: 500, ok: false };
        return { fixture: 'search-parser-rejection.html', status: 200 };
      } });
      const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li' } };
      await assert.rejects(plugin.search({ title: 'Dune' }, cfg, host), err => err?.kind === (mixed ? 'unreachable' : 'parser_error'));
      assert.equal(host.calls.length, 2);
    }
  });

  await test('Two-Pass: Terminal clean pass completion does NOT retry Mirror 2', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-off.html', status: 200 },
        },
      ],
    });

    const cfg = {
      baseUrl: 'https://libgen.bz',
      settings: { fallbackMirrors: 'https://libgen.li' },
    };

    // Mirror 1 completes with 2 releases (limit 10 requested)
    const releases = await plugin.search({ title: 'Dune', limit: 10 }, cfg, mockHost);
    assert.equal(releases.length, 2);
    // Must NOT have queried Mirror 2
    assert.equal(mockHost.calls.length, 1);
  });

  await test('Two-Pass: Terminal unsupported-only completion does NOT retry Mirror 2', async () => {
    // 4 pages of Russian books
    const russianRows = Array.from({ length: 25 }, (_, i) => ({
      md5: `555555555555555555555555555555${String(i).padStart(2, '0')}`,
      title: `Russian Book ${i}`,
      language: 'Russian',
      format: 'epub',
    }));
    const pageHtml = makeLibgenPageHtml(russianRows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { text: pageHtml, status: 200 },
        },
        {
          pattern: 'https://libgen.li',
          handler: { status: 500, ok: false },
        },
      ],
    });

    const cfg = {
      baseUrl: 'https://libgen.bz',
      settings: { fallbackMirrors: 'https://libgen.li', maxPages: 4 },
    };

    const releases = await plugin.search({ title: 'Dune', language: 'en' }, cfg, mockHost);
    assert.deepEqual(releases, []);
    // Must have walked 4 pages on Mirror 1 and NOT called Mirror 2
    assert.equal(mockHost.calls.length, 4);
    assert(mockHost.calls.every(c => c.url.startsWith('https://libgen.bz')));
  });

  await test('Mixed Status: ISBN empty + text unsupported-only cleanly returns []', async () => {
    // Pass 1: ISBN returns empty table
    const emptyHtml = makeLibgenPageHtml([], '<div id="paginator">no books found</div>');
    // Pass 2: 4 pages of Russian
    const russianRows = Array.from({ length: 25 }, (_, i) => ({
      md5: `666666666666666666666666666666${String(i).padStart(2, '0')}`,
      title: `Russian Edition ${i}`,
      language: 'Russian',
      format: 'epub',
    }));
    const russianHtml = makeLibgenPageHtml(russianRows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('columns%5B%5D=i'),
          handler: { text: emptyHtml, status: 200 },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { text: russianHtml, status: 200 },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { maxPages: 2 } };
    const query = { isbn13: '9780306406157', title: 'Dune', language: 'en' };
    const releases = await plugin.search(query, cfg, mockHost);
    assert.deepEqual(releases, []);
  });

  await test('Mixed Status: ISBN empty + text pass failure throws structured unreachable', async () => {
    const emptyHtml = makeLibgenPageHtml([], '<div id="paginator">no books found</div>');
    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('columns%5B%5D=i'),
          handler: { text: emptyHtml, status: 200 },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { status: 500, ok: false, text: 'Server Error' },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: '' } };
    const query = { isbn13: '9780306406157', title: 'Dune' };
    await assert.rejects(
      async () => await plugin.search(query, cfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'unreachable');
        return true;
      }
    );
  });

  await test('Two-Pass: Hybrid query where all mirrors fail ISBN pass throws structured error', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: /https:\/\/libgen\./,
          handler: { status: 500, ok: false, text: 'Server Error' },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li' } };
    const query = { isbn13: '9780306406157', title: 'Dune' };
    await assert.rejects(
      async () => await plugin.search(query, cfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'unreachable');
        return true;
      }
    );
  });

  await test('Error Classification: Network socket failure vs HTTP 500 vs 429 vs 504', async () => {
    // 1. Network error
    const netHost = { fetch: async () => { throw new Error('fetch failed'); } };
    await assert.rejects(
      plugin.search({ title: 'Dune' }, defaultCfg, netHost),
      err => err.kind === 'unreachable'
    );

    // 2. HTTP 500
    const err500Host = createMockHost({ defaultHandler: () => ({ status: 500, ok: false }) });
    await assert.rejects(
      plugin.search({ title: 'Dune' }, defaultCfg, err500Host),
      err => err.kind === 'unreachable' && err.message.includes('500')
    );

    // 3. HTTP 429 Throttled
    const err429Host = createMockHost({ defaultHandler: () => ({ status: 429, ok: false }) });
    await assert.rejects(
      plugin.search({ title: 'Dune' }, defaultCfg, err429Host),
      err => err.kind === 'throttled'
    );

    // 4. HTTP 504 Timeout
    const err504Host = createMockHost({ defaultHandler: () => ({ status: 504, ok: false }) });
    await assert.rejects(
      plugin.search({ title: 'Dune' }, defaultCfg, err504Host),
      err => err.kind === 'timeout'
    );
  });

  await test('Budget: Post-fetch budget preemption with zero candidates throws timeout', async () => {
    // Page 1 has 25 Russian rows (all rejected)
    const russianRows = Array.from({ length: 25 }, (_, i) => ({
      md5: `777777777777777777777777777777${String(i).padStart(2, '0')}`,
      title: `Russian Title ${i}`,
      language: 'Russian',
      format: 'epub',
    }));
    const page1Html = makeLibgenPageHtml(russianRows);

    let currentTime = 1000;
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: () => {
            // Advance clock past budget ceiling during fetch
            currentTime += 16000;
            return { text: page1Html, status: 200 };
          },
        },
      ],
    });

    const cfg = {
      baseUrl: 'https://libgen.bz',
      settings: { searchBudgetMs: 15000, maxPages: 4 },
      _nowFn: () => currentTime,
    };

    await assert.rejects(
      async () => await plugin.search({ title: 'Dune', language: 'en' }, cfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'timeout');
        return true;
      }
    );
  });

  await test('Budget: Pre-fetch budget preemption with zero candidates throws timeout', async () => {
    let calls = 0;
    const mockHost = { fetch: async () => { calls++; return { ok: true }; } };
    let clock = 1000;
    const cfg = {
      baseUrl: 'https://libgen.bz',
      settings: { searchBudgetMs: 5000 },
      _nowFn: () => {
        const val = clock;
        clock += 6000;
        return val;
      },
    };

    await assert.rejects(
      async () => await plugin.search({ title: 'Dune' }, cfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'timeout');
        return true;
      }
    );
    assert.equal(calls, 0);
  });

  await test('Pagination: Later-page failure with zero candidates retains error', async () => {
    const russianRows = Array.from({ length: 25 }, (_, i) => ({
      md5: `888888888888888888888888888888${String(i).padStart(2, '0')}`,
      title: `Russian Book ${i}`,
      language: 'Russian',
      format: 'epub',
    }));
    const page1Html = makeLibgenPageHtml(russianRows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('page=2'),
          handler: { status: 500, ok: false, text: 'Internal Server Error' },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { text: page1Html, status: 200 },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: '', maxPages: 3 } };
    await assert.rejects(
      async () => await plugin.search({ title: 'Dune', language: 'en' }, cfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'unreachable');
        return true;
      }
    );
  });

  await test('Pagination: Later-page failure with existing candidates returns partial results', async () => {
    const page1Rows = [
      { md5: '99999999999999999999999999999901', title: 'English Candidate 1', language: 'English', format: 'epub' },
      { md5: '99999999999999999999999999999902', title: 'English Candidate 2', language: 'English', format: 'epub' },
      ...Array.from({ length: 23 }, (_, i) => ({
        md5: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa${String(i).padStart(2, '0')}`,
        title: `Russian Book ${i}`,
        language: 'Russian',
        format: 'epub',
      })),
    ];
    assert.equal(page1Rows.length, 25);
    const page1Html = makeLibgenPageHtml(page1Rows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('page=2'),
          handler: { status: 500, ok: false, text: 'Internal Server Error' },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { text: page1Html, status: 200 },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { maxPages: 3 } };
    const releases = await plugin.search({ title: 'Dune', language: 'en' }, cfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(releases[0].title, 'English Candidate 1');
    assert.equal(releases[1].title, 'English Candidate 2');
  });

  await test('Two-Pass: Full workflow with deduplication across passes', async () => {
    // Pass 1 ISBN hits: 2 items (GUIDs 111... and 222...)
    const isbnRows = [
      { md5: '11111111111111111111111111111111', title: 'Dune (ISBN Match 1)', language: 'English', format: 'epub' },
      { md5: '22222222222222222222222222222222', title: 'Dune (ISBN Match 2)', language: 'English', format: 'epub' },
    ];
    const isbnHtml = makeLibgenPageHtml(isbnRows);

    // Pass 2 Text hits: 5 items (one duplicate 111..., four new: 333..., 444..., 555..., 666...)
    const textRows = [
      { md5: '11111111111111111111111111111111', title: 'Dune (Duplicate)', language: 'English', format: 'epub' },
      { md5: '33333333333333333333333333333333', title: 'Dune (Text Match 1)', language: 'English', format: 'epub' },
      { md5: '44444444444444444444444444444444', title: 'Dune (Text Match 2)', language: 'English', format: 'epub' },
      { md5: '55555555555555555555555555555555', title: 'Dune (Text Match 3)', language: 'English', format: 'epub' },
      { md5: '66666666666666666666666666666666', title: 'Dune (Text Match 4)', language: 'English', format: 'epub' },
    ];
    const textHtml = makeLibgenPageHtml(textRows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('columns%5B%5D=i'),
          handler: { text: isbnHtml, status: 200 },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { text: textHtml, status: 200 },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz' };
    const query = { isbn13: '9780306406157', title: 'Dune', limit: 5 };
    const releases = await plugin.search(query, cfg, mockHost);

    // Limit 5 requested: 2 from Pass 1 lead, followed by 3 unique from Pass 2
    assert.equal(releases.length, 5);
    assert.equal(releases[0].guid, '11111111111111111111111111111111');
    assert.equal(releases[1].guid, '22222222222222222222222222222222');
    assert.equal(releases[2].guid, '33333333333333333333333333333333');
    assert.equal(releases[3].guid, '44444444444444444444444444444444');
    assert.equal(releases[4].guid, '55555555555555555555555555555555');
  });

  await test('Two-Pass: ISBN-only bare string skips text pass', async () => {
    const isbnRows = [
      { md5: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01', title: 'ISBN Novel', language: 'English', format: 'epub' },
    ];
    const isbnHtml = makeLibgenPageHtml(isbnRows);

    let textPassCalled = false;
    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('columns%5B%5D=i'),
          handler: { text: isbnHtml, status: 200 },
        },
        {
          pattern: (url) => url.includes('columns%5B%5D=t'),
          handler: () => {
            textPassCalled = true;
            return { text: '', status: 200 };
          },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz' };
    const releases = await plugin.search('9780306406157', cfg, mockHost);
    assert.equal(releases.length, 1);
    assert.equal(releases[0].guid, 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01');
    assert.equal(textPassCalled, false, 'Text pass must NOT be called for bare ISBN query');
  });

  await test('Two-Pass: Cross-pass resilience preserves Pass 1 hits when Pass 2 fails', async () => {
    const isbnRows = [
      { md5: 'cccccccccccccccccccccccccccccc01', title: 'ISBN Edition 1', language: 'English', format: 'epub' },
      { md5: 'cccccccccccccccccccccccccccccc02', title: 'ISBN Edition 2', language: 'English', format: 'epub' },
    ];
    const isbnHtml = makeLibgenPageHtml(isbnRows);

    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('columns%5B%5D=i'),
          handler: { text: isbnHtml, status: 200 },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { status: 500, ok: false },
        },
        {
          pattern: 'https://libgen.li',
          handler: { status: 500, ok: false },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li' } };
    const query = { isbn13: '9780306406157', title: 'Dune', limit: 10 };
    const releases = await plugin.search(query, cfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(releases[0].guid, 'cccccccccccccccccccccccccccccc01');
    assert.equal(releases[1].guid, 'cccccccccccccccccccccccccccccc02');
  });

  await test('Cancellation: Caller cancellation is terminal and returns []', async () => {
    const page1Rows = Array.from({ length: 25 }, (_, i) => ({
      md5: `dddddddddddddddddddddddddddddd${String(i).padStart(2, '0')}`,
      title: `Book ${i}`,
      language: 'English',
      format: 'epub',
    }));
    const page1Html = makeLibgenPageHtml(page1Rows);

    const controller = new AbortController();
    const mockHost = createMockHost({
      routes: [
        {
          pattern: (url) => url.includes('page=2'),
          handler: () => {
            controller.abort();
            return { text: '', status: 200 };
          },
        },
        {
          pattern: 'https://libgen.bz',
          handler: { text: page1Html, status: 200 },
        },
      ],
    });

    const cfg = { baseUrl: 'https://libgen.bz', settings: { maxPages: 4 } };
    const releases = await plugin.search({ title: 'Dune', limit: 50 }, cfg, mockHost, controller.signal);
    assert.deepEqual(releases, [], 'Caller cancellation must return [] immediately without partial leakage');
  });

  // =========================================================================
  // 3. Multi-mirror Failover Tests
  // =========================================================================
  suite('3. Multi-mirror Failover Tests');


  // Models the pinned host: init.signal is not supported. A stuck request/body
  // must not hold up mirror failover. A ref'ed deadline ensures these tests settle.
  for (const stage of ['fetch', 'body']) {
    await test(`Search wait deadline: stuck ${stage} fails over without init.signal`, async () => {
      const calls = [];
      const html = fs.readFileSync(path.join(FIXTURES_DIR, 'search-covers-on.html'), 'utf8');
      const host = {
        async fetch(url, init) {
          assert.equal(init.signal, undefined);
          calls.push(url);
          if (calls.length === 1 && stage === 'fetch') return new Promise(() => {});
          return {
            ok: true, url,
            text: () => calls.length === 1 && stage === 'body'
              ? new Promise(() => {}) : Promise.resolve(html),
          };
        },
      };
      const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li', timeoutMs: 10 } };
      const releases = await plugin.search({ title: 'Dune' }, cfg, host);
      assert.equal(calls.length, 2);
      assert.equal(releases[0].guid, '0123456789abcdef0123456789abcdef');
    });

    await test(`Resolver wait deadline: stuck ${stage} fails over without init.signal`, async () => {
      const calls = [];
      const host = {
        async fetch(url, init) {
          assert.equal(init.signal, undefined);
          calls.push(url);
          if (calls.length === 1 && stage === 'fetch') return new Promise(() => {});
          return {
            ok: true, url, headers: { get: () => 'text/html' },
            text: () => calls.length === 1 && stage === 'body'
              ? new Promise(() => {}) : Promise.resolve('<a href="get.php?key=XYZ">GET</a>'),
          };
        },
      };
      const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li', timeoutMs: 10 } };
      const release = { guid: '0123456789abcdef0123456789abcdef', title: 'Dune', format: 'epub' };
      const resolved = await plugin.resolveFile(release, cfg, host);
      assert.equal(calls.length, 2);
      assert.equal(new URL(resolved.url).origin, 'https://libgen.li');
    });
  }

  await test('Caller cancellation interrupts an in-flight fetch without trying another mirror', async () => {
    for (const resolving of [false, true]) {
      const controller = new AbortController();
      const reason = new Error('Caller cancelled');
      let calls = 0;
      const host = { fetch() { calls++; controller.abort(reason); return new Promise(() => {}); } };
      const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li' } };
      const result = resolving
        ? plugin.resolveFile({ guid: '0123456789abcdef0123456789abcdef', title: 'Dune', format: 'epub' }, cfg, host, controller.signal)
        : plugin.search({ title: 'Dune' }, cfg, host, controller.signal);
      if (resolving) await assert.rejects(result, error => error === reason);
      else assert.deepEqual(await result, []);
      assert.equal(calls, 1);
    }
  });

  await test('Timed-out fetch discards its late response and observes late rejection', async () => {
    for (const rejects of [false, true]) {
      let finish;
      let cancelled = 0;
      const bounded = createBoundedRequestSignal(undefined, 5);
      try {
        const pending = bounded.run(() => new Promise((resolve, reject) => { finish = rejects ? reject : resolve; }));
        await assert.rejects(pending, { name: 'TimeoutError' });
        if (rejects) finish(new Error('Late host rejection'));
        else finish({ body: { cancel() { cancelled++; return Promise.resolve(); } } });
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(cancelled, rejects ? 0 : 1);
      } finally {
        bounded.cleanup();
      }
    }
  });

  await test('All stuck mirrors report timeout instead of an empty catalog', async () => {
    const host = createMockHost({ defaultHandler: () => new Promise(() => {}) });
    const cfg = { baseUrl: 'https://libgen.bz', settings: { fallbackMirrors: 'https://libgen.li', timeoutMs: 5 } };
    await assert.rejects(plugin.search({ title: 'Dune' }, cfg, host), error => error.kind === 'timeout');
    assert.equal(host.calls.length, 2);
  });

  await test('Failover: Mirror 1 fails (500), Mirror 2 succeeds', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { status: 500, ok: false, text: 'Internal Server Error' },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
    assert.equal(mockHost.calls.length, 2);
  });

  await test('Failover: Mirror 1 fails (429 Throttled), Mirror 2 succeeds', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { status: 429, ok: false, text: 'Too Many Requests' },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
  });

  await test('Failover: Mirror 1 fails (504 Gateway Timeout), Mirror 2 succeeds', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { status: 504, ok: false, text: 'Gateway Timeout' },
        },
        {
          pattern: 'https://libgen.li',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.equal(releases.length, 2);
  });

  await test('Failover: All mirrors 429 -> throws host.fail("throttled")', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: /https:\/\/libgen\./,
          handler: { status: 429, ok: false, text: 'Too Many Requests' },
        },
      ],
    });

    await assert.rejects(
      async () => await plugin.search({ title: 'Dune' }, defaultCfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'throttled');
        assert(err?.message.includes('429'));
        return true;
      }
    );
  });

  await test('Failover: All mirrors 504 -> throws host.fail("timeout")', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: /https:\/\/libgen\./,
          handler: { status: 504, ok: false, text: 'Gateway Timeout' },
        },
      ],
    });

    await assert.rejects(
      async () => await plugin.search({ title: 'Dune' }, defaultCfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'timeout');
        return true;
      }
    );
  });

  await test('Failover: All mirrors unreachable -> throws host.fail("unreachable")', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: /https:\/\/libgen\./,
          handler: { status: 500, ok: false, text: 'Server Error' },
        },
      ],
    });

    await assert.rejects(
      async () => await plugin.search({ title: 'Dune' }, defaultCfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'unreachable');
        return true;
      }
    );
  });

  await test('Verified empty search is terminal without mirror failover', async () => {
    const mockHost = createMockHost({
      routes: [
        { pattern: 'https://libgen.bz', handler: { fixture: 'empty-search.html', status: 200 } },
        { pattern: 'https://libgen.li', handler: { status: 500, ok: false } },
      ],
    });
    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert.deepEqual(releases, []);
    assert.equal(mockHost.calls.length, 1);
  });

  await test('Failover: request-local timeout (AbortError) on Mirror 1 fails over to Mirror 2', async () => {
    let mirror1Called = false;
    let mirror2Called = false;

    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: () => {
            mirror1Called = true;
            const err = new Error('The operation was aborted');
            err.name = 'AbortError';
            return err;
          },
        },
        {
          pattern: 'https://libgen.li',
          handler: () => {
            mirror2Called = true;
            return { fixture: 'search-covers-on.html', status: 200 };
          },
        },
      ],
    });

    const callerController = new AbortController();
    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost, callerController.signal);
    assert.equal(mirror1Called, true, 'Mirror 1 must have been called');
    assert.equal(mirror2Called, true, 'Mirror 2 must have been called after Mirror 1 timed out');
    assert.equal(releases.length, 2, 'Search must succeed on healthy mirror');
  });

  await test('Cancellation: AbortSignal aborted halts search immediately', async () => {
    const controller = new AbortController();
    controller.abort();

    const mockHost = createMockHost({
      routes: [
        {
          pattern: /https:\/\/libgen\./,
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const results = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost, controller.signal);
    assert.deepEqual(results, []);
    assert.equal(mockHost.calls.length, 0);
  });

  // =========================================================================
  // 4. Download Resolution (resolveFile) Tests
  // =========================================================================
  suite('4. Download Resolution (resolveFile) Tests');

  await test('resolveFile: rejects unsafe formats before fetching any target', async () => {
    for (const format of ['epub/../../outside', 'epub\\..\\outside', 'epub\r\nsecret', '.epub', 'EPUB', 'exe', '', null, undefined, {}]) {
      const host = createMockHost();
      await assert.rejects(plugin.resolveFile({ guid: 'a'.repeat(32), title: 'Book', format }, defaultCfg, host), /Unsupported or malformed/);
      assert.equal(host.calls.length, 0);
    }
  });

  await test('resolveFile: all supported formats produce safe names on binary and HTML paths', async () => {
    for (const format of namedExports.PREFERRED_EXTENSIONS) {
      for (const binary of [true, false]) {
        const host = createMockHost({ defaultHandler: () => ({ status: 200,
          headers: { 'content-type': binary ? 'application/octet-stream' : 'text/html' },
          text: '<a href="https://storage.example/book">GET</a>',
        }) });
        const file = await plugin.resolveFile({ guid: 'a'.repeat(32), title: '../Book\\Title', format }, defaultCfg, host);
        assert.equal(file.format, format);
        assert(file.fileName.endsWith(`.${format}`));
        assert(!/[/\\\r\n]/.test(file.fileName));
      }
    }
  });

  await test('resolveFile: rejects malformed GUID (not 32 hex chars)', async () => {
    const mockHost = createMockHost();
    const candidate = {
      guid: 'invalid-guid',
      title: 'Dune',
      format: 'epub',
      downloadUrl: 'https://libgen.bz/ads.php?md5=invalid-guid',
    };

    await assert.rejects(
      async () => await plugin.resolveFile(candidate, defaultCfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'error');
        assert(err?.message.includes('32-character hex MD5'));
        return true;
      }
    );
  });

  await test('resolveFile: rejects unsupported scheme (ftp://) and reconstructs safe mirror targets', async () => {
    const targetMd5 = '0123456789abcdef0123456789abcdef';
    const mockHost = createMockHost({
      routes: [
        {
          pattern: `https://libgen.bz/ads.php?md5=${targetMd5}`,
          handler: { fixture: 'mirror-page-direct.html', status: 200 },
        },
      ],
    });

    const candidate = {
      guid: targetMd5,
      title: 'Dune',
      format: 'epub',
      downloadUrl: `ftp://malicious.org/file.epub?md5=${targetMd5}`,
      sizeBytes: 1234567,
    };

    const resolved = await plugin.resolveFile(candidate, defaultCfg, mockHost);
    assert(resolved.url.startsWith('https://'));
    // Ensure ftp:// URL was never passed to mockHost.fetch
    assert(!mockHost.calls.some((c) => c.url.startsWith('ftp://')));
  });

  await test('resolveFile: handles binary direct content type (e.g. application/octet-stream)', async () => {
    const targetMd5 = '0123456789abcdef0123456789abcdef';
    const directUrl = `https://dl.libgen.bz/main/${targetMd5}`;
    const mockHost = createMockHost({
      routes: [
        {
          pattern: directUrl,
          handler: {
            status: 200,
            headers: { 'content-type': 'application/octet-stream' },
            text: 'BINARY_EPUB_CONTENT_PLACEHOLDER',
          },
        },
      ],
    });

    const candidate = {
      guid: targetMd5,
      title: 'Dune',
      bookTitle: 'Dune',
      format: 'epub',
      downloadUrl: directUrl,
      sizeBytes: 1258291,
    };

    const resolved = await plugin.resolveFile(candidate, defaultCfg, mockHost);
    assert.equal(resolved.url, directUrl);
    assert.equal(resolved.format, 'epub');
    assert.equal(resolved.fileName, 'Dune.epub');
    assert.equal(resolved.sizeBytes, 1258291);
    assert(resolved.headers?.['User-Agent'], 'Headers must contain User-Agent');
  });

  await test('resolveFile: AbortSignal aborted halts resolution immediately', async () => {
    const controller = new AbortController();
    controller.abort();

    const targetMd5 = '0123456789abcdef0123456789abcdef';
    const mockHost = createMockHost({
      routes: [
        {
          pattern: /https:\/\/libgen\./,
          handler: { fixture: 'mirror-page-direct.html', status: 200 },
        },
      ],
    });

    const candidate = {
      guid: targetMd5,
      title: 'Dune',
      format: 'epub',
      downloadUrl: `https://libgen.bz/ads.php?md5=${targetMd5}`,
      sizeBytes: 1258291,
    };

    await assert.rejects(
      async () => await plugin.resolveFile(candidate, defaultCfg, mockHost, controller.signal),
      /aborted/i
    );
    assert.equal(mockHost.calls.length, 0);
  });

  await test('Fixture: mirror-page-key.html (preserves query params like get.php?key=XYZ)', async () => {
    const targetMd5 = '0123456789abcdef0123456789abcdef';
    const adsUrl = `https://libgen.bz/ads.php?md5=${targetMd5}`;
    const mockHost = createMockHost({
      routes: [
        {
          pattern: adsUrl,
          handler: { fixture: 'mirror-page-key.html', status: 200, url: adsUrl },
        },
      ],
    });

    const candidate = {
      guid: targetMd5,
      title: 'Dune',
      format: 'epub',
      downloadUrl: adsUrl,
      sizeBytes: 1258291,
    };

    const resolved = await plugin.resolveFile(candidate, defaultCfg, mockHost);
    assert(resolved.url.includes('get.php'));
    assert(resolved.url.includes('key=XYZ123ABC'));
    assert(resolved.url.includes(`md5=${targetMd5}`));
    assert.equal(resolved.format, 'epub');
  });

  await test('Fixture: mirror-page-direct.html (resolves direct CDN/storage link)', async () => {
    const targetMd5 = '0123456789abcdef0123456789abcdef';
    const adsUrl = `https://libgen.bz/ads.php?md5=${targetMd5}`;
    const mockHost = createMockHost({
      routes: [
        {
          pattern: adsUrl,
          handler: { fixture: 'mirror-page-direct.html', status: 200, url: adsUrl },
        },
      ],
    });

    const candidate = {
      guid: targetMd5,
      title: 'Dune',
      format: 'epub',
      downloadUrl: adsUrl,
      sizeBytes: 1258291,
    };

    const resolved = await plugin.resolveFile(candidate, defaultCfg, mockHost);
    assert.equal(resolved.url, 'https://dl.libgen.bz/file.epub');
    assert.equal(resolved.fileName, 'Dune.epub');
    assert.equal(resolved.format, 'epub');
  });

  await test('Fixture: mirror-page-conflicting-md5.html (rejects conflicting MD5, falls back to next mirror)', async () => {
    const targetMd5 = '0123456789abcdef0123456789abcdef';
    const primaryAds = `https://libgen.bz/ads.php?md5=${targetMd5}`;
    const fallbackAds = `https://libgen.li/ads.php?md5=${targetMd5}`;

    const mockHost = createMockHost({
      routes: [
        {
          pattern: primaryAds,
          handler: { fixture: 'mirror-page-conflicting-md5.html', status: 200, url: primaryAds },
        },
        {
          pattern: fallbackAds,
          handler: { fixture: 'mirror-page-direct.html', status: 200, url: fallbackAds },
        },
      ],
    });

    const candidate = {
      guid: targetMd5,
      title: 'Dune',
      format: 'epub',
      downloadUrl: primaryAds,
      sizeBytes: 1258291,
    };

    const resolved = await plugin.resolveFile(candidate, defaultCfg, mockHost);
    assert.equal(resolved.url, 'https://dl.libgen.bz/file.epub');
    assert.equal(resolved.format, 'epub');
  });

  await test('resolveFile: redirected URL to conflicting MD5 on binary stream is rejected (P1)', async () => {
    const md5A = '0123456789abcdef0123456789abcdef';
    const md5B = 'fedcba9876543210fedcba9876543210';
    const singleMirrorCfg = {
      baseUrl: 'https://libgen.bz',
      settings: { fallbackMirrors: '', maxMirrorAttempts: 1 },
    };

    const mockHost = createMockHost({
      routes: [
        {
          pattern: `https://libgen.bz/ads.php?md5=${md5A}`,
          handler: {
            status: 200,
            url: `https://dl.libgen.bz/main/${md5B}.epub`, // Conflicting MD5 on redirected binary response
            headers: { 'content-type': 'application/epub+zip' },
            text: 'BINARY_DATA',
          },
        },
      ],
    });

    const candidate = {
      guid: md5A,
      title: 'Dune',
      format: 'epub',
      downloadUrl: `https://libgen.bz/ads.php?md5=${md5A}`,
      sizeBytes: 1258291,
    };

    await assert.rejects(
      async () => await plugin.resolveFile(candidate, singleMirrorCfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'error');
        assert(err?.message.includes('Redirected to conflicting identity'));
        return true;
      }
    );
  });

  await test('resolveFile: redirected URL to conflicting MD5 on HTML landing page is rejected (P1)', async () => {
    const md5A = '0123456789abcdef0123456789abcdef';
    const md5B = 'fedcba9876543210fedcba9876543210';
    const singleMirrorCfg = {
      baseUrl: 'https://libgen.bz',
      settings: { fallbackMirrors: '', maxMirrorAttempts: 1 },
    };

    const mockHost = createMockHost({
      routes: [
        {
          pattern: `https://libgen.bz/ads.php?md5=${md5A}`,
          handler: {
            status: 200,
            url: `https://libgen.bz/ads.php?md5=${md5B}`, // Redirected landing page for other book
            headers: { 'content-type': 'text/html' },
            text: `<html><body><a href="https://dl.libgen.bz/other-book.epub">GET</a></body></html>`,
          },
        },
      ],
    });

    const candidate = {
      guid: md5A,
      title: 'Dune',
      format: 'epub',
      downloadUrl: `https://libgen.bz/ads.php?md5=${md5A}`,
      sizeBytes: 1258291,
    };

    await assert.rejects(
      async () => await plugin.resolveFile(candidate, singleMirrorCfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'error');
        assert(err?.message.includes('Redirected to conflicting identity'));
        return true;
      }
    );
  });

  await test('resolveFile: redirected URL with duplicate MD5 parameters is rejected (P1)', async () => {
    const md5A = '0123456789abcdef0123456789abcdef';
    const singleMirrorCfg = {
      baseUrl: 'https://libgen.bz',
      settings: { fallbackMirrors: '', maxMirrorAttempts: 1 },
    };

    const mockHost = createMockHost({
      routes: [
        {
          pattern: `https://libgen.bz/ads.php?md5=${md5A}`,
          handler: {
            status: 200,
            url: `https://libgen.bz/ads.php?md5=${md5A}&md5=${md5A}`, // Tampered duplicate md5 params
            headers: { 'content-type': 'text/html' },
            text: `<html><body><a href="https://dl.libgen.bz/file.epub">GET</a></body></html>`,
          },
        },
      ],
    });

    const candidate = {
      guid: md5A,
      title: 'Dune',
      format: 'epub',
      downloadUrl: `https://libgen.bz/ads.php?md5=${md5A}`,
      sizeBytes: 1258291,
    };

    await assert.rejects(
      async () => await plugin.resolveFile(candidate, singleMirrorCfg, mockHost),
      (err) => {
        assert.equal(err?.kind, 'error');
        assert(err?.message.includes('Redirected to conflicting identity'));
        return true;
      }
    );
  });

  await test('Fixture: captured-libgen-li-landing.html (realistic libgen.li landing page link resolution)', async () => {
    const targetMd5 = 'c1111111111111111111111111111111';
    const adsUrl = `https://libgen.li/ads.php?md5=${targetMd5}`;
    const mockHost = createMockHost({
      routes: [
        {
          pattern: adsUrl,
          handler: { fixture: 'captured-libgen-li-landing.html', status: 200, url: adsUrl },
        },
      ],
    });

    const candidate = {
      guid: targetMd5,
      title: 'Hyperion',
      bookTitle: 'Hyperion',
      format: 'epub',
      downloadUrl: adsUrl,
      sizeBytes: 1887436,
    };

    const resolved = await plugin.resolveFile(candidate, defaultCfg, mockHost);
    assert(resolved.url.includes('get.php'));
    assert(resolved.url.includes(`md5=${targetMd5}`));
    assert(resolved.url.includes('key=K91A2B3C4D'));
    assert.equal(resolved.fileName, 'Hyperion.epub');
    assert.equal(resolved.format, 'epub');
    assert.equal(resolved.sizeBytes, 1887436);
  });

  await test('Full Pipeline: search -> host candidate sanitization -> resolveFile', async () => {
    const searchUrl = 'https://libgen.bz/index.php';
    const adsUrl = 'https://libgen.bz/ads.php?md5=0123456789abcdef0123456789abcdef';

    const mockHost = createMockHost({
      routes: [
        {
          pattern: searchUrl,
          handler: { fixture: 'search-covers-on.html', status: 200, url: searchUrl },
        },
        {
          pattern: adsUrl,
          handler: { fixture: 'mirror-page-direct.html', status: 200, url: adsUrl },
        },
      ],
    });

    // 1. Search phase
    const releases = await plugin.search({ title: 'Dune' }, defaultCfg, mockHost);
    assert(releases.length > 0, 'Search must return releases');

    // 2. Simulate BookOrbit Host Candidate Sanitization (strips plugin private properties)
    const rawCandidate = releases[0];
    const sanitizedCandidate = {
      guid: rawCandidate.guid,
      title: rawCandidate.title,
      bookTitle: rawCandidate.bookTitle,
      author: rawCandidate.author,
      format: rawCandidate.format,
      sizeBytes: rawCandidate.sizeBytes,
      downloadUrl: rawCandidate.downloadUrl,
      language: rawCandidate.language,
    };

    // 3. Resolve file phase
    const resolved = await plugin.resolveFile(sanitizedCandidate, defaultCfg, mockHost);
    assert(resolved.url.startsWith('https://'), 'Must resolve valid https URL');
    assert.equal(resolved.format, 'epub');
    assert.equal(resolved.fileName, 'Dune.epub');
    assert.equal(resolved.sizeBytes, 1258291);
    assert(resolved.headers?.['User-Agent'], 'Must return browser headers for host downloader');
    assert.equal(resolved.headers['User-Agent'], BROWSER_HEADERS['User-Agent']);
  });

  // =========================================================================
  // 5. Downloader simulation only: upstream structural validation is NOT verified.
  // =========================================================================
  suite('5. Mock Downloader Simulation (NOT upstream payload validation)');

  const testTmpDir = path.join(__dirname, '.test-tmp');
  const testBookdropDir = path.join(__dirname, '.test-bookdrop');

  function cleanupTestDirs() {
    if (fs.existsSync(testTmpDir)) fs.rmSync(testTmpDir, { recursive: true, force: true });
    if (fs.existsSync(testBookdropDir)) fs.rmSync(testBookdropDir, { recursive: true, force: true });
  }

  // Ensure clean directories before and after
  cleanupTestDirs();

  await test('MockDownloader: successfully downloads and publishes valid EPUB atomically to bookdrop', async () => {
    cleanupTestDirs();
    const epubBuf = createValidEpubBuffer();
    const fileUrl = 'https://dl.libgen.bz/main/dune.epub';

    const mockHost = createMockHost({
      routes: [
        {
          pattern: fileUrl,
          handler: {
            status: 200,
            buffer: epubBuf,
            headers: { 'content-type': 'application/epub+zip', 'content-length': String(epubBuf.length) },
          },
        },
      ],
    });

    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const resolvedFile = {
      url: fileUrl,
      headers: { 'User-Agent': BROWSER_HEADERS['User-Agent'] },
      fileName: 'Dune.epub',
      sizeBytes: epubBuf.length,
      format: 'epub',
    };

    const res = await downloader.downloadAndPublish(resolvedFile);
    assert.equal(res.success, true);
    assert.equal(res.filePath, path.join(testBookdropDir, 'Dune.epub'));
    assert(fs.existsSync(res.filePath), 'File must exist in bookdrop');
    assert(!fs.existsSync(path.join(testTmpDir, 'Dune.epub.tmp')), 'Temporary file must be cleaned up');
  });

  await test('MockDownloader: successfully downloads and publishes valid PDF atomically to bookdrop', async () => {
    cleanupTestDirs();
    const pdfBuf = createValidPdfBuffer();
    const fileUrl = 'https://dl.libgen.bz/main/dune.pdf';

    const mockHost = createMockHost({
      routes: [
        {
          pattern: fileUrl,
          handler: {
            status: 200,
            buffer: pdfBuf,
            headers: { 'content-type': 'application/pdf', 'content-length': String(pdfBuf.length) },
          },
        },
      ],
    });

    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const resolvedFile = {
      url: fileUrl,
      headers: { 'User-Agent': BROWSER_HEADERS['User-Agent'] },
      fileName: 'Dune.pdf',
      sizeBytes: pdfBuf.length,
      format: 'pdf',
    };

    const res = await downloader.downloadAndPublish(resolvedFile);
    assert.equal(res.success, true);
    assert(fs.existsSync(path.join(testBookdropDir, 'Dune.pdf')));
    assert(!fs.existsSync(path.join(testTmpDir, 'Dune.pdf.tmp')));
  });

  await test('MockDownloader: successfully downloads and publishes valid MOBI atomically to bookdrop', async () => {
    cleanupTestDirs();
    const mobiBuf = createValidMobiBuffer();
    const fileUrl = 'https://dl.libgen.bz/main/dune.mobi';

    const mockHost = createMockHost({
      routes: [
        {
          pattern: fileUrl,
          handler: {
            status: 200,
            buffer: mobiBuf,
            headers: { 'content-type': 'application/x-mobipocket-ebook', 'content-length': String(mobiBuf.length) },
          },
        },
      ],
    });

    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const resolvedFile = {
      url: fileUrl,
      headers: { 'User-Agent': BROWSER_HEADERS['User-Agent'] },
      fileName: 'Dune.mobi',
      sizeBytes: mobiBuf.length,
      format: 'mobi',
    };

    const res = await downloader.downloadAndPublish(resolvedFile);
    assert.equal(res.success, true);
    assert(fs.existsSync(path.join(testBookdropDir, 'Dune.mobi')));
    assert(!fs.existsSync(path.join(testTmpDir, 'Dune.mobi.tmp')));
  });

  await test('MockDownloader: successfully downloads and publishes valid CBZ atomically to bookdrop', async () => {
    cleanupTestDirs();
    const cbzBuf = createValidCbzBuffer();
    const fileUrl = 'https://dl.libgen.bz/main/dune.cbz';

    const mockHost = createMockHost({
      routes: [
        {
          pattern: fileUrl,
          handler: {
            status: 200,
            buffer: cbzBuf,
            headers: { 'content-type': 'application/vnd.comicbook+zip', 'content-length': String(cbzBuf.length) },
          },
        },
      ],
    });

    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const resolvedFile = {
      url: fileUrl,
      headers: { 'User-Agent': BROWSER_HEADERS['User-Agent'] },
      fileName: 'Dune.cbz',
      sizeBytes: cbzBuf.length,
      format: 'cbz',
    };

    const res = await downloader.downloadAndPublish(resolvedFile);
    assert.equal(res.success, true);
    assert(fs.existsSync(path.join(testBookdropDir, 'Dune.cbz')));
    assert(!fs.existsSync(path.join(testTmpDir, 'Dune.cbz.tmp')));
  });

  await test('MockDownloader: truncated stream fails transport completeness and does not publish to bookdrop', async () => {
    cleanupTestDirs();
    const fileUrl = 'https://dl.libgen.bz/main/truncated.epub';
    const partialBuf = Buffer.from('PK\x03\x04partial-truncated-data');

    const mockHost = createMockHost({
      routes: [
        {
          pattern: fileUrl,
          handler: {
            status: 200,
            buffer: partialBuf,
            // Header claims 500000 bytes, but body only delivers partialBuf.length bytes
            headers: { 'content-type': 'application/epub+zip', 'content-length': '500000' },
          },
        },
      ],
    });

    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const resolvedFile = {
      url: fileUrl,
      headers: { 'User-Agent': BROWSER_HEADERS['User-Agent'] },
      fileName: 'Truncated.epub',
      sizeBytes: 500000,
      format: 'epub',
    };

    await assert.rejects(
      async () => await downloader.downloadAndPublish(resolvedFile),
      /Transport incomplete: expected 500000 bytes/
    );

    assert(!fs.existsSync(path.join(testBookdropDir, 'Truncated.epub')), 'Must NOT publish truncated file');
    assert(!fs.existsSync(path.join(testTmpDir, 'Truncated.epub.tmp')), 'Must clean up temporary staging file');
  });

  await test('MockDownloader: HTML interstitial under application/octet-stream fails validation and is rejected', async () => {
    cleanupTestDirs();
    const fileUrl = 'https://dl.libgen.bz/main/blocked-ip.epub';

    const mockHost = createMockHost({
      routes: [
        {
          pattern: fileUrl,
          handler: {
            fixture: 'host-downloader-octet-stream-html.html',
            status: 200,
            headers: { 'content-type': 'application/octet-stream' },
          },
        },
      ],
    });

    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const resolvedFile = {
      url: fileUrl,
      headers: { 'User-Agent': BROWSER_HEADERS['User-Agent'] },
      fileName: 'Blocked.epub',
      sizeBytes: 1000,
      format: 'epub',
    };

    await assert.rejects(
      async () => await downloader.downloadAndPublish(resolvedFile),
      /Anti-bot HTML interstitial detected in payload/
    );

    assert(!fs.existsSync(path.join(testBookdropDir, 'Blocked.epub')), 'Must NOT publish interstitial HTML to bookdrop');
    assert(!fs.existsSync(path.join(testTmpDir, 'Blocked.epub.tmp')), 'Must clean up temporary staging file');
  });

  await test('MockDownloader: missing forwarded headers fails host contract', async () => {
    cleanupTestDirs();
    const mockHost = createMockHost();
    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const badResolvedFile = {
      url: 'https://dl.libgen.bz/file.epub',
      headers: {}, // Missing User-Agent
      fileName: 'BadHeaders.epub',
      format: 'epub',
    };

    await assert.rejects(
      async () => await downloader.downloadAndPublish(badResolvedFile),
      /Missing forwarded User-Agent header/
    );
    assert.equal(mockHost.calls.length, 0, 'No HTTP request should be dispatched when headers contract is violated');
  });

  await test('MockDownloader: forbidden CR/LF/NUL in forwarded headers throws security error', async () => {
    cleanupTestDirs();
    const mockHost = createMockHost();
    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const crlfResolvedFile = {
      url: 'https://dl.libgen.bz/file.epub',
      headers: {
        'User-Agent': 'ValidAgent',
        'X-Injected': 'foo\r\nSet-Cookie: evil=1',
      },
      fileName: 'Injected.epub',
      format: 'epub',
    };

    await assert.rejects(
      async () => await downloader.downloadAndPublish(crlfResolvedFile),
      /Forbidden CR\/LF\/NUL character in header/
    );
    assert.equal(mockHost.calls.length, 0);
  });

  await test('MockDownloader: filters reserved headers (Content-Length, Host, Connection) while forwarding User-Agent and Cookie', async () => {
    cleanupTestDirs();
    const epubBuf = createValidEpubBuffer();
    const fileUrl = 'https://dl.libgen.bz/main/filtered-headers.epub';

    let capturedHeaders = null;
    const mockHost = createMockHost({
      routes: [
        {
          pattern: fileUrl,
          handler: (reqUrl, options) => {
            capturedHeaders = options?.headers || {};
            return {
              status: 200,
              buffer: epubBuf,
              headers: { 'content-type': 'application/epub+zip', 'content-length': String(epubBuf.length) },
            };
          },
        },
      ],
    });

    const downloader = createMockHostDownloader({
      bookdropDir: testBookdropDir,
      tempDir: testTmpDir,
      host: mockHost,
    });

    const resolvedFile = {
      url: fileUrl,
      headers: {
        'User-Agent': 'BookOrbitTestAgent/1.0',
        'Cookie': 'covers=on',
        'Host': 'spoofed.libgen.bz',
        'Content-Length': '999999',
        'Connection': 'close',
      },
      fileName: 'FilteredHeaders.epub',
      format: 'epub',
    };

    const res = await downloader.downloadAndPublish(resolvedFile);
    assert.equal(res.success, true);
    assert.equal(capturedHeaders['User-Agent'], 'BookOrbitTestAgent/1.0');
    assert.equal(capturedHeaders['Cookie'], 'covers=on');
    assert.equal(capturedHeaders['Accept'], '*/*');
    // Reserved headers must be stripped
    assert.equal(capturedHeaders['Host'], undefined);
    assert.equal(capturedHeaders['Content-Length'], undefined);
    assert.equal(capturedHeaders['Connection'], undefined);
  });

  // Final cleanup of test directories
  cleanupTestDirs();

  // =========================================================================
  // 6. Connection Test (test)
  // =========================================================================
  suite('6. Connection Test (test)');

  await test('test: succeeds on valid mirror with tablelibgen', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'search-covers-on.html', status: 200 },
        },
      ],
    });

    const res = await plugin.test(defaultCfg, mockHost);
    assert.equal(res.success, true);
    assert(res.indexerName.includes('Library Genesis'));
  });

  await test('test: fails on missing baseUrl', async () => {
    const mockHost = createMockHost();
    const res = await plugin.test({ baseUrl: '' }, mockHost);
    assert.equal(res.success, false);
    assert(res.error.includes('No Base URL'));
  });

  await test('test: fails on non-http/https protocol baseUrl', async () => {
    const mockHost = createMockHost();
    const res = await plugin.test({ baseUrl: 'ftp://libgen.bz' }, mockHost);
    assert.equal(res.success, false);
    assert(res.error.includes('Invalid protocol'));
    assert.equal(mockHost.calls.length, 0);
  });

  await test('test: fails on non-ok response', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { status: 503, ok: false, text: 'Service Unavailable' },
        },
      ],
    });

    const res = await plugin.test(defaultCfg, mockHost);
    assert.equal(res.success, false);
    assert(res.error.includes('503'));
  });

  await test('test: fails on unrecognized page (neither table nor form)', async () => {
    const mockHost = createMockHost({
      routes: [
        {
          pattern: 'https://libgen.bz',
          handler: { fixture: 'challenge-page.html', status: 200 },
        },
      ],
    });

    const res = await plugin.test(defaultCfg, mockHost);
    assert.equal(res.success, false);
    assert(res.error.includes('not a recognized libgen.li'));
  });

  // =========================================================================
  // Summary Reporting
  // =========================================================================
  const duration = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log('\n======================================================');
  console.log(`Verification Suite Results (${duration}s):`);
  console.log(`  Total:  ${totalTests}`);
  console.log(`  Passed: ${passedTests}`);
  console.log(`  Failed: ${failedTests}`);
  console.log('======================================================');

  if (failedTests > 0) {
    console.error(`\n${failedTests} test(s) failed:`);
    for (const f of failures) {
      console.error(`  - ${f.name}: ${f.error?.message || f.error}`);
    }
    process.exit(1);
  } else {
    console.log('\nAll tests passed successfully! ✨');
    process.exit(0);
  }
}

// Execute tests if executed directly
runAllTests().catch((err) => {
  console.error('Fatal test runner exception:', err);
  process.exit(1);
});
