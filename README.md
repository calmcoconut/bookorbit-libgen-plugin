# Libgen plugin for BookOrbit

Search Library Genesis and resolve ebook download links from `libgen.li` /
`libgen.bz`-family mirrors. This plugin runs in **BookOrbit**, not in BookBot's
acquisition pipeline.

The plugin needs no credentials or extra dependencies. It supports EPUB, MOBI,
PDF, AZW3, and CBZ results. Mirrors using the `libgen.rs` / `libgen.is` layout
aren't supported.

[`index.mjs`](index.mjs) is the entry point: a standalone ECMAScript module
exporting plugin `libgen`, version `0.1.0`, for BookOrbit API v1.

**Not yet verified for production use:** passing the offline tests doesn't prove
that BookOrbit safely validates files before publishing them. See
[host compatibility and release status](#host-compatibility-and-release-status)
for the remaining work.

## Configuration

Set these fields in BookOrbit, not in BookBot's configuration:

| Field | Default | What it controls |
| --- | --- | --- |
| `baseUrl` | `https://libgen.bz` | The primary mirror. It must use the `libgen.li`-family layout. |
| `settings.fallbackMirrors` | `https://libgen.li, https://libgen.la, https://libgen.gl` | Comma-separated backup mirrors, tried in order. |
| `settings.maxMirrorAttempts` | `3` | The maximum number of configured mirrors to try, including the primary. Clamped to 1–10. |
| `settings.timeoutMs` | `8000` | How long to wait for each search or resolution attempt, in milliseconds. Must be positive. |

These defaults come from the plugin's metadata; they don't guarantee that a
mirror is currently online. BookOrbit must pass the URLs to the plugin—the
plugin doesn't fill in missing URLs itself.

The plugin keeps only each mirror's origin (scheme, hostname, and port), removes
duplicates, and limits the list to `maxMirrorAttempts`. With the defaults above,
a search can try the primary mirror and the first two backups, not all four.

## How it works

### Search

The plugin tries mirrors in order and returns the first usable set of results.
It doesn't combine results from different mirrors. If a mirror fails, returns
an unrecognized page, has no results, or offers only unsupported formats, the
plugin moves on to the next one.

If no mirror produces usable results, the plugin returns an empty list when at
least one mirror returned a recognized empty result or only unsupported formats.
Otherwise, it reports `throttled`, `timeout`, or `unreachable`, depending on the
failures. Caller cancellation stops further attempts and returns an empty list.

### Download links

Each release must have a 32-character hexadecimal MD5 GUID. The plugin first
tries the candidate's HTTP(S) download URL if it identifies that MD5 without
conflicting identifiers. It then tries the configured mirrors' `/ads.php?md5=...`
landing pages as needed.

A successful resolution returns a URL, request headers, filename, format, and
reported size. **It doesn't verify the file's contents or checksum.** Content
types and landing-page links help locate a download; they aren't proof that the
file is valid.

The plugin doesn't save or publish files. However, its GET requests can transfer
file bytes before a response is classified and discarded. The amount depends
on how BookOrbit buffers and cancels requests.

### Connection test

BookOrbit's connection test checks only whether the primary mirror returns a
recognized search page. It doesn't check backup mirrors or resolve a book. It
also relies on BookOrbit's request limits rather than the plugin's `timeoutMs`.

## Timeouts and cancellation

By default, the plugin waits up to 8 seconds per search mirror or resolution
target. That budget covers both the request and reading the HTML response body.
When time runs out, the plugin moves on; if the caller cancels, it stops trying
new targets. It handles late failures and makes a best-effort attempt to discard
unused responses.

**A timeout stops the plugin waiting, not necessarily the network request.**
BookOrbit controls network access and cancellation. A request or body read may
remain active until the host's request limit or the caller's deadline, so
fallback requests can overlap. All requests go through `host.fetch`.

`maxMirrorAttempts` limits the configured mirror list, not the total number of
resolution targets: resolution may also try the candidate's validated URL.

## Run the offline tests

Install Node.js 22 (the CI version), then run this from the repository root:

```bash
node plugins/libgen/verify.mjs
```

The repository's `bash scripts/check.sh` and CI also run this suite. No
credentials or network access are needed. Tests use fixtures and temporary
simulation directories, never a real library or watched bookdrop.

Live searches and file-download tests require separate operator authorization.

## Host compatibility and release status

The host behavior documented here is based on source inspection at BookOrbit
commit [`c19f728ba4f2894b14048b1f6ef402bc5e5635a3`](https://github.com/bookorbit/bookorbit/commit/c19f728ba4f2894b14048b1f6ef402bc5e5635a3).
This is a source reference, not a verified BookOrbit release version or evidence
of a passing integration test against the real host.

At that commit:

- [`packages/plugin-api/src/index.ts`](https://github.com/bookorbit/bookorbit/blob/c19f728ba4f2894b14048b1f6ef402bc5e5635a3/packages/plugin-api/src/index.ts)
  supports `PluginReleaseFile.headers`, but `PluginRequestInit` has no `signal`.
- [`plugin-host.ts`](https://github.com/bookorbit/bookorbit/blob/c19f728ba4f2894b14048b1f6ef402bc5e5635a3/server/src/modules/book-request/indexers/plugins/plugin-host.ts)
  sanitizes resolved-file headers and enforces a 25-second request limit along
  with the caller's deadline. It doesn't use `init.signal`.
- [`direct-download.service.ts`](https://github.com/bookorbit/bookorbit/blob/c19f728ba4f2894b14048b1f6ef402bc5e5635a3/server/src/modules/book-request/fulfillment/direct-download.service.ts)
  forwards source headers, strips credentials on cross-origin redirects, checks
  transfer completeness, and writes to private staging. It does **not** validate
  each file format's structure or use an atomic temporary-file rename. Publishing
  to Book Dock happens in a separate import stage.

### What still blocks production readiness

Before production use, the real BookOrbit pipeline must be shown to validate
files *before* publishing them to a watched directory. If that validation is
missing, it needs to be implemented upstream. Coverage must include:

- EPUB ZIP structure, `mimetype`, and `container.xml`.
- PDF cross-reference and trailer structure.
- MOBI/AZW3 records and readable images inside CBZ archives.
- Corrupt or encrypted containers and HTML disguised as binary data.
- Truncated transfers and streams that don't finish cleanly.

A plugin that only returns a URL can't provide this guarantee. This repository
doesn't maintain BookOrbit's runtime code.

The offline suite tests this plugin and a mock downloader—not the real BookOrbit
downloader. The mock's signature checks, header handling, and temporary-file
rename don't prove that the upstream pipeline is safe. Even when all tests pass,
`HOST_CONTRACT.payloadValidationVerified` remains `false`.
