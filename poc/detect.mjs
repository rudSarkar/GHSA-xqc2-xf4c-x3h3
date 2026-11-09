/**
 * "Is my application affected by GHSA-xqc2-xf4c-x3h3?"
 *
 * Two independent checks, because they answer different questions:
 *
 *   --scan [dir]   Which copies of the RSC runtime are installed, and is the fix
 *                  in them? This is the authoritative answer on exposure. It
 *                  keys on code signatures rather than version numbers, so it
 *                  also covers the copies a framework vendors (Next.js
 *                  precompiles React into next/dist/compiled, where
 *                  `npm ls react-server-dom-webpack` finds nothing).
 *
 *   --url <url>    Does a live response actually desynchronise? This is the
 *                  answer on *exploitability* for one endpoint, and the only one
 *                  of the two that tells you the "rare case" precondition is
 *                  met. Read-only: it fetches and parses, nothing else.
 *
 *   --crawl <url>  The same check across one origin, because the precondition
 *                  lives on whichever route happens to return binary - usually
 *                  not the one you would check by hand.
 *
 * Usage:
 *   node poc/detect.mjs --scan .
 *   node poc/detect.mjs --url http://localhost:3000/rsc?full=1
 *   node poc/detect.mjs --url https://app.example.com/some/page --rsc
 *   node poc/detect.mjs --crawl https://app.example.com --rsc --pages 40
 *
 * Crawl options: --pages 25  --depth 2  --delay 250  --ignore-robots
 *                --urls <file>   check exactly these routes (one per line)
 *                --no-sitemap    do not seed from the sitemap
 * Shared:        --rsc  --header 'K: V'  --method  --body
 *
 * The crawler is read-only and sends only GETs that a browser would send. It is
 * single-origin, capped, serialised with a delay, and honours robots.txt by
 * default - it is for an app you own or are authorised to test, not for scanning
 * hosts at large.
 */
import {readdir, readFile, stat} from 'node:fs/promises';
import {join, relative, resolve, basename} from 'node:path';
import {parseRows, formatRows, preview} from '../src/wire.mjs';

const args = parseArgs(process.argv.slice(2));

// Code the 19.0.9 / 19.1.10 / 19.2.9 / 19.3.1 fix introduced.
//
// These are deliberately *string literals* rather than error messages or
// identifier names. A framework that re-bundles React renames identifiers and
// may strip error messages - Next.js keeps the detach check but drops the
// "Cannot transport a detached buffer" message - whereas a property-name string
// has to survive for the code to work. Measured across the standalone packages
// and Next.js's four vendored copies, each of these appears in 0/N builds before
// the fix and N/N after it.
const SIGNATURES = {
  server: {
    // supportsArrayBufferDetached = hasOwnProperty.call(ArrayBuffer.prototype, 'detached')
    // The root-cause fix: a view that does not span its buffer is copied, and a
    // detached buffer raises instead of being written as a zero-length body
    // behind a header that already declared its length.
    needle: /["']detached["']/,
    label: 'server (Flight renderer)',
  },
  client: {
    // createModel() / loadServerReference(): `key === 'then'`.
    // The hardening that stops a forged chunk from making a deserialized object
    // thenable, shipped alongside the Response-behind-a-Symbol change.
    needle: /["']then["']/,
    label: 'client (Flight consumer)',
  },
};

// Strings that identify a file as a Flight build regardless of version, and
// which half of the protocol it implements. Both survive minification, so they
// work on the production builds that actually ship. They are what lets the scan
// ignore the dozen or so re-export shims that sit beside the real builds.
const FLIGHT_MARKERS = {
  server: 'Existence of byteLengthOfChunk should have',
  client: 'in the React Server Consumer Manifest',
};

const NOT_FLIGHT_HELP =
  '  This does not look like an RSC payload. Point --url at the payload itself,\n' +
  '  not the HTML page. How to ask for it is framework-specific; --rsc sends\n' +
  '  `Accept: text/x-component` and `RSC: 1`, which is the convention, and the\n' +
  '  Network tab of a working app will show you the real request.';

// Only useful when a version is actually readable; the signature check is what
// decides the verdict.
const AFFECTED_RANGES = [
  [[19, 0, 0], [19, 0, 8]],
  [[19, 1, 0], [19, 1, 9]],
  [[19, 2, 0], [19, 2, 8]],
  [[19, 3, 0], [19, 3, 0]],
];

/**
 * Invoked at the very bottom of the file rather than here. Running the dispatch
 * before the declarations below are initialized is how `const`s further down the
 * module end up in their temporal dead zone, which surfaces as a confusing
 * "cannot access X before initialization" from deep inside a helper.
 */
async function main() {
  if (!args.scan && !args.url && !args.crawl) {
    console.log(
      'Pass --scan [dir], --url <url> and/or --crawl <url>. See the header of this file.',
    );
    return 2;
  }
  let worst = 0;
  if (args.scan) worst = Math.max(worst, await scan(resolve(args.scan === true ? '.' : args.scan)));
  if (args.url) worst = Math.max(worst, await probe(args.url));
  if (args.crawl) worst = Math.max(worst, await crawl(args.crawl));
  return worst;
}

// ------------------------------------------------------------------ dependency

async function scan(root) {
  banner(`Installed RSC runtimes under ${root}`);

  const candidates = await findCandidates(root);
  if (candidates.length === 0) {
    console.log(
      '  No RSC runtime found.\n\n' +
        '  That means this tree has no react-server-dom-* package and no vendored\n' +
        '  copy that this scan recognises. An app with no RSC runtime is not\n' +
        "  affected - but if you expected one, check you are scanning the right\n" +
        '  directory and that dependencies are installed.',
    );
    return 0;
  }

  let affected = 0;
  for (const candidate of candidates) {
    const results = [];
    for (const [kind, {needle, label}] of Object.entries(SIGNATURES)) {
      const files = candidate.files.filter(f => f.kind === kind || f.kind === 'both');
      if (files.length === 0) continue;
      let patched = 0;
      for (const file of files) {
        if (needle.test(await readFile(file.path, 'utf8'))) patched++;
      }
      results.push({kind, label, total: files.length, patched});
    }

    const anyAffected = results.some(r => r.patched === 0);
    const mixed = results.some(r => r.patched > 0 && r.patched < r.total);
    if (anyAffected || mixed) affected++;

    console.log(
      `\n  ${anyAffected ? 'AFFECTED' : mixed ? 'MIXED   ' : 'patched '} ${candidate.name}` +
        (candidate.version ? ` ${candidate.version}` : ' (version not declared)'),
    );
    console.log(`           ${relative(root, candidate.dir) || '.'}`);
    for (const r of results) {
      console.log(
        `           ${r.label.padEnd(26)} fix present in ${r.patched}/${r.total} builds` +
          (r.patched === 0 ? '  <-- vulnerable' : ''),
      );
    }
    if (candidate.version) {
      const byVersion = isAffectedVersion(candidate.version);
      if (byVersion !== null && byVersion !== anyAffected) {
        console.log(
          `           note: the declared version says ${
            byVersion ? 'affected' : 'patched'
          } but the code says otherwise - trust the code`,
        );
      }
    }
  }

  console.log(
    affected
      ? `\n  ${affected} of ${candidates.length} runtime copies are missing the fix. Upgrade to\n` +
          '  19.0.9 / 19.1.10 / 19.2.9 / 19.3.1 or later. For a framework that vendors\n' +
          '  React (Next.js), upgrade the framework - bumping react alone will not\n' +
          '  replace its precompiled copy.'
      : `\n  All ${candidates.length} runtime copies carry the fix.`,
  );
  return affected ? 1 : 0;
}


/**
 * Finds every copy of the Flight runtime in the tree:
 *
 *  - real `react-server-dom-*` packages;
 *  - the copies a framework vendors under the same name (Next.js ships four:
 *    webpack/turbopack, each also in an `-experimental` flavour);
 *  - a framework's prebuilt server runtimes, which inline the whole thing.
 */
async function findCandidates(root) {
  const out = [];
  await walk(root, 0);
  return out;

  async function walk(dir, depth) {
    if (depth > 12) return;
    let entries;
    try {
      entries = await readdir(dir, {withFileTypes: true});
    } catch {
      return;
    }

    for (const entry of entries) {
      if (!entry.isDirectory() || entry.name === '.git') continue;
      const path = join(dir, entry.name);

      if (/^react-server-dom-/.test(entry.name)) {
        const copy = await describeCopy(path, await listFiles(path, 2));
        if (copy) out.push(copy);
        continue; // no nested copies inside
      }

      // Prebuilt framework server runtimes with the Flight code inlined.
      if (entry.name === 'next-server') {
        const bundles = (await listFiles(path, 1)).filter(f => /\.runtime\..*\.js$/.test(f));
        const copy = await describeCopy(path, bundles);
        if (copy) out.push(copy);
        continue;
      }

      await walk(path, depth + 1);
    }
  }
}

/**
 * Keeps only the files that really are Flight builds, and labels each with the
 * half it implements. Returns null if the directory holds none.
 */
async function describeCopy(dir, paths) {
  const files = [];
  for (const path of paths) {
    if (!/\.(js|cjs|mjs)$/.test(path) || path.endsWith('.map')) continue;
    let text;
    try {
      text = await readFile(path, 'utf8');
    } catch {
      continue;
    }
    const isServer = text.includes(FLIGHT_MARKERS.server);
    const isClient = text.includes(FLIGHT_MARKERS.client);
    if (!isServer && !isClient) continue; // a shim, a plugin, or unrelated
    files.push({path, kind: isServer && isClient ? 'both' : isServer ? 'server' : 'client'});
  }
  if (files.length === 0) return null;

  let name = basename(dir);
  let version = null;
  try {
    const pkg = JSON.parse(await readFile(join(dir, 'package.json'), 'utf8'));
    version = pkg.version ?? null;
  } catch {
    /* vendored copies often have no version of their own */
  }
  if (version === null) {
    // Attribute it to the package that ships it, so the fix is actionable.
    let owner = dir;
    for (let i = 0; i < 5; i++) {
      owner = resolve(owner, '..');
      try {
        const pkg = JSON.parse(await readFile(join(owner, 'package.json'), 'utf8'));
        if (pkg.name && pkg.version) {
          name = `${name}  [vendored by ${pkg.name}@${pkg.version}]`;
          break;
        }
      } catch {
        /* keep walking up */
      }
    }
  }
  return {name, dir, version, files};
}

async function listFiles(dir, depth = 1) {
  const out = [];
  try {
    for (const entry of await readdir(dir, {withFileTypes: true})) {
      const path = join(dir, entry.name);
      if (entry.isFile()) out.push(path);
      else if (entry.isDirectory() && depth > 1) out.push(...(await listFiles(path, depth - 1)));
    }
  } catch {
    /* unreadable */
  }
  return out;
}

function isAffectedVersion(version) {
  const parts = /^(\d+)\.(\d+)\.(\d+)/.exec(version);
  if (!parts) return null;
  const v = parts.slice(1, 4).map(Number);
  const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  return AFFECTED_RANGES.some(([lo, hi]) => cmp(v, lo) >= 0 && cmp(v, hi) <= 0);
}

// --------------------------------------------------------------------- runtime

/**
 * Fetches one response and checks whether its Flight framing is self-consistent.
 *
 * A dropped binary body is visible without knowing what the server meant to
 * send: the declared length runs past the end of the stream, or it swallows text
 * that is plainly the next row's header, or the trailing rows carry nonsense ids
 * because the parser resynchronised mid-value.
 */
/** The request headers a framework's own client sends to ask for the payload. */
function requestHeaders() {
  const headers = {
    // Generic client name on purpose: no identifying details go to the target.
    'user-agent': 'rsc-framing-check/1.0 (+GHSA-xqc2-xf4c-x3h3 triage)',
  };
  if (args.rsc) {
    headers.accept = 'text/x-component';
    headers.RSC = '1';
  }
  for (const h of [].concat(args.header ?? [])) {
    const idx = String(h).indexOf(':');
    if (idx > 0) headers[String(h).slice(0, idx).trim()] = String(h).slice(idx + 1).trim();
  }
  return headers;
}

/**
 * The analysis itself: given the bytes of a response, decide whether it is a
 * Flight payload and whether its framing is self-consistent.
 *
 * Every symptom here is detectable without knowing what the server meant to
 * send, which is what makes this usable against a black box.
 */
function analyzeFraming(bytes) {
  const rows = parseRows(bytes);
  const isFlight = rows.length > 0 && rows.some(r => r.kind === 'length' || r.id === 0);
  const binary = rows.filter(r => r.kind === 'length' && r.tag !== 'T');
  const text = rows.filter(r => r.kind === 'length' && r.tag === 'T');
  const findings = [];

  for (const row of rows) {
    if (row.kind !== 'length') continue;
    if (row.truncated) {
      findings.push(
        `row ${row.idHex} declares ${row.declaredLength} bytes but the stream ends ` +
          `after ${row.bodyLength}`,
      );
    }
    // A body that begins with something shaped like "<hex>:<tag>" is the next
    // row's header, i.e. this row's own body was never written.
    if (/^[0-9a-f]{1,8}:[A-Za-z]/.test(row.body.toString('latin1', 0, 10))) {
      findings.push(
        `row ${row.idHex} declares ${row.declaredLength} bytes, but its body starts ` +
          `with what looks like another row header: ` +
          `${JSON.stringify(preview(row.body.subarray(0, 24), 24))}`,
      );
    }
  }
  if (rows.some(r => r.incomplete)) findings.push('the stream ends mid-row');
  const weirdIds = rows.filter(r => !r.incomplete && (r.id < 0 || r.id > 0xffffff));
  if (weirdIds.length) {
    findings.push(
      `${weirdIds.length} row(s) carry implausible chunk ids ` +
        `(${weirdIds.map(r => r.id).slice(0, 3).join(', ')}), which is what reading a ` +
        `chunk id out of the middle of a value looks like`,
    );
  }

  return {
    rows,
    isFlight,
    findings,
    binaryRows: binary.length,
    // The largest binary row matters: the bug needs one over VIEW_SIZE (2048).
    largestBinary: binary.reduce((m, r) => Math.max(m, r.declaredLength), 0),
    textRows: text.length,
    largestText: text.reduce((m, r) => Math.max(m, r.declaredLength), 0),
  };
}

async function probe(url) {
  banner(`Live response framing: ${url}`);

  let response;
  try {
    response = await fetch(url, {
      method: args.method ?? (args.body ? 'POST' : 'GET'),
      headers: requestHeaders(),
      body: args.body,
      redirect: 'follow',
    });
  } catch (error) {
    console.log(`  request failed: ${error.message}`);
    return 2;
  }

  const bytes = Buffer.from(await response.arrayBuffer());
  const type = response.headers.get('content-type') ?? '(none)';
  console.log(`  ${response.status} ${response.statusText}, ${bytes.length} bytes, ${type}`);

  const report = analyzeFraming(bytes);
  if (!report.isFlight) {
    console.log('\n' + NOT_FLIGHT_HELP);
    return 2;
  }

  console.log('\n' + formatRows(report.rows));
  console.log(
    `\n  binary rows: ${report.binaryRows}` +
      (report.binaryRows ? ` (largest ${report.largestBinary} bytes)` : '') +
      `   outlined text rows: ${report.textRows}` +
      (report.textRows ? ` (largest ${report.largestText} bytes)` : ''),
  );

  if (report.findings.length === 0) {
    console.log(describeClean(report));
    return 0;
  }

  console.log('  DESYNCHRONISED:');
  for (const f of report.findings) console.log(`    - ${f}`);
  console.log(
    '\n  This response is corrupt on the wire. Any attacker-influenced string of\n' +
      '  1024+ characters in it can be positioned to land on the resync point and\n' +
      '  be parsed as Flight rows. Treat as exploitable.',
  );
  return 1;
}

/**
 * A clean result means different things depending on whether the precondition
 * was even present, so say which.
 */
function describeClean(report) {
  if (report.binaryRows === 0) {
    return (
      '  framing is self-consistent, and this response carries no typed arrays at\n' +
      '  all - so the bug cannot apply to it whatever version is installed. That\n' +
      '  clears this response, not the application: look for routes that return\n' +
      '  binary (file previews, image or PDF pipelines, export endpoints).'
    );
  }
  if (report.largestBinary <= 2048) {
    return (
      '  framing is self-consistent. This response does carry typed arrays, but the\n' +
      `  largest is ${report.largestBinary} bytes, under the 2048-byte VIEW_SIZE at which React\n` +
      '  stops copying and hands the view straight to the destination. Worth\n' +
      '  rechecking against larger inputs on the same route.'
    );
  }
  return (
    '  framing is self-consistent: no dropped body on this response. It does carry\n' +
    `  a ${report.largestBinary}-byte typed array, so the size precondition is met and only the\n` +
    '  buffer sharing is missing - recheck if that code path changes.'
  );
}

// --------------------------------------------------------------------- crawler

const SKIP_EXTENSIONS =
  /\.(png|jpe?g|gif|svg|webp|avif|ico|css|js|mjs|map|woff2?|ttf|eot|otf|pdf|zip|gz|mp4|webm|mp3|wasm|txt|xml|json|webmanifest)$/i;

/**
 * Walks one origin, asks each route for its RSC payload, and checks the framing.
 *
 * Read-only: GET only, nothing crafted, no payload injection - the same requests
 * a browser makes. Deliberately single-origin and capped, and polite by default
 * (one request at a time with a delay, robots.txt honoured) so that pointing it
 * at a host is a measured action rather than a scan.
 */
async function crawl(rootUrl) {
  const root = new URL(rootUrl);
  const limit = Number(args.pages ?? 25);
  const delay = Number(args.delay ?? 250);
  const maxDepth = Number(args.depth ?? 2);

  banner(`Crawling ${root.origin} (max ${limit} pages, depth ${maxDepth})`);

  const robots = await readRobots(root.origin);
  const disallowed = args['ignore-robots'] ? [] : robots.disallowed;
  if (disallowed.length) {
    console.log(`  robots.txt: ${disallowed.length} disallowed prefix(es) will be skipped`);
  }

  const queue = [{url: root.href, depth: 0}];
  const seen = new Set([normalize(root.href)]);
  const results = [];

  // Seed the queue with routes the app publishes, because following hrefs alone
  // under-reports badly on a client-rendered app.
  let seeds = [];
  if (args.urls) {
    const listed = (await readFile(args.urls, 'utf8'))
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));
    for (const entry of listed) {
      try {
        const url = new URL(entry, root.origin);
        if (url.origin === root.origin) seeds.push(url.href);
      } catch {
        /* skip unparseable lines */
      }
    }
    console.log(`  seeded ${seeds.length} route(s) from ${args.urls}`);
  } else if (!args['no-sitemap']) {
    const sitemap = await readSitemaps(root.origin, robots.sitemaps, limit * 2);
    seeds = sitemap.routes;
    console.log(
      seeds.length
        ? `  sitemap: seeded ${seeds.length} route(s) from ${sitemap.from.length} sitemap file(s)`
        : `  sitemap: none found (tried ${sitemap.from.length}) - falling back to following links`,
    );
  }

  for (const seed of seeds) {
    const key = normalize(seed);
    if (seen.has(key)) continue;
    seen.add(key);
    queue.push({url: seed, depth: maxDepth}); // seeds are leaves: check, do not expand
  }

  console.log(
    `  read-only: GET with ${args.rsc ? '`RSC: 1`' : 'default headers (consider --rsc)'}, ` +
      `${delay}ms apart\n`,
  );

  while (queue.length && results.length < limit) {
    const {url, depth} = queue.shift();
    if (disallowed.some(prefix => new URL(url).pathname.startsWith(prefix))) continue;

    let response;
    let bytes;
    try {
      response = await fetch(url, {headers: requestHeaders(), redirect: 'follow'});
      bytes = Buffer.from(await response.arrayBuffer());
    } catch (error) {
      results.push({url, error: error.message});
      console.log(`  ${'ERR  '} ${short(url, root)}  ${error.message}`);
      continue;
    }

    // Back off rather than hammer a struggling or rate-limiting host.
    if (response.status === 429 || response.status === 503) {
      const wait = Number(response.headers.get('retry-after') ?? 5) * 1000;
      console.log(`  ${response.status}   ${short(url, root)}  backing off ${wait}ms`);
      await sleep(Math.min(wait, 30000));
    }

    const report = analyzeFraming(bytes);
    const verdict = !report.isFlight
      ? 'not-rsc'
      : report.findings.length
        ? 'DESYNC '
        : report.binaryRows
          ? 'binary '
          : 'clean  ';

    results.push({url, status: response.status, bytes: bytes.length, report, verdict});
    console.log(
      `  ${verdict} ${String(response.status).padEnd(4)} ${short(url, root).padEnd(44)} ` +
        `${String(bytes.length).padStart(7)}B  ` +
        (report.isFlight
          ? `bin:${report.binaryRows}${
              report.binaryRows ? `/${report.largestBinary}B` : ''
            } txt:${report.textRows}${report.textRows ? `/${report.largestText}B` : ''}`
          : ''),
    );

    if (depth < maxDepth) {
      let links = extractLinks(bytes, url, root);

      // A framework whose RSC payload is the element tree carries its own links,
      // so the crawl costs one request per route. When the payload has none -
      // because the route is not RSC, or the model is plain data - fall back to
      // asking for the HTML once, for link discovery only.
      if (links.length === 0 && args.rsc) {
        const discovery = {...requestHeaders(), accept: 'text/html,*/*'};
        delete discovery.RSC;
        try {
          const page = await fetch(url, {headers: discovery, redirect: 'follow'});
          links = extractLinks(Buffer.from(await page.arrayBuffer()), url, root);
        } catch (error) {
          // Best-effort, but say so: a silent catch here hides real faults.
          console.log(`         (link discovery failed: ${error.message})`);
        }
      }

      for (const link of links) {
        const key = normalize(link);
        if (seen.has(key) || seen.size >= limit * 6) continue;
        seen.add(key);
        queue.push({url: link, depth: depth + 1});
      }
    }

    if (queue.length && results.length < limit) await sleep(delay);
  }

  // ------------------------------------------------------------------ summary
  const flight = results.filter(r => r.report?.isFlight);
  const desynced = flight.filter(r => r.report.findings.length);
  const withBinary = flight.filter(r => r.report.binaryRows > 0);
  const bigBinary = withBinary.filter(r => r.report.largestBinary > 2048);
  const bigText = flight.filter(r => r.report.largestText >= 1024);

  console.log(`\n  ${results.length} routes fetched, ${flight.length} returned an RSC payload`);

  if (flight.length === 0) {
    console.log('\n' + NOT_FLIGHT_HELP);
    return 2;
  }

  console.log(
    `  ${withBinary.length} carry typed arrays (${bigBinary.length} over the 2048-byte VIEW_SIZE)\n` +
      `  ${bigText.length} carry an outlined text row of 1024+ bytes`,
  );

  if (desynced.length) {
    console.log(`\n  DESYNCHRONISED routes (${desynced.length}):`);
    for (const r of desynced) {
      console.log(`    ${short(r.url, root)}`);
      for (const f of r.report.findings) console.log(`      - ${f}`);
    }
    console.log(
      '\n  Re-run with --url on one of these for the full row dump. Treat as\n' +
        '  exploitable where an attacker-influenced string also rides along.',
    );
    return 1;
  }

  if (bigBinary.length) {
    console.log(
      `\n  No desynchronised route found, but these meet the size precondition and\n` +
        `  are where to look if the code path changes:`,
    );
    for (const r of bigBinary) {
      console.log(`    ${short(r.url, root)}  largest typed array ${r.report.largestBinary} bytes`);
    }
    return 0;
  }

  console.log(
    '\n  No desynchronised route, and nothing crawled transports a typed array over\n' +
      '  2048 bytes - the precondition is absent on everything reached. This is a\n' +
      '  sample of one origin at the depth given, not a proof about the whole app;\n' +
      '  the installed-runtime check (--scan) is the authoritative one.',
  );
  return 0;
}

/**
 * Same-origin links, read out of either HTML or an RSC payload - both carry
 * them as `href` values, so one pattern covers both and the crawl needs only
 * one request per route.
 */
function extractLinks(bytes, from, root) {
  const text = bytes.toString('utf8');
  const out = new Set();
  for (const match of text.matchAll(/["']?href["']?\s*[:=]\s*["']([^"'\\]+)["']/g)) {
    let href = match[1];
    if (!href || href.startsWith('#') || /^(mailto|tel|javascript|data):/i.test(href)) continue;
    let url;
    try {
      url = new URL(href, from);
    } catch {
      continue;
    }
    if (url.origin !== root.origin) continue; // single origin, on purpose
    if (SKIP_EXTENSIONS.test(url.pathname)) continue;
    url.hash = '';
    out.add(url.href);
  }
  return [...out];
}

async function readRobots(origin) {
  const disallowed = [];
  const sitemaps = [];
  try {
    const response = await fetch(new URL('/robots.txt', origin), {
      headers: requestHeaders(),
    });
    if (!response.ok) return {disallowed, sitemaps};
    const text = await response.text();
    let applies = false;
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.replace(/#.*$/, '').trim();
      const [field, ...rest] = line.split(':');
      const value = rest.join(':').trim();
      if (/^user-agent$/i.test(field)) applies = value === '*';
      else if (applies && /^disallow$/i.test(field) && value) disallowed.push(value);
      // Sitemap directives are global, not per user-agent group.
      else if (/^sitemap$/i.test(field) && value) sitemaps.push(value);
    }
  } catch {
    /* no robots.txt is normal */
  }
  return {disallowed, sitemaps};
}

/**
 * Seeds the crawl from the site's own sitemap.
 *
 * Following `href`s is not enough on a real app: when the page body is a client
 * component, the navigation is built in the browser, so it appears in neither
 * the RSC payload nor the static HTML and an href crawler sees almost nothing.
 * The sitemap is the route list the site publishes for exactly this purpose.
 *
 * Handles a sitemap index (a sitemap of sitemaps) one level deep.
 */
async function readSitemaps(origin, advertised, budget) {
  const queue = advertised.length ? [...advertised] : [new URL('/sitemap.xml', origin).href];
  const routes = [];
  const fetched = new Set();
  let nested = 0;

  while (queue.length && routes.length < budget) {
    const target = queue.shift();
    if (fetched.has(target) || fetched.size > 6) continue;
    fetched.add(target);
    if (/\.gz$/i.test(target)) continue; // compressed sitemaps are not worth the dependency

    let xml;
    try {
      const response = await fetch(target, {headers: requestHeaders(), redirect: 'follow'});
      if (!response.ok) continue;
      xml = await response.text();
    } catch {
      continue;
    }

    const isIndex = /<sitemapindex/i.test(xml);
    for (const match of xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
      let url;
      try {
        url = new URL(match[1]);
      } catch {
        continue;
      }
      if (url.origin !== origin) continue;
      if (isIndex) {
        if (nested++ < 5) queue.push(url.href);
      } else if (!SKIP_EXTENSIONS.test(url.pathname) && routes.length < budget) {
        url.hash = '';
        routes.push(url.href);
      }
    }
  }
  return {routes, from: [...fetched]};
}

/**
 * Dedupe key. The query string is kept: on an RSC app a parameter routinely
 * selects what gets transported, which is exactly what this check cares about.
 */
function normalize(href) {
  const url = new URL(href);
  url.hash = '';
  return url.href.replace(/\/$/, '');
}

function short(href, root) {
  const url = new URL(href);
  const path = (url.pathname + url.search) || '/';
  return path.length > 42 ? path.slice(0, 41) + '…' : path;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// --------------------------------------------------------------------- helpers

function banner(text) {
  console.log('\n' + '='.repeat(78) + `\n${text}\n` + '='.repeat(78));
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    const value = argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[++i] : true;
    if (key in out) out[key] = [].concat(out[key], value);
    else out[key] = value;
  }
  return out;
}

process.exit(await main());
