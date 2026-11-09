/**
 * The RSC *server* half. Must run under `node --conditions=react-server`, the
 * same condition a real framework's server runtime uses.
 *
 * Renders the application model to an RSC payload, writes the raw bytes to a
 * file, and reports what happened to the typed arrays during the render.
 *
 * Usage:
 *   node --conditions=react-server poc/render.mjs \
 *        --env <dir> --out <file> --note-file <file> [--mode pool] [--size 3000]
 */
import {writeFile, readFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {makeBlobs, buildModel} from '../src/app.mjs';

const args = parseArgs(process.argv.slice(2));
const env = resolve(args.env);
const {ReactServerDOMServer, version} = await import(`${env}/load-server.mjs`);

const mode = args.mode ?? 'pool';
const size = Number(args.size ?? 3000);
const note = args['note-file']
  ? await readFile(args['note-file'], 'utf8')
  : 'a short, harmless note';

const {first, second, shared, how} = makeBlobs({mode, size});
const model = buildModel({first, second, note});

const report = {
  version,
  mode,
  size,
  how,
  sharedArrayBuffer: shared,
  noteBytes: Buffer.byteLength(note, 'utf8'),
  declaredA: first.byteLength,
  declaredB: second.byteLength,
};

let bytes = null;
let renderError = null;
try {
  const stream = ReactServerDOMServer.renderToReadableStream(model, {}, {
    onError(error) {
      report.onError ??= [];
      report.onError.push(String(error && error.message ? error.message : error));
    },
  });
  bytes = Buffer.from(await new Response(stream).arrayBuffer());
} catch (error) {
  renderError = error;
}

// After the render the views tell us whether the destination took ownership of
// their backing store. A byte ReadableStream transfers (detaches) the whole
// ArrayBuffer of every chunk it is handed.
report.afterRender = {
  aByteLength: first.byteLength,
  bByteLength: second.byteLength,
  backingDetached: Boolean(first.buffer.detached ?? second.buffer.detached),
};
report.renderError = renderError ? String(renderError.message ?? renderError) : null;
report.wireBytes = bytes ? bytes.length : 0;

if (bytes) {
  await writeFile(args.out, bytes);
}
process.stdout.write(JSON.stringify(report, null, 2) + '\n');

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) out[argv[i].slice(2)] = argv[++i];
  }
  return out;
}
