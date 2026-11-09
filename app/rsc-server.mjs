/**
 * The RSC render tier: the "regional" server in React's own flight topology.
 *
 * Runs under `node --conditions=react-server`. It renders the application model
 * to an RSC payload and streams it back as `text/x-component`. It is internal:
 * only the web tier talks to it.
 *
 *   GET  /render?note=<text>   note from the query string
 *   POST /render               note from the request body
 *        &full=1               full-resolution attachments instead of thumbnails
 *   GET  /health
 *
 * The model is the advisory's precondition and nothing more: two typed arrays
 * that happen to be views over one ArrayBuffer, plus one string that came from
 * the user. No part of this file is adversarial.
 */
import {createServer} from 'node:http';
import {AsyncLocalStorage} from 'node:async_hooks';

globalThis.AsyncLocalStorage ??= AsyncLocalStorage;

const {renderToReadableStream} = await import('react-server-dom-webpack/server.node');
const {createRequire} = await import('node:module');
const require = createRequire(import.meta.url);
const VERSION = require('react-server-dom-webpack/package.json').version;

const PORT = Number(process.env.PORT ?? 3001);
// Thumbnails are small enough that React copies them into its own 2 KiB staging
// view, so the shared backing store is never handed to the destination and the
// app is perfectly healthy. Full-resolution attachments cross VIEW_SIZE and are
// written straight through - which is the whole difference.
const THUMB_SIZE = Number(process.env.THUMB_SIZE ?? 1024);
const FULL_SIZE = Number(process.env.FULL_SIZE ?? 3000);

/**
 * Two attachments carved out of one decode buffer - the shape an application
 * ends up with whenever it splits a single blob into parts, or slices an upload
 * into a header and a body.
 *
 * A Buffer cannot be transported as binary at all: `JSON.stringify` calls its
 * `toJSON()` before React's replacer ever sees the value, so it would arrive as
 * `{type:'Buffer',data:[...]}`. Handing React a plain `Uint8Array` view is the
 * only way to get real binary transport - and the view inherits the buffer it
 * was carved from.
 */
function buildModel(note, full) {
  const size = full ? FULL_SIZE : THUMB_SIZE;
  const decoded = new ArrayBuffer(size * 2);
  const attachmentA = new Uint8Array(decoded, 0, size).fill(0x41);
  const attachmentB = new Uint8Array(decoded, size, size).fill(0x42);
  return {attachmentA, attachmentB, userNote: note};
}

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/health') {
    return json(res, 200, {ok: true, tier: 'rsc', version: VERSION});
  }

  if (url.pathname !== '/render') {
    return json(res, 404, {error: 'not found'});
  }

  const note =
    req.method === 'POST' ? await readBody(req) : url.searchParams.get('note') ?? '';
  const full = url.searchParams.get('full') === '1';

  try {
    const stream = renderToReadableStream(buildModel(note, full), {}, {
      onError(error) {
        console.error('[rsc] render error:', error.message);
      },
    });
    res.writeHead(200, {
      'content-type': 'text/x-component; charset=utf-8',
      'cache-control': 'no-store',
    });
    for await (const chunk of stream) res.write(chunk);
    res.end();
  } catch (error) {
    console.error('[rsc] render threw:', error.message);
    json(res, 500, {error: error.message});
  }
}).listen(PORT, '0.0.0.0', () => {
  console.log(`[rsc]  react-server-dom-webpack ${VERSION} on ${PORT} (node ${process.version})`);
});

function readBody(req) {
  return new Promise((resolve, reject) => {
    const parts = [];
    req.on('data', c => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}
