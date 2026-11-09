/**
 * The public web tier: the "global" server in React's own flight topology, and
 * the equivalent of a framework's SSR pass.
 *
 * It runs under the *default* export conditions, fetches the RSC payload from
 * the internal render tier, deserializes it with `createFromReadableStream` and
 * renders HTML. This is the process the payload executes in, which is what makes
 * the advisory server-side RCE rather than a client-side problem.
 *
 *   GET|POST /       render the page (note from ?note= or the request body)
 *   GET|POST /rsc    pass the raw RSC payload through, as a real RSC app does
 *            ?full=1 ask for full-resolution attachments instead of thumbnails
 *   GET  /health
 */
import {createServer} from 'node:http';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);

// `react-server-dom-webpack/client` cannot run without these: they are how it
// loads client references, and it throws the moment one is missing. In a real
// deployment webpack supplies them - they are the bundle's own module registry
// accessor and chunk loader. This stands in for a webpack *server* bundle
// (Next.js's `node` target), where Node core modules are emitted as external
// modules that delegate to `require`.
globalThis.__webpack_require__ ??= id => require(id);
globalThis.__webpack_chunk_load__ ??= () => Promise.resolve();

const {createFromReadableStream} = await import('react-server-dom-webpack/client.edge');
const VERSION = require('react-server-dom-webpack/package.json').version;

const PORT = Number(process.env.PORT ?? 3000);
const RSC_ORIGIN = process.env.RSC_ORIGIN ?? 'http://rsc:3001';

// No client references are in play, so an empty map is all the consumer needs.
// It is also the only thing that normally decides which modules a payload may
// reach - which is precisely what the forged chunk in the exploit sidesteps.
const CONSUMER_MANIFEST = {
  serverConsumerManifest: {moduleMap: {}, moduleLoading: null, serverModuleMap: null},
};

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/health') {
    return json(res, 200, {ok: true, tier: 'web', version: VERSION, node: process.version});
  }

  // A real app publishes its route list here. It matters for triage: when the
  // page body is a client component the navigation is built in the browser, so
  // it appears in neither the RSC payload nor the static HTML, and following
  // links alone finds almost nothing.
  if (url.pathname === '/robots.txt') {
    return text(res, 200, 'text/plain', `User-agent: *\nSitemap: ${origin(req)}/sitemap.xml\n`);
  }
  if (url.pathname === '/sitemap.xml') {
    const routes = ['/', '/?full=1', '/about', '/gallery?full=1'];
    return text(
      res,
      200,
      'application/xml',
      '<?xml version="1.0" encoding="UTF-8"?>\n' +
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
        routes.map(r => `  <url><loc>${origin(req)}${r}</loc></url>\n`).join('') +
        '</urlset>\n',
    );
  }

  const note =
    req.method === 'POST' ? await readBody(req) : url.searchParams.get('note') ?? '';

  const full = url.searchParams.get('full') === '1' ? '?full=1' : '';

  let upstream;
  try {
    upstream = await fetch(`${RSC_ORIGIN}/render${full}`, {
      method: 'POST',
      headers: {'content-type': 'text/plain; charset=utf-8'},
      body: note,
    });
  } catch (error) {
    return json(res, 502, {error: `render tier unreachable: ${error.message}`});
  }

  if (!upstream.ok) {
    const body = await upstream.text();
    return json(res, 502, {error: 'render tier failed', status: upstream.status, body});
  }

  // Pass-through: a real RSC app serves this payload to the browser, which is
  // how an attacker gets to observe the framing it needs to measure. Frameworks
  // signal the request with an `RSC: 1` header on the page's own URL rather than
  // a separate path, so honour both.
  if (url.pathname === '/rsc' || req.headers.rsc === '1') {
    res.writeHead(200, {
      'content-type': 'text/x-component; charset=utf-8',
      'cache-control': 'no-store',
    });
    for await (const chunk of upstream.body) res.write(chunk);
    return res.end();
  }

  // The SSR path. Deserializing the payload is already enough.
  try {
    const data = await createFromReadableStream(upstream.body, CONSUMER_MANIFEST);
    res.writeHead(200, {'content-type': 'text/html; charset=utf-8'});
    res.end(renderPage(data));
  } catch (error) {
    console.error('[web] failed to consume the RSC payload:', error.message);
    json(res, 500, {error: error.message});
  }
}).listen(PORT, '0.0.0.0', () => {
  console.log(`[web]  react-server-dom-webpack ${VERSION} on ${PORT} (node ${process.version})`);
  console.log(`[web]  render tier: ${RSC_ORIGIN}`);
});

function renderPage(data) {
  const note = typeof data.userNote === 'string' ? data.userNote : '';
  // The nav gives a crawler something to walk, the way a real app's would.
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Attachments</title></head>
<body>
  <h1>Attachments</h1>
  <nav>
    <a href="/">thumbnails</a>
    <a href="/?full=1">full resolution</a>
    <a href="/about">about</a>
    <a href="/health">health</a>
  </nav>
  <p>A: ${describe(data.attachmentA)}</p>
  <p>B: ${describe(data.attachmentB)}</p>
  <h2>Note</h2>
  <pre>${escapeHtml(note.slice(0, 200))}</pre>
</body></html>
`;
}

function describe(value) {
  if (value && typeof value.byteLength === 'number') {
    return `${value.constructor.name}, ${value.byteLength} bytes`;
  }
  return 'missing';
}

function escapeHtml(text) {
  return String(text).replace(
    /[&<>"']/g,
    c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'})[c],
  );
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const parts = [];
    req.on('data', c => parts.push(c));
    req.on('end', () => resolve(Buffer.concat(parts).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res, status, body) {
  text(res, status, 'application/json', JSON.stringify(body));
}

function text(res, status, type, payload) {
  res.writeHead(status, {
    'content-type': type,
    'content-length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function origin(req) {
  return `http://${req.headers.host ?? '127.0.0.1'}`;
}
