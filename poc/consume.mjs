/**
 * The RSC *client* half: the consumer of the payload. In a real framework this
 * is either the browser bundle or - more interestingly for impact - the SSR
 * pass, which runs in the same Node process as the server.
 *
 * Runs under the default export conditions, like any RSC consumer.
 *
 * Usage:
 *   node poc/consume.mjs --env <dir> --wire <file> [--marker <file>]
 */
import {readFile, rm, readFile as read} from 'node:fs/promises';
import {resolve} from 'node:path';

const args = parseArgs(process.argv.slice(2));
const env = resolve(args.env);
const {ReactServerDOMClient, version} = await import(`${env}/load-client.mjs`);

const wire = await readFile(args.wire);

// Clear any marker from a previous run so the result cannot be stale.
if (args.marker) await rm(args.marker, {force: true});

const stream = new ReadableStream({
  type: 'bytes',
  start(controller) {
    controller.enqueue(new Uint8Array(wire));
    controller.close();
  },
});

const report = {version, nodeEnv: process.env.NODE_ENV ?? 'development'};

try {
  const root = await withTimeout(
    ReactServerDOMClient.createFromReadableStream(stream, {
      // A consumer manifest, as any framework supplies. Note that the PoC never
      // relies on its contents: the chain below never goes through the bundler
      // manifest at all.
      serverConsumerManifest: {
        moduleMap: {},
        moduleLoading: null,
        serverModuleMap: null,
      },
    }),
    3000,
  );
  report.rootKeys = root && typeof root === 'object' ? Object.keys(root) : typeof root;
  report.userNote = summarize(root && root.userNote);
} catch (error) {
  report.error = String(error && error.message ? error.message : error);
}

if (args.marker) {
  try {
    report.marker = JSON.parse(await read(args.marker, 'utf8'));
    report.codeExecuted = true;
  } catch {
    report.codeExecuted = false;
  }
}

process.stdout.write(JSON.stringify(report, null, 2) + '\n');

function summarize(value) {
  if (value === undefined) return 'undefined';
  if (typeof value === 'function') return `function ${value.name || '(anonymous)'}`;
  if (typeof value === 'string') return `string(${value.length})`;
  if (value && typeof value === 'object') return `object{${Object.keys(value).join(',')}}`;
  return String(value);
}

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(
        () => reject(new Error(`timed out after ${ms}ms waiting for the root chunk`)),
        ms,
      ).unref(),
    ),
  ]);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) out[argv[i].slice(2)] = argv[++i];
  }
  return out;
}
