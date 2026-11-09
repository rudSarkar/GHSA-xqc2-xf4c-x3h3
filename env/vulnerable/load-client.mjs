// RSC *client* half: the consumer of the payload. In a real framework this is
// either the browser bundle or - more interestingly for impact - the SSR pass,
// which runs in the same Node process as the server. Loaded under the default
// export conditions, like any RSC consumer.
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);

// `react-server-dom-webpack/client` cannot run without these two globals: they
// are how it loads client references, and it throws the moment one is missing.
// In a real consumer webpack supplies them - they are the bundle's own module
// registry accessor and chunk loader. Here they stand in for a webpack *server*
// bundle (Next.js's `node` target), where Node core modules are emitted as
// external modules that delegate to `require`.
//
// None of the PoC depends on the shape of this shim. What matters is that a
// consumer always has some `__webpack_require__`, that the consumer manifest
// passed to `createFromReadableStream` is normally the only thing deciding which
// module ids a payload may reach, and that a forged chunk reaches
// `__webpack_require__` without consulting that manifest at all.
globalThis.__webpack_require__ ??= id => require(id);
globalThis.__webpack_chunk_load__ ??= () => Promise.resolve();

const ReactServerDOMClient = await import('react-server-dom-webpack/client.edge');

export const version = require('react-server-dom-webpack/package.json').version;
export {ReactServerDOMClient};
