// RSC *server* half. Must be loaded under `node --conditions=react-server`,
// exactly like a real framework's server runtime.
import {AsyncLocalStorage} from 'node:async_hooks';
globalThis.AsyncLocalStorage ??= AsyncLocalStorage;

import * as ReactServerDOMServer from 'react-server-dom-webpack/server.node';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
export const version = require('react-server-dom-webpack/package.json').version;
export {ReactServerDOMServer};
