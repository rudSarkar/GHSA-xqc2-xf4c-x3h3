/**
 * The "vulnerable application": the shape of an RSC response that satisfies the
 * advisory's precondition - "responses [that] transport multiple typed arrays
 * and an attacker-controlled value".
 *
 * Nothing here is adversarial. It is a server component result holding two
 * binary blobs and one string that came from a user.
 */

export const SHARING_MODES = ['pool', 'subarray', 'separate'];

/**
 * A Buffer cannot be transported as binary: `JSON.stringify` calls `toJSON()`
 * before React's replacer ever sees the value, so a Buffer arrives as
 * `{type:'Buffer',data:[...]}`. An application that wants real binary transport
 * therefore has to hand React a plain `Uint8Array` view - which is what React's
 * own regression tests for this advisory do too.
 *
 * The conversion is a view, not a copy, so the view inherits whatever
 * ArrayBuffer the Buffer was sitting in.
 */
export function toPlainView(buf) {
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/**
 * Returns two typed arrays plus a note on how they came to share (or not share)
 * an ArrayBuffer.
 *
 *  - `pool`     Two ordinary Buffers, converted for transport. Node serves every
 *               allocation below `Buffer.poolSize >>> 1` (32 KiB on current
 *               Node) out of one shared 64 KiB slab, so two unrelated
 *               `Buffer.allocUnsafe()` / `fs.readFile()` results are views on
 *               the *same* ArrayBuffer. This is the realistic case: the
 *               application does nothing unusual.
 *  - `subarray` One blob sliced into parts, e.g. a record split into a header
 *               and a body.
 *  - `separate` The control: each view owns its buffer, so nothing is detached
 *               and the response is well-formed.
 */
export function makeBlobs({mode, size}) {
  switch (mode) {
    case 'pool': {
      // > 2048 bytes, so React writes it straight to the destination instead of
      // copying it into its own 2 KiB staging view; and < Buffer.poolSize >>> 1,
      // so Node serves it out of the shared pool slab.
      const a = Buffer.allocUnsafe(size).fill(0x41);
      const b = Buffer.allocUnsafe(size).fill(0x42);
      const first = toPlainView(a);
      const second = toPlainView(b);
      return {
        first,
        second,
        shared: first.buffer === second.buffer,
        how:
          `two Buffer.allocUnsafe(${size}) values out of Node's ` +
          `${Buffer.poolSize}-byte pool slab, transported as Uint8Array views`,
      };
    }
    case 'subarray': {
      const whole = new ArrayBuffer(size * 2);
      const first = new Uint8Array(whole, 0, size).fill(0x41);
      const second = new Uint8Array(whole, size, size).fill(0x42);
      return {
        first,
        second,
        shared: first.buffer === second.buffer,
        how: `one ${size * 2}-byte ArrayBuffer split into two views`,
      };
    }
    case 'separate': {
      const first = new Uint8Array(size).fill(0x41);
      const second = new Uint8Array(size).fill(0x42);
      return {
        first,
        second,
        shared: first.buffer === second.buffer,
        how: 'two independently allocated Uint8Arrays (control)',
      };
    }
    default:
      throw new Error(`unknown sharing mode: ${mode}`);
  }
}

/**
 * The model the server component returns. Key order matters only in that it
 * fixes which chunk ids React hands out, which keeps the PoC's byte arithmetic
 * reproducible; the PoC re-reads the real ids off the wire regardless.
 */
export function buildModel({first, second, note}) {
  return {
    attachmentA: first,
    attachmentB: second,
    // Straight from the request. The application does not interpret it.
    userNote: note,
  };
}
