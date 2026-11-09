/**
 * A reader for the React Flight ("RSC payload") row framing, used to inspect
 * what the server actually put on the wire and to replay how the client parses
 * it.
 *
 * Framing, per `processBinaryChunk` in react-client/src/ReactFlightClient.js:
 *
 *   <hex id> ":" [tag] <body> "\n"             newline terminated row
 *   <hex id> ":" <tag> <hex byteLength> ","    length prefixed row
 *
 * Length prefixed tags are `T` (outlined text) plus every binary tag, which is
 * what makes them interesting here: their body is raw, unescaped bytes and the
 * only thing telling the client where that body ends is the declared length.
 */

// Tags that switch the parser into ROW_CHUNK_BY_LENGTH.
const LENGTH_PREFIXED = new Set(
  [...'TAOoUSsLlGgMmV'].map(c => c.charCodeAt(0)),
);

// Tags that are followed by a newline terminated body: A-Z, '#', 'r', 'x'.
function isTaggedLineTag(code) {
  return (code > 64 && code < 91) || code === 35 || code === 114 || code === 120;
}

const COLON = 0x3a;
const NEWLINE = 0x0a;
const COMMA = 0x2c;

function hexDigit(byte) {
  return byte > 96 ? byte - 87 : byte - 48;
}

/**
 * Walks `bytes` exactly the way the Flight client's row parser does and returns
 * one record per row it believes it saw.
 *
 * Because the parser trusts the declared length of a length prefixed row, a row
 * whose body was never written swallows whatever follows it. That shows up here
 * as a row whose `body` contains the text of later rows, and as a `resyncOffset`
 * pointing at wherever the parser picked up again.
 */
export function parseRows(bytes) {
  const rows = [];
  let i = 0;

  while (i < bytes.length) {
    const rowStart = i;

    // ROW_ID: hex digits until ':'
    let id = 0;
    let sawId = false;
    while (i < bytes.length && bytes[i] !== COLON) {
      id = (id << 4) | hexDigit(bytes[i]);
      sawId = true;
      i++;
    }
    if (i >= bytes.length) {
      rows.push({incomplete: 'id', rowStart});
      break;
    }
    i++; // consume ':'

    // ROW_TAG
    const tagByte = bytes[i];
    let tag = null;
    let kind;
    if (LENGTH_PREFIXED.has(tagByte)) {
      tag = String.fromCharCode(tagByte);
      kind = 'length';
      i++;
    } else if (isTaggedLineTag(tagByte)) {
      tag = String.fromCharCode(tagByte);
      kind = 'line';
      i++;
    } else {
      kind = 'line'; // untagged model row
    }

    let declaredLength = null;
    let bodyStart;
    let bodyEnd;

    if (kind === 'length') {
      // ROW_LENGTH: hex digits until ','
      let len = 0;
      while (i < bytes.length && bytes[i] !== COMMA) {
        len = (len << 4) | hexDigit(bytes[i]);
        i++;
      }
      i++; // consume ','
      declaredLength = len;
      bodyStart = i;
      bodyEnd = Math.min(i + len, bytes.length);
      i = bodyEnd;
    } else {
      bodyStart = i;
      const nl = bytes.indexOf(NEWLINE, i);
      bodyEnd = nl === -1 ? bytes.length : nl;
      i = bodyEnd + (nl === -1 ? 0 : 1);
    }

    rows.push({
      // Some rows carry no id at all - hints are emitted as `:H<code><json>`
      // and the timing row as `:N<time>` - so an absent id is normal and must
      // not be mistaken for a collision on chunk 0.
      hasId: sawId,
      id: sawId ? id : 0,
      idHex: (sawId ? id : 0).toString(16),
      tag,
      kind,
      declaredLength,
      rowStart,
      headerLength: bodyStart - rowStart,
      bodyStart,
      bodyEnd,
      bodyLength: bodyEnd - bodyStart,
      truncated: declaredLength !== null && bodyEnd - bodyStart < declaredLength,
      body: Buffer.from(bytes.buffer, bytes.byteOffset + bodyStart, bodyEnd - bodyStart),
    });
  }

  return rows;
}

/** Renders a row list as a compact table, collapsing long runs of one byte. */
export function formatRows(rows, {bodyLimit = 72} = {}) {
  const lines = [];
  for (const row of rows) {
    if (row.incomplete) {
      lines.push(`      <incomplete row at offset ${row.rowStart}>`);
      continue;
    }
    const head = `${row.hasId ? row.idHex : ''}:${row.tag ?? ''}${
      row.declaredLength !== null ? row.declaredLength.toString(16) + ',' : ''
    }`;
    const declared =
      row.declaredLength !== null ? `declared=${row.declaredLength}` : 'newline';
    lines.push(
      `  @${String(row.rowStart).padStart(5)} ${head.padEnd(12)} ${declared.padEnd(
        16,
      )} got=${String(row.bodyLength).padEnd(6)} ${preview(row.body, bodyLimit)}`,
    );
  }
  return lines.join('\n');
}

export function preview(buf, limit = 72) {
  const text = buf
    .toString('latin1')
    .replace(/(.)\1{9,}/g, (m, c) => `<${m.length}x${printable(c)}>`)
    .replace(/[\x00-\x08\x0b-\x1f\x7f-\xff]/g, '.');
  return text.length > limit ? text.slice(0, limit) + '...' : text;
}

function printable(c) {
  const code = c.charCodeAt(0);
  return code >= 0x20 && code < 0x7f ? c : '\\x' + code.toString(16).padStart(2, '0');
}

export function utf8Length(str) {
  return Buffer.byteLength(str, 'utf8');
}
