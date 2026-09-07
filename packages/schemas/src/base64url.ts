/**
 * Unpadded base64url coding plus the compact-JWS canonicality guard.
 *
 * Why this exists: base64url decoders discard the low bits of a segment's
 * final character, so one byte sequence can have several distinct spellings
 * that all decode to the same bytes. JOSE signature verification runs on the
 * decoded bytes, so an attacker who changes only the discarded bits of the
 * signature segment produces a different compact-JWS string that still
 * verifies — the session-cookie bypass this module closes. Every verification
 * entry point must round-trip each segment (decode → re-encode) and refuse any
 * spelling that is not byte-for-byte canonical.
 *
 * Pure TypeScript on purpose: this package is consumed by browser bundles (the
 * wallet) and Node servers alike, so no `Buffer` and no new dependencies.
 * Tested against Node's own base64url as an oracle (schemas.test.ts).
 */

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** Index of each ASCII character in the alphabet, -1 for anything else. */
const BASE64URL_INDEX = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < BASE64URL_ALPHABET.length; i += 1) {
    table[BASE64URL_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Encodes bytes as unpadded base64url (RFC 4648 §5). Always canonical. */
export function encodeBase64Url(bytes: Uint8Array): string {
  let out = "";
  const fullGroups = bytes.length - (bytes.length % 3);
  for (let i = 0; i < fullGroups; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1]!;
    const b2 = bytes[i + 2]!;
    out += BASE64URL_ALPHABET[b0 >> 2]!;
    out += BASE64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]!;
    out += BASE64URL_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)]!;
    out += BASE64URL_ALPHABET[b2 & 0x3f]!;
  }

  const remainder = bytes.length - fullGroups;
  if (remainder === 1) {
    const b0 = bytes[fullGroups]!;
    // Second character carries 2 significant bits; the low 4 bits are zero in
    // the canonical spelling.
    out += BASE64URL_ALPHABET[b0 >> 2]!;
    out += BASE64URL_ALPHABET[(b0 & 0x03) << 4]!;
  } else if (remainder === 2) {
    const b0 = bytes[fullGroups]!;
    const b1 = bytes[fullGroups + 1]!;
    // Third character carries 4 significant bits; the low 2 bits are zero in
    // the canonical spelling.
    out += BASE64URL_ALPHABET[b0 >> 2]!;
    out += BASE64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]!;
    out += BASE64URL_ALPHABET[(b1 & 0x0f) << 2]!;
  }
  return out;
}

/**
 * Decodes unpadded base64url to bytes, or null if the input contains any
 * character outside the base64url alphabet. Unused trailing bits are accepted
 * (they are what the canonicality guard exists to detect); callers that need
 * canonical input must re-encode and compare.
 */
export function decodeBase64Url(input: string): Uint8Array | null {
  const out: number[] = [];
  let i = 0;
  const length = input.length;

  for (; i + 4 <= length; i += 4) {
    const a = valueOf(input.charCodeAt(i));
    const b = valueOf(input.charCodeAt(i + 1));
    const c = valueOf(input.charCodeAt(i + 2));
    const d = valueOf(input.charCodeAt(i + 3));
    if (a < 0 || b < 0 || c < 0 || d < 0) return null;
    out.push((a << 2) | (b >> 4));
    out.push(((b & 0x0f) << 4) | (c >> 2));
    out.push(((c & 0x03) << 6) | d);
  }

  const trailing = length - i;
  if (trailing === 1) {
    return null; // a single leftover sextet cannot form a byte
  }
  if (trailing === 2) {
    const a = valueOf(input.charCodeAt(i));
    const b = valueOf(input.charCodeAt(i + 1));
    if (a < 0 || b < 0) return null;
    out.push((a << 2) | (b >> 4));
  } else if (trailing === 3) {
    const a = valueOf(input.charCodeAt(i));
    const b = valueOf(input.charCodeAt(i + 1));
    const c = valueOf(input.charCodeAt(i + 2));
    if (a < 0 || b < 0 || c < 0) return null;
    out.push((a << 2) | (b >> 4));
    out.push(((b & 0x0f) << 4) | (c >> 2));
  }

  return new Uint8Array(out);
}

function valueOf(charCode: number): number {
  return charCode < 128 ? BASE64URL_INDEX[charCode]! : -1;
}

/**
 * True only when `token` is a compact JWS with exactly three segments and
 * every segment is the canonical base64url spelling of its own bytes.
 *
 * Verification entry points must run this before trusting a signature: JOSE
 * libraries verify against the decoded bytes, so a non-canonical spelling is
 * otherwise indistinguishable from the genuine token.
 */
export function isCanonicalCompactJws(token: string): boolean {
  const segments = token.split(".");
  if (segments.length !== 3) return false;

  for (const segment of segments) {
    if (segment.length === 0) return false;
    const bytes = decodeBase64Url(segment);
    if (bytes === null) return false;
    if (encodeBase64Url(bytes) !== segment) return false;
  }
  return true;
}
