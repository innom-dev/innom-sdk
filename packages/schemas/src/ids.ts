/**
 * Prefixed, sortable identifiers in Crockford base32.
 *
 * Layout mirrors ULID: 48 bits of millisecond timestamp followed by 80 bits of
 * randomness, rendered as 26 characters. Time-ordered so the evidence vault's
 * append-only reads are sequential, and Crockford so a value read off a screen
 * during a demo cannot be mistranscribed (no I, L, O or U).
 *
 * Implemented on Web Crypto (`globalThis.crypto`) rather than `node:crypto` so
 * the module is isomorphic: the schemas package is imported by browser bundles,
 * and a Node-only import here would break every client build.
 */
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function randomBytesArray(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function encodeCrockford(bytes: Uint8Array, length: number): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += CROCKFORD[(value << (5 - bits)) & 31];
  }
  return output.slice(0, length);
}

function ulidLike(): string {
  const now = Date.now();
  const timeBytes = new Uint8Array(6);
  let remaining = now;
  for (let index = 5; index >= 0; index -= 1) {
    timeBytes[index] = remaining % 256;
    remaining = Math.floor(remaining / 256);
  }
  const randomPart = randomBytesArray(10);
  const combined = new Uint8Array(16);
  combined.set(timeBytes, 0);
  combined.set(randomPart, 6);
  return encodeCrockford(combined, 26);
}

export function ceremonyId(): string {
  return `cer_${ulidLike()}`;
}

export function tokenId(): string {
  return `iat_${ulidLike()}`;
}

export function evidenceId(): string {
  return `ev_${ulidLike()}`;
}

export function attestationId(): string {
  return `att_${ulidLike()}`;
}

export function credentialId(): string {
  return `cred_${ulidLike()}`;
}

/** Opaque identifier for `jti` claims; not time-ordered, nothing reads it in order. */
export function opaqueId(bytes = 16): string {
  return base64UrlEncode(randomBytesArray(bytes));
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  // btoa exists in Node 20 and every browser; the replacements make it URL-safe.
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
