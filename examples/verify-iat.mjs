#!/usr/bin/env node
/**
 * verify-iat.mjs — verify a Innom Age Token with nothing but Node.js.
 *
 * This is the relying-party integration story in its most reduced form: no
 * SDK, no npm install, no network call back to Innom beyond one cached
 * JWKS fetch. If this script says a token is valid, the gateway signed it and
 * it is fresh, correctly addressed, and well-formed.
 *
 * Usage:
 *   node examples/verify-iat.mjs <token> [audience] [jwksUrl]
 *
 *   token     the IAT (compact JWS). Reads from stdin if omitted or "-".
 *   audience  your relying-party id (default: rp_amourette)
 *   jwksUrl   gateway JWKS endpoint (default: http://localhost:4000/...)
 *
 * Exit code 0 = valid, 1 = invalid, 2 = usage/environment error.
 *
 * On a valid token it prints VALID plus the token's audience, predicate,
 * assurance, method class and the remaining claims an RP needs to display or
 * audit (VAL-DEPLOY-010 requires the audience, predicate, assurance and
 * method class on stdout).
 *
 * COVERAGE DECISION (misc-ms1-review-followups item 8): this script has NO
 * unit tests and keeps none by design — it must stay dependency-free and
 * runnable by copy-paste, so it carries its own inline copy of the checks
 * rather than importing a workspace module. The canonicality guard and the
 * full accept/reject matrix are pinned by `e2e/wire-sdk-verify.spec.ts`
 * (VAL-WIRE-054), which spawns this script as a subprocess and asserts the
 * exit codes: valid token 0, single-character byte mutation 1, and
 * padding-bit-only mutation 1. If you change this file, VAL-WIRE-054 is the
 * pin to keep green.
 */

const DEFAULT_AUDIENCE = "rp_amourette";
const DEFAULT_JWKS_URL = "http://localhost:4000/api/v1/.well-known/jwks.json";
const CLOCK_TOLERANCE_SECONDS = 5;

/** Key substrings that must never appear in a token claiming to reveal nothing. */
const FORBIDDEN_CLAIM_HINTS = [
  "dob",
  "birth",
  "name",
  "document",
  "passport",
  "email",
  "phone",
  "address",
  "selfie",
  "photo",
  "gender",
];

function fail(reason, detail) {
  console.error(`INVALID: ${reason}`);
  if (detail) console.error(`  ${detail}`);
  process.exit(1);
}

function base64UrlDecode(segment) {
  const padded = segment.replaceAll("-", "+").replaceAll("_", "/");
  return Buffer.from(padded, "base64");
}

/** Unpadded base64url spelling of a byte buffer (RFC 4648 §5). Always canonical. */
function base64UrlEncode(bytes) {
  return bytes
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/, "");
}

/**
 * True only when `segment` is the canonical base64url spelling of its own
 * bytes. base64url decoders discard the low bits of a segment's final
 * character, so one byte sequence can have several spellings that all decode
 * to the same bytes — and JOSE signature verification runs on the decoded
 * bytes, so a mutator who changes only those discarded bits produces a
 * different compact-JWS string that still verifies. Refusing any spelling
 * that is not the exact re-encoding of its bytes closes the same bypass the
 * SDK's `isCanonicalCompactJws` closes, kept inline here so this script
 * imports nothing but Node's built-ins.
 */
function isCanonicalSegment(segment) {
  if (segment.length === 0) return false;
  return base64UrlEncode(base64UrlDecode(segment)) === segment;
}

async function readToken(argv) {
  const arg = argv[2];
  if (arg && arg !== "-") return arg.trim();
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function main() {
  const token = await readToken(process.argv);
  const audience = process.argv[3] ?? DEFAULT_AUDIENCE;
  const jwksUrl = process.argv[4] ?? DEFAULT_JWKS_URL;

  if (!token) {
    console.error("usage: node examples/verify-iat.mjs <token> [audience] [jwksUrl]");
    process.exit(2);
  }

  // ---- 1. Structure -------------------------------------------------------
  const parts = token.split(".");
  if (parts.length !== 3) fail("malformed", "a IAT is a compact JWS: three base64url segments");
  const [headerSegment, payloadSegment, signatureSegment] = parts;

  // Refuse any segment that is not the canonical spelling of its own bytes
  // before the signature is trusted: a padding-bit-only mutation decodes to
  // the same signature bytes and would otherwise verify (§ VAL-WIRE-054).
  for (const segment of [headerSegment, payloadSegment, signatureSegment]) {
    if (!isCanonicalSegment(segment)) {
      fail("malformed", "a compact-JWS segment is not the canonical base64url spelling of its bytes");
    }
  }

  let header, payload;
  try {
    header = JSON.parse(base64UrlDecode(headerSegment).toString("utf8"));
    payload = JSON.parse(base64UrlDecode(payloadSegment).toString("utf8"));
  } catch {
    fail("malformed", "header or payload is not valid JSON");
  }

  if (header.alg !== "ES256") fail("wrong_algorithm", `expected ES256, received ${header.alg}`);
  if (header.typ !== "innom-iat+jwt") fail("wrong_type", `expected innom-iat+jwt, received ${header.typ}`);
  if (typeof header.kid !== "string") fail("malformed", "header carries no key id");

  // ---- 2. Key discovery -----------------------------------------------------
  let jwks;
  try {
    const response = await fetch(jwksUrl);
    if (!response.ok) fail("jwks_unavailable", `${jwksUrl} returned ${response.status}`);
    jwks = await response.json();
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("INVALID")) throw error;
    fail("jwks_unavailable", `${jwksUrl}: ${error.message ?? error}`);
  }

  const jwk = (jwks.keys ?? []).find((key) => key.kid === header.kid);
  if (!jwk) fail("unknown_key", `no key with kid "${header.kid}" in the gateway JWKS`);

  // ---- 3. Signature ---------------------------------------------------------
  // JWS ES256 signatures are raw R||S (IEEE P1363), which is exactly the format
  // WebCrypto's ECDSA verifier expects — no DER transcoding required.
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const signature = new Uint8Array(base64UrlDecode(signatureSegment));
  const signed = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, signed);
  if (!valid) fail("bad_signature", "the signature does not verify against the gateway key");

  // ---- 4. Claims ------------------------------------------------------------
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp + CLOCK_TOLERANCE_SECONDS < now) {
    fail("expired", `exp=${payload.exp} is more than ${CLOCK_TOLERANCE_SECONDS}s in the past`);
  }
  if (typeof payload.iat !== "number" || payload.iat - CLOCK_TOLERANCE_SECONDS > now) {
    fail("not_yet_valid", `iat=${payload.iat} is in the future`);
  }
  if (payload.exp - payload.iat > 600) {
    fail("ttl_too_long", "a IAT may live at most 600 seconds (PRD 4.2.3)");
  }
  if (payload.aud !== audience) {
    fail("wrong_audience", `token is for ${payload.aud}, you are ${audience}`);
  }
  const expectedIssuer = new URL(jwksUrl).origin;
  if (payload.iss !== expectedIssuer) {
    fail("wrong_issuer", `token issuer is ${payload.iss}, expected ${expectedIssuer}`);
  }

  // ---- 5. The point of the product ------------------------------------------
  const claimNames = Object.keys(payload).map((key) => key.toLowerCase().replace(/[^a-z0-9]/g, ""));
  const leaked = claimNames.filter((key) =>
    FORBIDDEN_CLAIM_HINTS.some((hint) => key.includes(hint)),
  );
  // `age_over` carries a statutory threshold, never a person's age.
  const leakedButThreshold = leaked.filter((key) => key !== "ageover");
  if (leakedButThreshold.length > 0) {
    fail("pii_present", `token carries identifying claim(s): ${leakedButThreshold.join(", ")}`);
  }

  console.log("VALID");
  console.log(`  subject    : ${payload.sub} (pairwise, unlinkable across sites)`);
  console.log(`  audience   : ${payload.aud}`);
  console.log(`  predicate  : age_over ${payload.predicate?.age_over}`);
  console.log(`  assurance  : ${payload.assurance} via ${payload.method_class}`);
  console.log(`  policy     : ${payload.policy_id} (${String(payload.policy_hash).slice(0, 16)}…)`);
  console.log(`  evidence   : ${payload.evidence_ref}`);
  console.log(`  expires    : ${new Date(payload.exp * 1000).toISOString()}`);
}

main().catch((error) => {
  console.error(`error: ${error instanceof Error ? error.message : error}`);
  process.exit(2);
});
