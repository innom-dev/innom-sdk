import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  assertIatPayload,
  isCanonicalCompactJws,
  meetsAssurance,
  type Assurance,
  type IatPayload,
} from "@innom/schemas";

/**
 * Server-side IAT verification for relying parties.
 *
 * Relying parties should verify offline against the gateway's JWKS rather than
 * calling `POST /v1/tokens/verify`, because the whole point of a bearer token
 * is that the RP can validate it without a round-trip (PRD 4.2.3: < 5ms). This
 * module is that offline path: it fetches the JWKS once, caches it, and verifies
 * every IAT against the IAT key's public half.
 *
 * Usage in a Next.js server component or route handler:
 *
 * ```ts
 * import { verifyIat } from "@innom/sdk/server";
 *
 * const result = await verifyIat(token, {
 *   audience: "rp_amourette",
 *   jwksUrl: "https://gateway.example/api/v1/.well-known/jwks.json",
 *   issuer: "https://gateway.example",
 * });
 * ```
 */

export interface VerifyIatOptions {
  /** The `rpId` the token was minted for. Must match the IAT `aud`. */
  audience: string;
  /** Gateway JWKS endpoint. Defaults to the hosted gateway. */
  jwksUrl?: string;
  /** Gateway origin, used as the expected `iss`. Defaults to the JWKS origin. */
  issuer?: string;
  /** Minimum age the RP requires; fails if the token's predicate is weaker. */
  requireAgeOver?: number;
  /** Minimum assurance the RP requires. */
  requireMinAssurance?: Assurance;
  /** Clock skew tolerance in seconds (default 5). */
  clockTolerance?: number;
}

export type VerifyIatResult =
  | { ok: true; claims: IatPayload }
  | {
      ok: false;
      reason:
        | "malformed"
        | "bad_signature"
        | "expired"
        | "wrong_audience"
        | "wrong_issuer"
        | "unknown_key"
        | "schema_violation"
        | "predicate_not_met"
        | "assurance_not_met";
      detail: string;
    };

const DEFAULT_JWKS_URL = "http://localhost:4000/api/v1/.well-known/jwks.json";

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJwks(url: string): ReturnType<typeof createRemoteJWKSet> {
  let jwks = jwksCache.get(url);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url));
    jwksCache.set(url, jwks);
  }
  return jwks;
}

export async function verifyIat(
  token: string,
  options: VerifyIatOptions,
): Promise<VerifyIatResult> {
  // Refuse any token whose compact-JWS segments are not the canonical base64url
  // spelling of their bytes before the signature is trusted: a mutator can
  // change the final signature character's discarded bits to a different
  // cookie string that still decodes to the same signature bytes, and jose (or
  // any JOSE library) would verify it. Shared with the gateway's
  // verifyIatLocally via @innom/schemas.
  if (!isCanonicalCompactJws(token)) {
    return {
      ok: false,
      reason: "malformed",
      detail: "token is not a canonically-encoded compact JWS",
    };
  }

  const jwksUrl = options.jwksUrl ?? DEFAULT_JWKS_URL;
  const issuer = options.issuer ?? new URL(jwksUrl).origin;
  const jwks = getJwks(jwksUrl);

  let payload: unknown;
  try {
    const result = await jwtVerify(token, jwks, {
      issuer,
      audience: options.audience,
      algorithms: ["ES256"],
      typ: "innom-iat+jwt",
      clockTolerance: options.clockTolerance ?? 5,
    });
    payload = result.payload;
  } catch (error) {
    const message = error instanceof Error ? error.message : "jwtVerify threw";
    return { ok: false, reason: classifyFailure(message), detail: message };
  }

  let claims: IatPayload;
  try {
    claims = assertIatPayload(payload);
  } catch (error) {
    return {
      ok: false,
      reason: "schema_violation",
      detail: error instanceof Error ? error.message : "payload failed the IAT schema",
    };
  }

  if (options.requireAgeOver !== undefined && claims.predicate.age_over < options.requireAgeOver) {
    return {
      ok: false,
      reason: "predicate_not_met",
      detail: `token asserts age_over ${String(claims.predicate.age_over)}; RP requires ${String(options.requireAgeOver)}`,
    };
  }

  if (
    options.requireMinAssurance &&
    !meetsAssurance(claims.assurance, options.requireMinAssurance)
  ) {
    return {
      ok: false,
      reason: "assurance_not_met",
      detail: `token assurance is ${claims.assurance}; RP requires ${options.requireMinAssurance}`,
    };
  }

  return { ok: true, claims };
}

type IatRejectionReason = Extract<VerifyIatResult, { ok: false }>["reason"];

function classifyFailure(message: string): IatRejectionReason {
  // jose reports claim failures as `unexpected "aud" claim value`, so match the
  // quoted claim names: a bare /exp/ would also match the word "unexpected".
  if (/"aud"/.test(message)) return "wrong_audience";
  if (/"iss"/.test(message)) return "wrong_issuer";
  if (/"exp"|JWTExpired/.test(message)) return "expired";
  if (/signature/i.test(message)) return "bad_signature";
  if (/key|kid|JWKS/i.test(message)) return "unknown_key";
  return "malformed";
}

export { assertIatPayload, meetsAssurance } from "@innom/schemas";
export type { IatPayload, Assurance } from "@innom/schemas";
