import { z } from "zod";
import { assertNoPii } from "./pii.js";
import {
  AssuranceSchema,
  EvidenceIdSchema,
  JurisdictionSchema,
  MethodClassSchema,
  PolicyIdSchema,
  PredicateClaimSchema,
  RpIdSchema,
  Sha256HexSchema,
  TokenIdSchema,
} from "./primitives.js";

/** Maximum IAT lifetime in seconds (PRD 4.2.3: `exp <= 600s`). */
export const IAT_MAX_TTL_SECONDS = 600;

/** Pairwise subject: per-RP salted, stable for one holder at one RP. */
export const PairwiseSubjectSchema = z
  .string()
  .regex(/^pairwise_[0-9a-f]{8,64}$/, "expected pairwise_<hex>");

/**
 * Innom Age Token payload (PRD 4.2.3).
 *
 * `strictObject` is load-bearing: it is what makes "forbidden by schema: any
 * identity attribute" mechanically true rather than aspirational. `assertIatPayload`
 * additionally runs the PII key gate, so a future claim named `holder_name`
 * fails even if someone widens the schema.
 */
export const IatPayloadSchema = z
  .strictObject({
    iss: z.string().url(),
    aud: RpIdSchema,
    sub: PairwiseSubjectSchema,
    iat: z.number().int().positive(),
    exp: z.number().int().positive(),
    jti: TokenIdSchema,
    jurisdiction: JurisdictionSchema,
    policy_id: PolicyIdSchema,
    policy_hash: Sha256HexSchema,
    predicate: PredicateClaimSchema,
    assurance: AssuranceSchema,
    method_class: MethodClassSchema,
    evidence_ref: EvidenceIdSchema,
  })
  .refine((claims) => claims.exp > claims.iat, {
    error: "exp must be after iat",
    path: ["exp"],
  })
  .refine((claims) => claims.exp - claims.iat <= IAT_MAX_TTL_SECONDS, {
    error: `IAT lifetime must not exceed ${IAT_MAX_TTL_SECONDS}s (PRD 4.2.3)`,
    path: ["exp"],
  });

export type IatPayload = z.infer<typeof IatPayloadSchema>;

/** Parse + PII gate. The only sanctioned way to construct a IAT payload. */
export function assertIatPayload(value: unknown): IatPayload {
  const claims = IatPayloadSchema.parse(value);
  assertNoPii(claims, "iat");
  return claims;
}

export const IatHeaderSchema = z.strictObject({
  alg: z.literal("ES256"),
  typ: z.literal("innom-iat+jwt"),
  kid: z.string().min(4).max(128),
});
export type IatHeader = z.infer<typeof IatHeaderSchema>;

/** `POST /v1/tokens/verify` request. */
export const TokenVerifyRequestSchema = z.strictObject({
  // Deliberately no length floor: a structurally malformed token such as
  // "not.a.jws" must reach the verifier and be answered `200 {valid: false,
  // reason: "malformed"}` (VAL-WIRE-031), not refused 400 at the door — the
  // endpoint's contract is that "this token is invalid" is a successful
  // answer. Size abuse is bounded by the body-size guard in the route layer.
  token: z.string().min(1),
  audience: RpIdSchema,
  /** Optional predicate assertion: fails the call if the token is weaker. */
  requirePredicate: z.strictObject({ ageOver: z.number().int().min(1).max(120) }).optional(),
  requireMinAssurance: AssuranceSchema.optional(),
});
export type TokenVerifyRequest = z.infer<typeof TokenVerifyRequestSchema>;

export const TokenVerifyResponseSchema = z.discriminatedUnion("valid", [
  z.strictObject({
    valid: z.literal(true),
    claims: z.looseObject({}),
    verifiedInMs: z.number().nonnegative(),
  }),
  z.strictObject({
    valid: z.literal(false),
    reason: z.enum([
      "malformed",
      "bad_signature",
      "expired",
      "wrong_audience",
      "wrong_issuer",
      "unknown_key",
      "schema_violation",
      "predicate_not_met",
      "assurance_not_met",
      "replayed",
    ]),
    verifiedInMs: z.number().nonnegative(),
  }),
]);
export type TokenVerifyResponse = z.infer<typeof TokenVerifyResponseSchema>;
