import { z } from "zod";
import {
  AssuranceSchema,
  AttestationIdSchema,
  CeremonyIdSchema,
  CredentialIdSchema,
  FieldElementSchema,
  MethodClassSchema,
  PolicyIdSchema,
  PrefixedSha256Schema,
  Sha256HexSchema,
} from "./primitives.js";

/**
 * A compact JWS: three base64url segments.
 *
 * Deliberately permissive: the character class accepts non-canonical base64url
 * spellings (same decoded bytes, different string). This is NOT a security
 * check — canonicality is enforced at the trust boundaries, before signature
 * verification, by `isCanonicalCompactJws` in `base64url.ts`.
 */
export const CompactJwsSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, "expected compact JWS");
export type CompactJws = z.infer<typeof CompactJwsSchema>;

/** snarkjs Groth16 proof over bn128. */
export const Groth16ProofSchema = z.strictObject({
  pi_a: z.tuple([FieldElementSchema, FieldElementSchema, FieldElementSchema]),
  pi_b: z.tuple([
    z.tuple([FieldElementSchema, FieldElementSchema]),
    z.tuple([FieldElementSchema, FieldElementSchema]),
    z.tuple([FieldElementSchema, FieldElementSchema]),
  ]),
  pi_c: z.tuple([FieldElementSchema, FieldElementSchema, FieldElementSchema]),
  protocol: z.literal("groth16"),
  curve: z.literal("bn128"),
});
export type Groth16Proof = z.infer<typeof Groth16ProofSchema>;

/**
 * Public signal ordering is fixed by the `public` list on `component main` in
 * `age_over.circom`. Anything that reads or writes public signals must go
 * through these indices; a silent reorder is a soundness bug.
 */
export const PUBLIC_SIGNAL_ORDER = Object.freeze({
  thresholdDays: 0,
  todayDays: 1,
  commitment: 2,
  nonce: 3,
} as const);

export const PUBLIC_SIGNAL_COUNT = 4;

export const PublicSignalsSchema = z
  .array(FieldElementSchema)
  .length(PUBLIC_SIGNAL_COUNT, { error: "age_over exposes exactly 4 public signals" });
export type PublicSignals = z.infer<typeof PublicSignalsSchema>;

export interface DecodedPublicSignals {
  thresholdDays: number;
  todayDays: number;
  commitment: string;
  nonce: string;
}

export function decodePublicSignals(signals: readonly string[]): DecodedPublicSignals {
  const parsed = PublicSignalsSchema.parse(signals);
  return {
    thresholdDays: Number(parsed[PUBLIC_SIGNAL_ORDER.thresholdDays]),
    todayDays: Number(parsed[PUBLIC_SIGNAL_ORDER.todayDays]),
    commitment: parsed[PUBLIC_SIGNAL_ORDER.commitment] as string,
    nonce: parsed[PUBLIC_SIGNAL_ORDER.nonce] as string,
  };
}

export function encodePublicSignals(values: DecodedPublicSignals): PublicSignals {
  const signals = new Array<string>(PUBLIC_SIGNAL_COUNT);
  signals[PUBLIC_SIGNAL_ORDER.thresholdDays] = String(values.thresholdDays);
  signals[PUBLIC_SIGNAL_ORDER.todayDays] = String(values.todayDays);
  signals[PUBLIC_SIGNAL_ORDER.commitment] = values.commitment;
  signals[PUBLIC_SIGNAL_ORDER.nonce] = values.nonce;
  return PublicSignalsSchema.parse(signals);
}

/**
 * Mock-wallet credential payload: an issuer's signed assertion that it verified
 * a date of birth and that the holder's commitment binds to it. The DOB itself
 * never appears here, which is the entire point — the issuer signs the
 * commitment, the holder proves the predicate.
 */
export const CommitmentCredentialClaimsSchema = z.strictObject({
  iss: z.string().url(),
  /** Credential identifier. Not a subject identifier: rotates per issuance. */
  sub: CredentialIdSchema,
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  jti: z.string().min(8).max(64),
  vct: z.literal("innom.demo.age-commitment.v1"),
  /** RFC 7800-style confirmation: the committed value the holder must open. */
  cnf: z.strictObject({
    commitment: FieldElementSchema,
    alg: z.literal("poseidon-bn128-t3"),
  }),
  /** Which real-world issuer this mock stands in for; shown in the reality panel. */
  issuer_profile: z.literal("mock-france-identite"),
  /** Assurance the issuer's own onboarding would confer (PRD 4.2.1 M1 = P-AAL3). */
  source_assurance: AssuranceSchema,
});
export type CommitmentCredentialClaims = z.infer<typeof CommitmentCredentialClaimsSchema>;

/**
 * Acceptance-plane → attestation-plane challenge ticket.
 *
 * PRD 4.3 step 1. Carries only `{threshold, min_assurance, pack_hash, expiry}`
 * plus the freshness nonce and circuit identity. It deliberately contains no
 * relying-party identifier and no ceremony identifier, so the attestation plane
 * cannot learn the destination. P2 replaces the plain signature with an
 * OPRF-blinded one, which additionally removes the nonce as a correlation
 * handle.
 */
export const ChallengeTicketClaimsSchema = z.strictObject({
  iss: z.string().url(),
  aud: z.literal("innom-attest"),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  jti: z.string().min(8).max(64),
  nonce: FieldElementSchema,
  thresholdDays: z.number().int().min(0).max(65535),
  todayDays: z.number().int().min(0).max(65535),
  minAssurance: AssuranceSchema,
  packHash: Sha256HexSchema,
  circuitId: z.string().min(3).max(64),
  circuitHash: Sha256HexSchema,
});
export type ChallengeTicketClaims = z.infer<typeof ChallengeTicketClaimsSchema>;

/**
 * Attestation-plane → acceptance-plane result. PRD 4.3 step 3. The gateway
 * learns "a valid P-AAL3 attestation occurred against this nonce" and nothing
 * about the method transcript beyond its class and hash.
 */
export const AttestationClaimsSchema = z.strictObject({
  iss: z.string().url(),
  aud: z.literal("innom-gateway"),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  jti: AttestationIdSchema,
  nonce: FieldElementSchema,
  method_class: MethodClassSchema,
  assurance: AssuranceSchema,
  /**
   * HMAC(ATTEST_PEPPER, commitment). Lets the acceptance plane derive a stable
   * pairwise `sub` without ever seeing the commitment.
   */
  subject_seed: Sha256HexSchema,
  transcript_hash: PrefixedSha256Schema,
  circuit_id: z.string().min(3).max(64),
});
export type AttestationClaims = z.infer<typeof AttestationClaimsSchema>;

/** `POST /v1/attest/zk` request. Reaches the attestation plane only. */
export const ZkAttestRequestSchema = z.strictObject({
  challengeTicket: CompactJwsSchema,
  credential: CompactJwsSchema,
  proof: Groth16ProofSchema,
  publicSignals: PublicSignalsSchema,
  /** Client-measured proving milliseconds; recorded as telemetry, never trusted. */
  provingMs: z.number().int().nonnegative().max(600_000).optional(),
});
export type ZkAttestRequest = z.infer<typeof ZkAttestRequestSchema>;

export const ZkAttestResponseSchema = z.strictObject({
  attestation: CompactJwsSchema,
  methodClass: MethodClassSchema,
  assurance: AssuranceSchema,
  verifiedInMs: z.number().nonnegative(),
});
export type ZkAttestResponse = z.infer<typeof ZkAttestResponseSchema>;

/** `POST /v1/tokens` request. Reaches the acceptance plane only. */
export const TokenMintRequestSchema = z.strictObject({
  ceremonyId: CeremonyIdSchema,
  attestation: CompactJwsSchema,
});
export type TokenMintRequest = z.infer<typeof TokenMintRequestSchema>;

export const TokenMintResponseSchema = z.strictObject({
  token: CompactJwsSchema,
  assurance: AssuranceSchema,
  method: MethodClassSchema,
  expiresAt: z.iso.datetime(),
  ceremonyId: CeremonyIdSchema,
  evidenceRef: z.string().min(3),
  policyId: PolicyIdSchema,
});
export type TokenMintResponse = z.infer<typeof TokenMintResponseSchema>;
