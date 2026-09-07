import { z } from "zod";
import { CompactJwsSchema, Groth16ProofSchema, PublicSignalsSchema } from "./attest.js";
import {
  AssuranceSchema,
  CredentialIdSchema,
  FieldElementSchema,
  MethodClassSchema,
} from "./primitives.js";

/**
 * The age-band map asserted by a Innom reusable credential (architecture §6).
 *
 * Bands are computed at mint time from the holder's real date of birth, inside
 * the wallet where the DOB lives, and asserted by the attestation-plane issuer
 * into a signed credential. The three bands are a strict chain: clearing 18
 * implies clearing 15, and clearing 21 implies clearing both. An issuer that
 * signs an incoherent map (e.g. `age_over_21: true` without 15 or 18) is
 * minting a lie, so the mint endpoint rejects incoherent maps before signing.
 */
export const AgeBandsSchema = z.strictObject({
  age_over_15: z.boolean(),
  age_over_18: z.boolean(),
  age_over_21: z.boolean(),
});
export type AgeBands = z.infer<typeof AgeBandsSchema>;

/**
 * Rejects an internally contradictory band map. Does NOT judge the map's truth
 * against a date of birth the issuer can verify — the mint endpoint does that
 * with a real proof — it only refuses nonsense an issuer must never assert.
 */
export function assertCoherentAgeBands(bands: AgeBands): void {
  if (bands.age_over_18 && !bands.age_over_15) {
    throw new Error("incoherent age bands: age_over_18 without age_over_15");
  }
  if (bands.age_over_21 && !bands.age_over_18) {
    throw new Error("incoherent age bands: age_over_21 without age_over_18");
  }
}

/**
 * The three statutory age bands a Innom credential can assert, ascending.
 *
 * Order is load-bearing for minting: the circuit proves `age >= threshold` for
 * one threshold, and age only grows, so a proof that clears band N
 * authenticates every band below N. The mint endpoint derives the signed band
 * map from the highest band the holder could prove rather than trusting any
 * caller-supplied booleans.
 */
export const AGE_BANDS = Object.freeze([15, 18, 21] as const);
export type AgeBand = (typeof AGE_BANDS)[number];

/**
 * A Groth16 proof that a specific commitment clears one age band.
 *
 * Carried by the credential mint request. The wallet proves the threshold of
 * the HIGHEST band it claims true, with the minting ceremony's date and
 * nonce; the issuer verifies it and derives the signed band map from the
 * proven band (monotonically, so proving 21 authenticates 15 and 18 too).
 */
export const BandProofSchema = z.strictObject({
  proof: Groth16ProofSchema,
  publicSignals: PublicSignalsSchema,
});
export type BandProof = z.infer<typeof BandProofSchema>;

/**
 * The band map a verified proof at `provenBand` years authenticates.
 *
 * Monotone by construction: clearing 18 implies clearing 15, clearing 21
 * implies clearing both. `null` (no proof) authenticates nothing — every band
 * reads false, which is why the mint refuses a request that claims any band
 * true without evidence rather than signing an unauthenticated boolean.
 */
export function ageBandsFromProvenBand(provenBand: number | null): AgeBands {
  return {
    age_over_15: provenBand !== null && provenBand >= 15,
    age_over_18: provenBand !== null && provenBand >= 18,
    age_over_21: provenBand !== null && provenBand >= 21,
  };
}

/** Structural equality for band maps; the mint's refused-with-`band_mismatch` comparison. */
export function ageBandsEqual(left: AgeBands, right: AgeBands): boolean {
  return (
    left.age_over_15 === right.age_over_15 &&
    left.age_over_18 === right.age_over_18 &&
    left.age_over_21 === right.age_over_21
  );
}

/** `vct` carried by every Innom age-bands credential (§6.1). */
export const INNOM_CREDENTIAL_VCT = "innom.credential.age-bands.v1" as const;

/** Lifetime of a minted Innom credential in whole days (PRD range 30-180). */
export const INNOM_CREDENTIAL_LIFETIME_DAYS = 90 as const;

/**
 * Committed-value algorithm in `cnf.alg`. Same Poseidon commitment the M1
 * minting ceremony proved against; the credential is only useful while the
 * holder can still open this commitment.
 */
export const INNOM_CREDENTIAL_CNF_ALG = "poseidon-bn128-t3" as const;

/**
 * `POST /v1/credentials` request — the wallet origin to the attestation plane.
 *
 * The wallet computes the bands from the real DOB it holds and proves that its
 * commitment clears the ceremony threshold through the ordinary M1 path. The
 * attestation is the mint's evidence that an attestation was genuinely earned
 * for this commitment: the mint endpoint verifies it and requires the
 * requested commitment to derive to the attestation's subject seed, so a
 * random visitor cannot mint a credential for a chosen identity without first
 * completing a real ceremony. Only the wallet origin legitimately builds this
 * request; the sites origin never holds the material to construct one.
 *
 * `minted_method` and `source_assurance` are deliberately NOT request fields —
 * the issuer copies them from the verified attestation, never from the client,
 * so a caller cannot launder its claimed assurance into a signed credential.
 *
 * `passkeyId` is the device binding (architecture §6.1/§6.2): a resident
 * WebAuthn credential the wallet registers on its own origin at mint time. It
 * is signed into `cnf.passkey_id` so the credential is cryptographically bound
 * to the device that minted it (VAL-REUSE-008). Null under `?binding=soft` or
 * when registration is unavailable — the credential then degrades to soft
 * binding and the record carries no passkey reference.
 */
export const MintCredentialRequestSchema = z.strictObject({
  commitment: FieldElementSchema,
  bands: AgeBandsSchema,
  /** The M1 attestation this holder just earned for the same commitment. */
  attestation: CompactJwsSchema,
  /**
   * A fresh Groth16 proof that `commitment` opens to a date of birth clearing
   * the threshold of the HIGHEST band in `bands`, evaluated on the minting
   * ceremony's date and bound to the same ceremony nonce as the attestation.
   *
   * This is the issuer's only age evidence. The attestation authenticates the
   * commitment (and one threshold); the band proof authenticates each band the
   * credential will assert. The issuer verifies it and derives the signed band
   * map monotonically from the proven band; a request whose `bands` disagree
   * with what the proof authenticates is refused with `band_mismatch`.
   * Caller-supplied booleans are never age evidence.
   */
  bandProof: BandProofSchema,
  /**
   * Base64url credential id of the wallet-origin resident passkey registered
   * for this holder, or null when soft-bound. Absent requests (pre-binding
   * callers) are treated as soft too.
   */
  passkeyId: z.string().min(8).max(128).nullable().optional(),
});
export type MintCredentialRequest = z.infer<typeof MintCredentialRequestSchema>;

export const MintCredentialResponseSchema = z.strictObject({
  credential: CompactJwsSchema,
  /** The stored record's `credential_id`; equals the credential's own claim. */
  credentialId: CredentialIdSchema,
  issuedAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  bands: AgeBandsSchema,
});
export type MintCredentialResponse = z.infer<typeof MintCredentialResponseSchema>;

/**
 * Payload of the signed Innom age-bands credential (architecture §6.1).
 *
 * Issued by the attestation plane with the attestation key immediately after a
 * first successful M1 pass. `minted_method` and `source_assurance` are copied
 * from the verified attestation — never from the client. The commitment is the
 * same value the minting ceremony proved, which is what keeps invariant §3-2
 * ("the commitment used for verification comes from the issuer's signed
 * credential") true for the M0 presentation path.
 */
export const InnomCredentialClaimsSchema = z.strictObject({
  /** Attestation-plane issuer URL (same plane that signs attestations). */
  iss: z.string().url(),
  iat: z.number().int().positive(),
  exp: z.number().int().positive(),
  vct: z.literal(INNOM_CREDENTIAL_VCT),
  /** RFC 7800-style confirmation: the committed value the holder must open. */
  cnf: z.strictObject({
    commitment: FieldElementSchema,
    alg: z.literal(INNOM_CREDENTIAL_CNF_ALG),
    /**
     * Device binding. Null until the passkey registration feature binds the
     * credential to a resident key; the stored record keeps the reference.
     */
    passkey_id: z.string().min(8).max(128).nullable(),
  }),
  bands: AgeBandsSchema,
  /** The method class of the ceremony that minted it (always M1 in P0). */
  minted_method: MethodClassSchema,
  /** Assurance of the minting attestation (M1 = P-AAL3); caps M0 presentations. */
  source_assurance: AssuranceSchema,
  credential_id: CredentialIdSchema,
});
export type InnomCredentialClaims = z.infer<typeof InnomCredentialClaimsSchema>;
