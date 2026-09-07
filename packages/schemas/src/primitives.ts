import { z } from "zod";

/**
 * Jurisdictions shipped as signed policy packs. M1 ships FR only; M2 adds the
 * remaining four (DEMO.md 6).
 */
export const JurisdictionSchema = z.enum(["FR", "UK", "DE", "US-TX", "US-CA"]);
export type Jurisdiction = z.infer<typeof JurisdictionSchema>;

/** Method registry identifiers (PRD 4.2.1). */
export const MethodClassSchema = z.enum(["M0", "M1", "M2", "M3", "M4", "M5"]);
export type MethodClass = z.infer<typeof MethodClassSchema>;

/**
 * P0 demo persona identifiers (architecture §12a.5, validation contract
 * "Personas"). Seven actors: four wallet-less, three wallet-holding.
 *
 * The identifier is part of the wallet handoff — the relying party names the
 * actor so the wallet (which holds the date of birth) resolves the same persona
 * from `@innom/personas` rather than duplicating it. It is a wire
 * identifier in P0 because the wallet is a simulated stand-in; a production
 * handoff would name a holder session instead.
 */
export const PersonaIdSchema = z.enum([
  "claire-31-fr",
  "claire-returning",
  "nina-19-fr",
  "sam-19-uk-nowallet",
  "dana-27-de",
  "alex-16-fr",
  "jordan-20-tx",
]);
export type PersonaId = z.infer<typeof PersonaIdSchema>;

/** Innom assurance classes (PRD 4.2.1). */
export const AssuranceSchema = z.enum(["P-AAL1", "P-AAL2", "P-AAL3"]);
export type Assurance = z.infer<typeof AssuranceSchema>;

/** Ordering used when a pack declares `min_assurance`. */
export const ASSURANCE_RANK: Readonly<Record<Assurance, number>> = Object.freeze({
  "P-AAL1": 1,
  "P-AAL2": 2,
  "P-AAL3": 3,
});

export function meetsAssurance(actual: Assurance, minimum: Assurance): boolean {
  return ASSURANCE_RANK[actual] >= ASSURANCE_RANK[minimum];
}

/**
 * The only predicate class in P0. `ageOver` is a whole number of years; the
 * statutory thresholds in scope are 13/15/16/18/21.
 */
export const PredicateSchema = z.strictObject({
  ageOver: z.number().int().min(1).max(120),
});
export type Predicate = z.infer<typeof PredicateSchema>;

/** Wire form of the predicate inside a IAT (snake_case per PRD 4.2.3). */
export const PredicateClaimSchema = z.strictObject({
  age_over: z.number().int().min(1).max(120),
});
export type PredicateClaim = z.infer<typeof PredicateClaimSchema>;

/** Lowercase hex, no prefix. */
export const HexSchema = z
  .string()
  .regex(/^[0-9a-f]+$/, "expected lowercase hex")
  .min(2);

export const Sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/, "expected 32-byte sha256 hex");

/** `sha256:<64 hex>` — the transcript hash form used in evidence records. */
export const PrefixedSha256Schema = z
  .string()
  .regex(/^sha256:[0-9a-f]{64}$/, "expected sha256:<hex>");

export const Base64UrlSchema = z
  .string()
  .regex(/^[A-Za-z0-9_-]+$/, "expected unpadded base64url")
  .min(1);

/** A bn128 field element rendered as a decimal string (snarkjs convention). */
export const FieldElementSchema = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/, "expected non-negative decimal integer string");

/**
 * Identifier scheme: `<prefix>_<base32-crockford>`. Matches the sample values in
 * DEMO.md 7 (`cer_01J9ZW3E8KQ4`, `iat_01J9ZW9QF2`, `ev_01J9ZWA3TP`).
 */
export function prefixedIdSchema(prefix: string) {
  return z.string().regex(new RegExp(`^${prefix}_[0-9A-HJKMNP-TV-Z]{10,26}$`), {
    error: `expected ${prefix}_<crockford base32>`,
  });
}

export const CeremonyIdSchema = prefixedIdSchema("cer");
export const TokenIdSchema = prefixedIdSchema("iat");
export const EvidenceIdSchema = prefixedIdSchema("ev");
export const CredentialIdSchema = prefixedIdSchema("cred");
export const AttestationIdSchema = prefixedIdSchema("att");

export type CeremonyId = z.infer<typeof CeremonyIdSchema>;
export type EvidenceId = z.infer<typeof EvidenceIdSchema>;

/** Relying-party identifier as it appears in the IAT `aud` claim. */
export const RpIdSchema = z.string().regex(/^rp_[a-z0-9_]{3,40}$/, "expected rp_<slug>");
export type RpId = z.infer<typeof RpIdSchema>;

/** Policy pack identifier, e.g. `FR-adult-v7`. */
export const PolicyIdSchema = z
  .string()
  .regex(/^[A-Z]{2}(-[A-Z]{2})?-[a-z0-9]+-v\d+$/, "expected e.g. FR-adult-v7");
export type PolicyId = z.infer<typeof PolicyIdSchema>;

/** Device capability flags fed to the policy evaluator (PRD 4.2.2). */
export const DeviceCapabilitiesSchema = z.strictObject({
  hasEudiWallet: z.boolean(),
  hasMdl: z.boolean(),
  hasOsAgeSignal: z.boolean(),
  hasCamera: z.boolean(),
  hasPasskey: z.boolean(),
  hasInnomCredential: z.boolean(),
  /** Client can run the WASM prover (memory + WebAssembly + Worker present). */
  canProveZk: z.boolean(),
});
export type DeviceCapabilities = z.infer<typeof DeviceCapabilitiesSchema>;

export const DEFAULT_DEVICE_CAPABILITIES: DeviceCapabilities = Object.freeze({
  hasEudiWallet: false,
  hasMdl: false,
  hasOsAgeSignal: false,
  hasCamera: false,
  hasPasskey: false,
  hasInnomCredential: false,
  canProveZk: false,
});
