import { z } from "zod";
import { CompactJwsSchema } from "./attest.js";
import { EvidenceFormatSchema } from "./evidence.js";
import {
  AssuranceSchema,
  JurisdictionSchema,
  MethodClassSchema,
  PolicyIdSchema,
  RpIdSchema,
  Sha256HexSchema,
} from "./primitives.js";

/**
 * Content category declared by the relying party. PRD 2.3 makes this the RP's
 * assertion, not something Innom infers: we do not scan content.
 */
export const RpCategorySchema = z.enum([
  "adult",
  "dating",
  "social",
  "video_sharing",
  "gambling",
  "alcohol",
  "tobacco",
  "cannabis",
  "firearms",
  "ai_companion",
  "marketplace",
]);
export type RpCategory = z.infer<typeof RpCategorySchema>;

export const RpContextSchema = z.strictObject({
  rpId: RpIdSchema,
  displayName: z.string().min(1).max(80),
  category: RpCategorySchema,
  origin: z.string().url(),
});
export type RpContext = z.infer<typeof RpContextSchema>;

export const CategoryRuleSchema = z.strictObject({
  /** Statutory minimum age for this category in this jurisdiction. */
  threshold: z.number().int().min(1).max(120),
  minAssurance: AssuranceSchema,
  /** Statute reference that sets this threshold; rendered in the pack inspector. */
  basis: z.string().min(2).max(120),
});
export type CategoryRule = z.infer<typeof CategoryRuleSchema>;

export const EvidenceRuleSchema = z.strictObject({
  format: EvidenceFormatSchema,
  retentionDays: z.number().int().min(0).max(3650),
  /** Always `forbidden`. Present so the prohibition is visible in the artefact. */
  storeDob: z.literal("forbidden"),
});
export type EvidenceRule = z.infer<typeof EvidenceRuleSchema>;

/**
 * Legal sign-off recorded inside the pack (PRD 4.2.2: "legal review sign-off
 * recorded in-pack"). In P0 these are demo values, labelled as such by
 * `reviewStatus`.
 */
export const LegalReviewSchema = z.strictObject({
  reviewStatus: z.enum(["demo-unreviewed", "counsel-reviewed", "regulator-acknowledged"]),
  reviewedBy: z.string().min(2).max(120),
  reviewedAt: z.iso.date(),
  reference: z.string().max(200),
});
export type LegalReview = z.infer<typeof LegalReviewSchema>;

/** Jurisdiction pack payload (PRD 4.2.2). Hashed canonically to yield `packHash`. */
export const PolicyPackSchema = z.strictObject({
  pack: PolicyIdSchema,
  jurisdiction: JurisdictionSchema,
  version: z.number().int().positive(),
  effectiveFrom: z.iso.date(),
  statutes: z.array(z.string().min(2).max(64)).min(1),
  /**
   * Exhaustive by construction: `z.record` over an enum key requires every
   * category. A pack that omitted one would leave a registered relying party with
   * no resolvable threshold, and the safe failure is a build-time parse error
   * rather than a runtime fallback nobody reviewed.
   */
  categories: z.record(RpCategorySchema, CategoryRuleSchema),
  /** CNIL double anonymity: `required` activates the blinded exchange (PRD 4.3). */
  doubleAnonymity: z.enum(["required", "recommended", "not_required"]),
  /** Methods permitted at all, in waterfall order. Order is normative. */
  methodOrder: z.array(MethodClassSchema).min(1),
  /**
   * Assurance each method yields under this jurisdiction's reading. Partial: a
   * barred method has no assurance, and asserting one would be contradictory.
   * `partialRecord` still rejects keys outside the method enum, so a typo is a
   * parse error rather than a silently ignored rule.
   */
  methodAssurance: z.partialRecord(MethodClassSchema, AssuranceSchema),
  /** Methods explicitly barred, with the reason a regulator would recognise. */
  barredMethods: z.partialRecord(MethodClassSchema, z.string().min(4).max(200)),
  /** Ofcom-style challenge-age buffer for estimation (PRD 3). */
  m4ChallengeAge: z.number().int().min(1).max(120),
  /**
   * When false, a passing estimation must still cascade to a higher-assurance
   * method (Germany/KJM posture in DEMO.md 6).
   */
  m4AloneSufficient: z.boolean(),
  evidence: EvidenceRuleSchema,
  legalReview: LegalReviewSchema,
  notes: z.string().max(600),
});
export type PolicyPack = z.infer<typeof PolicyPackSchema>;

/**
 * On-disk pack file. The signature covers `sha256(canonicalize(payload))` rather
 * than the bytes, so reformatting the JSON cannot invalidate a legal artefact
 * while any semantic edit does.
 */
export const SignedPolicyPackSchema = z.strictObject({
  payload: PolicyPackSchema,
  packHash: Sha256HexSchema,
  signature: CompactJwsSchema,
});
export type SignedPolicyPack = z.infer<typeof SignedPolicyPackSchema>;

export const PackSignatureClaimsSchema = z.strictObject({
  iss: z.string().url(),
  aud: z.literal("innom-policy"),
  iat: z.number().int().positive(),
  sub: PolicyIdSchema,
  packHash: Sha256HexSchema,
});
export type PackSignatureClaims = z.infer<typeof PackSignatureClaimsSchema>;
