import { z } from "zod";
import { CompactJwsSchema } from "./attest.js";
import {
  AssuranceSchema,
  Base64UrlSchema,
  CeremonyIdSchema,
  DeviceCapabilitiesSchema,
  EvidenceIdSchema,
  JurisdictionSchema,
  MethodClassSchema,
  PersonaIdSchema,
  PolicyIdSchema,
  PredicateSchema,
  RpIdSchema,
  Sha256HexSchema,
} from "./primitives.js";
import { RpCategorySchema } from "./policy.js";

/**
 * Ceremony state machine (DEMO.md 5). M1 implements the M0-independent subset:
 * policy_resolved → method_offered → proving → proof_verifying → token_issued,
 * plus the terminal failure states. `presenting`, `estimating` and
 * `threshold_check` are declared here because the state type is the single
 * source of truth and M2 must not redefine it.
 */
export const CeremonyStateSchema = z.enum([
  "idle",
  "policy_resolved",
  "method_offered",
  "presenting",
  "proving",
  "estimating",
  "proof_verifying",
  "threshold_check",
  "cascade",
  "token_issued",
  "blocked",
  "exhausted",
  "cancelled",
  "expired",
]);
export type CeremonyState = z.infer<typeof CeremonyStateSchema>;

export const TERMINAL_CEREMONY_STATES: ReadonlySet<CeremonyState> = new Set<CeremonyState>([
  "token_issued",
  "blocked",
  "exhausted",
  "cancelled",
  "expired",
]);

/** Why a method is not offered. Rendered verbatim on MethodCard. */
export const IneligibilityReasonSchema = z.enum([
  "no_credential",
  "no_wallet",
  "no_mdl",
  "no_camera",
  "no_passkey",
  "no_zk_support",
  "barred_by_pack",
  "below_min_assurance",
  "already_attempted",
]);
export type IneligibilityReason = z.infer<typeof IneligibilityReasonSchema>;

export const MethodPlanEntrySchema = z.strictObject({
  method: MethodClassSchema,
  eligible: z.boolean(),
  /** Assurance this method would yield if it succeeds. Absent when ineligible. */
  assurance: AssuranceSchema.optional(),
  reason: IneligibilityReasonSchema.optional(),
  estimatedMs: z.number().int().nonnegative().optional(),
  challengeAge: z.number().int().min(1).max(120).optional(),
  note: z.string().max(240).optional(),
});
export type MethodPlanEntry = z.infer<typeof MethodPlanEntrySchema>;

export const PackRefSchema = z.strictObject({
  id: PolicyIdSchema,
  hash: Sha256HexSchema,
  statutes: z.array(z.string().min(2).max(64)).min(1),
});
export type PackRef = z.infer<typeof PackRefSchema>;

/**
 * Server-authored challenge for the committed-DOB circuit. The client needs
 * these to build a witness; the attestation plane recomputes every one of them
 * from its own ceremony record and never trusts the echoed copy.
 */
export const ZkChallengeSchema = z.strictObject({
  /** Ceremony-bound freshness value, a bn128 field element as decimal string. */
  nonce: z.string().regex(/^(0|[1-9][0-9]*)$/),
  /** Days between the statutory cut-off date and today (calendar-exact). */
  thresholdDays: z.number().int().min(0).max(65535),
  /** Days since 1970-01-01 UTC for the gateway's current date. */
  todayDays: z.number().int().min(0).max(65535),
  /** Circuit build identity; a proof from another build must not verify. */
  circuitId: z.string().min(3).max(64),
  circuitHash: Sha256HexSchema,
});
export type ZkChallenge = z.infer<typeof ZkChallengeSchema>;

/**
 * One category's statutory threshold serialized on the plan wire, so the sheet
 * can attribute each number to its category — US-CA's social 15 beside the
 * enforced dating 18, US-TX's alcohol 21/P-AAL2 — rather than inventing a
 * client-side copy of the pack (architecture §8.1, VAL-SWITCH-018/020).
 */
export const CategoryThresholdRuleSchema = z.strictObject({
  threshold: z.number().int().min(1).max(120),
  minAssurance: AssuranceSchema,
});
export type CategoryThresholdRule = z.infer<typeof CategoryThresholdRuleSchema>;

/** Every statutory category of the resolved pack, in authored order. */
export const CategoryThresholdsSchema = z.record(RpCategorySchema, CategoryThresholdRuleSchema);
export type CategoryThresholds = z.infer<typeof CategoryThresholdsSchema>;

/** `POST /v1/ceremonies` response (DEMO.md 7). */
export const MethodPlanSchema = z.strictObject({
  ceremonyId: CeremonyIdSchema,
  pack: PackRefSchema,
  jurisdiction: JurisdictionSchema,
  predicate: PredicateSchema,
  minAssurance: AssuranceSchema,
  /**
   * Evidence retention in days for the resolved pack. Zero means the pack
   * retains no identifying information; the audit record itself survives
   * (architecture §8.2, VAL-SWITCH-018).
   */
  retentionDays: z.number().int().nonnegative(),
  /**
   * The pack's double-anonymity stance, shown on the policy strip so the
   * "attestation plane never learns the destination" promise is a visible
   * property of the resolved pack (VAL-SWITCH-010).
   */
  doubleAnonymity: z.enum(["required", "recommended", "not_required"]),
  categories: CategoryThresholdsSchema,
  plan: z.array(MethodPlanEntrySchema).min(1),
  /**
   * The ordered subset of `plan` the ceremony orchestrator will actually
   * attempt: eligible and not tagged `not_executed_in_demo` (architecture
   * §5.1). The UI renders the full `plan` — offered-but-unavailable routes stay
   * visible with their labels — while the SDK walks `executable`, so US-CA's
   * early-ordered M3 (plannable, never executed in this demo) is never
   * selected (VAL-NOCTURNE-010/012, VAL-SWITCH-028). Empty when nothing can
   * run; the SDK then records a terminal `exhausted` outcome server-side (an
   * `exhaust` advance, VAL-WIRE-051) rather than pausing at the offer.
   */
  executable: z.array(MethodClassSchema),
  zkChallenge: ZkChallengeSchema,
  /**
   * Acceptance-plane authorisation the client hands to the attestation plane
   * (PRD 4.3 step 1). Contains the statement to prove and deliberately nothing
   * about the relying party or the ceremony.
   */
  challengeTicket: CompactJwsSchema,
  state: CeremonyStateSchema,
  expiresAt: z.iso.datetime(),
});
export type MethodPlan = z.infer<typeof MethodPlanSchema>;

/** `POST /v1/ceremonies` request body. */
export const CeremonyInitRequestSchema = z.strictObject({
  publishableKey: z.string().min(8).max(128),
  predicate: PredicateSchema,
  /** `auto` defers to the gateway's resolution; the demo switcher pins it. */
  jurisdiction: z.union([JurisdictionSchema, z.literal("auto")]).default("auto"),
  capabilities: DeviceCapabilitiesSchema,
  /**
   * Demo actor driving the ceremony (architecture §12a.5). The persona's
   * canned M4 estimate lives in `@innom/personas`, so the acceptance
   * plane needs the identifier to resolve the estimation adapter's answer.
   * A persona id is a demo label, not identity: the date of birth behind it
   * stays in the wallet origin and never reaches this request (§13-1).
   */
  persona: PersonaIdSchema.optional(),
  /** Echoed back by the SDK for correlation; never persisted. */
  clientRef: z.string().max(64).optional(),
});
export type CeremonyInitRequest = z.infer<typeof CeremonyInitRequestSchema>;

/**
 * `PATCH /v1/ceremonies/{id}` — client-driven state transitions.
 *
 * `cancel` records a `cancelled` terminal with a no-decision transcript;
 * `exhaust` records a terminal `exhausted` (the waterfall ran out of
 * executable methods with no underage signal — architecture §12a.6). Both are
 * terminal outcomes with a resolvable evidence reference, and both are legal
 * from any non-terminal state: the acceptance plane owns the audit record, so
 * a client cannot mint a token out of either.
 */
export const CeremonyAdvanceRequestSchema = z.strictObject({
  event: z.enum([
    "offer",
    "wallet_open",
    "consent",
    "proving_started",
    "capture_sim",
    "cancel",
    "exhaust",
  ]),
  method: MethodClassSchema.optional(),
});
export type CeremonyAdvanceRequest = z.infer<typeof CeremonyAdvanceRequestSchema>;

/** `GET /v1/ceremonies/{id}` and the `PATCH` response. */
export const CeremonyViewSchema = z.strictObject({
  ceremonyId: CeremonyIdSchema,
  state: CeremonyStateSchema,
  rpId: RpIdSchema,
  jurisdiction: JurisdictionSchema,
  predicate: PredicateSchema,
  pack: PackRefSchema,
  minAssurance: AssuranceSchema,
  plan: z.array(MethodPlanEntrySchema),
  activeMethod: MethodClassSchema.nullable(),
  attemptedMethods: z.array(MethodClassSchema),
  zkChallenge: ZkChallengeSchema,
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  evidenceRef: EvidenceIdSchema.nullable(),
  /**
   * Attestation-plane result for a band-1 M4 pass (architecture §7). The
   * estimator runs server-side; a passing estimate is signed into an M4
   * attestation that the client exchanges through the ordinary `POST
   * /tokens` path, so the single-use mint gates stay in one place. Absent
   * unless the ceremony is sitting at `threshold_check` with a pass.
   */
  m4Attestation: CompactJwsSchema.nullable(),
});
export type CeremonyView = z.infer<typeof CeremonyViewSchema>;

/**
 * Public event stream consumed by `Innom.on("ceremony:state", ...)`. Carries
 * only presentation state; no user data by construction.
 */
export const CeremonyEventSchema = z.strictObject({
  ceremonyId: CeremonyIdSchema,
  state: CeremonyStateSchema,
  activeMethod: MethodClassSchema.nullable(),
  plan: z.array(MethodPlanEntrySchema),
  pack: PackRefSchema,
  /** Sub-step label for ProofProgress: witness | proving | verifying. */
  phase: z.enum(["idle", "handoff", "witness", "proving", "verifying", "minting", "done"]),
  /** Real measured milliseconds per phase; drives the on-screen timings. */
  timings: z.record(z.string(), z.number().nonnegative()),
  message: z.string().max(200).optional(),
});
export type CeremonyEvent = z.infer<typeof CeremonyEventSchema>;

/** Successful `Innom.verify()` resolution (DEMO.md 4). */
export const VerifyResultSchema = z.strictObject({
  token: Base64UrlSchema.or(z.string().min(20)),
  assurance: AssuranceSchema,
  method: MethodClassSchema,
  expiresAt: z.iso.datetime(),
  ceremonyId: CeremonyIdSchema,
  evidenceRef: EvidenceIdSchema,
});
export type VerifyResult = z.infer<typeof VerifyResultSchema>;
