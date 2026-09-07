import { z } from "zod";
import { CompactJwsSchema, Groth16ProofSchema, PublicSignalsSchema } from "./attest.js";
import { PersonaIdSchema, PredicateSchema } from "./primitives.js";
import { ZkChallengeSchema } from "./ceremony.js";

/**
 * Relying party ↔ wallet handoff, carried over `postMessage`.
 *
 * The wallet is the trust anchor stand-in: it holds the date of birth, computes
 * the Poseidon commitment, has its own issuer sign that commitment, and
 * generates the Groth16 proof in its own origin. Consequently no date of birth
 * ever crosses a network boundary, which is what makes the DEMO.md 9 wire audit
 * pass rather than merely look like it passes.
 */
export const HANDOFF_PROTOCOL_VERSION = 1 as const;

export const WalletRequestSchema = z.strictObject({
  type: z.literal("innom.wallet.request"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
  /** Correlates request and response inside one browser session only. */
  requestId: z.string().min(8).max(64),
  /** Shown to the user on the consent screen. A wallet legitimately knows the RP. */
  rpDisplayName: z.string().min(1).max(80),
  rpOrigin: z.string().url(),
  predicate: PredicateSchema,
  zkChallenge: ZkChallengeSchema,
  /**
   * The demo actor driving this ceremony. The wallet resolves the persona's
   * date of birth from `@innom/personas/dob`, so no birth data crosses the
   * postMessage boundary and the wallet keeps no persona list of its own.
   */
  personaId: PersonaIdSchema,
});
export type WalletRequest = z.infer<typeof WalletRequestSchema>;

export const WalletResponseSchema = z.discriminatedUnion("ok", [
  z.strictObject({
    type: z.literal("innom.wallet.response"),
    version: z.literal(HANDOFF_PROTOCOL_VERSION),
    requestId: z.string().min(8).max(64),
    ok: z.literal(true),
    credential: CompactJwsSchema,
    proof: Groth16ProofSchema,
    publicSignals: PublicSignalsSchema,
    timings: z.strictObject({
      issueMs: z.number().nonnegative(),
      witnessMs: z.number().nonnegative(),
      provingMs: z.number().nonnegative(),
    }),
  }),
  z.strictObject({
    type: z.literal("innom.wallet.response"),
    version: z.literal(HANDOFF_PROTOCOL_VERSION),
    requestId: z.string().min(8).max(64),
    ok: z.literal(false),
    code: z.enum([
      "user_declined",
      "no_credential",
      "prover_failed",
      "issuer_unavailable",
      "unsupported_request",
    ]),
    message: z.string().max(200).optional(),
  }),
]);
export type WalletResponse = z.infer<typeof WalletResponseSchema>;

/** Sent by the wallet window once its prover assets are loaded. */
export const WalletReadySchema = z.strictObject({
  type: z.literal("innom.wallet.ready"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
});
export type WalletReady = z.infer<typeof WalletReadySchema>;

/** Progress ticks so the RP's ProofProgress shows real wallet-side phases. */
export const WalletProgressSchema = z.strictObject({
  type: z.literal("innom.wallet.progress"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
  requestId: z.string().min(8).max(64),
  phase: z.enum(["consent", "issuing", "witness", "proving"]),
  elapsedMs: z.number().nonnegative(),
});
export type WalletProgress = z.infer<typeof WalletProgressSchema>;

/**
 * Sites → wallet: the capability probe (architecture §6.3).
 *
 * Sent before a ceremony is created so `capabilities.hasInnomCredential` is
 * accurate in the initial plan. The wallet answers from its own IndexedDB and
 * the whole exchange is one boolean (VAL-REUSE-010): the relying party learns
 * whether a satisfying credential is HELD — never the bands, the identifier,
 * the expiry, the issuance time, the minting method or the assurance level.
 * The answer schema is deliberately `strictObject` with a single capability
 * field, so any future addition to the payload is a parse failure rather than
 * a silent leak.
 */
export const WalletProbeRequestSchema = z.strictObject({
  type: z.literal("innom.wallet.probe"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
  /** One probe per ceremony; correlates the answer. Not a ceremony id. */
  requestId: z.string().min(8).max(64),
  /** The gate's predicate: "do you hold a credential clearing age_over_N?". */
  ageOver: z.number().int().min(1).max(120),
});
export type WalletProbeRequest = z.infer<typeof WalletProbeRequestSchema>;

/**
 * Wallet → sites: the probe answer. One boolean and nothing else — no band
 * map, no credential identifier, no expiry, no issuance time, no minting
 * method and no assurance level (VAL-REUSE-010).
 */
export const WalletProbeAnswerSchema = z.strictObject({
  type: z.literal("innom.wallet.probe.answer"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
  requestId: z.string().min(8).max(64),
  hasCredential: z.boolean(),
});
export type WalletProbeAnswer = z.infer<typeof WalletProbeAnswerSchema>;

/**
 * SDK → wallet: mint and store the Innom credential after an M1 pass
 * (architecture §6.1).
 *
 * Sent by the relying-party SDK immediately after `/attest/zk` succeeds. The
 * wallet already holds the commitment, `dob_days` and `salt` from the proof it
 * just generated; it computes the bands and calls the attestation-plane issuer
 * itself, so neither the band map nor the credential passes through the
 * relying-party origin. `requestId` is the original handoff's id so the wallet
 * can correlate the mint to the ceremony that earned it.
 */
export const WalletMintRequestSchema = z.strictObject({
  type: z.literal("innom.wallet.mint"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
  requestId: z.string().min(8).max(64),
  /** The M1 attestation this holder just earned for this ceremony's commitment. */
  attestation: CompactJwsSchema,
});
export type WalletMintRequest = z.infer<typeof WalletMintRequestSchema>;

/**
 * Wallet → SDK: the mint attempt finished. `ok: false` (or a timeout) never
 * fails the ceremony — minting is best-effort by design (VAL-REUSE-006).
 */
export const WalletMintedSchema = z.strictObject({
  type: z.literal("innom.wallet.minted"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
  requestId: z.string().min(8).max(64),
  ok: z.boolean(),
});
export type WalletMinted = z.infer<typeof WalletMintedSchema>;

/**
 * Sites → wallet: present a stored Innom credential at a fresh ceremony
 * (architecture §6.3, VAL-REUSE-021/022/023).
 *
 * Sent instead of a consent-bound `innom.wallet.request` when the plan offers
 * M0: the wallet holds a passkey-bound credential from an earlier mint, and
 * this message asks it to release it against THIS ceremony's challenge. The
 * wallet does exactly one WebAuthn assertion — a get() against the
 * passkey_id registered at mint time, with user verification required — then
 * reads `{dob_days, salt}` from its own IndexedDB (never released) and proves
 * a FRESH Groth16 proof bound to `zkChallenge.nonce` and
 * `zkChallenge.thresholdDays`. Nothing identity-bearing crosses the channel:
 * the request is the predicate plus the challenge, the response is the stored
 * signed credential, the fresh proof and its public signals.
 *
 * The request carries no RP display context (M0 has no consent screen) and no
 * ceremony identifier — it is strict, like every wallet message, so an RP that
 * wants more must parse against a new schema rather than widen this one.
 */
export const WalletM0PresentRequestSchema = z.strictObject({
  type: z.literal("innom.wallet.m0_present"),
  version: z.literal(HANDOFF_PROTOCOL_VERSION),
  /** Correlates the response inside this browser session only. */
  requestId: z.string().min(8).max(64),
  /** The gate being asked: "do you hold a credential clearing age_over_N?". */
  predicate: PredicateSchema,
  /** The new ceremony's challenge; the fresh proof is bound to its nonce. */
  zkChallenge: ZkChallengeSchema,
});
export type WalletM0PresentRequest = z.infer<typeof WalletM0PresentRequestSchema>;

/**
 * Wallet → sites: the presentation attempt finished.
 *
 * `ok: true` releases the STORED signed credential plus a fresh proof bound to
 * the ceremony's nonce — the relying party forwards exactly these three to the
 * attestation plane. `ok: false` withholds everything and names a reason; the
 * failure codes are the contract's vocabulary (VAL-REUSE-022/023), so the
 * ceremony sheet can show a stated M0 failure without reading the wallet's
 * internals. The timings on success let the site render the <3s reuse receipt.
 */
export const WalletM0PresentResponseSchema = z.discriminatedUnion("ok", [
  z.strictObject({
    type: z.literal("innom.wallet.m0_present.response"),
    version: z.literal(HANDOFF_PROTOCOL_VERSION),
    requestId: z.string().min(8).max(64),
    ok: z.literal(true),
    /** The stored signed Innom JWS — unchanged from mint (not re-issued). */
    credential: CompactJwsSchema,
    proof: Groth16ProofSchema,
    publicSignals: PublicSignalsSchema,
    /**
     * How this credential was released. `hard` means the single WebAuthn
     * gesture happened; `soft` means `?binding=soft` was active and the
     * release skipped the passkey gesture entirely — device binding is
     * degraded and every surface labels it (VAL-REUSE-033).
     */
    binding: z.enum(["hard", "soft"]),
    timings: z.strictObject({
      /**
       * Wall-clock of the single WebAuthn assertion gesture; 0 when the
       * release was soft-bound (no gesture exists to measure).
       */
      passkeyMs: z.number().nonnegative(),
      witnessMs: z.number().nonnegative(),
      provingMs: z.number().nonnegative(),
    }),
  }),
  z.strictObject({
    type: z.literal("innom.wallet.m0_present.response"),
    version: z.literal(HANDOFF_PROTOCOL_VERSION),
    requestId: z.string().min(8).max(64),
    ok: z.literal(false),
    code: z.enum([
      /** No live stored credential clears the gate. */
      "no_credential",
      /** The only clearing credential has lapsed at its 90-day boundary. */
      "credential_expired",
      /** The credential exists but was stored without a device passkey. */
      "no_passkey",
      /**
       * The stored record's `passkey_id` mirror disagrees with the
       * issuer-signed `cnf.passkey_id`. The release is refused BEFORE any
       * gesture: a repointed mirror must never drive a get() against the
       * wrong key (ms3-scrutiny-reconcile-signed-passkey-id).
       */
      "passkey_mismatch",
      /** The get() gesture itself failed (no key on device, policy, timeout). */
      "passkey_assertion_failed",
      /** The assertion completed but user verification did not. */
      "user_verification_failed",
      /** The fresh proof could not be generated. */
      "prover_failed",
    ]),
    message: z.string().max(200).optional(),
  }),
]);
export type WalletM0PresentResponse = z.infer<typeof WalletM0PresentResponseSchema>;

/**
 * Every message either side may send over the channel.
 *
 * `WalletResponseSchema` is nested rather than spread: both of its branches carry
 * `type: "innom.wallet.response"` and discriminate on `ok`, so spreading them
 * would give the outer union two options with the same discriminator value, which
 * Zod rejects at parse time rather than at construction. Nesting keeps the fast
 * discriminated dispatch and parses both branches.
 */
export const WalletMessageSchema = z.discriminatedUnion("type", [
  WalletReadySchema,
  WalletProgressSchema,
  WalletMintRequestSchema,
  WalletMintedSchema,
  WalletProbeRequestSchema,
  WalletProbeAnswerSchema,
  WalletM0PresentRequestSchema,
  WalletM0PresentResponseSchema,
  WalletRequestSchema,
  WalletResponseSchema,
]);
export type WalletMessage = z.infer<typeof WalletMessageSchema>;

/** `POST /api/issue` on the mock wallet: commitment in, issuer JWS out. */
export const IssueCredentialRequestSchema = z.strictObject({
  commitment: z.string().regex(/^(0|[1-9][0-9]*)$/),
  /** Which real issuer this stand-in imitates. Only one profile exists in P0. */
  issuerProfile: z.literal("mock-france-identite").default("mock-france-identite"),
});
export type IssueCredentialRequest = z.infer<typeof IssueCredentialRequestSchema>;

export const IssueCredentialResponseSchema = z.strictObject({
  credential: CompactJwsSchema,
  expiresAt: z.iso.datetime(),
});
export type IssueCredentialResponse = z.infer<typeof IssueCredentialResponseSchema>;
