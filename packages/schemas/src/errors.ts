import { z } from "zod";
import { EvidenceIdSchema } from "./primitives.js";

/**
 * Stable, machine-readable failure taxonomy. RPs branch on these; they are part
 * of the public contract and may only be added to, never renamed.
 */
export const InnomErrorCodeSchema = z.enum([
  // Client/integration faults
  "invalid_request",
  "unknown_publishable_key",
  "unsupported_jurisdiction",
  "unsupported_predicate",
  // Ceremony lifecycle
  "ceremony_not_found",
  "ceremony_expired",
  "ceremony_terminal",
  "evidence_not_found",
  "batch_not_found",
  "batch_window_empty",
  // The window currently accepting appends cannot be anchored (VAL-EVIDENCE-026):
  // anchoring it would refuse every same-hour append that follows.
  "batch_window_open",
  // Read-only surfaces: the append-only vault refuses every mutating verb
  // (VAL-EVIDENCE-012). This is a router-level refusal, never a schema error.
  "method_not_allowed",
  "invalid_transition",
  "method_not_offered",
  "method_already_attempted",
  // Attestation faults
  "challenge_ticket_invalid",
  "challenge_ticket_expired",
  "credential_invalid",
  "credential_expired",
  "credential_untrusted_issuer",
  "commitment_mismatch",
  "nonce_mismatch",
  "threshold_mismatch",
  "clock_skew",
  "circuit_mismatch",
  "proof_invalid",
  "attestation_invalid",
  "attestation_replayed",
  // Credential mint faults (POST /v1/credentials)
  "band_mismatch",
  // Outcomes surfaced as errors to the caller
  "predicate_not_satisfied",
  "methods_exhausted",
  "user_cancelled",
  // Environment
  "prover_unavailable",
  "prover_failed",
  "wallet_unavailable",
  "network_error",
  "timeout",
  "rate_limited",
  "internal_error",
]);
export type InnomErrorCode = z.infer<typeof InnomErrorCodeSchema>;

/** HTTP status each code maps to, so every route answers consistently. */
export const ERROR_STATUS: Readonly<Record<InnomErrorCode, number>> = Object.freeze({
  invalid_request: 400,
  unknown_publishable_key: 401,
  unsupported_jurisdiction: 422,
  unsupported_predicate: 422,
  ceremony_not_found: 404,
  ceremony_expired: 410,
  ceremony_terminal: 409,
  evidence_not_found: 404,
  batch_not_found: 404,
  batch_window_empty: 422,
  batch_window_open: 422,
  method_not_allowed: 405,
  invalid_transition: 409,
  method_not_offered: 409,
  method_already_attempted: 409,
  challenge_ticket_invalid: 401,
  challenge_ticket_expired: 401,
  credential_invalid: 400,
  credential_expired: 400,
  credential_untrusted_issuer: 401,
  commitment_mismatch: 400,
  nonce_mismatch: 400,
  threshold_mismatch: 400,
  clock_skew: 400,
  circuit_mismatch: 400,
  proof_invalid: 400,
  attestation_invalid: 401,
  attestation_replayed: 409,
  band_mismatch: 400,
  predicate_not_satisfied: 403,
  methods_exhausted: 409,
  user_cancelled: 499,
  prover_unavailable: 501,
  prover_failed: 500,
  wallet_unavailable: 503,
  network_error: 502,
  timeout: 504,
  rate_limited: 429,
  internal_error: 500,
});

/**
 * Error envelope returned by every gateway route. `evidenceRef` is present
 * whenever the failure was recorded, which is what lets an RP prove to a
 * regulator that it blocked someone. It carries no user data.
 */
export const InnomErrorBodySchema = z.strictObject({
  error: z.strictObject({
    code: InnomErrorCodeSchema,
    message: z.string().min(1).max(300),
    evidenceRef: EvidenceIdSchema.nullish(),
    /** Field path for `invalid_request`, e.g. `predicate.ageOver`. */
    field: z.string().max(120).nullish(),
  }),
});
export type InnomErrorBody = z.infer<typeof InnomErrorBodySchema>;
