import { z } from "zod";
import { assertNoPii } from "./pii.js";
import {
  AssuranceSchema,
  EvidenceIdSchema,
  JurisdictionSchema,
  MethodClassSchema,
  PolicyIdSchema,
  PrefixedSha256Schema,
  RpIdSchema,
  Sha256HexSchema,
} from "./primitives.js";

export const EvidenceOutcomeSchema = z.enum([
  "pass",
  "block",
  "cascade",
  "exhausted",
  "cancelled",
  "expired",
  "error",
]);
export type EvidenceOutcome = z.infer<typeof EvidenceOutcomeSchema>;

/**
 * Why a ceremony did not pass. Deliberately coarse: fine-grained failure
 * reasons are how evidence logs turn into behavioural profiles.
 *
 * The three estimation-band reasons are distinct because a below-threshold
 * estimate (band 4, `estimate_below_threshold` — also the `block` code), an
 * estimate sitting between the threshold and the challenge age (band 3,
 * `estimate_ambiguous`) and an estimate above the challenge age that policy
 * still refuses to let M4 decide alone (band 2, `m4_not_alone_sufficient`)
 * are genuinely different things an auditor needs to keep apart
 * (architecture §7, VAL-EVIDENCE-002/003).
 */
export const EvidenceFailureCodeSchema = z.enum([
  "predicate_not_satisfied",
  "proof_invalid",
  "credential_invalid",
  "credential_expired",
  "commitment_mismatch",
  "nonce_mismatch",
  "challenge_stale",
  "circuit_mismatch",
  "method_unavailable",
  "estimate_below_threshold",
  "estimate_ambiguous",
  "m4_not_alone_sufficient",
  "user_cancelled",
  "ceremony_expired",
  "internal_error",
]);
export type EvidenceFailureCode = z.infer<typeof EvidenceFailureCodeSchema>;

/**
 * Merkle placement (PRD 4.2.7). Populated when the hourly batch closes; the M1
 * store records the batch key and leaf so M3 can build roots without a
 * migration.
 */
export const MerklePlacementSchema = z.strictObject({
  batch: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}$/, "expected YYYY-MM-DDTHH"),
  index: z.number().int().nonnegative(),
  leaf: Sha256HexSchema,
  root: Sha256HexSchema.nullable(),
});
export type MerklePlacement = z.infer<typeof MerklePlacementSchema>;

/** A Merkle batch window key: the UTC hour `YYYY-MM-DDTHH` (architecture §10). */
export const MerkleBatchKeySchema = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}$/, "expected YYYY-MM-DDTHH");
export type MerkleBatchKey = z.infer<typeof MerkleBatchKeySchema>;

/**
 * A closed Merkle batch (architecture §10). Rows are anchored once: `root` is
 * the tree built over `leaves` (ordered by Merkle index ascending, odd node
 * promoted unchanged); `leaf_count` mirrors the leaves array so an auditor can
 * check size without trusting a second source. `closed_at` records when the
 * window was anchored. The wire object is what an offline inclusion-proof
 * script and the console batch browser read (VAL-EVIDENCE-013/020/021).
 */
export const MerkleBatchSchema = z.strictObject({
  batch: MerkleBatchKeySchema,
  root: Sha256HexSchema,
  leaf_count: z.number().int().nonnegative(),
  leaves: z.array(Sha256HexSchema),
  closed_at: z.iso.datetime(),
});
export type MerkleBatch = z.infer<typeof MerkleBatchSchema>;

/** Close-request body: which batch window to anchor. */
export const CloseBatchRequestSchema = z.strictObject({
  batch: MerkleBatchKeySchema,
});
export type CloseBatchRequest = z.infer<typeof CloseBatchRequestSchema>;

/**
 * One level of a Merkle inclusion proof. `direction` names which side the
 * sibling occupies relative to the current node at that level: `"right"`
 * means the parent is `sha256(current || sibling)`, `"left"` means the parent
 * is `sha256(sibling || current)`. A level where the node was promoted
 * unchanged (an odd trailing node, never duplicated) carries NO step — so a
 * promoted node's proof never contains a sibling equal to the node itself
 * (VAL-EVIDENCE-029). The direction is load-bearing: a verifier that sorts
 * each pair instead of honoring the recorded order would accept a flipped
 * flag, which is exactly the tamper case VAL-EVIDENCE-029(b) pins.
 */
export const MerkleProofStepSchema = z.strictObject({
  sibling: Sha256HexSchema,
  direction: z.enum(["left", "right"]),
});
export type MerkleProofStep = z.infer<typeof MerkleProofStepSchema>;

/**
 * An inclusion proof for one row of a closed batch (VAL-EVIDENCE-028). The
 * verifier recomputes the root from `leaf` through `steps` and compares it to
 * `root`; `root` is restated here so a consumer can cross-check the proof
 * against the batch's published root without a second request. Standalone
 * verifiers must consume exactly this shape with no repository imports.
 */
export const MerkleProofSchema = z.strictObject({
  batch: MerkleBatchKeySchema,
  index: z.number().int().nonnegative(),
  leaf: Sha256HexSchema,
  root: Sha256HexSchema,
  steps: z.array(MerkleProofStepSchema),
});
export type MerkleProof = z.infer<typeof MerkleProofSchema>;

/**
 * Evidence record (DEMO.md 7, PRD 4.2.7). Append-only. Every field here must be
 * defensible to a regulator *and* useless to an attacker, which is why the
 * schema is strict and `assertEvidenceRecord` runs the PII gate.
 */
export const EvidenceRecordSchema = z.strictObject({
  evidence_id: EvidenceIdSchema,
  ts: z.iso.datetime(),
  rp_id: RpIdSchema,
  jurisdiction: JurisdictionSchema,
  policy_id: PolicyIdSchema,
  policy_hash: Sha256HexSchema,
  /**
   * The method rail this record concerns. Never null: `method_class` is the
   * 13th of the vault's key set and the Postgres column is NOT NULL.
   *
   * For a record where NO method executed — an `exhausted` ceremony whose
   * waterfall ran out before any attempt, or a `cancelled`/`expired` ceremony
   * dismissed before the first offer — this names the rail the ceremony was
   * heading for (the first executable method, else the first policy-eligible
   * plan entry), and the record never claims the method ran: `outcome`,
   * `failure_code` and the transcript digest carry whether it did. The
   * no-decision outcomes use the explicit zero digest, and the
   * no-executable-methods exhaustion hashes a version-1 digest containing no
   * `method_class` at all (demo claim C4: nothing may read back as a method
   * executed when none was).
   */
  method_class: MethodClassSchema,
  assurance: AssuranceSchema,
  outcome: EvidenceOutcomeSchema,
  failure_code: EvidenceFailureCodeSchema.nullable(),
  transcript_hash: PrefixedSha256Schema,
  /** Retention ceiling copied from the pack at write time, in days. */
  retention_days: z.number().int().min(0).max(3650),
  merkle: MerklePlacementSchema,
});
export type EvidenceRecord = z.infer<typeof EvidenceRecordSchema>;

export function assertEvidenceRecord(value: unknown): EvidenceRecord {
  const record = EvidenceRecordSchema.parse(value);
  assertNoPii(record, "evidence");
  return record;
}

/**
 * The vault's own account of how append-only is enforced (VAL-EVIDENCE-014).
 *
 * Served as `metadata` on the evidence listing and carried verbatim in the
 * export artifact, so both surfaces tell the same story. The statement is
 * deliberately precise on the two points an auditor probes:
 *
 *   - enforcement is at the DATABASE level, by a trigger that raises on
 *     UPDATE and DELETE — never "by convention";
 *   - there is exactly ONE permitted mutation, the Merkle-root backfill at
 *     batch close — never "no mutation of any kind is possible", which would
 *     be untrue given the backfill.
 *
 * Both keys and values are kept out of the wire-audit pattern set (the
 * word-boundary terms `dob|birth|name|document|...`), because the full
 * serialized listing and export — metadata included — are VAL-EVIDENCE-008
 * sweep surfaces.
 *
 * The `anchoring` block (VAL-EVIDENCE-026) explains the one value in the vault
 * that reads as a gap without context: a row whose `merkle.root` is null. Null
 * is not a missing anchor or an unverifiable row — it is a row whose batch
 * window was still open for appends when it was read. Both the listing and the
 * export serve this exact object, so the question "why is this root null?" is
 * answered on every surface a row appears on.
 */
export const EvidenceVaultMetadataSchema = z.strictObject({
  appendOnly: z.strictObject({
    enforcement: z.literal("database_trigger"),
    statement: z.string(),
    permittedMutation: z.strictObject({
      scope: z.literal("merkle_root_backfill"),
      statement: z.string(),
    }),
  }),
  anchoring: z.strictObject({
    scope: z.literal("merkle_root_null"),
    statement: z.string(),
  }),
});
export type EvidenceVaultMetadata = z.infer<typeof EvidenceVaultMetadataSchema>;

export const EVIDENCE_VAULT_METADATA: EvidenceVaultMetadata = {
  appendOnly: {
    enforcement: "database_trigger",
    statement:
      "Append-only is enforced at the database level by a trigger on the evidence table that raises an exception on any UPDATE or DELETE.",
    permittedMutation: {
      scope: "merkle_root_backfill",
      statement:
        "The single permitted mutation is the Merkle-root backfill performed when a batch closes: rows in the closing batch receive merkle.root once, equal to the batch's published root. No other mutation is possible.",
    },
  },
  anchoring: {
    scope: "merkle_root_null",
    statement:
      "A row with merkle.root: null is not yet anchored in a closed batch: its batch window was still open for appends when the row was read, so the batch root does not exist yet. The row itself is sealed in the append-only vault, and it receives the batch's published root exactly once, at batch close. A closed batch never changes again.",
  },
};

/**
 * Evidence artifact formats a regulator export may be rendered under. The
 * policy pack declares the format its jurisdiction's regime expects
 * (`EvidenceRuleSchema.format`), and an export request may select any of them
 * as an output profile (architecture §11.1): the choice re-renders the same
 * PII-free facts and never restates which regime governs them, changes
 * retention, or alters which records are included.
 */
export const EvidenceFormatSchema = z.enum(["arcom-v2", "ofcom-heaa-v1", "kjm-v1", "generic-v1"]);
export type EvidenceFormat = z.infer<typeof EvidenceFormatSchema>;

/**
 * A regulator export artifact (architecture §11.1, VAL-EVIDENCE-031/032/034).
 *
 * One JSON document per jurisdiction, emitted under the policy pack's own
 * declared evidence format identifier by default (or the export request's
 * chosen output profile) and carrying the pack's retention value.
 * `range` restates the bounds the artifact was generated for (inclusive on
 * both ends, normalised to UTC ISO), `count` mirrors `rows`, and every row is
 * a plain EvidenceRecord — the export adds context around the records, never
 * fields inside them. The artifact is deterministic: no generation timestamp,
 * so two downloads of the same range are byte-identical.
 */
export const EvidenceExportSchema = z.strictObject({
  artifact: z.literal("innom-evidence-export"),
  version: z.literal(1),
  format: EvidenceFormatSchema,
  jurisdiction: JurisdictionSchema,
  policy_id: PolicyIdSchema,
  policy_hash: Sha256HexSchema,
  /**
   * The vault's enforcement statement (VAL-EVIDENCE-014): identical to the
   * metadata the evidence listing serves, so the export an auditor takes away
   * states its own enforcement mechanism and the single Merkle-root carve-out.
   */
  metadata: EvidenceVaultMetadataSchema,
  /** Retention ceiling from the pack, in days — same value every row carries. */
  retention_days: z.number().int().min(0).max(3650),
  /**
   * Prose explanation of the retention value, or null when the pack needs no
   * special wording. A `retention_days` of 0 (US-TX) must always carry prose:
   * zero refers to identifying information, of which PII-free records contain
   * none, and the record itself is still retained (architecture §8.2).
   */
  retention_note: z.string().max(600).nullable(),
  range: z.strictObject({
    from: z.iso.datetime().nullable(),
    to: z.iso.datetime().nullable(),
  }),
  count: z.number().int().nonnegative(),
  rows: z.array(EvidenceRecordSchema),
});
export type EvidenceExport = z.infer<typeof EvidenceExportSchema>;

export function assertEvidenceExport(value: unknown): EvidenceExport {
  const parsed = EvidenceExportSchema.parse(value);
  assertNoPii(parsed, "evidence_export");
  return parsed;
}

/**
 * Inputs hashed into `transcript_hash`. Canonicalised and hashed, never stored:
 * the hash lets an auditor confirm a decision was replayed bit-for-bit
 * (PRD S2) while the inputs themselves stay off disk.
 */
export const TranscriptInputSchema = z.strictObject({
  version: z.literal(1),
  circuit_id: z.string(),
  circuit_hash: Sha256HexSchema,
  verification_key_hash: Sha256HexSchema,
  public_signals: z.array(z.string()),
  proof_hash: Sha256HexSchema,
  credential_issuer: z.string(),
  credential_jti: z.string(),
  policy_hash: Sha256HexSchema,
  method_class: MethodClassSchema,
  attested_at: z.iso.datetime(),
});
export type TranscriptInput = z.infer<typeof TranscriptInputSchema>;
