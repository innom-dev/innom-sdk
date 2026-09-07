import type { DeviceCapabilities, Jurisdiction, PersonaId } from "@innom/schemas";

/**
 * Persona data model (architecture §12a.5).
 *
 * A persona is pure data: nothing here is detected at runtime, clocks in, or
 * reads the environment. That is what makes the demo deterministic — the same
 * actor always produces the same capability matrix, canned M4 outcome and
 * expected path from a cold profile (§13 invariant 10).
 */

/** What the actor's device carries, shown verbatim in the switcher list. */
export type PersonaDeviceSituation = "wallet" | "reusable_credential" | "neither";

/**
 * Canned M4 outcome (architecture §12a.5: "the canned M4 outcome is persona
 * data, so each persona carries its own `{age_estimate, confidence, liveness}`").
 *
 * Field names are camelCase here and snake_case on the wire; MS2's estimation
 * adapter maps between the two. Confidence is in [0, 1]. Liveness is the
 * outcome of the simulated liveness probe, not a real measurement.
 */
export interface M4Estimate {
  ageEstimate: number;
  confidence: number;
  liveness: "pass" | "fail";
}

export interface Persona {
  /** Stable identifier, also a wire value in the wallet handoff. */
  id: PersonaId;
  /** Display name, e.g. "Claire". */
  name: string;
  /** Display age in whole years (matches the DOB behind the `./dob` entry). */
  age: number;
  /** Home jurisdiction, shown in the switcher as context. */
  jurisdiction: Jurisdiction;
  /** wallet | reusable_credential | neither — drives the switcher's situation line. */
  deviceSituation: PersonaDeviceSituation;
  /** One-line description of the device situation (validation contract VAL-SWITCH-006). */
  description: string;
  /**
   * PRD persona archetype this actor exemplifies. The PRD test-mode vocabulary
   * names four: `adult-wallet`, `adult-no-wallet`, `minor`, `returning`
   * (architecture §12 conflict register: "Carry the PRD archetype as a field
   * on each persona").
   */
  prdArchetype: "adult-wallet" | "adult-no-wallet" | "minor" | "returning";
  /**
   * Deterministic device capability matrix sent to the gateway at ceremony
   * creation (VAL-SWITCH-013). A persona's matrix fully overrides device
   * detection so the request body is identical on every cold run.
   */
  capabilities: DeviceCapabilities;
  /**
   * Canned M4 estimate. Null for persona paths that never reach M4 (the three
   * wallet-holding actors).
   */
  m4Estimate: M4Estimate | null;
  /** The expected ceremony path for this actor, per the validation contract. */
  expectedPath: string;
}
