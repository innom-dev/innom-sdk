import type { DeviceCapabilities, PersonaId } from "@innom/schemas";
import type { Persona } from "./types.js";

/**
 * The seven demo actors (architecture §12a.5, validation contract "Personas").
 *
 * Four are wallet-less (`sam-19-uk-nowallet`, `dana-27-de`, `alex-16-fr`,
 * `jordan-20-tx`) and walk M4 without ever mounting the wallet iframe
 * (§12a.11); three are wallet-holding (`claire-31-fr`, `claire-returning`,
 * `nina-19-fr`). DOBs deliberately do not live in this module — they are
 * behind the `./dob` entry point so only the wallet origin ever sees them.
 *
 * The array is frozen at module load: deterministic paths from cold profiles
 * (§13 invariant 10) is a data property, not a convention.
 */

const WITHOUT_WALLET: Omit<DeviceCapabilities, "hasEudiWallet" | "canProveZk"> = {
  hasMdl: false,
  hasOsAgeSignal: false,
  hasCamera: true, // the M4 capture_sim rail (VAL-SWITCH-013: no-wallet bodies assert a camera)
  hasPasskey: false,
  hasInnomCredential: false,
};

const PERSONAS: readonly Persona[] = Object.freeze([
  Object.freeze({
    id: "claire-31-fr",
    name: "Claire",
    age: 31,
    jurisdiction: "FR",
    deviceSituation: "wallet",
    description: "France Identité wallet holder, no reusable credential yet.",
    prdArchetype: "adult-wallet",
    capabilities: Object.freeze<DeviceCapabilities>({
      ...WITHOUT_WALLET,
      hasEudiWallet: true,
      canProveZk: true,
    }),
    m4Estimate: null,
    expectedPath: "FR M1 ZK proof → token → credential minted",
  }),
  Object.freeze({
    id: "claire-returning",
    name: "Claire",
    age: 31,
    jurisdiction: "FR",
    deviceSituation: "reusable_credential",
    description: "Holds a passkey-bound Innom credential after a first pass.",
    prdArchetype: "returning",
    capabilities: Object.freeze<DeviceCapabilities>({
      ...WITHOUT_WALLET,
      hasEudiWallet: true,
      canProveZk: true,
      hasPasskey: true,
      hasInnomCredential: true,
    }),
    m4Estimate: null,
    expectedPath: "Any RP, M0 one tap under 3s",
  }),
  Object.freeze({
    id: "nina-19-fr",
    name: "Nina",
    age: 19,
    jurisdiction: "FR",
    deviceSituation: "wallet",
    description: "EUDI wallet holder whose credential must not clear a 21 gate.",
    prdArchetype: "adult-wallet",
    capabilities: Object.freeze<DeviceCapabilities>({
      ...WITHOUT_WALLET,
      hasEudiWallet: true,
      canProveZk: true,
    }),
    m4Estimate: null,
    expectedPath: "Mints bands 15/18 true, 21 false",
  }),
  Object.freeze({
    id: "sam-19-uk-nowallet",
    name: "Sam",
    age: 19,
    jurisdiction: "UK",
    deviceSituation: "neither",
    description: "No wallet, no credential; front-facing camera only.",
    prdArchetype: "adult-no-wallet",
    capabilities: Object.freeze<DeviceCapabilities>({
      ...WITHOUT_WALLET,
      hasEudiWallet: false,
      canProveZk: false,
    }),
    m4Estimate: Object.freeze({ ageEstimate: 24, confidence: 0.87, liveness: "pass" }),
    expectedPath: "UK, M1 skipped → M4 band 1 → pass",
  }),
  Object.freeze({
    id: "dana-27-de",
    name: "Dana",
    age: 27,
    jurisdiction: "DE",
    deviceSituation: "neither",
    description: "No wallet, no credential; forces DE's estimation-cascade card.",
    prdArchetype: "adult-no-wallet",
    capabilities: Object.freeze<DeviceCapabilities>({
      ...WITHOUT_WALLET,
      hasEudiWallet: false,
      canProveZk: false,
    }),
    m4Estimate: Object.freeze({ ageEstimate: 27, confidence: 0.93, liveness: "pass" }),
    expectedPath: "DE, M4 band 2 → forced cascade",
  }),
  Object.freeze({
    id: "alex-16-fr",
    name: "Alex",
    age: 16,
    jurisdiction: "FR",
    deviceSituation: "neither",
    description: "No wallet, no credential; underage at every FR gate.",
    prdArchetype: "minor",
    capabilities: Object.freeze<DeviceCapabilities>({
      ...WITHOUT_WALLET,
      hasEudiWallet: false,
      canProveZk: false,
    }),
    m4Estimate: Object.freeze({ ageEstimate: 17, confidence: 0.76, liveness: "pass" }),
    expectedPath: "FR, M4 band 4 → cascade → blocked",
  }),
  Object.freeze({
    id: "jordan-20-tx",
    name: "Jordan",
    age: 20,
    jurisdiction: "US-TX",
    deviceSituation: "neither",
    description: "No wallet, no credential; 20 against Nocturne's 21 gate.",
    prdArchetype: "minor",
    capabilities: Object.freeze<DeviceCapabilities>({
      ...WITHOUT_WALLET,
      hasEudiWallet: false,
      canProveZk: false,
    }),
    m4Estimate: Object.freeze({ ageEstimate: 20, confidence: 0.83, liveness: "pass" }),
    expectedPath: "US-TX 21 gate → band 4 → blocked",
  }),
]);

/**
 * The actor the SDK and wallet use when nothing selected one: the M1 baseline
 * persona the demo starts on (claire-31-fr).
 */
export const DEFAULT_PERSONA_ID: PersonaId = "claire-31-fr";

/** Every persona, in contract-table order. Frozen; do not mutate. */
export function allPersonas(): readonly Persona[] {
  return PERSONAS;
}

/** Looks up a persona by id; throws on an unknown id rather than guessing. */
export function getPersona(id: PersonaId): Persona {
  const persona = PERSONAS.find((candidate) => candidate.id === id);
  if (!persona) {
    throw new Error(`no demo persona "${id}"; known: ${PERSONAS.map((p) => p.id).join(", ")}`);
  }
  return persona;
}

/** The deterministic device capability matrix for a persona. */
export function personaCapabilities(id: PersonaId): DeviceCapabilities {
  return getPersona(id).capabilities;
}
