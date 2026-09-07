import { getPersona } from "@innom/personas";
import { DeviceCapabilitiesSchema, type DeviceCapabilities, type PersonaId } from "@innom/schemas";

/**
 * The deterministic capability matrix for a demo persona
 * (architecture §12a.5), with explicit device overrides layered on top.
 *
 * A persona's matrix is complete, so passing it to {@link detectCapabilities}
 * fully replaces device detection — the ceremony-creation body is therefore
 * identical on every cold run for a given actor (VAL-SWITCH-013,
 * VAL-SWITCH-035). Explicit `overrides` still win field-by-field, which lets
 * an integrator or the switcher perturb a single capability.
 */
export function capabilitiesForPersona(
  persona: PersonaId,
  overrides: Partial<DeviceCapabilities> = {},
): DeviceCapabilities {
  return { ...getPersona(persona).capabilities, ...overrides };
}

/**
 * Device capability detection.
 *
 * Capabilities decide which rails the waterfall can offer, so an over-optimistic
 * answer costs the user a dead end and an over-pessimistic one costs them the
 * fastest method. Every probe below is a real feature test; nothing is inferred
 * from a user-agent string.
 *
 * `hasInnomCredential` and `hasEudiWallet` cannot be feature-detected — asking the
 * browser "does this user have a wallet" would itself be a fingerprinting vector,
 * which is why the EUDI architecture routes it through an explicit user gesture.
 * The demo supplies them through `capabilities` overrides driven by the persona
 * switcher (DEMO.md 4), which is honest about the seam rather than faking it.
 *
 * A caller-supplied `hasInnomCredential` or `hasPasskey` value is a DETECTION
 * override only: in normal mode (`personaCapabilitiesAuthoritative` unset) the
 * SDK reconciles both fields against the wallet-origin possession probe before
 * the ceremony is created, so a claimed credential on an empty device can never
 * manufacture an M0-eligible plan (ms3-scrutiny-capability-override-bypass).
 */
export async function detectCapabilities(
  overrides: Partial<DeviceCapabilities> = {},
): Promise<DeviceCapabilities> {
  const detected: DeviceCapabilities = {
    hasPasskey: await detectPasskey(),
    hasInnomCredential: false,
    hasEudiWallet: false,
    hasMdl: false,
    hasOsAgeSignal: false,
    hasCamera: await detectCamera(),
    canProveZk: detectZkSupport(),
  };

  return DeviceCapabilitiesSchema.parse({ ...detected, ...overrides });
}

async function detectPasskey(): Promise<boolean> {
  if (typeof window === "undefined" || !("PublicKeyCredential" in window)) return false;
  const credential = window.PublicKeyCredential as unknown as {
    isConditionalMediationAvailable?: () => Promise<boolean>;
  };
  if (typeof credential.isConditionalMediationAvailable !== "function") return false;
  try {
    return await credential.isConditionalMediationAvailable();
  } catch {
    return false;
  }
}

/**
 * Enumerates devices rather than calling `getUserMedia`, which would raise a
 * permission prompt during capability detection — before the user has been asked
 * to verify anything.
 */
async function detectCamera(): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.mediaDevices?.enumerateDevices) return false;
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    return devices.some((device) => device.kind === "videoinput");
  } catch {
    return false;
  }
}

/**
 * The prover needs a Worker (so the main thread stays responsive), WebAssembly
 * (snarkjs's witness calculator) and BigInt. All three are required; a partial
 * environment produces a proof attempt that fails halfway through, which is worse
 * than never offering M1.
 */
function detectZkSupport(): boolean {
  return (
    typeof Worker !== "undefined" &&
    typeof WebAssembly !== "undefined" &&
    typeof BigInt !== "undefined"
  );
}
