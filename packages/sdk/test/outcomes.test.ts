import { afterEach, describe, expect, it } from "vitest";
import { ceremonyId, evidenceId, type CeremonyView, type MethodPlan, type MethodPlanEntry, type ZkChallenge } from "@innom/schemas";
import { Innom } from "../src/index.js";
import type { VerifyOutcome } from "../src/types.js";

/**
 * Terminal-outcome contract (architecture §12a.6, §12a.8; VAL-WIRE-050/051).
 *
 * `blocked` and `exhausted` are distinct SDK statuses: blocked means an
 * underage signal was observed (no recourse, no alternative), exhausted means
 * the waterfall ran out of executable methods with no underage signal and the
 * non-biometric alternative path is offered. Both carry an evidence reference
 * and no user data. The ceremonies here are driven with a stubbed fetch so the
 * assertions target the SDK's own verdict mapping, not the gateway's.
 */

const ZK_CHALLENGE: ZkChallenge = {
  nonce: "123456789012345678901234567890",
  thresholdDays: 6574,
  todayDays: 53539,
  circuitId: "age_over_v1",
  circuitHash: "a".repeat(64),
};

/** Builds a schema-valid plan whose executable list matches `executable`. */
function planWith(executable: string[], rows: MethodPlanEntry[] = unrunnableRows()): MethodPlan {
  return {
    ceremonyId: ceremonyId(),
    pack: {
      id: "FR-adult-v7",
      hash: "f".repeat(64),
      statutes: ["loi-2023-451"],
    },
    jurisdiction: "FR",
    predicate: { ageOver: 18 },
    minAssurance: "P-AAL2",
    retentionDays: 180,
    doubleAnonymity: "required",
    categories: {
      adult: { threshold: 18, minAssurance: "P-AAL2" },
      dating: { threshold: 18, minAssurance: "P-AAL2" },
      social: { threshold: 15, minAssurance: "P-AAL1" },
      video_sharing: { threshold: 18, minAssurance: "P-AAL2" },
      gambling: { threshold: 18, minAssurance: "P-AAL3" },
      alcohol: { threshold: 18, minAssurance: "P-AAL2" },
      tobacco: { threshold: 18, minAssurance: "P-AAL2" },
      cannabis: { threshold: 18, minAssurance: "P-AAL3" },
      firearms: { threshold: 18, minAssurance: "P-AAL3" },
      ai_companion: { threshold: 18, minAssurance: "P-AAL2" },
      marketplace: { threshold: 18, minAssurance: "P-AAL1" },
    },
    plan: rows,
    executable,
    zkChallenge: ZK_CHALLENGE,
    challengeTicket: "testheader.testpayload.testsignature",
    state: "policy_resolved",
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  };
}

/**
 * Every method planned but ineligible on this device (the empty-executable
 * case): no wallet, no credential, no camera, and the demo-only methods P0
 * never executes.
 */
function unrunnableRows(): MethodPlanEntry[] {
  return [
    { method: "M0", eligible: false, reason: "no_credential" },
    { method: "M1", eligible: false, reason: "no_wallet" },
    { method: "M2", eligible: true, assurance: "P-AAL3", note: "not_executed_in_demo" },
    { method: "M4", eligible: false, reason: "no_camera" },
    { method: "M5", eligible: true, assurance: "P-AAL3", note: "not_executed_in_demo" },
  ];
}

/** A terminal exhausted(view) the gateway would answer after an `exhaust` PATCH. */
function exhaustedView(evidenceRef: string): CeremonyView {
  return {
    ceremonyId: ceremonyId(),
    state: "exhausted",
    rpId: "rp_amourette",
    jurisdiction: "FR",
    predicate: { ageOver: 18 },
    pack: { id: "FR-adult-v7", hash: "f".repeat(64), statutes: ["loi-2023-451"] },
    minAssurance: "P-AAL2",
    plan: planWith([]).plan,
    activeMethod: null,
    attemptedMethods: [],
    zkChallenge: ZK_CHALLENGE,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    evidenceRef,
    m4Attestation: null,
  };
}

const REMOTE = "http://gateway.test";
const EVIDENCE_REF = evidenceId();

let originalFetch: typeof globalThis.fetch;
afterEach(() => {
  if (originalFetch) globalThis.fetch = originalFetch;
});

describe("terminal outcomes (VAL-WIRE-050/051)", () => {
  it("a ceremony with an empty executable list resolves to the SDK's own `exhausted` status, not `blocked`", async () => {
    let patched = "";
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "POST" && url.endsWith("/api/v1/ceremonies")) {
        return json(201, planWith([]));
      }
      if (method === "PATCH" && url.includes("/api/v1/ceremonies/")) {
        patched = init?.body ? String(init.body) : "";
        return json(200, exhaustedView(EVIDENCE_REF));
      }
      return json(404, {});
    }) as typeof fetch;

    const innom = Innom.init({
      publishableKey: "pk_test_amourette",
      gatewayUrl: REMOTE,
      // No persona in the shipped demo produces this combination (no wallet,
      // no camera, no credential, and everything else not executed in demo),
      // so the capabilities are forced, exactly as VAL-WIRE-051 prescribes.
      persona: "alex-16-fr",
      jurisdiction: "FR",
      capabilities: {
        hasEudiWallet: false,
        canProveZk: false,
        hasInnomCredential: false,
        hasPasskey: false,
        hasCamera: false,
        hasMdl: false,
        hasOsAgeSignal: false,
      },
    });

    const emitted: string[] = [];
    innom.on("ceremony_created", () => emitted.push("ceremony_created"));
    innom.on("exhausted", () => emitted.push("exhausted"));
    innom.on("blocked", () => emitted.push("blocked"));

    const outcome = await innom.verify({ ageOver: 18 });

    // The gateway is asked to record the terminal verdict server-side so the
    // outcome carries a resolvable evidence reference.
    expect(patched).toContain('"exhaust"');

    // `exhausted` is its own status with its own stable code, distinct from
    // the `blocked`/`predicate_not_satisfied` pair in VAL-WIRE-050.
    expect(outcome.status).toBe("exhausted");
    if (outcome.status === "exhausted") {
      expect(outcome.code).toBe("methods_exhausted");
      // Not null: the evidence record is what lets an RP show a regulator why
      // the waterfall ended.
      expect(outcome.evidenceRef).toBe(EVIDENCE_REF);
      // The non-biometric alternative path is named, not a terminal refusal.
      expect(outcome.message).toMatch(/digital ID wallet/);
      expect(outcome.message).toMatch(/in person/);
      // No user data: no estimate, no identity attributes, only presentation
      // state and a reference.
      expect(JSON.stringify(outcome)).not.toMatch(/dob|birth|estimate|confidence/i);
    }

    // Distinctness is at the discriminant: a caller switching on `status`
    // reaches different branches, and the blocked branch is still reachable as
    // a separate, differently-coded variant of the union.
    const blockedVariant: VerifyOutcome = {
      status: "blocked",
      code: "predicate_not_satisfied",
      message: "refused",
      evidenceRef: EVIDENCE_REF,
    };
    expect(blockedVariant.status).not.toBe(outcome.status);
    expect(emitted).toEqual(["ceremony_created", "exhausted"]);
  });

  it("keeps the exhausted outcome typed even when the gateway cannot record the verdict", async () => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "POST" && url.endsWith("/api/v1/ceremonies")) {
        return json(201, planWith([]));
      }
      return json(502, "Bad Gateway");
    }) as typeof fetch;

    const innom = Innom.init({
      publishableKey: "pk_test_amourette",
      gatewayUrl: REMOTE,
      persona: "alex-16-fr",
      capabilities: { hasCamera: false },
    });

    const outcome = await innom.verify({ ageOver: 18 });
    expect(outcome.status).toBe("exhausted");
    if (outcome.status === "exhausted") {
      expect(outcome.code).toBe("methods_exhausted");
      expect(outcome.evidenceRef).toBeNull();
      expect(outcome.message).toMatch(/digital ID wallet/);
    }
  });

  it("resolves cancelled — not exhausted — when the caller aborts while the exhaust PATCH is pending", async () => {
    // The ceremony sheet dismisses by aborting the run signal, and the sheet
    // stays dismissible for the whole non-terminal run: an abort landing on
    // the verdict PATCH must surface as the caller's cancellation, exactly as
    // it would on any other call in the run, never as `exhausted`.
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "POST" && url.endsWith("/api/v1/ceremonies")) {
        return json(201, planWith([]));
      }
      if (method === "PATCH" && url.includes("/api/v1/ceremonies/")) {
        // The exhaust PATCH stays in flight until the caller aborts; the real
        // transport then sees the fetch reject on abort and converts it into
        // InnomError("user_cancelled").
        const signal = init?.signal;
        return new Promise<Response>((_resolve, reject) => {
          signal?.addEventListener(
            "abort",
            () => reject(new DOMException("The user aborted a request.", "AbortError")),
            { once: true },
          );
        });
      }
      return json(404, {});
    }) as typeof fetch;

    const innom = Innom.init({
      publishableKey: "pk_test_amourette",
      gatewayUrl: REMOTE,
      persona: "alex-16-fr",
      jurisdiction: "FR",
      capabilities: {
        hasEudiWallet: false,
        canProveZk: false,
        hasInnomCredential: false,
        hasPasskey: false,
        hasMdl: false,
        hasOsAgeSignal: false,
        hasCamera: false,
      },
    });

    const emitted: string[] = [];
    innom.on("exhausted", () => emitted.push("exhausted"));
    innom.on("cancelled", () => emitted.push("cancelled"));

    const controller = new AbortController();
    const outcomePromise = innom.verify({ ageOver: 18 }, controller.signal);
    // Let the ceremony POST resolve and the exhaust PATCH reach the wire.
    await new Promise((resolve) => setTimeout(resolve, 10));
    controller.abort();
    const outcome = await outcomePromise;

    // The abort is mapped through `verify`'s existing `toOutcome`: typed
    // `cancelled`, never the swallowed `exhausted`.
    expect(outcome).toEqual({ status: "cancelled", evidenceRef: null });
    expect(emitted).toEqual([]);
  });

  it("treats a ceremony_terminal answer to the exhaust PATCH as the cancellation it already is", async () => {
    // The sheet's own cancelCeremony PATCH can land first: the gateway then
    // answers `ceremony_terminal` carrying the cancelled record's evidence
    // reference, and the SDK must report the ceremony as cancelled — never
    // `exhausted` for a record the gateway says is done.
    originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = init?.method ?? "GET";
      if (method === "POST" && url.endsWith("/api/v1/ceremonies")) {
        return json(201, planWith([]));
      }
      if (method === "PATCH" && url.includes("/api/v1/ceremonies/")) {
        return json(409, {
          error: {
            code: "ceremony_terminal",
            message: "This ceremony has already finished. state is cancelled",
            evidenceRef: EVIDENCE_REF,
            field: null,
          },
        });
      }
      return json(404, {});
    }) as typeof fetch;

    const innom = Innom.init({
      publishableKey: "pk_test_amourette",
      gatewayUrl: REMOTE,
      persona: "alex-16-fr",
      jurisdiction: "FR",
      capabilities: { hasCamera: false, hasEudiWallet: false, canProveZk: false },
    });

    const emitted: string[] = [];
    innom.on("exhausted", () => emitted.push("exhausted"));
    innom.on("cancelled", () => emitted.push("cancelled"));

    const outcome = await innom.verify({ ageOver: 18 });
    expect(outcome).toEqual({ status: "cancelled", evidenceRef: EVIDENCE_REF });
    // The cancellation is surfaced through the event stream, and the
    // exhausted branch never fires.
    expect(emitted).toEqual(["cancelled"]);
  });
});

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
