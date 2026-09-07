import { describe, expect, it } from "vitest";
import { ceremonyId, type MethodClass, type MethodPlan, type MethodPlanEntry } from "@innom/schemas";
import { nextExecutableMethod, pickMethod } from "../src/selectMethod.js";

/**
 * Method-route selection (VAL-SWITCH-008/009/010/011, VAL-SWITCH-028).
 *
 * The orchestrator must pick the first eligible route the pack's waterfall
 * actually executes: M1 for a wallet holder, M0 for a returning-credential
 * holder (the pack orders M0 first under every jurisdiction), M4 for a
 * wallet-less persona whose wallet rail is skipped, and — because US-CA orders
 * M3 ahead of the wallet route — never M3, which P0 renders but does not run.
 * Fixtures mirror the real plans the policy evaluator produces per persona.
 */

/**
 * A wallet-holding persona under FR: M0 ineligible (no credential), M1/M4
 * eligible, and M2/M5 offered-but-unexecuted — the not-executed methods stay
 * offered whatever the device matrix says.
 */
const WALLET_FR: readonly MethodPlanEntry[] = [
  { method: "M0", eligible: false, reason: "no_credential" },
  { method: "M1", eligible: true, assurance: "P-AAL3", estimatedMs: 9000 },
  { method: "M2", eligible: true, assurance: "P-AAL3", estimatedMs: 6000, note: "not_executed_in_demo" },
  { method: "M4", eligible: true, assurance: "P-AAL2", estimatedMs: 8000 },
  { method: "M5", eligible: true, assurance: "P-AAL3", estimatedMs: 45000, note: "not_executed_in_demo" },
  { method: "M3", eligible: false, reason: "barred_by_pack", note: "self-asserted signals are not accepted" },
];

/** Returning-credential holder: M0 leads the pack's order and is eligible everywhere. */
const RETURNING: readonly MethodPlanEntry[] = [
  { method: "M0", eligible: true, assurance: "P-AAL2", estimatedMs: 2000 },
  { method: "M1", eligible: true, assurance: "P-AAL3", estimatedMs: 9000 },
  { method: "M2", eligible: true, assurance: "P-AAL3", estimatedMs: 6000, note: "not_executed_in_demo" },
  { method: "M4", eligible: true, assurance: "P-AAL2", estimatedMs: 8000 },
  { method: "M5", eligible: true, assurance: "P-AAL3", estimatedMs: 45000, note: "not_executed_in_demo" },
];

/** Wallet-less persona under UK: M1 ineligible for the missing wallet, M4 the first runnable rail. */
const NOWALLET_UK: readonly MethodPlanEntry[] = [
  { method: "M0", eligible: false, reason: "no_credential" },
  { method: "M1", eligible: false, reason: "no_wallet" },
  { method: "M2", eligible: true, assurance: "P-AAL3", estimatedMs: 6000, note: "not_executed_in_demo" },
  { method: "M4", eligible: true, assurance: "P-AAL2", estimatedMs: 8000, challengeAge: 23 },
  { method: "M5", eligible: true, assurance: "P-AAL3", estimatedMs: 45000, note: "not_executed_in_demo" },
  { method: "M3", eligible: false, reason: "barred_by_pack", note: "highly effective standard" },
];

/**
 * US-CA wallet holder: M3 is permitted and ordered before M1 but never executed
 * in P0 — offered-but-unavailable with its low-assurance badge, so the picker
 * must skip it and land on M1.
 */
const USCA_WALLET: readonly MethodPlanEntry[] = [
  { method: "M0", eligible: false, reason: "no_credential" },
  { method: "M3", eligible: true, assurance: "P-AAL1", estimatedMs: 500, note: "not_executed_in_demo" },
  { method: "M1", eligible: true, assurance: "P-AAL3", estimatedMs: 9000 },
  { method: "M2", eligible: true, assurance: "P-AAL3", estimatedMs: 6000, note: "not_executed_in_demo" },
  { method: "M4", eligible: true, assurance: "P-AAL2", estimatedMs: 8000 },
  { method: "M5", eligible: true, assurance: "P-AAL3", estimatedMs: 45000, note: "not_executed_in_demo" },
];

const FR_CATEGORIES = {
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
} as const;

function makePlan(
  entries: readonly MethodPlanEntry[],
  jurisdiction: "FR" | "US-TX" = "FR",
  executable?: readonly MethodClass[],
): MethodPlan {
  return {
    ceremonyId: ceremonyId(),
    pack: {
      id: jurisdiction === "US-TX" ? "US-TX-adult-v4" : "FR-adult-v7",
      hash: "a".repeat(64),
      statutes: [jurisdiction === "US-TX" ? "US-TX-HB1181-2023" : "FR-SREN-2024"],
    },
    jurisdiction,
    predicate: { ageOver: 18 },
    minAssurance: "P-AAL2",
    retentionDays: jurisdiction === "US-TX" ? 0 : 180,
    doubleAnonymity: jurisdiction === "US-TX" ? "not_required" : "required",
    categories: jurisdiction === "US-TX"
      ? { ...FR_CATEGORIES, alcohol: { threshold: 21, minAssurance: "P-AAL2" } }
      : FR_CATEGORIES,
    plan: [...entries],
    // Mirrors the policy evaluator's `executable`: the ordered subset of
    // eligible entries not tagged `not_executed_in_demo`. Tests may pass an
    // explicit list to pin the "trust the wire" contract.
    executable: executable
      ? [...executable]
      : entries
          .filter((entry) => entry.eligible && entry.note !== "not_executed_in_demo")
          .map((entry) => entry.method),
    zkChallenge: {
      nonce: "123456789012345678901234567890",
      thresholdDays: 6574,
      todayDays: 53539,
      circuitId: "age_over_v1",
      circuitHash: "a".repeat(64),
    },
    challengeTicket: "aaa.bbb.ccc",
    state: "policy_resolved",
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
  };
}

describe("pickMethod", () => {
  it("makes the wallet route the live route for a wallet-holding persona (VAL-SWITCH-008)", () => {
    expect(pickMethod(makePlan(WALLET_FR))).toBe("M1");
  });

  it("makes M0 the lead route for the returning holder under FR (VAL-SWITCH-011)", () => {
    expect(pickMethod(makePlan(RETURNING))).toBe("M0");
  });

  it("keeps M0 the lead route for the returning holder under US-TX (VAL-SWITCH-011)", () => {
    expect(pickMethod(makePlan(RETURNING, "US-TX"))).toBe("M0");
  });

  it("skips the ineligible wallet rail and makes M4 the lead route for a wallet-less persona (VAL-SWITCH-009)", () => {
    expect(pickMethod(makePlan(NOWALLET_UK))).toBe("M4");
  });

  it("never stalls on US-CA's early-ordered, not-executed M3 (VAL-SWITCH-028)", () => {
    expect(pickMethod(makePlan(USCA_WALLET))).toBe("M1");
  });

  it("never returns a method P0 renders but does not execute", () => {
    for (const entries of [WALLET_FR, RETURNING, NOWALLET_UK, USCA_WALLET]) {
      const picked = pickMethod(makePlan(entries));
      expect(picked).not.toBe("M2");
      expect(picked).not.toBe("M3");
      expect(picked).not.toBe("M5");
    }
  });

  it("returns null when every route is ineligible (methods exhausted)", () => {
    const allIneligible: readonly MethodPlanEntry[] = [
      { method: "M0", eligible: false, reason: "no_credential" },
      { method: "M1", eligible: false, reason: "no_wallet" },
    ];
    expect(pickMethod(makePlan(allIneligible))).toBeNull();
  });

  it("returns null when the only eligible routes are not executed in the demo", () => {
    const onlyNotExecuted: readonly MethodPlanEntry[] = [
      { method: "M2", eligible: true, assurance: "P-AAL3", note: "not_executed_in_demo" },
      { method: "M5", eligible: true, assurance: "P-AAL3", note: "not_executed_in_demo" },
    ];
    expect(pickMethod(makePlan(onlyNotExecuted))).toBeNull();
  });

  it("walks the server-authored `executable`: an empty list exhausts methods even when the plan offers eligible ones", () => {
    // The gateway resolved this ceremony to nothing executable (a stricter
    // evaluation than this fixture's plan suggests). The SDK must trust the
    // wire list, not re-derive it from `plan` (VAL-NOCTURNE-012, §5.1).
    expect(pickMethod(makePlan(WALLET_FR, "FR", []))).toBeNull();
  });

  it("returns a valid MethodClass or null, never something else", () => {
    for (const entries of [WALLET_FR, RETURNING, NOWALLET_UK, USCA_WALLET]) {
      const picked = pickMethod(makePlan(entries));
      if (picked !== null) {
        expect((["M0", "M1", "M2", "M3", "M4", "M5"] as MethodClass[])).toContain(picked);
      }
    }
  });
});

describe("nextExecutableMethod", () => {
  it("walks the waterfall after an M0 refusal to the route that can mint a replacement", () => {
    // The returning holder's executable order is M0, M1, M4 (RETURNING above).
    // When M0's presentation is refused with credential_expired, the ceremony
    // must continue to the NEXT executable route — M1, which re-verifies and
    // mints a fresh credential (ms3-scrutiny-expired-credential-cascade).
    const plan = makePlan(RETURNING);
    expect(nextExecutableMethod(plan, "M0")).toBe("M1");
    expect(nextExecutableMethod(plan, "M1")).toBe("M4");
    expect(nextExecutableMethod(plan, "M4")).toBeNull();
  });

  it("returns null when the refused method is the last executable route", () => {
    expect(nextExecutableMethod(makePlan(NOWALLET_UK), "M4")).toBeNull();
  });

  it("returns null when the current method is not in the executable list at all", () => {
    // A not-executed route (M2/M5) or a barred one (M3) is never a cascade
    // origin: the waterfall only continues FROM a method the ceremony ran.
    const plan = makePlan(RETURNING);
    expect(nextExecutableMethod(plan, "M2")).toBeNull();
    expect(nextExecutableMethod(plan, "M3")).toBeNull();
    expect(nextExecutableMethod(plan, "M5")).toBeNull();
  });

  it("skips not-executed routes the same way pickMethod does: the wire list, never the plan", () => {
    // M2 sits between M0 and M4 in RETURNING's plan but is NOT in
    // `executable` (not_executed_in_demo), so the next runnable route after
    // M1 is M4, never M2 — the trust-the-wire rule of VAL-NOCTURNE-012.
    const plan = makePlan(RETURNING);
    expect(nextExecutableMethod(plan, "M0")).toBe("M1");
  });
});
