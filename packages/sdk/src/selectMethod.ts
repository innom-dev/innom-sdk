import type { MethodClass, MethodPlan } from "@innom/schemas";

/**
 * Route selection (VAL-SWITCH-008/009/010/011, VAL-SWITCH-028).
 *
 * The policy pack's waterfall order already encodes the preference: M0 first
 * for a returning-credential holder, M1 for a wallet holder, M4 for a
 * wallet-less persona whose wallet rail is skipped, and under US-CA M3 ahead of
 * the wallet route. The gateway serializes the ordered attempt list as
 * `plan.executable` (§5.1) — eligible routes the ceremony orchestrator will
 * actually attempt, i.e. eligible entries in pack order that are not tagged
 * `not_executed_in_demo`. The SDK trusts that wire list rather than
 * re-deriving it from `plan`, so US-CA's early-ordered M3 (plannable yet never
 * executed in this demo) can never be selected, and a plan whose `executable`
 * is empty rightfully exhausts methods even when the plan still offers not-
 * executed routes (VAL-NOCTURNE-012, VAL-SWITCH-028).
 */

/**
 * The method the ceremony will attempt: the first entry in the gateway's
 * `executable` order that the caller has not excluded, or `null` when nothing
 * executable remains.
 *
 * `exclude` is the relying party's "use another method" gesture: the user
 * declined the lead route on a previous run, so the next run must start from
 * the route after it. Exclusion never reorders — pack order still decides.
 */
export function pickMethod(plan: MethodPlan, exclude: readonly MethodClass[] = []): MethodClass | null {
  return plan.executable.find((method) => !exclude.includes(method)) ?? null;
}

/**
 * The route the ceremony's waterfall continues to after `current` fails to
 * run (architecture §5 cascade semantics).
 *
 * The gateway's ordered `executable` list is the attempt order — the same
 * list {@link pickMethod} trusts — so the next candidate is simply the entry
 * after `current`. An M0 presentation refused with `credential_expired` is
 * exactly this case: the wallet purged the expired record, and the next
 * executable method (M1 for the returning holder) can re-verify and mint a
 * fresh credential, so the run must continue to it instead of dead-ending on
 * the refusal (ms3-scrutiny-expired-credential-cascade).
 */
export function nextExecutableMethod(
  plan: MethodPlan,
  current: MethodClass,
  exclude: readonly MethodClass[] = [],
): MethodClass | null {
  const index = plan.executable.indexOf(current);
  if (index === -1) return null;
  return plan.executable.slice(index + 1).find((method) => !exclude.includes(method)) ?? null;
}
