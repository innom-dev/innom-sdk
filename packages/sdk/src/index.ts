import { DEFAULT_PERSONA_ID } from "@innom/personas";
import type {
  DeviceCapabilities,
  Jurisdiction,
  MethodClass,
  MethodPlan,
  PersonaId,
  TokenMintResponse,
} from "@innom/schemas";
import { capabilitiesForPersona, detectCapabilities } from "./capabilities.js";
import { walletIframePermissionsPolicy } from "./iframePermissions.js";
import { nextExecutableMethod, pickMethod } from "./selectMethod.js";
import { GatewayTransport } from "./transport.js";
import { newRequestId, WalletChannel } from "./walletChannel.js";
import type {
  InnomEvent,
  InnomEventListener,
  InnomEventType,
  InnomInitOptions,
  Unsubscribe,
  VerifyOptions,
  VerifyOutcome,
} from "./types.js";
import { InnomError } from "./types.js";

export { InnomError } from "./types.js";
export type {
  InnomEvent,
  InnomEventListener,
  InnomEventType,
  InnomInitOptions,
  Unsubscribe,
  VerifyOptions,
  VerifyOutcome,
} from "./types.js";
export { capabilitiesForPersona, detectCapabilities } from "./capabilities.js";
export { walletIframePermissionsPolicy } from "./iframePermissions.js";
export { statusForErrorCode } from "./transport.js";

/**
 * Innom client SDK.
 *
 * One instance per relying-party origin. `init` is cheap and idempotent; `verify`
 * runs a single ceremony and resolves with a token or a typed failure.
 *
 * The SDK never touches user data. The wallet (a separate origin) holds the date
 * of birth, computes the commitment, and generates the proof. The SDK's job is
 * to relay the challenge to the wallet, relay the proof to the attestation
 * plane, and relay the attestation back to the acceptance plane for a token.
 * Every relay is schema-validated, so a drift in any API surface fails with a
 * typed error rather than a runtime crash inside a customer's checkout flow.
 */

const DEFAULT_GATEWAY_URL = "http://localhost:4000";
const DEFAULT_WALLET_URL = "http://localhost:4002";

/**
 * Terminal M4 outcome copy. Dignified and empty of data: the refusal states
 * that access cannot be granted and discloses no estimate, confidence or any
 * age other than the statutory threshold (VAL-NOCTURNE-021). The exhausted
 * variant names the non-biometric alternative the PRD requires (§12a.6).
 */
const REFUSAL_MESSAGE =
  "We could not verify the age required for this content, so access cannot be granted. Nothing about you was shared with the site.";
const EXHAUSTED_MESSAGE =
  "No verification method could be completed on this device. You can still verify with a digital ID wallet, or visit in person — no camera needed.";

/**
 * Fallback copy for a refused one-tap presentation when the wallet's response
 * carries no message of its own. The codes are the M0 contract's vocabulary
 * (schema `WalletM0PresentResponseSchema`); name-only, no credential content.
 */
const M0_REFUSAL_MESSAGES: Record<string, string> = {
  no_credential: "No reusable credential on this device clears this gate.",
  credential_expired:
    "The reusable credential on this device has expired. Verify again to mint a fresh one.",
  no_passkey: "The stored credential has no device passkey binding; one tap is not available for it.",
  passkey_mismatch:
    "The stored record disagrees with the device binding the issuer signed; the credential was not released.",
  passkey_assertion_failed: "The device passkey could not be asserted; the credential was not released.",
  user_verification_failed: "User verification did not complete; the credential was not released.",
  prover_failed: "A fresh proof could not be generated; the credential was not released.",
};

/** Resolves after `ms`, or immediately when the caller aborts. */
function delayMs(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}

/**
 * Best-effort wait for an iframe's initial navigation to commit.
 *
 * Used before the first wallet request post: until the frame's `src` document
 * loads, its window is an `about:blank` document inheriting the embedding
 * page's origin, so a wallet-origin-targeted postMessage warns ("target origin
 * does not match the recipient window's origin") and is dropped. Best-effort
 * rather than a gate: if the frame never fires `load`, the wait releases after
 * the timeout and WalletChannel.exchange's retry interval delivers the request
 * anyway.
 */
function waitForFrameLoad(frame: HTMLIFrameElement, timeoutMs = 10_000): Promise<void> {
  return new Promise<void>((resolve) => {
    const finish = (): void => {
      clearTimeout(timer);
      frame.removeEventListener("load", onLoad);
      resolve();
    };
    const onLoad = (): void => finish();
    const timer = setTimeout(finish, timeoutMs);
    frame.addEventListener("load", onLoad);
  });
}

/**
 * The wallet-origin address of the capability probe (architecture §6.3).
 *
 * A hidden frame runs the probe against the wallet's lightweight `/probe`
 * surface (apps/wallet/app/probe/route.ts) rather than the full wallet page:
 * the answer is read from the same IndexedDB store the ceremony writes, but
 * the frame costs tens of milliseconds instead of a React hydration, which
 * keeps the probe inside the M0 reuse (<3s) and switcher re-resolution
 * (<300ms) budgets. The wallet's soft-binding mode (`?binding=soft` on the
 * relying party's page) is forwarded like the ceremony frame's URL, because
 * the probe's releasability answer depends on the mode (VAL-REUSE-033).
 */
function walletProbeUrl(walletUrl: string): string {
  const url = new URL(walletUrl);
  url.pathname = "/probe";
  url.search = "";
  url.hash = "";
  const binding = new URLSearchParams(globalThis.location.search).get("binding");
  if (binding) url.searchParams.set("binding", binding);
  return url.toString();
}

export class Innom {
  private readonly publishableKey: string;
  private readonly gatewayUrl: string;
  private readonly walletUrl: string;
  private readonly jurisdiction: Jurisdiction | "auto";
  private readonly persona: PersonaId | undefined;
  private readonly capabilityOverrides: Partial<DeviceCapabilities>;
  private readonly personaCapabilitiesAuthoritative: boolean;
  private readonly transport: GatewayTransport;
  private readonly listeners = new Map<InnomEventType, Set<InnomEventListener>>();
  /**
   * The ceremony this instance opened. Set once the gateway answers with a
   * plan, cleared when the run reaches its outcome. This is what lets a
   * relying party dismiss a live ceremony through {@link cancelCeremony} and
   * still get an audit trail: without it the sheet would have to reach into
   * transport internals to cancel.
   */
  private activeCeremony: { ceremonyId: string } | null = null;

  private constructor(options: InnomInitOptions) {
    this.publishableKey = options.publishableKey;
    this.gatewayUrl = options.gatewayUrl ?? DEFAULT_GATEWAY_URL;
    this.walletUrl = options.walletUrl ?? DEFAULT_WALLET_URL;
    this.jurisdiction = options.jurisdiction ?? "auto";
    this.persona = options.persona;
    this.capabilityOverrides = options.capabilities ?? {};
    this.personaCapabilitiesAuthoritative = options.personaCapabilitiesAuthoritative ?? false;
    this.transport = new GatewayTransport({ gatewayUrl: this.gatewayUrl });
  }

  static init(options: InnomInitOptions): Innom {
    return new Innom(options);
  }

  /**
   * Run a full age-verification ceremony.
   *
   * Never rejects: every error path is a resolved value so callers can use a
   * single `switch` without a try/catch wrapper.
   */
  async verify(options: VerifyOptions, signal?: AbortSignal): Promise<VerifyOutcome> {
    try {
      return await this.runCeremony(options, signal);
    } catch (error) {
      return this.toOutcome(error);
    }
  }

  /**
   * Cancels the ceremony this instance is running and returns the evidence
   * reference of the resulting `cancelled` record.
   *
   * The server-side half of a user-initiated dismissal: a relying party whose
   * sheet lets the user escape mid-ceremony must record a real cancellation —
   * with an audit reference to prove it — rather than let the ceremony die
   * silently and sweep as `expired`. Best-effort by design: resolves `null`
   * when no ceremony is active or the gateway is unreachable, and never
   * throws. Each call is one fire-and-forget PATCH, so a double dismissal
   * converges on the same cancelled record (a second PATCH against a terminal
   * ceremony surfaces its evidenceRef through the gateway's error envelope).
   */
  async cancelCeremony(): Promise<{ evidenceRef: string | null } | null> {
    const ceremony = this.activeCeremony;
    if (!ceremony) return null;
    try {
      const view = await this.transport.advanceCeremony(ceremony.ceremonyId, {
        event: "cancel",
      });
      return { evidenceRef: view.evidenceRef };
    } catch (error) {
      if (error instanceof InnomError) {
        // Already terminal (e.g. a racing second dismissal): the gateway
        // answers with the record's own evidenceRef in the error envelope.
        return { evidenceRef: error.evidenceRef };
      }
      return null;
    }
  }

  on<T extends InnomEventType>(type: T, listener: InnomEventListener<T>): Unsubscribe {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(listener as unknown as InnomEventListener);
    return () => set!.delete(listener as unknown as InnomEventListener);
  }

  private emit(event: InnomEvent): void {
    const set = this.listeners.get(event.type);
    if (!set) return;
    for (const listener of set) {
      (listener as InnomEventListener)(event);
    }
  }

  private async runCeremony(options: VerifyOptions, signal?: AbortSignal): Promise<VerifyOutcome> {
    const capabilities = await this.resolveCapabilities();

    // Real credential probe before the ceremony is created (architecture
    // §6.3, ms3-scrutiny-capability-override-bypass). The wallet-origin
    // possession probe is AUTHORITATIVE in normal mode: it runs before every
    // ceremony — persona or not — and its one-boolean answer, real device
    // state read from the wallet origin's own IndexedDB, overrides BOTH the
    // persona matrix's static credential claims AND any caller-supplied
    // `capabilities.hasInnomCredential` / `hasPasskey` overrides. A
    // `claire-returning` persona on a fresh device whose wallet store is
    // empty therefore plans M0 ineligible (`no_credential`) instead of
    // inheriting the matrix's `true`; a production caller who supplies
    // `capabilities: { hasInnomCredential: true, hasPasskey: true }` on an
    // empty device gets the same honest answer instead of a manufactured
    // M0-eligible plan; and a device that genuinely holds a releasable
    // credential is upgraded even when the matrix or caller claims none
    // (VAL-REUSE-029). An unreachable wallet resolves false and the plan
    // reflects the device's real inability to present.
    //
    // One seam may bypass the probe, and only that one:
    //
    //  - `personaCapabilitiesAuthoritative` trusts the configured persona's
    //    credential claims (plus any caller overrides layered on them) and
    //    skips the probe entirely — an explicit test-mode flag for scripts
    //    that must pin persona behaviour independent of device state (e.g.
    //    driving the wallet's expired-credential refusal path). Without this
    //    flag the real store always decides, which is what stops a claimed
    //    credential on an empty device from ever manufacturing an M0-eligible
    //    plan.
    if (!this.personaCapabilitiesAuthoritative && typeof window !== "undefined") {
      const held = await this.probeWalletForCredential(options.ageOver);
      capabilities.hasInnomCredential = held;
      // A releasable credential implies the release gesture exists on the
      // device; a store that holds none leaves no passkey for the one-tap
      // either. Both fields must be true for M0 to be offered, and the
      // gateway evaluates them independently.
      capabilities.hasPasskey = held;
    }

    const plan = await this.transport.createCeremony(
      {
        publishableKey: this.publishableKey,
        predicate: { ageOver: options.ageOver },
        jurisdiction: this.jurisdiction,
        capabilities,
        // The demo actor rides along so the acceptance plane can resolve the
        // M4 estimator's canned answer (architecture §12a.5). It is a wire
        // identifier, and it never appears in any gateway response.
        persona: this.persona,
      },
      signal,
    );
    this.emit({ type: "ceremony_created", plan });
    this.activeCeremony = { ceremonyId: plan.ceremonyId };

    const method = this.pickMethod(plan, options.excludeMethods);
    if (!method) {
      // Empty `executable`: every planned route is ineligible on this device or
      // not executed in this demo, and no underage signal was ever observed —
      // the waterfall simply ran out of methods. That is `exhausted`, a
      // terminal distinct from `blocked` (no recourse vs. a non-biometric
      // alternative path), per architecture §12a.6/§12a.8 and VAL-WIRE-051.
      // The verdict is recorded server-side so the outcome carries a genuine
      // evidence reference; if the gateway cannot record it the outcome stays
      // typed with the alternative path named and no reference.
      let evidenceRef: string | null = null;
      try {
        const view = await this.transport.advanceCeremony(
          plan.ceremonyId,
          { event: "exhaust" },
          signal,
        );
        evidenceRef = view.evidenceRef;
      } catch (error) {
        // Two real, typed failures must not be filed as exhaustion:
        //
        //  - `user_cancelled`: the caller aborted while the verdict PATCH was
        //    in flight (the ceremony sheet dismisses by aborting the run
        //    signal). Rethrow so `verify`'s existing `toOutcome` types it as
        //    `cancelled`, exactly as any other call in the run would.
        //  - `ceremony_terminal`: the record already reached a terminal — the
        //    sheet's own `cancelCeremony()` PATCH landing first is the
        //    canonical race. Treat it as the cancellation it already is,
        //    carrying the terminal record's own evidence reference from the
        //    error envelope, and drop the now-stale ceremony reference.
        if (error instanceof InnomError && error.code === "user_cancelled") {
          this.activeCeremony = null;
          throw error;
        }
        if (error instanceof InnomError && error.code === "ceremony_terminal") {
          this.activeCeremony = null;
          evidenceRef = error.evidenceRef;
          this.emit({ type: "cancelled", evidenceRef });
          return { status: "cancelled", evidenceRef };
        }
        // Any other gateway failure: the verdict could not be recorded. The
        // outcome stays typed `exhausted` with the alternative path named and
        // no reference (the 502 test in outcomes.test.ts pins this).
      }
      this.activeCeremony = null;
      this.emit({
        type: "exhausted",
        code: "methods_exhausted",
        message: EXHAUSTED_MESSAGE,
        evidenceRef,
      });
      return {
        status: "exhausted",
        code: "methods_exhausted",
        message: EXHAUSTED_MESSAGE,
        evidenceRef,
      };
    }

    const entry = plan.plan.find((e) => e.method === method)!;
    this.emit({ type: "method_offered", method, entry });

    await this.transport.advanceCeremony(plan.ceremonyId, { event: "offer", method }, signal);

    if (method === "M4") {
      // The wallet-less rail: the estimator runs server-side and the ceremony
      // resolves to a pass, a refusal, or exhaustion (architecture §7).
      return await this.runM4Flow(plan, method, signal);
    }

    if (method === "M0") {
      // The one-tap rail: present a stored passkey-bound credential against
      // this ceremony and exchange a fresh proof through the ordinary
      // attestation route (architecture §6.3, VAL-REUSE-015/016/017/018).
      return await this.runM0Flow(plan, method, options, signal);
    }

    if (method !== "M1") {
      // Any other offered method (M2, M5) is planned but not executed in this
      // build, so the ceremony pauses at the offer — the relying party
      // keeps rendering its waterfall and the caller decides what to show.
      //
      // `activeCeremony` is deliberately left set on this path: the gateway
      // record is still live, and a user who dismisses the parked sheet must
      // still produce a real `cancelled` record rather than letting the
      // ceremony sweep as `expired`.
      return {
        status: "blocked",
        code: "method_not_offered",
        message: `${method} is planned but not executed in this build; the ceremony stops at the offer.`,
        evidenceRef: null,
      };
    }

    return await this.runM1Flow(plan, method, options, signal);
  }

  /**
   * The ceremony-creation capability matrix. A configured persona supplies its
   * full deterministic matrix, so device detection is skipped entirely — the
   * two async probes (passkey mediation, camera enumeration) take hundreds of
   * milliseconds each ceremony and are fully overridden anyway. Skipping them
   * is what keeps a switcher re-resolution inside the 300ms budget
   * (VAL-SWITCH-022). Without a persona, detection runs and fills the rest.
   * Explicit `capabilities` overrides win field-by-field either way.
   */
  private async resolveCapabilities(): Promise<DeviceCapabilities> {
    if (this.persona) {
      return capabilitiesForPersona(this.persona, this.capabilityOverrides);
    }
    return detectCapabilities(this.capabilityOverrides);
  }

  /**
   * Picks the method the ceremony will attempt. See {@link pickMethod}: the
   * pack's waterfall order, minus routes P0 renders but does not execute, so
   * the lead route always matches the selected pack and persona
   * (VAL-SWITCH-008/009/010/011, VAL-SWITCH-028).
   */
  private pickMethod(plan: MethodPlan, exclude: readonly MethodClass[] = []): MethodClass | null {
    return pickMethod(plan, exclude);
  }

  private async runM1Flow(
    plan: MethodPlan,
    method: MethodClass,
    options: VerifyOptions,
    signal?: AbortSignal,
  ): Promise<VerifyOutcome> {
    await this.transport.advanceCeremony(plan.ceremonyId, { event: "wallet_open", method }, signal);
    this.emit({ type: "wallet_opened", method });

    const { frame: walletFrame, owned } = this.mountWalletFrame(options.walletContainer);
    try {
      const channel = new WalletChannel({
        walletUrl: this.walletUrl,
        targetWindow: walletFrame.contentWindow!,
      });

      // A freshly mounted iframe's window is an `about:blank` document that
      // inherits the embedding page's origin until its `src` commits. Posting
      // the wallet-origin-targeted request before that commit makes Chrome log
      // a target-origin mismatch and silently drop the message; the exchange's
      // retry interval would eventually deliver it, but that console noise is
      // exactly what the embed's cleanliness contract forbids. Wait for the
      // wallet document to load so the very first post is truly wallet-origin.
      await waitForFrameLoad(walletFrame);

      const requestId = newRequestId();
      const rpOrigin = globalThis.location.origin;

      const response = await channel.exchange({
        requestId,
        predicate: plan.predicate,
        zkChallenge: plan.zkChallenge,
        rpDisplayName: this.extractRpName(),
        rpOrigin,
        personaId: this.persona ?? DEFAULT_PERSONA_ID,
        onProgress: (progress) => {
          this.emit({ type: "progress", phase: progress.phase, elapsedMs: progress.elapsedMs });
        },
        signal,
      });

      if (!response.ok) {
        if (response.code === "user_declined") {
          // The user's own "no" is a first-class outcome, not a failure: the
          // gateway records a `cancelled` evidence record whose reference the
          // relying party can show ("nothing was shared, no token issued").
          const view = await this.transport
            .advanceCeremony(plan.ceremonyId, { event: "cancel" })
            .catch(() => null);
          const evidenceRef = view?.evidenceRef ?? null;
          this.activeCeremony = null;
          this.emit({ type: "cancelled", evidenceRef });
          return { status: "cancelled", evidenceRef };
        }
        return {
          status: "error",
          code: "prover_failed",
          message: response.message ?? response.code,
        };
      }

      await this.transport.advanceCeremony(
        plan.ceremonyId,
        { event: "proving_started", method },
        signal,
      );

      const attestation = await this.transport.attestZk(
        {
          challengeTicket: plan.challengeTicket,
          credential: response.credential,
          proof: response.proof,
          publicSignals: response.publicSignals,
          provingMs: Math.round(response.timings.provingMs),
        },
        signal,
      );
      this.emit({
        type: "attested",
        assurance: attestation.assurance,
        verifiedInMs: attestation.verifiedInMs,
      });

      // Mint the long-lived Innom credential from the wallet on an M1 pass
      // (architecture §6.1). The wallet computes the bands from the real DOB
      // it holds, calls the attestation-plane issuer itself and stores the
      // record in its own IndexedDB, so the credential and band map never
      // pass through this relying party. Best-effort and awaited only up to
      // the channel's 400ms cap, so the store is populated before the reveal
      // in the healthy case while a lost or stalled wallet ack can never push
      // the token mint past VAL-REUSE-006's 500ms disturbance budget: the ack
      // is a store-population gate, never a ceremony gate (VAL-REUSE-001/006).
      await channel.requestCredentialMint({
        requestId,
        attestation: attestation.attestation,
      });

      const token = await this.transport.mintToken(
        { ceremonyId: plan.ceremonyId, attestation: attestation.attestation },
        signal,
      );
      // Terminal: the ceremony is spent, so a later cancelCeremony() must not
      // touch it (it would surface the success reference as though cancelled).
      this.activeCeremony = null;
      this.emit({ type: "verified", result: token });

      if (options.deliver === "cookie" && options.sessionEndpoint) {
        await this.deliverCookie(token, options.sessionEndpoint);
      }

      return { status: "verified", result: token };
    } finally {
      this.unmountWalletFrame(walletFrame, owned);
    }
  }

  /**
   * The M0 one-tap rail (architecture §6.3, VAL-REUSE-015/016/017/018).
   *
   * The ceremony plan offered a stored reusable credential as the lead route,
   * so instead of opening a consent-bound wallet request this flow asks the
   * wallet to PRESENT the credential: one `innom.wallet.m0_present` round
   * trip performs the single passkey assertion (the one tap, with user
   * verification required), reads `{dob_days, salt}` inside the wallet origin,
   * and returns the STORED signed credential plus a fresh Groth16 proof bound
   * to THIS ceremony's nonce and threshold. The SDK relays exactly those three
   * to the attestation plane — the same route M1 uses, where the verifier
   * derives `method_class: "M0"` and the P-AAL2 ceiling from the verified
   * credential kind (VAL-REUSE-020).
   *
   * No consent screen, no persona picker, no second gesture: the passkey
   * assertion is the only user interaction after the gate opens. The fresh
   * proof makes this a real cryptographic presentation, not a replayed bearer
   * token, and it is ceremony-bound by the nonce public input (§13 invariant
   * 12). An expired, absent, soft-bound or non-clearing credential is withheld
   * by the wallet with a stated reason, which surfaces as a `prover_failed`
   * error carrying the wallet's message — the same error vocabulary the M1
   * rail uses for a wallet-side failure.
   */
  private async runM0Flow(
    plan: MethodPlan,
    method: MethodClass,
    options: VerifyOptions,
    signal?: AbortSignal,
  ): Promise<VerifyOutcome> {
    await this.transport.advanceCeremony(plan.ceremonyId, { event: "wallet_open", method }, signal);
    this.emit({ type: "wallet_opened", method });

    const { frame: walletFrame, owned } = this.mountWalletFrame(options.walletContainer);
    try {
      const channel = new WalletChannel({
        walletUrl: this.walletUrl,
        targetWindow: walletFrame.contentWindow!,
      });

      // Same first-post discipline as runM1Flow: wait for the wallet document
      // so the very first post targets a real wallet-origin window.
      await waitForFrameLoad(walletFrame);

      const requestId = newRequestId();
      const response = await channel.presentCredential({
        requestId,
        predicate: plan.predicate,
        zkChallenge: plan.zkChallenge,
        signal,
      });

      if (!response.ok) {
        // The one-tap could not release the credential. For an EXPIRED
        // credential this is a device-side dead end, not a ceremony verdict:
        // the wallet has already purged the lapsed record (so it can never be
        // selected again), and the ceremony's own waterfall (§5.1) still holds
        // a further executable route — M1 for the returning holder — which can
        // re-verify and MINT a fresh credential. Cascade that route on THIS
        // ceremony instead of ending the run at the refusal, so the surfaced
        // instruction to "verify again to mint a fresh one" actually completes
        // (ms3-scrutiny-expired-credential-cascade).
        if (response.code === "credential_expired") {
          const next = nextExecutableMethod(plan, method, options.excludeMethods);
          if (next !== null) {
            // The ceremony state machine (PATCH /ceremonies/{id}) treats
            // `offer` as legal from any non-terminal state, so the record —
            // currently parked at `presenting` for M0 — is moved to the next
            // offered route exactly as the cascade walk intends (§5).
            const entry = plan.plan.find((candidate) => candidate.method === next);
            await this.transport.advanceCeremony(
              plan.ceremonyId,
              { event: "offer", method: next },
              signal,
            );
            if (entry) this.emit({ type: "method_offered", method: next, entry });
            // Tear the M0 presentation frame down before the next rail mounts
            // its own, so never two overlays for one ceremony.
            this.unmountWalletFrame(walletFrame, owned);
            if (next === "M1") return await this.runM1Flow(plan, next, options, signal);
            if (next === "M4") return await this.runM4Flow(plan, next, signal);
            // M2/M5: planned but not executed in this build; park the
            // ceremony at the offer exactly like a first-selected one (§5.1).
            this.activeCeremony = null;
            return {
              status: "blocked",
              code: "method_not_offered",
              message: `${next} is planned but not executed in this build; the ceremony stops at the offer.`,
              evidenceRef: null,
            };
          }
        }
        // No further executable route could carry the ceremony, or the refusal
        // was for a non-expiry cause (no_credential / no_passkey / a refused
        // or failed assertion / a failed proof). The wallet withheld
        // everything, so nothing reached the gateway; report the typed failure
        // with the wallet's own stated reason. The ceremony record is left to
        // the sweep: this is a device-side refusal, not a user cancellation,
        // and no evidence of a decision was produced.
        this.activeCeremony = null;
        return {
          status: "error",
          code: response.code === "credential_expired" ? "credential_expired" : "prover_failed",
          message: response.message ?? M0_REFUSAL_MESSAGES[response.code] ?? response.code,
        };
      }

      // The presentation is a real ceremony step with real measured timings:
      // surface the passkey gesture and the fresh proof into the receipt the
      // relying party renders, then advance the state machine as a proving
      // ceremony and exchange the proof through the ordinary attestation route.
      this.emit({ type: "progress", phase: "passkey", elapsedMs: response.timings.passkeyMs });
      this.emit({ type: "progress", phase: "witness", elapsedMs: response.timings.witnessMs });
      this.emit({ type: "progress", phase: "proving", elapsedMs: response.timings.provingMs });

      await this.transport.advanceCeremony(
        plan.ceremonyId,
        { event: "proving_started", method },
        signal,
      );

      const attestation = await this.transport.attestZk(
        {
          challengeTicket: plan.challengeTicket,
          credential: response.credential,
          proof: response.proof,
          publicSignals: response.publicSignals,
          provingMs: Math.round(response.timings.provingMs),
        },
        signal,
      );
      this.emit({
        type: "attested",
        assurance: attestation.assurance,
        verifiedInMs: attestation.verifiedInMs,
      });

      const token = await this.transport.mintToken(
        { ceremonyId: plan.ceremonyId, attestation: attestation.attestation },
        signal,
      );
      // Terminal: the ceremony is spent, so a later cancelCeremony() must not
      // touch it.
      this.activeCeremony = null;
      this.emit({ type: "verified", result: token });

      if (options.deliver === "cookie" && options.sessionEndpoint) {
        await this.deliverCookie(token, options.sessionEndpoint);
      }

      return { status: "verified", result: token };
    } finally {
      this.unmountWalletFrame(walletFrame, owned);
    }
  }

  /**
   * The M4 estimation rail (architecture §7).
   *
   * The estimator runs server-side with a canned delay; the SDK advances the
   * ceremony with `capture_sim` and then polls until the verdict lands. The
   * gateway's poll-driven resolution means the wire itself shows the ceremony
   * passing through `estimating`, and a reloading client converges on the
   * same terminal without re-running the estimator.
   *
   * Outcomes: a band-1 pass parks the ceremony at `threshold_check` with an
   * M4 attestation which this flow exchanges through the ordinary token route
   * (single-use gates stay in one place); bands 2-4 cascade to a terminal —
   * `blocked` when an underage signal was observed, `exhausted` otherwise.
   * The terminal views carry the evidence reference and never a number: the
   * site learns "refused", not "estimated at 20" (VAL-NOCTURNE-021).
   */
  private async runM4Flow(
    plan: MethodPlan,
    method: MethodClass,
    signal?: AbortSignal,
  ): Promise<VerifyOutcome> {
    await this.transport.advanceCeremony(plan.ceremonyId, { event: "capture_sim", method }, signal);
    this.emit({ type: "estimating", method });

    let view = await this.transport.getCeremony(plan.ceremonyId, signal);
    while (view.state === "estimating") {
      await delayMs(300, signal);
      if (signal?.aborted) {
        throw new InnomError("user_cancelled", "the caller aborted the request");
      }
      view = await this.transport.getCeremony(plan.ceremonyId, signal);
    }

    switch (view.state) {
      case "threshold_check": {
        // Band 1: the estimate cleared the challenge age and M4 may decide
        // alone. The gateway signed an M4 attestation and parked the ceremony
        // here; exchange it through the ordinary mint path.
        if (!view.m4Attestation) {
          return {
            status: "error",
            code: "internal_error",
            message: "the estimator produced no attestation.",
          };
        }
        const token = await this.transport.mintToken(
          { ceremonyId: view.ceremonyId, attestation: view.m4Attestation },
          signal,
        );
        this.activeCeremony = null;
        this.emit({ type: "verified", result: token });
        return { status: "verified", result: token };
      }
      case "blocked": {
        this.activeCeremony = null;
        const message = REFUSAL_MESSAGE;
        this.emit({
          type: "blocked",
          code: "predicate_not_satisfied",
          message,
          evidenceRef: view.evidenceRef,
        });
        return {
          status: "blocked",
          code: "predicate_not_satisfied",
          message,
          evidenceRef: view.evidenceRef,
        };
      }
      case "exhausted": {
        this.activeCeremony = null;
        const message = EXHAUSTED_MESSAGE;
        this.emit({
          type: "exhausted",
          code: "methods_exhausted",
          message,
          evidenceRef: view.evidenceRef,
        });
        return {
          status: "exhausted",
          code: "methods_exhausted",
          message,
          evidenceRef: view.evidenceRef,
        };
      }
      case "cancelled": {
        this.activeCeremony = null;
        this.emit({ type: "cancelled", evidenceRef: view.evidenceRef });
        return { status: "cancelled", evidenceRef: view.evidenceRef };
      }
      case "expired": {
        this.activeCeremony = null;
        return {
          status: "error",
          code: "ceremony_expired",
          message: "The ceremony expired before the estimation completed.",
        };
      }
      case "method_offered": {
        // The cascade handed the ceremony to a further method. No shipped
        // persona matrix reaches this (M4 is always the last executable), but
        // a graceful pause keeps `activeCeremony` live so a dismissal still
        // records a cancellation.
        const offered = view.activeMethod ?? "M?";
        return {
          status: "blocked",
          code: "method_not_offered",
          message: `${offered} is planned but not executed in this build; the ceremony stops at the offer.`,
          evidenceRef: null,
        };
      }
      default: {
        return {
          status: "error",
          code: "internal_error",
          message: `The ceremony reached an unexpected state: ${view.state}.`,
        };
      }
    }
  }

  /**
   * Probes the wallet for a live credential clearing `ageOver` (architecture
   * §6.3, VAL-REUSE-010). Mounts a dedicated hidden frame pointed at the
   * wallet origin's lightweight `/probe` surface — a plain HTML page that
   * reads the SAME IndexedDB store the wallet page writes, so the answer is
   * real device state, but the frame loads in tens of milliseconds instead
   * of a full Next/React hydration (which would leak hundreds of
   * milliseconds into the M0 reuse and switcher re-resolution budgets each
   * ceremony). Asks a single boolean question and tears the frame down
   * before the ceremony begins — the probe round trip is observable end to
   * end without interfering with the ceremony's own wallet frame. Never
   * throws: any failure resolves `false` (no credential), which overrides
   * the capability matrix exactly as an honest "no" from the store would.
   */
  private async probeWalletForCredential(ageOver: number): Promise<boolean> {
    const frame = document.createElement("iframe");
    frame.src = walletProbeUrl(this.walletUrl);
    // No aria-label: the ceremony's own frame carries "Innom wallet", so
    // locators scoping to the labelled frame never match this one.
    frame.style.cssText =
      "position:fixed;left:-10px;top:-10px;width:1px;height:1px;border:0;opacity:0;pointer-events:none;";
    document.body.appendChild(frame);
    try {
      await waitForFrameLoad(frame, 5_000);
      const channel = new WalletChannel({
        walletUrl: this.walletUrl,
        targetWindow: frame.contentWindow!,
      });
      return await channel.probeCredential({ requestId: newRequestId(), ageOver });
    } catch {
      return false;
    } finally {
      frame.remove();
    }
  }

  /**
   * Mounts the wallet iframe. Two lifecycles:
   *
   * - RP-provided container: the RP owns the DOM. We clear any frame from a
   *   previous ceremony, mount ours, and deliberately leave it in place when
   *   the ceremony ends — the wallet's final state ("proof shared", timings)
   *   is part of what the RP is showing the user, and tearing it down the
   *   instant the token arrives would flash it away before anyone can read it.
   * - No container: we overlay the page ourselves and remove that overlay on
   *   the way out, since no RP chrome exists to manage it.
   */
  private mountWalletFrame(container?: HTMLElement): { frame: HTMLIFrameElement; owned: boolean } {
    const iframe = document.createElement("iframe");
    // ?binding=soft on the RP's own page degrades device binding at mint and
    // release (§6.2, VAL-REUSE-033). Forward it into the wallet iframe URL so
    // the wallet can observe the same degraded mode from its own location.
    const walletFrameUrl = new URL(this.walletUrl);
    const siteParams = new URLSearchParams(globalThis.location.search);
    const binding = siteParams.get("binding");
    if (binding) walletFrameUrl.searchParams.set("binding", binding);
    iframe.src = walletFrameUrl.toString();
    iframe.setAttribute("aria-label", "Innom wallet");
    iframe.setAttribute("allow", walletIframePermissionsPolicy(this.walletUrl));
    if (container) {
      iframe.style.cssText =
        "width:100%;height:100%;border:0;display:block;background:transparent;";
      container.replaceChildren();
      container.appendChild(iframe);
      return { frame: iframe, owned: false };
    }
    iframe.style.cssText =
      "position:fixed;inset:0;width:100%;height:100%;border:0;z-index:2147483647;background:transparent;";
    document.body.appendChild(iframe);
    return { frame: iframe, owned: true };
  }

  private unmountWalletFrame(frame: HTMLIFrameElement, owned: boolean): void {
    if (owned && frame.parentNode) frame.parentNode.removeChild(frame);
  }

  private extractRpName(): string {
    const meta = document.querySelector('meta[name="innom-rp-display-name"]');
    return meta?.getAttribute("content") ?? (document.title || "this site");
  }

  private async deliverCookie(token: TokenMintResponse, endpoint: string): Promise<void> {
    await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token.token }),
      credentials: "same-origin",
    });
  }

  private toOutcome(error: unknown): VerifyOutcome {
    if (error instanceof InnomError) {
      if (error.code === "user_cancelled") {
        // The caller cancelled the run. The ceremony's `cancelled` record is
        // the caller's job to request (see cancelCeremony); there is no
        // evidence reference available from inside the aborted run.
        return { status: "cancelled", evidenceRef: null };
      }
      return {
        status: "error",
        code: error.code,
        message: error.message,
      };
    }
    return {
      status: "error",
      code: "internal_error",
      message: error instanceof Error ? error.message : "unknown error",
    };
  }
}
