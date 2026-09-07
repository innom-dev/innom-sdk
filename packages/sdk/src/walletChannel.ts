import {
  HANDOFF_PROTOCOL_VERSION,
  WalletMessageSchema,
  type PersonaId,
  type Predicate,
  type WalletM0PresentRequest,
  type WalletM0PresentResponse,
  type WalletProgress,
  type WalletRequest,
  type WalletResponse,
  type ZkChallenge,
} from "@innom/schemas";
import { InnomError } from "./types.js";

/**
 * postMessage channel to the wallet origin.
 *
 * Three checks decide whether a message is trusted, and all three are required:
 * the event's origin must equal the wallet origin exactly, the event source must
 * be the window this channel created, and the payload must parse. Origin alone is
 * not enough — any frame on the wallet's origin could otherwise answer — and
 * source alone is not enough, because a navigated frame keeps its window handle.
 *
 * `requestId` is checked on top of that, so a stale response from an earlier
 * attempt in the same session cannot satisfy the current one.
 */

export interface WalletChannelOptions {
  walletUrl: string;
  targetWindow: Window;
  /** How long to wait for the wallet's `ready` before giving up. */
  readyTimeoutMs?: number;
  /** How long to wait for a response once the request has been delivered. */
  responseTimeoutMs?: number;
}

export interface WalletExchange {
  requestId: string;
  predicate: Predicate;
  zkChallenge: ZkChallenge;
  rpDisplayName: string;
  rpOrigin: string;
  /** Demo actor driving the ceremony; the wallet resolves the DOB for it. */
  personaId: PersonaId;
  onProgress?: (progress: WalletProgress) => void;
  signal?: AbortSignal;
}

const DEFAULT_READY_TIMEOUT_MS = 30_000;
/**
 * Generous because it covers the user's own deliberation on the consent screen,
 * not just machine time. A user who stops to read the disclosure should not lose
 * their verification.
 */
const DEFAULT_RESPONSE_TIMEOUT_MS = 120_000;

/**
 * Cap on the wallet capability probe (architecture §6.3). The probe answers
 * from a local IndexedDB read after the wallet page has mounted; five seconds
 * is far beyond the wallet load + one READ round trip in every environment
 * that will actually demo M0.
 */
const DEFAULT_PROBE_TIMEOUT_MS = 5_000;

/**
 * Cap on the wallet's credential-mint acknowledgement. The acknowledgement is
 * awaited so the store is populated before the reveal in the healthy case, but
 * it must never push the token mint past VAL-REUSE-006's 500ms
 * ceremony-disturbance ceiling. A lost or stalled wallet ack (an unresponsive
 * iframe, a dropped message) must leave the ceremony inside that budget, so the
 * cap is 400ms; a timeout (or a rejected ack) resolves `{ ok: false }` and the
 * token mint proceeds regardless. A late ack arriving after the cap is ignored
 * — the wait's listener is removed the moment it resolves.
 */
const DEFAULT_MINT_TIMEOUT_MS = 400;

export class WalletChannel {
  private readonly walletOrigin: string;
  private readonly targetWindow: Window;
  private readonly readyTimeoutMs: number;
  private readonly responseTimeoutMs: number;
  private ready: Promise<void> | null = null;

  constructor(options: WalletChannelOptions) {
    this.walletOrigin = new URL(options.walletUrl).origin;
    this.targetWindow = options.targetWindow;
    this.readyTimeoutMs = options.readyTimeoutMs ?? DEFAULT_READY_TIMEOUT_MS;
    this.responseTimeoutMs = options.responseTimeoutMs ?? DEFAULT_RESPONSE_TIMEOUT_MS;
  }

  /** Resolves once the wallet reports that its prover assets are loaded. */
  waitForReady(): Promise<void> {
    this.ready ??= new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(
          new InnomError(
            "wallet_unavailable",
            `the wallet at ${this.walletOrigin} did not signal ready within ${String(this.readyTimeoutMs)}ms`,
          ),
        );
      }, this.readyTimeoutMs);

      const listener = (event: MessageEvent): void => {
        const message = this.accept(event);
        if (message?.type !== "innom.wallet.ready") return;
        if (message.version !== HANDOFF_PROTOCOL_VERSION) {
          cleanup();
          reject(
            new InnomError(
              "wallet_unavailable",
              `wallet speaks handoff v${String(message.version)}; this SDK speaks v${String(HANDOFF_PROTOCOL_VERSION)}`,
            ),
          );
          return;
        }
        cleanup();
        resolve();
      };

      const cleanup = (): void => {
        clearTimeout(timer);
        window.removeEventListener("message", listener);
      };

      window.addEventListener("message", listener);
    });

    return this.ready;
  }

  async exchange(exchange: WalletExchange): Promise<WalletResponse> {
    // The wallet's ready broadcast is fire-and-forget and its request listener
    // attaches only once the iframe has mounted. Posting the request once can
    // therefore land before the listener exists and be silently dropped, which
    // previously surfaced as "the wallet did not respond in time" after the
    // response timeout. Instead, keep re-posting the request on an interval
    // until the wallet answers (the wallet's own ready loop stops on request
    // receipt, so this is idempotent from its side) or the response timeout
    // fires. The wallet's consent screen ignores duplicate requests because
    // the requestId is stable.
    return new Promise<WalletResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new InnomError("timeout", "the wallet did not respond in time"));
      }, this.responseTimeoutMs);

      const onAbort = (): void => {
        cleanup();
        reject(new InnomError("user_cancelled", "the caller cancelled while the wallet was open"));
      };

      const listener = (event: MessageEvent): void => {
        const message = this.accept(event);
        if (!message) return;

        if (message.type === "innom.wallet.progress") {
          if (message.requestId !== exchange.requestId) return;
          exchange.onProgress?.(message);
          return;
        }

        if (message.type !== "innom.wallet.response") return;
        if (message.requestId !== exchange.requestId) return;

        cleanup();
        resolve(message);
      };

      const cleanup = (): void => {
        clearTimeout(timer);
        window.removeEventListener("message", listener);
        clearInterval(retryInterval);
        exchange.signal?.removeEventListener("abort", onAbort);
      };

      window.addEventListener("message", listener);
      exchange.signal?.addEventListener("abort", onAbort, { once: true });

      const request: WalletRequest = {
        type: "innom.wallet.request",
        version: HANDOFF_PROTOCOL_VERSION,
        requestId: exchange.requestId,
        rpDisplayName: exchange.rpDisplayName,
        rpOrigin: exchange.rpOrigin,
        predicate: exchange.predicate,
        zkChallenge: exchange.zkChallenge,
        personaId: exchange.personaId,
      };

      // Targeted at the wallet origin rather than "*", so the request cannot be
      // read by whatever happens to be in the frame if the wallet navigated away.
      const post = (): void => {
        this.targetWindow.postMessage(request, this.walletOrigin);
      };

      // First post immediately, then re-post every 500ms. The interval stops as
      // soon as the wallet answers (cleanup clears it). If the wallet never
      // mounts, the response timeout rejects with a typed InnomError instead of
      // a silent hang.
      post();
      const retryInterval = setInterval(post, 500);
    });
  }

  /**
   * Asks the wallet to mint and store the Innom credential for the ceremony it
   * just proved (architecture §6.1), then waits for the acknowledgement.
   *
   * The wallet — not this SDK — calls the attestation-plane issuer and writes
   * the wallet-origin IndexedDB record, so the credential and the band map
   * never pass through the relying party. The wait is a store-population gate,
   * never a ceremony gate: it is capped at 400ms and resolves `{ ok: false }`
   * on a rejected ack or a timeout, so a lost or stalled wallet can never
   * delay the token mint past VAL-REUSE-006's 500ms disturbance budget.
   * Minting is best-effort by design and must not fail the ceremony.
   */
  async requestCredentialMint(input: {
    requestId: string;
    attestation: string;
    timeoutMs?: number;
  }): Promise<{ ok: boolean }> {
    return new Promise<{ ok: boolean }>((resolve) => {
      const timer = setTimeout(() => {
        cleanup();
        resolve({ ok: false });
      }, input.timeoutMs ?? DEFAULT_MINT_TIMEOUT_MS);

      const listener = (event: MessageEvent): void => {
        const message = this.accept(event);
        if (message?.type !== "innom.wallet.minted") return;
        if (message.requestId !== input.requestId) return;
        cleanup();
        resolve({ ok: message.ok });
      };

      const cleanup = (): void => {
        clearTimeout(timer);
        window.removeEventListener("message", listener);
      };

      window.addEventListener("message", listener);
      this.targetWindow.postMessage(
        {
          type: "innom.wallet.mint",
          version: HANDOFF_PROTOCOL_VERSION,
          requestId: input.requestId,
          attestation: input.attestation,
        },
        this.walletOrigin,
      );
    });
  }

  /**
   * One-round capability probe (architecture §6.3, VAL-REUSE-010).
   *
   * Asks the wallet whether it holds a RELEASABLE, LIVE credential clearing
   * `ageOver` — the wallet answers yes only for a passkey-bound record, because
   * a soft-bound credential has no passkey gesture to release it with (§6.2) —
   * and resolves a single boolean. Posted before a ceremony is created so
   * `hasInnomCredential` is accurate in the initial plan. A timeout or an
   * unreachable wallet resolves `false`: an answer this wallet cannot give must
   * not make the relying party believe a credential exists.
   *
   * The answer schema is the enforcement point of the boolean-only contract —
   * the payload is `{type, version, requestId, hasCredential}` and anything more
   * fails the `accept()` parse, so no band map, credential identifier, expiry,
   * issuance time, minting method or assurance level can ever leak through it.
   */
  async probeCredential(input: {
    requestId: string;
    ageOver: number;
    timeoutMs?: number;
  }): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => {
        cleanup();
        resolve(false);
      }, input.timeoutMs ?? DEFAULT_PROBE_TIMEOUT_MS);

      const listener = (event: MessageEvent): void => {
        const message = this.accept(event);
        if (message?.type !== "innom.wallet.probe.answer") return;
        if (message.requestId !== input.requestId) return;
        cleanup();
        resolve(message.hasCredential);
      };

      const cleanup = (): void => {
        clearTimeout(timer);
        window.removeEventListener("message", listener);
        clearInterval(retryInterval);
      };

      window.addEventListener("message", listener);

      const post = (): void => {
        this.targetWindow.postMessage(
          {
            type: "innom.wallet.probe",
            version: HANDOFF_PROTOCOL_VERSION,
            requestId: input.requestId,
            ageOver: input.ageOver,
          },
          this.walletOrigin,
        );
      };

      // Same delivery guarantee as exchange(): the wallet's listener attaches
      // once its document has mounted, so re-post until answered or timed out.
      post();
      const retryInterval = setInterval(post, 500);
    });
  }

  /**
   * One-tap M0 presentation (architecture §6.3, VAL-REUSE-015/016).
   *
   * Sends `innom.wallet.m0_present` — the predicate plus this ceremony's
   * challenge, nothing else — and resolves with the wallet's presentation
   * response. On success that is the STORED signed credential plus a fresh
   * Groth16 proof bound to this ceremony's nonce; on refusal it is `ok:false`
   * with a stated reason and no credential released.
   *
   * Same delivery contract as every other channel call: re-post on an interval
   * until the wallet answers or the timeout fires. The wallet deduplicates by
   * `requestId` (the presentation consumes exactly one WebAuthn assertion, so
   * a retried delivery must never re-run it — VAL-REUSE-021). An abort from
   * the caller (a dismissed sheet) rejects with `user_cancelled` so the
   * ceremony can record the cancellation.
   */
  async presentCredential(input: {
    requestId: string;
    predicate: Predicate;
    zkChallenge: ZkChallenge;
    timeoutMs?: number;
    signal?: AbortSignal;
  }): Promise<WalletM0PresentResponse> {
    return new Promise<WalletM0PresentResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new InnomError("timeout", "the wallet did not respond in time"));
      }, input.timeoutMs ?? DEFAULT_RESPONSE_TIMEOUT_MS);

      const onAbort = (): void => {
        cleanup();
        reject(new InnomError("user_cancelled", "the caller cancelled while the wallet was open"));
      };

      const listener = (event: MessageEvent): void => {
        const message = this.accept(event);
        if (message?.type !== "innom.wallet.m0_present.response") return;
        if (message.requestId !== input.requestId) return;
        cleanup();
        resolve(message);
      };

      const cleanup = (): void => {
        clearTimeout(timer);
        window.removeEventListener("message", listener);
        clearInterval(retryInterval);
        input.signal?.removeEventListener("abort", onAbort);
      };

      window.addEventListener("message", listener);
      input.signal?.addEventListener("abort", onAbort, { once: true });

      const request: WalletM0PresentRequest = {
        type: "innom.wallet.m0_present",
        version: HANDOFF_PROTOCOL_VERSION,
        requestId: input.requestId,
        predicate: input.predicate,
        zkChallenge: input.zkChallenge,
      };

      const post = (): void => {
        this.targetWindow.postMessage(request, this.walletOrigin);
      };

      // Same delivery guarantee as exchange(): the wallet's listener attaches
      // once its document has mounted, so re-post until answered or timed out.
      post();
      const retryInterval = setInterval(post, 500);
    });
  }

  private accept(event: MessageEvent): ReturnType<typeof WalletMessageSchema.parse> | null {
    if (event.origin !== this.walletOrigin) return null;
    if (event.source !== this.targetWindow) return null;
    const parsed = WalletMessageSchema.safeParse(event.data);
    return parsed.success ? parsed.data : null;
  }
}

/** Opaque correlation id for one handoff. Never leaves the browser session. */
export function newRequestId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}
