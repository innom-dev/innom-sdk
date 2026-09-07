import type {
  CeremonyState,
  DeviceCapabilities,
  Jurisdiction,
  MethodClass,
  MethodPlan,
  MethodPlanEntry,
  PersonaId,
  InnomErrorCode,
  TokenMintResponse,
} from "@innom/schemas";

/**
 * Public SDK surface.
 *
 * The types a relying party's engineer reads before anything else, so they say
 * what the product is: you ask for a predicate, you get a token or a reason. No
 * user data appears anywhere in this file, and that is deliberate — the type
 * signatures should make it obvious that there is nothing to leak.
 */

export interface InnomInitOptions {
  /** `pk_test_…` / `pk_live_…`. Safe to ship in client code. */
  publishableKey: string;
  /** Gateway base URL. Defaults to the hosted gateway. */
  gatewayUrl?: string;
  /** Wallet base URL used for the M1 handoff. */
  walletUrl?: string;
  /** Jurisdiction hint; `auto` lets the gateway resolve it. */
  jurisdiction?: Jurisdiction | "auto";
  /**
   * Demo persona (architecture §12a.5). When set, the persona's deterministic
   * capability matrix drives ceremony planning and the persona id travels to
   * the wallet in the handoff so the wallet resolves the same actor. The DOB
   * never leaves the wallet origin. Defaults to `claire-31-fr` when unset.
   */
  persona?: PersonaId;
  /** Overrides detection. Useful for the demo's persona switcher and for tests. */
  capabilities?: Partial<DeviceCapabilities>;
  /**
   * When `true`, the configured persona's statically-declared credential
   * capabilities (`hasInnomCredential`, `hasPasskey`) are trusted as-is —
   * with any caller-supplied `capabilities` overrides layered on top — and
   * the real wallet-origin possession probe is skipped. This is the ONLY
   * seam that bypasses the probe, and it is an EXPLICIT test-only override:
   * neither a persona matrix nor a caller `capabilities` override may claim
   * possession of a credential the device does not actually hold except with
   * this flag set (ms3-scrutiny-capability-override-bypass). Default
   * `false` — before every ceremony the SDK probes the wallet origin's own
   * store, and its one-boolean answer overrides the persona matrix and any
   * caller-supplied `hasInnomCredential` / `hasPasskey` claim in both
   * directions.
   */
  personaCapabilitiesAuthoritative?: boolean;
}

export interface VerifyOptions {
  /** Minimum age the relying party wants. The pack may raise it, never lower it. */
  ageOver: number;
  /**
   * Where to put the token. `cookie` posts it to the RP's own endpoint so the
   * session is set server-side; `token` hands it back and the caller decides.
   */
  deliver?: "token" | "cookie";
  /** Endpoint on the RP's origin that receives the token when `deliver: "cookie"`. */
  sessionEndpoint?: string;
  /**
   * Element the wallet iframe mounts into. When omitted, the wallet covers the
   * viewport as an overlay. The CeremonySheet passes its own phone-sized
   * container so the method plan and proof progress stay visible alongside the
   * wallet during the ceremony.
   */
  walletContainer?: HTMLElement;
  /**
   * Routes the user has declined for this run ("use another method"). The
   * ceremony starts from the first executable route not listed here; pack
   * order is otherwise untouched, and an empty remainder exhausts as usual.
   */
  excludeMethods?: readonly MethodClass[];
}

export type VerifyOutcome =
  | { status: "verified"; result: TokenMintResponse }
  | { status: "blocked"; code: InnomErrorCode; message: string; evidenceRef: string | null }
  | { status: "exhausted"; code: InnomErrorCode; message: string; evidenceRef: string | null }
  | { status: "cancelled"; evidenceRef: string | null }
  | { status: "error"; code: InnomErrorCode; message: string };

/**
 * Lifecycle events. A relying party can drive its own UI from these instead of
 * using the hosted sheet, which is how M2's "bring your own UI" story works
 * without a second SDK.
 */
export type InnomEvent =
  | { type: "ceremony_created"; plan: MethodPlan }
  | { type: "state_changed"; state: CeremonyState }
  | { type: "method_offered"; method: MethodClass; entry: MethodPlanEntry }
  | { type: "wallet_opened"; method: MethodClass }
  | { type: "estimating"; method: MethodClass }
  | {
      type: "progress";
      phase: "passkey" | "consent" | "issuing" | "witness" | "proving";
      elapsedMs: number;
    }
  | { type: "attested"; assurance: string; verifiedInMs: number }
  | { type: "verified"; result: TokenMintResponse }
  | { type: "blocked"; code: InnomErrorCode; message: string; evidenceRef: string | null }
  | { type: "exhausted"; code: InnomErrorCode; message: string; evidenceRef: string | null }
  | { type: "cancelled"; evidenceRef: string | null }
  | { type: "error"; code: InnomErrorCode; message: string };

export type InnomEventType = InnomEvent["type"];
export type InnomEventListener<T extends InnomEventType = InnomEventType> = (
  event: Extract<InnomEvent, { type: T }>,
) => void;

/** Unsubscribes a listener registered with `on`. */
export type Unsubscribe = () => void;

export class InnomError extends Error {
  readonly code: InnomErrorCode;
  readonly evidenceRef: string | null;

  constructor(code: InnomErrorCode, message: string, evidenceRef: string | null = null) {
    super(message);
    this.name = "InnomError";
    this.code = code;
    this.evidenceRef = evidenceRef;
  }
}
