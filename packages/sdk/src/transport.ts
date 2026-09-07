import {
  CeremonyViewSchema,
  ERROR_STATUS,
  MethodPlanSchema,
  TokenMintResponseSchema,
  ZkAttestResponseSchema,
  type CeremonyAdvanceRequest,
  type CeremonyInitRequest,
  type CeremonyView,
  type Groth16Proof,
  type MethodPlan,
  type InnomErrorCode,
  type PublicSignals,
  type TokenMintResponse,
  type ZkAttestResponse,
} from "@innom/schemas";
import { InnomError } from "./types.js";

/**
 * Gateway transport.
 *
 * Every response is parsed against the schema the gateway claims to return. A
 * client that trusts an API's shape is a client that ships a runtime crash the
 * first time the API drifts, and this SDK runs inside customers' checkout flows.
 */

export interface TransportOptions {
  gatewayUrl: string;
  fetchImpl?: typeof fetch;
  /** Aborts an in-flight request when the caller cancels. */
  signal?: AbortSignal;
}

interface ErrorEnvelope {
  error: { code: InnomErrorCode; message: string; evidenceRef: string | null; field: string | null };
}

export class GatewayTransport {
  private readonly gatewayUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: TransportOptions) {
    this.gatewayUrl = options.gatewayUrl.replace(/\/+$/, "");
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async createCeremony(body: CeremonyInitRequest, signal?: AbortSignal): Promise<MethodPlan> {
    return MethodPlanSchema.parse(
      await this.request("POST", "/api/v1/ceremonies", body, signal),
    );
  }

  async getCeremony(ceremonyId: string, signal?: AbortSignal): Promise<CeremonyView> {
    return CeremonyViewSchema.parse(
      await this.request("GET", `/api/v1/ceremonies/${encodeURIComponent(ceremonyId)}`, undefined, signal),
    );
  }

  async advanceCeremony(
    ceremonyId: string,
    body: CeremonyAdvanceRequest,
    signal?: AbortSignal,
  ): Promise<CeremonyView> {
    return CeremonyViewSchema.parse(
      await this.request(
        "PATCH",
        `/api/v1/ceremonies/${encodeURIComponent(ceremonyId)}`,
        body,
        signal,
      ),
    );
  }

  async attestZk(
    body: {
      challengeTicket: string;
      credential: string;
      proof: Groth16Proof;
      publicSignals: PublicSignals;
      provingMs?: number;
    },
    signal?: AbortSignal,
  ): Promise<ZkAttestResponse> {
    return ZkAttestResponseSchema.parse(
      await this.request("POST", "/api/v1/attest/zk", body, signal),
    );
  }

  async mintToken(
    body: { ceremonyId: string; attestation: string },
    signal?: AbortSignal,
  ): Promise<TokenMintResponse> {
    return TokenMintResponseSchema.parse(
      await this.request("POST", "/api/v1/tokens", body, signal),
    );
  }

  private async request(
    method: string,
    path: string,
    body?: unknown,
    signal?: AbortSignal,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.gatewayUrl}${path}`, {
        method,
        headers: body === undefined ? {} : { "Content-Type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal,
        // The gateway is cross-origin from the relying party and authenticates on
        // the publishable key alone, so cookies must not ride along.
        credentials: "omit",
        mode: "cors",
      });
    } catch (error) {
      if (signal?.aborted) throw new InnomError("user_cancelled", "the caller aborted the request");
      throw new InnomError(
        "network_error",
        error instanceof Error ? error.message : `${method} ${path} failed`,
      );
    }

    if (response.ok) {
      return (await response.json()) as unknown;
    }

    throw await this.toInnomError(response);
  }

  /**
   * Maps a failed response onto a typed error.
   *
   * Falls back to inferring a code from the status when the body is not a Innom
   * envelope, which happens when something in front of the gateway answers: a
   * proxy 502 or a CDN 429 should still reach the caller as `network_error` or
   * `rate_limited` rather than as a JSON parse exception.
   */
  private async toInnomError(response: Response): Promise<InnomError> {
    let envelope: ErrorEnvelope | null = null;
    try {
      const parsed = (await response.json()) as unknown;
      if (
        typeof parsed === "object" &&
        parsed !== null &&
        "error" in parsed &&
        typeof (parsed as ErrorEnvelope).error?.code === "string"
      ) {
        envelope = parsed as ErrorEnvelope;
      }
    } catch {
      envelope = null;
    }

    if (envelope) {
      return new InnomError(envelope.error.code, envelope.error.message, envelope.error.evidenceRef);
    }

    const code: InnomErrorCode =
      response.status === 429
        ? "rate_limited"
        : response.status === 404
          ? "ceremony_not_found"
          : response.status >= 500
            ? "network_error"
            : "invalid_request";

    return new InnomError(code, `gateway returned ${String(response.status)} without an error envelope`);
  }
}

/** Exposed so a relying party can assert its own retry policy against the taxonomy. */
export function statusForErrorCode(code: InnomErrorCode): number {
  return ERROR_STATUS[code];
}
