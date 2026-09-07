import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { SignJWT, exportJWK, generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { DeviceCapabilitiesSchema, ceremonyId, type MethodPlan } from "@innom/schemas";
import { capabilitiesForPersona } from "../src/capabilities.js";
import { GatewayTransport } from "../src/transport.js";
import { InnomError } from "../src/types.js";
import { verifyIat } from "../src/server/index.js";

/**
 * SDK tests. Two halves: the transport's schema validation and error mapping
 * (the part that runs inside a customer's checkout flow and must fail typed,
 * never crash) and the RP-side offline IAT verification that every server
 * integration depends on.
 */

/** The base64url alphabet in index order (RFC 4648 §5). */
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Returns a differently-spelled copy of `token` whose signature segment decodes
 * to the same bytes. An ES256 signature is exactly 64 bytes, so its unpadded
 * base64url spelling ends in a character carrying only 2 significant bits; the
 * low 4 bits are discarded on decode, so 16 spellings produce one signature.
 */
function nonCanonicalSignatureSpelling(token: string): string {
  const [header, payload, signature] = token.split(".");
  if (!signature) throw new Error("not a compact JWS");
  const last = signature.charAt(signature.length - 1);
  const index = BASE64URL_ALPHABET.indexOf(last);
  if (index < 0) throw new Error("signature ends in a non-base64url character");
  const significant = index & 0x30;
  const mutated = significant | ((index + 7) & 0x0f);
  expect(mutated).not.toBe(index);
  const newLast = BASE64URL_ALPHABET[mutated]!;
  return `${header}.${payload}.${signature.slice(0, -1)}${newLast}`;
}

const VALID_PLAN: MethodPlan = {
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
  plan: [
    { method: "M1", eligible: true, assurance: "P-AAL3", estimatedMs: 2500 },
    { method: "M3", eligible: false, reason: "barred_by_pack", note: "Arcom reference method" },
  ],
  // The gateway's ordered executable subset: M1 runs, barred M3 never is.
  executable: ["M1"],
  zkChallenge: {
    nonce: "123456789012345678901234567890",
    thresholdDays: 6574,
    todayDays: 53539,
    circuitId: "age_over_v1",
    circuitHash: "a".repeat(64),
  },
  challengeTicket: "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl",
  state: "policy_resolved",
  expiresAt: new Date(Date.now() + 600_000).toISOString(),
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("GatewayTransport", () => {
  it("parses a schema-valid ceremony response", async () => {
    const transport = new GatewayTransport({
      gatewayUrl: "http://gateway.test/",
      fetchImpl: async () => jsonResponse(201, VALID_PLAN),
    });
    const plan = await transport.createCeremony({
      publishableKey: "pk_test_amourette",
      predicate: { ageOver: 18 },
      jurisdiction: "auto",
    });
    expect(plan.ceremonyId).toBe(VALID_PLAN.ceremonyId);
  });

  it("strips a trailing slash from the gateway URL", async () => {
    let seenUrl = "";
    const transport = new GatewayTransport({
      gatewayUrl: "http://gateway.test///",
      fetchImpl: async (input) => {
        seenUrl = String(input);
        return jsonResponse(201, VALID_PLAN);
      },
    });
    await transport.createCeremony({
      publishableKey: "pk_test_amourette",
      predicate: { ageOver: 18 },
      jurisdiction: "FR",
    });
    expect(seenUrl).toBe("http://gateway.test/api/v1/ceremonies");
  });

  it("maps a Innom error envelope to a typed InnomError", async () => {
    const transport = new GatewayTransport({
      gatewayUrl: "http://gateway.test",
      fetchImpl: async () =>
        jsonResponse(410, {
          error: {
            code: "ceremony_expired",
            message: "the ceremony expired",
            evidenceRef: null,
            field: null,
          },
        }),
    });
    const error = await transport
      .getCeremony("cer_01JTESTGONE0000000000001")
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(InnomError);
    expect((error as InnomError).code).toBe("ceremony_expired");
  });

  it("maps a proxy failure without an envelope to network_error", async () => {
    const transport = new GatewayTransport({
      gatewayUrl: "http://gateway.test",
      fetchImpl: async () => new Response("Bad Gateway", { status: 502 }),
    });
    const error = await transport
      .getCeremony("cer_01JTESTGONE0000000000001")
      .catch((caught: unknown) => caught);
    expect((error as InnomError).code).toBe("network_error");
  });

  it("maps a bare 429 to rate_limited", async () => {
    const transport = new GatewayTransport({
      gatewayUrl: "http://gateway.test",
      fetchImpl: async () => new Response("slow down", { status: 429 }),
    });
    const error = await transport
      .getCeremony("cer_01JTESTGONE0000000000001")
      .catch((caught: unknown) => caught);
    expect((error as InnomError).code).toBe("rate_limited");
  });

  it("throws on a success response that does not match the schema", async () => {
    const transport = new GatewayTransport({
      gatewayUrl: "http://gateway.test",
      fetchImpl: async () => jsonResponse(201, { ceremonyId: "not-a-ceremony" }),
    });
    await expect(
      transport.createCeremony({
        publishableKey: "pk_test_amourette",
        predicate: { ageOver: 18 },
        jurisdiction: "FR",
      }),
    ).rejects.toThrow();
  });

  it("maps a fetch rejection to network_error", async () => {
    const transport = new GatewayTransport({
      gatewayUrl: "http://gateway.test",
      fetchImpl: async () => {
        throw new TypeError("fetch failed");
      },
    });
    const error = await transport
      .getCeremony("cer_01JTESTGONE0000000000001")
      .catch((caught: unknown) => caught);
    expect((error as InnomError).code).toBe("network_error");
  });
});

describe("persona capabilities", () => {
  it("maps a wallet-less persona to a deterministic matrix with a camera and no wallet", () => {
    const matrix = capabilitiesForPersona("sam-19-uk-nowallet");
    expect(matrix.hasEudiWallet).toBe(false);
    expect(matrix.canProveZk).toBe(false);
    expect(matrix.hasPasskey).toBe(false);
    expect(matrix.hasInnomCredential).toBe(false);
    expect(matrix.hasCamera).toBe(true);
  });

  it("maps wallet personas to wallet + ZK capability without a credential", () => {
    const matrix = capabilitiesForPersona("claire-31-fr");
    expect(matrix.hasEudiWallet).toBe(true);
    expect(matrix.canProveZk).toBe(true);
    expect(matrix.hasInnomCredential).toBe(false);
  });

  it("maps the returning holder to credential + passkey capability", () => {
    const matrix = capabilitiesForPersona("claire-returning");
    expect(matrix.hasInnomCredential).toBe(true);
    expect(matrix.hasPasskey).toBe(true);
  });

  it("lets explicit device overrides win over the persona matrix", () => {
    const matrix = capabilitiesForPersona("claire-31-fr", {
      hasInnomCredential: true,
      hasPasskey: true,
    });
    expect(matrix.hasInnomCredential).toBe(true);
    expect(matrix.hasPasskey).toBe(true);
    expect(matrix.hasEudiWallet).toBe(true);
  });

  it("always yields a complete schema-valid DeviceCapabilities", () => {
    for (const id of [
      "claire-31-fr",
      "claire-returning",
      "nina-19-fr",
      "sam-19-uk-nowallet",
      "dana-27-de",
      "alex-16-fr",
      "jordan-20-tx",
    ] as const) {
      const matrix = capabilitiesForPersona(id);
      expect(DeviceCapabilitiesSchema.parse(matrix), id).toEqual(matrix);
    }
  });
});

describe("verifyIat (offline JWKS path)", () => {
  let server: Server;
  let jwksUrl: string;
  let issuer: string;
  let privateKey: CryptoKey | Awaited<ReturnType<typeof generateKeyPair>>["privateKey"];
  let kid: string;

  async function mint(overrides: Record<string, unknown> = {}): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({
      iss: issuer,
      aud: "rp_amourette",
      sub: "pairwise_0123456789abcdef",
      iat: now,
      exp: now + 300,
      jti: "iat_01JTESTSDK0000000000000",
      jurisdiction: "FR",
      policy_id: "FR-adult-v7",
      policy_hash: "f".repeat(64),
      predicate: { age_over: 18 },
      assurance: "P-AAL3",
      method_class: "M1",
      evidence_ref: "ev_01JTEST0000000000000000000",
      ...overrides,
    })
      .setProtectedHeader({ alg: "ES256", kid, typ: "innom-iat+jwt" })
      .sign(privateKey);
  }

  beforeAll(async () => {
    const pair = await generateKeyPair("ES256", { extractable: true });
    privateKey = pair.privateKey;
    const jwk = await exportJWK(pair.publicKey);
    kid = "test-iat-key";
    jwk.kid = kid;
    jwk.alg = "ES256";
    jwk.use = "sig";

    server = createServer((request, response) => {
      if (request.url?.endsWith("/jwks.json")) {
        response.writeHead(200, { "Content-Type": "application/json" });
        response.end(JSON.stringify({ keys: [jwk] }));
        return;
      }
      response.writeHead(404);
      response.end();
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address() as AddressInfo;
    issuer = `http://127.0.0.1:${String(port)}`;
    jwksUrl = `${issuer}/api/v1/.well-known/jwks.json`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => {
        resolve();
      });
    });
  });

  it("verifies a well-formed IAT offline", async () => {
    const result = await verifyIat(await mint(), { audience: "rp_amourette", jwksUrl });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.claims.sub).toBe("pairwise_0123456789abcdef");
      expect(result.claims.predicate).toEqual({ age_over: 18 });
    }
  });

  it("rejects the wrong audience", async () => {
    const result = await verifyIat(await mint(), { audience: "rp_nocturne", jwksUrl });
    expect(result).toMatchObject({ ok: false, reason: "wrong_audience" });
  });

  it("rejects an expired token", async () => {
    const now = Math.floor(Date.now() / 1000);
    const result = await verifyIat(await mint({ iat: now - 900, exp: now - 600 }), {
      audience: "rp_amourette",
      jwksUrl,
    });
    expect(result).toMatchObject({ ok: false, reason: "expired" });
  });

  it("rejects a token asserting less than the RP requires", async () => {
    const result = await verifyIat(await mint(), {
      audience: "rp_amourette",
      jwksUrl,
      requireAgeOver: 21,
    });
    expect(result).toMatchObject({ ok: false, reason: "predicate_not_met" });
  });

  it("rejects a token below the RP's assurance floor", async () => {
    const result = await verifyIat(await mint({ assurance: "P-AAL2" }), {
      audience: "rp_amourette",
      jwksUrl,
      requireMinAssurance: "P-AAL3",
    });
    expect(result).toMatchObject({ ok: false, reason: "assurance_not_met" });
  });

  it("rejects a garbage token as malformed", async () => {
    const result = await verifyIat("not-a-jwt", { audience: "rp_amourette", jwksUrl });
    expect(result.ok).toBe(false);
  });

  it("rejects a IAT whose signature differs only in its base64url spelling", async () => {
    // The canonicality bypass the validator found in the session cookie:
    // only the signature segment's final character is changed, and only in
    // bits the base64url decoder discards, so the signature bytes are
    // identical and jose's signature check cannot tell the strings apart.
    const token = await mint();
    const mutated = nonCanonicalSignatureSpelling(token);
    expect(mutated).not.toBe(token);
    const [, , originalSignature] = token.split(".");
    const [, , mutatedSignature] = mutated.split(".");
    expect(Buffer.from(mutatedSignature!, "base64url")).toEqual(
      Buffer.from(originalSignature!, "base64url"),
    );

    const result = await verifyIat(mutated, { audience: "rp_amourette", jwksUrl });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("malformed");
    }
  });

  it("rejects a IAT whose payload segment was tampered", async () => {
    // A payload mutation must stay refused (it changes the signing input) —
    // this pins the no-regression half of the canonicality fix.
    const token = await mint();
    const [header, payload, signature] = token.split(".");
    const middle = BASE64URL_ALPHABET.indexOf(payload!.charAt(3));
    const mutatedPayload =
      payload!.slice(0, 3) + BASE64URL_ALPHABET[middle ^ 1] + payload!.slice(4);
    const forged = `${header}.${mutatedPayload}.${signature}`;

    const result = await verifyIat(forged, { audience: "rp_amourette", jwksUrl });
    expect(result.ok).toBe(false);
  });
});
