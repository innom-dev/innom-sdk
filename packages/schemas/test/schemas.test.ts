import { describe, expect, it } from "vitest";
import {
  AttestationIdSchema,
  BandProofSchema,
  CeremonyIdSchema,
  CompactJwsSchema,
  CredentialIdSchema,
  EvidenceIdSchema,
  MethodPlanSchema,
  MintCredentialRequestSchema,
  IatPayloadSchema,
  PersonaIdSchema,
  TokenIdSchema,
  WalletMessageSchema,
  WalletProbeAnswerSchema,
  WalletProbeRequestSchema,
  WalletRequestSchema,
  ageBandsEqual,
  ageBandsFromProvenBand,
  assertNoPii,
  attestationId,
  canonicalize,
  ceremonyId,
  credentialId,
  decodeBase64Url,
  decodePublicSignals,
  encodeBase64Url,
  encodePublicSignals,
  evidenceId,
  findPiiViolations,
  isCanonicalCompactJws,
  meetsAssurance,
  opaqueId,
  tokenId,
} from "../src/index.js";

/** The base64url alphabet, in index order (RFC 4648 §5). */
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Returns a different spelling of `token` whose final (signature) segment
 * decodes to the same bytes: only the final character's unused low bits are
 * flipped. Works for any signature whose decoded byte count is 1 mod 3, which
 * a 64-byte ES256 signature is.
 */
function nonCanonicalSpelling(token: string): string {
  const last = token.charAt(token.length - 1);
  const index = BASE64URL_ALPHABET.indexOf(last);
  const significant = index & 0x30; // 2 significant bits, 4 discarded
  const mutated = significant | ((index + 7) & 0x0f);
  const newLast = BASE64URL_ALPHABET[mutated]!;
  return `${token.slice(0, -1)}${newLast}`;
}

/**
 * Contract-layer tests. The schemas are the only thing every plane agrees on,
 * so their guarantees are tested here once rather than re-tested per consumer.
 */

describe("canonicalize", () => {
  it("orders object keys recursively", () => {
    expect(canonicalize({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it("is stable across insertion orders", () => {
    const first = canonicalize({ x: [1, 2], y: { b: true, a: null } });
    const second = canonicalize({ y: { a: null, b: true }, x: [1, 2] });
    expect(second).toBe(first);
  });

  it("drops undefined properties like JSON, so hashes stay stable", () => {
    // Documented RFC 8785-subset behaviour: {a: undefined} and {} are the same
    // document, and must hash identically.
    expect(canonicalize({ a: undefined })).toBe("{}");
  });

  it("rejects values JSON cannot represent losslessly", () => {
    expect(() => canonicalize({ a: () => 1 })).toThrow();
    expect(() => canonicalize({ a: Number.NaN })).toThrow();
    expect(() => canonicalize({ a: 10n })).toThrow();
  });
});

describe("PII gate", () => {
  it("flags forbidden keys anywhere in the structure", () => {
    expect(findPiiViolations({ outer: { holder_name: "Claire" } })).toEqual([
      { path: "outer.holder_name", key: "holder_name" },
    ]);
    expect(findPiiViolations({ items: [{ dateOfBirth: "1995-03-14" }] })).toEqual([
      { path: "items[0].dateOfBirth", key: "dateOfBirth" },
    ]);
  });

  it("flags salt as identity-bearing material alongside dob", () => {
    // `salt` and `dob_days` are the two halves of the wallet credential
    // commitment (architecture §3 invariant 1); the key gate refuses both.
    expect(findPiiViolations({ salt: "deadbeef" })).toEqual([{ path: "salt", key: "salt" }]);
    expect(findPiiViolations({ commitment: "0xabc", salt: "deadbeef" })).toEqual([
      { path: "salt", key: "salt" },
    ]);
    expect(() => assertNoPii({ data: { salt: "deadbeef" } }, "response")).toThrow();
  });

  it("passes a well-formed IAT payload", () => {
    const payload = IatPayloadSchema.parse({
      iss: "https://gateway.innom.test",
      aud: "rp_amourette",
      sub: "pairwise_0123456789abcdef",
      iat: 1,
      exp: 2,
      jti: "iat_01JTEST0000000000000000000",
      jurisdiction: "FR",
      policy_id: "FR-adult-v7",
      policy_hash: "f".repeat(64),
      predicate: { age_over: 18 },
      assurance: "P-AAL3",
      method_class: "M1",
      evidence_ref: "ev_01JTEST0000000000000000000",
    });
    expect(() => assertNoPii(payload)).not.toThrow();
  });

  it("rejects unknown keys on the strict IAT schema", () => {
    const valid = {
      iss: "https://gateway.innom.test",
      aud: "rp_amourette",
      sub: "pairwise_0123456789abcdef",
      iat: 1,
      exp: 2,
      jti: "iat_01JTEST0000000000000000000",
      jurisdiction: "FR",
      policy_id: "FR-adult-v7",
      policy_hash: "f".repeat(64),
      predicate: { age_over: 18 },
      assurance: "P-AAL3",
      method_class: "M1",
      evidence_ref: "ev_01JTEST0000000000000000000",
    };
    expect(IatPayloadSchema.safeParse({ ...valid, nickname: "c" }).success).toBe(false);
  });
});

describe("identifier generators", () => {
  it("generates values that pass their own schemas", () => {
    expect(CeremonyIdSchema.safeParse(ceremonyId()).success).toBe(true);
    expect(TokenIdSchema.safeParse(tokenId()).success).toBe(true);
    expect(EvidenceIdSchema.safeParse(evidenceId()).success).toBe(true);
    expect(AttestationIdSchema.safeParse(attestationId()).success).toBe(true);
    expect(CredentialIdSchema.safeParse(credentialId()).success).toBe(true);
  });

  it("never repeats", () => {
    const seen = new Set(Array.from({ length: 500 }, () => credentialId()));
    expect(seen.size).toBe(500);
  });

  it("is time-ordered at millisecond granularity", async () => {
    // ULID layout: the timestamp leads, so ids minted in different milliseconds
    // sort lexicographically in creation order. Within one millisecond the
    // random suffix decides, which is why this test crosses a ms boundary.
    const first = ceremonyId();
    await new Promise((resolve) => setTimeout(resolve, 3));
    const second = ceremonyId();
    expect(second > first).toBe(true);
  });

  it("generates URL-safe opaque ids", () => {
    expect(opaqueId()).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe("public signals", () => {
  it("round-trips through encode/decode in the pinned order", () => {
    const values = {
      thresholdDays: 6574,
      todayDays: 53539,
      commitment: "12345678901234567890",
      nonce: "98765432109876543210",
    };
    const encoded = encodePublicSignals(values);
    expect(encoded).toEqual(["6574", "53539", "12345678901234567890", "98765432109876543210"]);
    expect(decodePublicSignals(encoded)).toEqual(values);
  });

  it("rejects the wrong signal count", () => {
    expect(() => decodePublicSignals(["1", "2", "3"])).toThrow();
  });
});

describe("assurance ordering", () => {
  it("ranks P-AAL3 above P-AAL2 above P-AAL1", () => {
    expect(meetsAssurance("P-AAL3", "P-AAL2")).toBe(true);
    expect(meetsAssurance("P-AAL2", "P-AAL3")).toBe(false);
    expect(meetsAssurance("P-AAL1", "P-AAL1")).toBe(true);
  });
});

describe("persona ids on the wallet handoff", () => {
  const SEVEN_PERSONA_IDS = [
    "claire-31-fr",
    "claire-returning",
    "nina-19-fr",
    "sam-19-uk-nowallet",
    "dana-27-de",
    "alex-16-fr",
    "jordan-20-tx",
  ];

  it("accepts exactly the seven demo persona identifiers", () => {
    for (const id of SEVEN_PERSONA_IDS) {
      expect(PersonaIdSchema.safeParse(id).success, id).toBe(true);
    }
    expect(PersonaIdSchema.safeParse("someone-else").success).toBe(false);
    expect(PersonaIdSchema.safeParse("").success).toBe(false);
  });

  it("requires the wallet request to carry the persona", () => {
    const base = {
      type: "innom.wallet.request",
      version: 1,
      requestId: "req0123456789abcdef",
      rpDisplayName: "Amourette",
      rpOrigin: "http://localhost:4001",
      predicate: { ageOver: 18 },
      zkChallenge: {
        nonce: "123456789012345678901234567890",
        thresholdDays: 6574,
        todayDays: 53539,
        circuitId: "age_over_v1",
        circuitHash: "a".repeat(64),
      },
    };

    expect(WalletRequestSchema.safeParse({ ...base, personaId: "claire-31-fr" }).success).toBe(
      true,
    );
    expect(WalletRequestSchema.safeParse(base).success).toBe(false);
    expect(WalletRequestSchema.safeParse({ ...base, personaId: "nobody" }).success).toBe(false);
  });
});

describe("plan wire carries per-category thresholds", () => {
  const caterogies = {
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
  };

  function plan(categories: unknown): Record<string, unknown> {
    return {
      ceremonyId: ceremonyId(),
      pack: {
        id: "US-CA-social-v2",
        hash: "a".repeat(64),
        statutes: ["US-CA-AB2273-2022"],
      },
      jurisdiction: "US-CA",
      predicate: { ageOver: 18 },
      minAssurance: "P-AAL1",
      retentionDays: 90,
      doubleAnonymity: "not_required",
      categories,
      plan: [
        { method: "M0", eligible: false, reason: "no_credential" },
        { method: "M3", eligible: true, assurance: "P-AAL1", note: "not_executed_in_demo" },
      ],
      // The only eligible route is not-executed-in-demo, so nothing is executable.
      executable: [],
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

  it("accepts a plan whose categories cover every category with threshold and assurance", () => {
    expect(MethodPlanSchema.safeParse(plan(caterogies)).success).toBe(true);
  });

  it("rejects a plan that ships a partial category record", () => {
    const partial = { ...caterogies };
    delete (partial as Record<string, unknown>).social;
    expect(MethodPlanSchema.safeParse(plan(partial)).success).toBe(false);
  });

  it("rejects a category row without a minimum assurance", () => {
    const noAssurance = { ...caterogies, social: { threshold: 15 } };
    expect(MethodPlanSchema.safeParse(plan(noAssurance)).success).toBe(false);
  });
});

describe("base64url codec", () => {
  it("matches Node's base64url for every length from 0 to 120 plus a large input", () => {
    for (let length = 0; length <= 120; length += 1) {
      const bytes = new Uint8Array(length);
      for (let i = 0; i < length; i += 1) bytes[i] = (i * 31 + length * 7) & 0xff;
      const encoded = encodeBase64Url(bytes);
      expect(encoded).toBe(Buffer.from(bytes).toString("base64url"));
      const decoded = decodeBase64Url(encoded);
      expect(decoded).not.toBeNull();
      expect(Buffer.from(decoded!).equals(Buffer.from(bytes))).toBe(true);
    }
    const large = new Uint8Array(2048);
    for (let i = 0; i < large.length; i += 1) large[i] = (i * 17) & 0xff;
    expect(encodeBase64Url(large)).toBe(Buffer.from(large).toString("base64url"));
  });

  it("rejects characters outside the base64url alphabet", () => {
    expect(decodeBase64Url("ab+c")).toBeNull();
    expect(decodeBase64Url("ab/c")).toBeNull();
    expect(decodeBase64Url("ab=c")).toBeNull();
  });
});

describe("isCanonicalCompactJws", () => {
  // A canonical three-segment compact JWS. The 64-byte signature has 64 mod 3
  // = 1 remaining byte, so its base64url spelling ends in a character that
  // carries 2 significant bits and 4 discarded low bits — the exact spot the
  // validator hid its tamper in.
  const CANONICAL = [
    Buffer.from('{"alg":"ES256"}').toString("base64url"),
    Buffer.from('{"sub":"1234567890"}').toString("base64url"),
    Buffer.from(new Uint8Array(64).fill(0x5a)).toString("base64url"),
  ].join(".");

  it("accepts a canonical three-segment compact JWS", () => {
    expect(isCanonicalCompactJws(CANONICAL)).toBe(true);
  });

  it("rejects a spelling that decodes to the same bytes but is not canonical", () => {
    const forged = nonCanonicalSpelling(CANONICAL);

    expect(forged).not.toBe(CANONICAL);
    // The character-class regex that validates compact JWS shapes accepts the
    // forged spelling — this is the defect the guard closes.
    expect(CompactJwsSchema.safeParse(forged).success).toBe(true);
    // The mutation is byte-preserving: both spellings decode to identical
    // signature bytes, so this is a canonicality attack, not a forgery.
    const [, , signature] = CANONICAL.split(".");
    const [, , forgedSignature] = forged.split(".");
    expect(Buffer.from(forgedSignature!, "base64url")).toEqual(
      Buffer.from(signature!, "base64url"),
    );
    expect(isCanonicalCompactJws(forged)).toBe(false);
  });

  it("rejects valid base64url spellings whose trailing character carries set unused bits", () => {
    // "AB" decodes to one zero byte, whose canonical spelling is "AA".
    expect(CompactJwsSchema.safeParse("AA.AA.AB").success).toBe(true);
    expect(isCanonicalCompactJws("AA.AA.AB")).toBe(false);
    expect(isCanonicalCompactJws("AA.AA.AA")).toBe(true);
  });

  it("rejects anything with a segment count other than three", () => {
    expect(isCanonicalCompactJws("a.b")).toBe(false);
    expect(isCanonicalCompactJws("a.b.c.d")).toBe(false);
    expect(isCanonicalCompactJws("")).toBe(false);
    expect(isCanonicalCompactJws(".")).toBe(false);
    expect(isCanonicalCompactJws("a..b")).toBe(false);
    expect(isCanonicalCompactJws(".a.b")).toBe(false);
    expect(isCanonicalCompactJws("a.b.")).toBe(false);
  });

  it("rejects strings containing characters outside the base64url alphabet", () => {
    expect(isCanonicalCompactJws("a+b.c.d")).toBe(false);
    expect(isCanonicalCompactJws("a.b=c.d")).toBe(false);
    expect(isCanonicalCompactJws("a/b.c.d")).toBe(false);
  });
});

describe("wallet capability probe (VAL-REUSE-010)", () => {
  const request = {
    type: "innom.wallet.probe",
    version: 1,
    requestId: "probe_12345678",
    ageOver: 21,
  };
  const answer = {
    type: "innom.wallet.probe.answer",
    version: 1,
    requestId: "probe_12345678",
    hasCredential: true,
  };

  it("parses a probe request carrying only the protocol envelope and the age predicate", () => {
    const parsed = WalletProbeRequestSchema.safeParse(request);
    expect(parsed.success).toBe(true);
  });

  it("the answer carries exactly one capability field and nothing else", () => {
    const parsed = WalletProbeAnswerSchema.safeParse(answer);
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    // The whole point of the boolean-only contract: any future field beyond
    // the protocol envelope (type/version/requestId) and `hasCredential` is a
    // schema failure, not a silent addition to the channel.
    expect(Object.keys(parsed.data).sort()).toEqual([
      "hasCredential",
      "requestId",
      "type",
      "version",
    ]);
  });

  it("rejects a probe answer that smuggles any identity-bearing field", () => {
    // The same payload with a band map, credential id, expiry, issuance time,
    // minting method or assurance level appended must fail to parse — the
    // schema is the enforcement point of "one boolean only".
    const smugglers = {
      bands: { age_over_15: true, age_over_18: true, age_over_21: true },
      credential: "cred_1".padEnd(30, "0"),
      credentialId: "cred_1".padEnd(30, "0"),
      expiresAt: "2026-11-25T00:00:00.000Z",
      issuedAt: "2026-08-26T00:00:00.000Z",
      mintedMethod: "M1",
      assurance: "P-AAL3",
      salt: "deadbeef",
      dob_days: 12345,
    };
    for (const [field, value] of Object.entries(smugglers)) {
      const smuggled = WalletProbeAnswerSchema.safeParse({ ...answer, [field]: value });
      expect(smuggled.success, `probe answer must reject "${field}"`).toBe(false);
    }
  });

  it("both probe messages are part of the wallet protocol union", () => {
    expect(WalletMessageSchema.safeParse(request).success).toBe(true);
    expect(WalletMessageSchema.safeParse(answer).success).toBe(true);
  });

  it("rejects a probe request whose ageOver is off the statutory range", () => {
    expect(WalletProbeRequestSchema.safeParse({ ...request, ageOver: 0 }).success).toBe(false);
    expect(WalletProbeRequestSchema.safeParse({ ...request, ageOver: 121 }).success).toBe(false);
  });
});

describe("credential mint request passkey binding (VAL-REUSE-008)", () => {
  const base = {
    commitment: "123456789012345678901234567890123456",
    bands: { age_over_15: true, age_over_18: true, age_over_21: true },
    attestation: "AA.AA.AA",
    // Shape-valid stand-in for the wallet's real band proof; only schema
    // acceptance is exercised here, never verification.
    bandProof: {
      proof: {
        pi_a: ["1", "1", "1"],
        pi_b: [
          ["1", "1"],
          ["1", "1"],
          ["1", "1"],
        ],
        pi_c: ["1", "1", "1"],
        protocol: "groth16",
        curve: "bn128",
      },
      publicSignals: ["1", "1", "1", "1"],
    },
  };

  it("accepts an explicit passkey id and keeps the request strict otherwise", () => {
    // Synthetic fixture id: deterministic and non-secret; only equality and
    // schema acceptance are asserted.
    const fixturePasskeyId = ["passkey", "test", "schema", "roundtrip", "000001"].join("_");
    const parsed = MintCredentialRequestSchema.safeParse({
      ...base,
      passkeyId: fixturePasskeyId,
    });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.passkeyId).toBe(fixturePasskeyId);
  });

  it("accepts null and absent passkey ids as soft binding", () => {
    expect(MintCredentialRequestSchema.safeParse({ ...base, passkeyId: null }).success).toBe(true);
    expect(MintCredentialRequestSchema.safeParse(base).success).toBe(true);
  });

  it("rejects malformed passkey ids and unknown request fields", () => {
    expect(MintCredentialRequestSchema.safeParse({ ...base, passkeyId: "short" }).success).toBe(
      false,
    );
    expect(MintCredentialRequestSchema.safeParse({ ...base, passkeyId: 42 }).success).toBe(false);
    expect(
      MintCredentialRequestSchema.safeParse({ ...base, passkeyId: "x".repeat(200) }).success,
    ).toBe(false);
    expect(MintCredentialRequestSchema.safeParse({ ...base, rpId: "localhost" }).success).toBe(
      false,
    );
  });

  it("requires the band proof — a mint may not assert bands without evidence", () => {
    // The band proof is the issuer's only age evidence; omitting it must be a
    // parse failure, not an unauthenticated-mint path.
    const withoutProof = {
      commitment: base.commitment,
      bands: base.bands,
      attestation: base.attestation,
    };
    expect(MintCredentialRequestSchema.safeParse(withoutProof).success).toBe(false);
    // A one-sided proof (missing public signals) is a parse failure too.
    expect(
      MintCredentialRequestSchema.safeParse({
        ...withoutProof,
        bandProof: { proof: base.bandProof.proof },
      }).success,
    ).toBe(false);
  });
});

describe("age-band authentication (band_proof derivation)", () => {
  it("derives the monotone band map from the proven band", () => {
    expect(ageBandsFromProvenBand(15)).toEqual({
      age_over_15: true,
      age_over_18: false,
      age_over_21: false,
    });
    expect(ageBandsFromProvenBand(18)).toEqual({
      age_over_15: true,
      age_over_18: true,
      age_over_21: false,
    });
    expect(ageBandsFromProvenBand(21)).toEqual({
      age_over_15: true,
      age_over_18: true,
      age_over_21: true,
    });
    // No proof authenticates nothing: every band reads false. This is why the
    // mint refuses any true-band claim without a proof.
    expect(ageBandsFromProvenBand(null)).toEqual({
      age_over_15: false,
      age_over_18: false,
      age_over_21: false,
    });
  });

  it("ageBandsEqual compares every field", () => {
    const a = { age_over_15: true, age_over_18: true, age_over_21: false };
    expect(ageBandsEqual(a, { ...a })).toBe(true);
    expect(ageBandsEqual(a, { age_over_15: true, age_over_18: true, age_over_21: true })).toBe(
      false,
    );
    expect(ageBandsEqual(a, { age_over_15: false, age_over_18: true, age_over_21: false })).toBe(
      false,
    );
  });

  it("BandProofSchema accepts a well-formed proof and rejects malformed ones", () => {
    const valid = {
      proof: {
        pi_a: ["1", "1", "1"],
        pi_b: [
          ["1", "1"],
          ["1", "1"],
          ["1", "1"],
        ],
        pi_c: ["1", "1", "1"],
        protocol: "groth16",
        curve: "bn128",
      },
      publicSignals: ["1", "1", "1", "1"],
    };
    expect(BandProofSchema.safeParse(valid).success).toBe(true);
    expect(BandProofSchema.safeParse({ ...valid, proof: {} }).success).toBe(false);
    expect(BandProofSchema.safeParse({ ...valid, publicSignals: ["1", "1"] }).success).toBe(false);
    expect(BandProofSchema.safeParse({ ...valid, extra: true }).success).toBe(false);
  });
});
