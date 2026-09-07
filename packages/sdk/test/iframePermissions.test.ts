import { describe, expect, it } from "vitest";
import { walletIframePermissionsPolicy } from "../src/iframePermissions.js";

/**
 * The two WebAuthn feature tokens a cross-origin wallet frame needs. `get`
 * covers passkey sign-in (the silent UV presentation), `create` covers passkey
 * registration (the M0 credential binding).
 */
const WEBAUTHN_FEATURES = ["publickey-credentials-create", "publickey-credentials-get"] as const;

const WALLET_ORIGIN = "http://localhost:4002";

/** Parses the serialized permissions-policy allow attribute into feature → allowlist. */
function parseDirectives(serialized: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const rawDirective of serialized.split(";")) {
    const tokens = rawDirective.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const [feature, ...allowlist] = tokens;
    directives.set(feature!, allowlist);
  }
  return directives;
}

describe("wallet iframe permissions policy", () => {
  it("delegates both WebAuthn feature tokens scoped to the wallet origin, never a bare wildcard", () => {
    const directives = parseDirectives(walletIframePermissionsPolicy(WALLET_ORIGIN));
    for (const feature of WEBAUTHN_FEATURES) {
      // VAL-REUSE-024: each feature must be delegated to the WALLET ORIGIN
      // (`http://localhost:4002`), not to every embedder via `*` and not as an
      // unscoped token. An unscoped feature name delegates nothing and `*`
      // over-delegates past the frame that is supposed to receive the
      // capability — least privilege is part of the contract.
      expect(directives.get(feature), feature).toEqual([WALLET_ORIGIN]);
    }
    expect(walletIframePermissionsPolicy(WALLET_ORIGIN)).not.toContain("*");
  });

  it("keeps the origin when the wallet URL carries a path or query", () => {
    const value = walletIframePermissionsPolicy("http://localhost:4002/?binding=soft");
    expect(value).toBe(
      "publickey-credentials-create http://localhost:4002; publickey-credentials-get http://localhost:4002",
    );
  });

  it("labels every directive with an explicit allowlist", () => {
    const directives = parseDirectives(walletIframePermissionsPolicy(WALLET_ORIGIN));
    expect(directives.size).toBeGreaterThan(0);
    for (const [feature, allowlist] of directives) {
      expect(allowlist.length, feature).toBeGreaterThan(0);
    }
  });

  it("never reverts to the invalid singleton token Chrome rejects", () => {
    // "publickey-credentials *" is not a real feature name. Chrome logs
    // "Unrecognized feature" for it and delegates nothing, so a passkey call in
    // the frame stays blocked. Pinned so a future "simplification" back to the
    // old form fails this test immediately.
    const tokens = walletIframePermissionsPolicy(WALLET_ORIGIN).split(/[;\s]+/).filter(Boolean);
    expect(tokens).not.toContain("publickey-credentials");
  });
});
