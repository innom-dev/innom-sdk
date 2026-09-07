/**
 * Permissions-Policy delegation for the wallet iframe's `allow` attribute.
 *
 * WebAuthn is disabled in cross-origin frames by default, and the wallet runs
 * on a different origin than the relying party, so both capabilities the wallet
 * may need must be delegated explicitly by the embedding document:
 *
 * - `publickey-credentials-get` — passkey sign-in (a silent UV presentation).
 * - `publickey-credentials-create` — passkey registration (the reusable
 *   credential's device binding).
 *
 * Each token is scoped to the wallet origin (VAL-REUSE-024): the allowlist is
 * the frame's own serialized origin (scheme, host and port), never a bare `*`.
 * `*` over-delegates the feature to every embedder the wallet frame might be
 * replaced by, and least privilege is part of the delegation contract — the
 * only origin that may call either API is the wallet itself.
 *
 * The previous value, `"publickey-credentials *"`, was not a real feature
 * token: Chrome logged `Unrecognized feature: 'publickey-credentials'` on every
 * embed while delegating nothing (identical behaviour to no attribute at all).
 * Keep both real tokens spelled out — ms1's regression test pins the exact
 * serialization so a "simplification" back to the old form fails immediately.
 */
export function walletIframePermissionsPolicy(walletUrl: string): string {
  const origin = new URL(walletUrl).origin;
  return `publickey-credentials-create ${origin}; publickey-credentials-get ${origin}`;
}
