# @innom/sdk

Privacy-preserving age assurance for the web. Prove an age predicate — "over 18", "over 21" — without sharing identity.

The SDK runs one verification ceremony between your page, the user's wallet (a separate origin that holds the date of birth), and the Innom attestation plane. The result is a signed, short-lived Innom Age Token (IAT) that carries a predicate, an assurance class and a method class — and nothing else. No name, no document, no date of birth ever crosses the wire.

Documentation: [innom.dev/docs](https://innom.dev/docs)

## Install

```sh
npm i @innom/sdk
```

## Use — client

One instance per relying-party origin. `init` is cheap and idempotent; `verify` runs a single ceremony and resolves with a token or a typed failure. `verify` never rejects — every error path is a resolved value, so callers can use a single `switch` without a `try`/`catch` wrapper.

```ts
import { Innom } from "@innom/sdk";

const innom = Innom.init({
  publishableKey: "pk_…",
});

const outcome = await innom.verify({ ageOver: 18 });
switch (outcome.status) {
  case "verified":
    // outcome.result is the signed Innom Age Token
    break;
  case "blocked":
  case "exhausted":
  case "cancelled":
  case "error":
    // typed failure, each with its own code and message
    break;
}
```

The SDK never touches user data. The wallet computes the proof inside its own origin; the SDK relays the challenge to the wallet, the proof to the attestation plane, and the attestation back for a token. A user-dismissed mid-ceremony sheet can be recorded as a real cancellation through `cancelCeremony()`, which resolves with the resulting evidence reference.

## Use — server

Verify an Innom Age Token offline against the gateway's JWKS — no round-trip to Innom required. That is the point of a bearer token: the relying party validates it in under 5ms.

```ts
import { verifyIat } from "@innom/sdk/server";

const result = await verifyIat(token, {
  audience: "rp_yoursite",
  jwksUrl: "https://gateway.example/api/v1/.well-known/jwks.json",
  requireAgeOver: 18,
});
if (result.ok) {
  // result.claims: predicate, assurance, method class, expiry
} else {
  // result.reason: malformed | bad_signature | expired | wrong_audience | …
}
```

## Verify with nothing but Node

[`examples/verify-iat.mjs`](./examples/verify-iat.mjs) verifies a token with zero dependencies and no SDK install: one cached JWKS fetch, canonical base64url checks, ES256 via WebCrypto, and a PII guard that rejects a token claiming to reveal anything.

```sh
node examples/verify-iat.mjs <token> [audience] [jwksUrl]
```

Exit code 0 = valid, 1 = invalid, 2 = usage error.

## Packages

| Package            | What it is                                                              |
| ------------------ | ----------------------------------------------------------------------- |
| `@innom/sdk`       | The client ceremony SDK, plus offline server-side IAT verification      |
| `@innom/schemas`   | Zod schemas for every wire surface, and the runtime PII gate            |
| `@innom/personas`  | The demo device-capability personas used by the SDK's test matrix       |

Every object Innom signs, persists, or returns passes through the schemas package's PII gate (`assertNoPii`), which rejects any key resembling date of birth, name, document, contact or biometric data. The gate is the belt to the wire schema's braces: adding an identity field anywhere fails a test rather than shipping.

## Development

```sh
pnpm install
pnpm build
pnpm test
```

## License

[MIT](./LICENSE)
