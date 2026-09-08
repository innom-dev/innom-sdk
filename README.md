# @innom/sdk

Age verification that proves a predicate, never an identity. One call in the browser runs a verification ceremony; your server receives a signed, short-lived **Innom Age Token (IAT)** that says a person is over a threshold, how strongly, and by which method. No name, date of birth, document or image ever reaches your app or Innom, and the token schema refuses to carry one.

- Docs: [docs.innom.dev](https://docs.innom.dev) · [Quickstart](https://docs.innom.dev/docs) · [Client SDK](https://docs.innom.dev/docs/client) · [Server verification](https://docs.innom.dev/docs/server)
- Agents: point your coding agent at [docs.innom.dev/SKILL.md](https://docs.innom.dev/SKILL.md)

## Install

```sh
npm i @innom/sdk
```

Node 20.9 or later on the server. `@innom/sdk/server` uses [`jose`](https://github.com/panva/jose) for JWKS and ES256.

## Client

`Innom.init` once per page; `verify()` once per gate. `verify()` never rejects: every path resolves to one of five outcomes so a single `switch` covers everything.

```ts
import { Innom } from "@innom/sdk";

const innom = Innom.init({ publishableKey: "pk_test_demo" });

const outcome = await innom.verify({
  ageOver: 18,
  deliver: "cookie",            // POST the token to your endpoint for you
  sessionEndpoint: "/api/session",
});

switch (outcome.status) {
  case "verified":  // outcome.result.token is the IAT; the cookie is already being set
    location.assign("/members");
    break;
  case "blocked":   // threshold not met; outcome.evidenceRef records the refusal
  case "exhausted": // no verification method could run on this device
  case "cancelled": // the person closed the sheet
  case "error":     // integration or network failure; outcome.code says which
    break;
}
```

The SDK renders the ceremony sheet, picks the first method the policy pack allows for this device, and cascades silently when one cannot complete. It relays a challenge to the wallet, a zero-knowledge proof to the attestation plane, and the attestation back for a token. It never sees or stores personal data. Options, every `code`, events for custom UI and `cancelCeremony()` are on [Client SDK](https://docs.innom.dev/docs/client).

## Server

The browser is never the authority. Verify every token offline against the gateway JWKS before granting access:

```ts
import { verifyIat } from "@innom/sdk/server";

const result = await verifyIat(token, {
  audience: "rp_demo",                                             // your RP id, must equal `aud`
  jwksUrl: "https://<gateway>/api/v1/.well-known/jwks.json",       // cached for you
  requireAgeOver: 18,
  requireMinAssurance: "P-AAL2",                                   // P-AAL1 < P-AAL2 < P-AAL3
});

if (result.ok) {
  // result.claims.predicate.age_over, .assurance, .method_class, .exp, .evidence_ref
} else {
  // result.reason: malformed | bad_signature | expired | wrong_audience | wrong_issuer
  //              | unknown_key | schema_violation | predicate_not_met | assurance_not_met
}
```

`verifyIat` checks the ES256 signature, `typ`, `aud`, `iss`, `exp` (tokens live at most 600 s), the strict claim schema and the PII gate, then your predicate and assurance floors. Read `predicate.age_over` from the token rather than assuming your `ageOver` was applied: the policy pack may have raised it. Python and Go verifiers with the same eight checks are on [Server verification](https://docs.innom.dev/docs/server).

## Verify with nothing but Node

[`examples/verify-iat.mjs`](./examples/verify-iat.mjs) verifies a token with zero dependencies: one cached JWKS fetch, canonical base64url checks, ES256 via WebCrypto, and the same PII guard.

```sh
node examples/verify-iat.mjs <token> [audience] [jwksUrl]
```

Exit code `0` valid, `1` invalid, `2` usage error.

## The token

A compact JWS (`typ: innom-iat+jwt`, `alg: ES256`) with exactly thirteen claims:

```json
{
  "iss": "https://<gateway>", "aud": "rp_demo", "sub": "pairwise_3f9a1c…",
  "iat": 1767225600, "exp": 1767226200, "jti": "iat_01J9ZW9QF2",
  "jurisdiction": "FR", "policy_id": "FR-adult-v7", "policy_hash": "9f3a…",
  "predicate": { "age_over": 18 }, "assurance": "P-AAL3", "method_class": "M1",
  "evidence_ref": "ev_01J9ZWA3TP"
}
```

`sub` is salted per relying party, so two sites cannot join their users. `evidence_ref` resolves to a PII-free audit record. Any claim whose name looks like a date of birth, name, document, contact or biometric field fails the schema on both the signing and the verifying side. Full claim table: [Innom Age Token](https://docs.innom.dev/docs/token).

## Test mode

`pk_test_` keys run in test mode against a local or hosted test gateway. Seven deterministic personas drive every path (a pass on a digital ID, a saved-credential pass, camera estimation, an under-age block, a wallet-less laptop that exhausts); pass `persona` to `Innom.init`. The date of birth behind a persona exists only inside the wallet origin. Personas, capability overrides and the three tests worth writing are on [Testing and troubleshooting](https://docs.innom.dev/docs/testing).

## Packages

| Package | What it is |
| --- | --- |
| `@innom/sdk` | The browser ceremony SDK, plus `@innom/sdk/server` for offline IAT verification |
| `@innom/schemas` | Zod schemas for every wire surface, and the runtime PII gate |
| `@innom/personas` | The deterministic device-capability personas used in test mode |

Every object Innom signs, persists or returns passes through the schemas package's PII gate (`assertNoPii`), which rejects any key resembling date of birth, name, document, contact or biometric data. Adding an identity field anywhere fails a test rather than shipping.

## Rules that keep the integration honest

- Never trust the browser: only a server-side `verifyIat` (or the dependency-free script) grants access.
- Never store the token beyond its `exp`, and never use `sub` as an identity.
- Never call the attestation plane (`/api/v1/attest/zk`, `/api/v1/credentials`) from application code.
- Never put a method class, assurance class or reason code in front of the person; the sheet speaks in their words.

## Development

```sh
pnpm install
pnpm build
pnpm test
```

## License

[MIT](./LICENSE)
