/**
 * Runtime PII gate.
 *
 * PRD 4.2.7 requires a schema linter that rejects any PII-typed field, and
 * DEMO.md 9 gates the demo on a wire audit for `dob|birth|name|document`. Zod
 * strict objects already reject unknown keys, but strictness only helps where a
 * schema exists. This guard is the belt to that braces: it runs on every object
 * Innom is about to sign, persist, or return, so adding an identity field
 * anywhere fails a test rather than shipping.
 */

/**
 * Key substrings that may never appear in a signed token, evidence record, or
 * attestation result. Matching is case-insensitive and applied to the
 * normalised key (non-alphanumerics stripped), so `date_of_birth`,
 * `dateOfBirth` and `date-of-birth` all collapse to one pattern.
 */
const FORBIDDEN_KEY_PATTERNS: readonly RegExp[] = Object.freeze([
  /dob/,
  // Identity-bearing material in its own right: the wallet credential store
  // pairs `salt` with `dob_days` to form the commitment, so a response that
  // smuggled `salt` under any name would leak the offline preimage half of
  // every user's commitment (architecture §3 invariant 1). The key gate used
  // to flag only `dob`; both are now mutually covered.
  /salt/,
  /birth/,
  /dateofbirth/,
  /\bage\b/,
  /firstname/,
  /lastname/,
  /surname/,
  /givenname/,
  /familyname/,
  /middlename/,
  /fullname/,
  // Any key ending in "name" (holdername, username, nickname, filename) is
  // forbidden; the exact-name allowlist below is where exceptions must live.
  /name$/,
  /displayname/,
  /legalname/,
  /document/,
  /passport/,
  /idcard/,
  /idnumber/,
  /licen[cs]e/,
  /nationalid/,
  /ssn/,
  /taxid/,
  /email/,
  /phone/,
  /msisdn/,
  /address/,
  /postcode/,
  /zipcode/,
  /latitude/,
  /longitude/,
  /ipaddr/,
  /^ip$/,
  /useragent/,
  /selfie/,
  /faceimage/,
  /facescan/,
  /photo/,
  /portrait/,
  /biometric/,
  /fingerprint/,
  /template/,
  /nationality/,
  /placeofbirth/,
  /gender/,
  /sex$/,
]);

/**
 * Keys that read like PII but are structurally required and provably
 * non-identifying. Each entry is justified, because an allowlist is exactly how
 * a PII gate rots.
 */
const ALLOWED_EXACT_KEYS: ReadonlySet<string> = new Set([
  // `age_over` / `ageOver` carry a statutory threshold (18), never a person's age.
  "ageover",
  "agebands",
  "ageoverclaims",
  // Assurance/threshold plumbing that happens to contain "age".
  "challengeage",
  "m4challengeage",
  "minage",
  // Method identifiers.
  "methodclass",
  "packagename",
]);

function normaliseKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export class PiiViolationError extends Error {
  readonly path: string;
  readonly key: string;

  constructor(path: string, key: string) {
    super(`PII gate: forbidden field "${key}" at ${path || "<root>"}`);
    this.name = "PiiViolationError";
    this.path = path;
    this.key = key;
  }
}

/**
 * Depth-first scan for forbidden keys. Returns every violation rather than the
 * first so a failing test names the whole problem.
 */
export function findPiiViolations(value: unknown, path = ""): { path: string; key: string }[] {
  const violations: { path: string; key: string }[] = [];

  const walk = (node: unknown, currentPath: string, depth: number): void => {
    if (depth > 32) return;
    if (node === null || typeof node !== "object") return;

    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, `${currentPath}[${index}]`, depth + 1));
      return;
    }

    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const childPath = currentPath ? `${currentPath}.${key}` : key;
      const normalised = normaliseKey(key);

      if (!ALLOWED_EXACT_KEYS.has(normalised)) {
        for (const pattern of FORBIDDEN_KEY_PATTERNS) {
          if (pattern.test(normalised)) {
            violations.push({ path: childPath, key });
            break;
          }
        }
      }

      walk(child, childPath, depth + 1);
    }
  };

  walk(value, path, 0);
  return violations;
}

/**
 * Throws on the first violation. Call this immediately before signing,
 * persisting, or returning any object.
 */
export function assertNoPii<T>(value: T, context = ""): T {
  const violations = findPiiViolations(value, context);
  const first = violations[0];
  if (first) {
    throw new PiiViolationError(first.path, first.key);
  }
  return value;
}

/**
 * Patterns the wire audit greps for (DEMO.md 9). Exported so the Playwright HAR
 * assertion and this module cannot drift apart.
 */
export const WIRE_AUDIT_PATTERNS: readonly RegExp[] = Object.freeze([
  /\bdob\b/i,
  /birth/i,
  /\bname\b/i,
  /document/i,
  /passport/i,
  /selfie/i,
]);
