/**
 * Deterministic JSON canonicalisation (RFC 8785 subset).
 *
 * Policy pack hashes and transcript hashes are load-bearing: PRD S2 requires any
 * historical decision to be replayable bit-for-bit from the evidence record. If
 * two runs serialise the same object differently, the hash changes and the audit
 * claim collapses. `JSON.stringify` preserves insertion order, so it cannot be
 * used directly.
 *
 * Subset, and the reasons: numbers must be finite and are emitted via
 * `JSON.stringify` (safe because every number in scope is a small integer or a
 * millisecond count); `undefined` properties are dropped; `bigint`, functions
 * and symbols throw rather than serialise ambiguously.
 */
export function canonicalize(value: unknown): string {
  return serialize(value, 0);
}

function serialize(value: unknown, depth: number): string {
  if (depth > 64) {
    throw new Error("canonicalize: structure too deep (max 64)");
  }

  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "number": {
      if (!Number.isFinite(value)) {
        throw new Error(`canonicalize: non-finite number ${String(value)}`);
      }
      // Normalise -0 to 0 so two structurally equal inputs hash identically.
      return JSON.stringify(value === 0 ? 0 : value);
    }
    case "string":
      return JSON.stringify(value);
    case "bigint":
      throw new Error("canonicalize: bigint is not representable; pass a decimal string");
    case "function":
    case "symbol":
    case "undefined":
      throw new Error(`canonicalize: ${typeof value} is not serialisable`);
    case "object":
      break;
    default:
      throw new Error(`canonicalize: unsupported type ${typeof value}`);
  }

  if (Array.isArray(value)) {
    const items = value.map((item) => (item === undefined ? "null" : serialize(item, depth + 1)));
    return `[${items.join(",")}]`;
  }

  if (value instanceof Date) {
    return JSON.stringify(value.toISOString());
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => compareCodeUnits(a, b));

  const body = entries
    .map(([key, v]) => `${JSON.stringify(key)}:${serialize(v, depth + 1)}`)
    .join(",");

  return `{${body}}`;
}

/** RFC 8785 orders keys by UTF-16 code unit, which is what `<` already does. */
function compareCodeUnits(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}
