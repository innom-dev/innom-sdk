/**
 * @innom/personas — deterministic demo actors (architecture §12a.5).
 *
 * The main entry carries persona metadata, capabilities and canned M4
 * estimates. Date-of-birth material lives behind `@innom/personas/dob` and
 * is intentionally NOT re-exported here: the sites origin must never pull a
 * birth date into its bundle (§13 invariant 1).
 */
export * from "./types.js";
export * from "./personas.js";
