/**
 * Bounded, duplicate-rejecting, source-preserving JSON parser for untrusted
 * JOSE input.
 *
 * `JSON.parse` cannot satisfy this contract. It silently keeps one of several
 * duplicate member names, which would let an attacker hide a second `alg` that
 * a different implementation reads instead; it converts every number to
 * IEEE-754, losing exact integer values; and it reports no source offsets, so
 * byte-accurate size accounting is impossible. None of that can be recovered by
 * re-serializing afterwards, because the information is already gone by then.
 *
 * The parser therefore runs directly over the source octets. That also lets
 * sizes be measured in bytes including internal whitespace, which is what the
 * header size budgets are defined over.
 *
 * Budgets are enforced during traversal so that a hostile document is rejected
 * while being read rather than after a complete value graph exists.
 */

import type { JsonValue } from './types.ts';

export type JsonFailure =
  /** Structurally invalid JSON, including trailing data and bad escapes. */
  | 'malformed'
  /** Duplicate member name within one object, compared after escape decoding. */
  | 'duplicate_member'
  /** A depth, count, or size budget was exceeded. */
  | 'resource_limit'
  /** Invalid UTF-8 in a string, or a lone surrogate escape. */
  | 'invalid_encoding';

export type JsonParseResult =
  | { readonly ok: true; readonly value: JsonValue; readonly nodes: number }
  | { readonly ok: false; readonly failure: JsonFailure };

export interface JsonBudget {
  readonly jsonDepth: number;
  readonly jsonObjectMembers: number;
  readonly jsonArrayElements: number;
  readonly jsonNodes: number;
  readonly jsonString: number;
  readonly numberLexeme: number;
  readonly numberExponentMagnitude: number;
}
