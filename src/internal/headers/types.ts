/**
 * Header provenance model.
 *
 * Provenance is carried with every value rather than flattened away, because a
 * protected value and an identically named unprotected value have different
 * security meaning. Only the protected one is covered by the signature or by
 * the additional authenticated data of an encrypted object; an unprotected
 * value stays an unauthenticated hint even after the cryptographic operation
 * succeeds. Flattening the two together would let an attacker-supplied hint be
 * mistaken for authenticated data.
 */

import type { JsonValue } from '../json/types.ts';

export type HeaderOrigin =
  | 'protected'
  /** JWE shared unprotected header, or a JWS/JWE flattened `header` member. */
  | 'shared_unprotected'
  /** Per-recipient or per-signature unprotected header. */
  | 'per_entry_unprotected';

export interface HeaderParameter {
  readonly name: string;
  readonly value: JsonValue;
  readonly origin: HeaderOrigin;
}

/**
 * A merged JOSE header with provenance retained per parameter.
 *
 * Merging is only defined once the disjointness check has succeeded, so
 * a name can never map to two origins within one merged header.
 */
export interface MergedHeader {
  readonly parameters: ReadonlyMap<string, HeaderParameter>;
  /**
   * Total UTF-8 source octets of the contributing header objects, including
   * internal whitespace. Budgets are defined over source bytes rather
   * than decoded member counts, so this cannot be derived from `parameters`: a
   * one-member object padded with whitespace is small by member count and large
   * by bytes.
   */
  readonly sourceBytes: number;
}
