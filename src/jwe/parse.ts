/**
 * JWE structural parsing.
 *
 * Compact and JSON forms produce the same parsed shape so that later stages
 * never branch on serialization to decide what a component means. Every
 * component is kept as its original string: the authenticated data is built
 * from the received protected-header bytes, so reserializing a decoded header
 * would authenticate different octets whenever whitespace or member order
 * differ.
 *
 * A missing member and a present-but-empty one are different states throughout.
 * The format requires empty optional values to be omitted, so an explicit empty
 * string is a malformed encoding rather than an alias for absence. Treating
 * the two alike would let an attacker choose which reading applies.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import type { JsonObject } from '../internal/json/types.ts';
import type { Limits } from '../policy/limits.ts';

/** One recipient's key-management contribution. */
export interface JweRecipient {
  /** Per-recipient unprotected header, absent when the member is omitted. */
  readonly unprotectedHeader: JsonObject | undefined;
  /**
   * Original Base64url encrypted key, absent for direct modes.
   *
   * Absence is meaningful: direct key use and direct agreement carry no
   * encrypted key at all, while every wrapping algorithm requires bytes here.
   */
  readonly encryptedKeyComponent: string | undefined;
}

export interface ParsedJwe {
  /** Original Base64url protected header string. */
  readonly protectedComponent: string;
  /** Shared unprotected header, absent when the member is omitted. */
  readonly sharedUnprotectedHeader: JsonObject | undefined;
  readonly recipients: readonly JweRecipient[];
  readonly ivComponent: string;
  readonly ciphertextComponent: string;
  readonly tagComponent: string;
  /**
   * Original Base64url external AAD string, absent when the member is omitted.
   *
   * The original string is retained because the authenticated data is built by
   * concatenating encoded components, never decoded octets.
   */
  readonly aadComponent: string | undefined;
  readonly form: 'compact' | 'flattened' | 'general';
}

export type JweParseResult =
  | { readonly ok: true; readonly value: ParsedJwe }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(reason: string, category: ErrorCategory = 'malformed_input'): JweParseResult {
  return { ok: false, category, reason };
}

/**
 * Parses the Compact form.
 *
 * Exactly five components separated by four periods. The count is checked
 * before anything is decoded, so a token with a missing or extra separator is
 * refused as malformed rather than being read with components shifted by one.
 */
export function parseCompactJwe(token: string, limits: Limits): JweParseResult {
  if (token.length > limits.joseInput) {
    return reject('jwe_too_large', 'resource_limit');
  }

  const parts = token.split('.');
  if (parts.length !== 5) {
    return reject('compact_component_count');
  }

  const [protectedComponent, encryptedKeyComponent, ivComponent, ciphertextComponent, tagComponent] = parts as [
    string,
    string,
    string,
    string,
    string,
  ];

  if (protectedComponent.length === 0) {
    return reject('protected_empty', 'invalid_header');
  }
  // The IV and tag are fixed-width for every supported content algorithm, so an
  // empty component cannot describe one. Exact widths are checked once the
  // algorithm is known.
  if (ivComponent.length === 0) {
    return reject('iv_empty');
  }
  if (tagComponent.length === 0) {
    return reject('tag_empty');
  }

  return {
    ok: true,
    value: {
      protectedComponent,
      sharedUnprotectedHeader: undefined,
      recipients: [
        {
          unprotectedHeader: undefined,
          // Compact carries an empty component for direct modes, which is the
          // same state the JSON forms express by omitting the member.
          encryptedKeyComponent: encryptedKeyComponent.length === 0 ? undefined : encryptedKeyComponent,
        },
      ],
      ivComponent,
      ciphertextComponent,
      tagComponent,
      aadComponent: undefined,
      form: 'compact',
    },
  };
}
