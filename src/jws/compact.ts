/**
 * Compact JWS serialization.
 *
 * Compact form is exactly three Base64url components separated by two periods.
 * The received component strings are retained verbatim, because the signature
 * covers those exact bytes: rebuilding them from the decoded header would
 * authenticate different bytes whenever whitespace or member order differ.
 */

import type { ErrorCategory } from '../errors/codes.ts';

export interface CompactParts {
  /** Original protected component, exactly as received. */
  readonly protectedComponent: string;
  /** Original payload component. Empty string in detached form. */
  readonly payloadComponent: string;
  /** Original signature component. */
  readonly signatureComponent: string;
}

export type CompactParseResult =
  | { readonly ok: true; readonly parts: CompactParts }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(reason: string, category: ErrorCategory = 'malformed_input'): CompactParseResult {
  return { ok: false, category, reason };
}

/**
 * Splits a Compact JWS into its three components.
 *
 * Splitting is exact rather than lenient: a fourth component, a missing one, or
 * surrounding whitespace all reject. A token with an extra period could
 * otherwise be read as a different object by a more permissive parser, and the
 * two would disagree about what was signed.
 */
export function parseCompact(token: string, maxBytes: number): CompactParseResult {
  if (token.length > maxBytes) {
    return reject('input_too_large', 'resource_limit');
  }

  const first = token.indexOf('.');
  if (first < 0) {
    return reject('missing_separator');
  }

  const second = token.indexOf('.', first + 1);
  if (second < 0) {
    return reject('missing_separator');
  }

  // A third period means more components than this serialization defines; it is
  // never treated as an encrypted object or as trailing data to ignore.
  if (token.indexOf('.', second + 1) >= 0) {
    return reject('too_many_components');
  }

  const protectedComponent = token.slice(0, first);
  const payloadComponent = token.slice(first + 1, second);
  const signatureComponent = token.slice(second + 1);

  // The protected header carries the algorithm, so it cannot be absent.
  if (protectedComponent.length === 0) {
    return reject('empty_protected_header', 'invalid_header');
  }

  // Every supported algorithm produces a nonempty signature; an empty one is
  // the shape an unsecured object takes, which is never accepted.
  if (signatureComponent.length === 0) {
    return reject('empty_signature');
  }

  return { ok: true, parts: { protectedComponent, payloadComponent, signatureComponent } };
}

export function serializeCompact(parts: CompactParts): string {
  return `${parts.protectedComponent}.${parts.payloadComponent}.${parts.signatureComponent}`;
}
