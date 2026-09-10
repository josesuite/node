/**
 * Unauthenticated protected-header inspection.
 *
 * This exists for the decisions that must happen before a key is available:
 * routing by `kid`, selecting a candidate issuer configuration, or logging why
 * a token could not be handled. It is deliberately not a verification step, and
 * the type it returns is named so a call site cannot read as one.
 *
 * Nothing here establishes authenticity. The protected header of an unverified
 * token is attacker-controlled in full: `alg`, `kid`, `enc`, and every other
 * member may be chosen freely by whoever produced the token. An inspected value
 * may only narrow candidates that trusted configuration already permits; it can
 * never widen an algorithm allowlist, select a trusted issuer, or nominate an
 * endpoint.
 *
 * The payload is deliberately not returned. A JWS payload is unauthenticated
 * and a JWE payload is not readable at all without decryption, so returning
 * either would invite a caller to act on data no check has covered.
 */

import type { ErrorCategory } from './errors/codes.ts';
import type { Limits } from './policy/limits.ts';

/**
 * Which serialization the input is required to be.
 *
 * Supplied by trusted configuration rather than sniffed from the token. A
 * component count is attacker-controlled, so letting the input choose its own
 * parser would let a caller expecting one serialization be handed another.
 */
export type InspectSerialization = 'jws-compact' | 'jwe-compact';

export interface InspectOptions {
  readonly serialization: InspectSerialization;
  readonly limits?: Limits;
}

/**
 * A decoded protected header that no cryptographic operation has covered.
 *
 * Every field is a plain JSON projection of attacker-controlled bytes. The
 * `unverified` prefix is part of the contract: it is what stops a downstream
 * reader from mistaking this for the header of a verified result.
 */
export interface UnverifiedHeader {
  /**
   * Protected-header members, escape-decoded, with values as plain JSON.
   *
   * Numbers arrive as their original lexeme rather than as `number`, matching
   * how the verifying parsers model them, so an integer beyond 2^53 is not
   * silently rounded by inspection.
   */
  readonly unverifiedParameters: Readonly<Record<string, unknown>>;
  /** `alg`, present only when it is a string. Never an allowlist input. */
  readonly unverifiedAlgorithm: string | undefined;
  /** `kid`, present only when it is a string. An opaque identifier. */
  readonly unverifiedKeyId: string | undefined;
  /** `enc`, present only for an encrypted object and only when it is a string. */
  readonly unverifiedContentAlgorithm: string | undefined;
}

export type InspectResult =
  | { readonly ok: true; readonly header: UnverifiedHeader }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

type InspectFailure = { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(reason: string, category: ErrorCategory = 'malformed_input'): InspectFailure {
  return { ok: false, category, reason };
}
