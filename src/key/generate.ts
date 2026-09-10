/**
 * Policy-bound key generation.
 *
 * Generation produces a JWK and then admits it through the ordinary import
 * path, so a generated key reaches the caller having passed exactly the checks
 * an imported one does and carrying the same single-algorithm, single-operation
 * binding. Returning a key straight from the provider would create a second
 * admission path, and the two would eventually disagree about what is
 * acceptable.
 *
 * Parameters come from the requested algorithm and from trusted configuration,
 * never from a provider default. A backend's own defaults have changed across
 * releases and are not a policy this library can inherit: RSA-02 fixes the
 * exponent at 65,537 and the modern modulus floor at 3,072 bits, and those are
 * applied here rather than assumed.
 */

import type { ErrorCategory } from '../errors/codes.ts';
import type { UsableKey } from './import.ts';
import type { EcCurve, KeyOperation } from './types.ts';
import type { Limits } from '../policy/limits.ts';

/** RSA-02: the only public exponent this library generates. */
const RSA_EXPONENT = 65537;

/** RSA-02: modern-profile modulus floor. Generation never uses a legacy size. */
const RSA_MINIMUM_MODULUS_BITS = 3072;

export interface GenerateKeyOptions {
  /** The single algorithm the generated key is bound to. */
  readonly algorithm: string;
  /**
   * Content algorithms a key-management key may protect or recover.
   *
   * Required for every `jwe_alg` identifier, carrying the same binding an
   * imported key-management key must supply.
   */
  readonly contentAlgorithms?: readonly string[];
  /**
   * Curve for an algorithm that does not name one.
   *
   * ECDSA identifiers fix their own curve, so this is required only where the
   * algorithm genuinely leaves the choice open, and it is then supplied by
   * configuration rather than inferred.
   */
  readonly curve?: EcCurve;
  /**
   * RSA modulus size in bits. Defaults to the modern floor.
   *
   * A larger value is accepted up to the resource limit; a smaller one is
   * refused, because generation has no compatibility case for a legacy size.
   */
  readonly modulusBits?: number;
  readonly limits?: Limits;
}

/**
 * A generated asymmetric pair, with each half bound to its own operation.
 *
 * The two are separate keys rather than one key granted every operation: a
 * signing key that also verifies, or a decryption key that also encrypts,
 * widens what a single compromised value permits.
 */
export interface GeneratedKeyPair {
  readonly privateKey: UsableKey;
  readonly publicKey: UsableKey;
}

export type GenerateKeyPairResult =
  | { readonly ok: true; readonly keys: GeneratedKeyPair }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

export type GenerateSecretResult =
  | { readonly ok: true; readonly key: UsableKey }
  | { readonly ok: false; readonly category: ErrorCategory; readonly reason: string };

function reject(
  reason: string,
  category: ErrorCategory = 'policy_violation',
): {
  readonly ok: false;
  readonly category: ErrorCategory;
  readonly reason: string;
} {
  return { ok: false, category, reason };
}

/** Operation pair each generated asymmetric family binds its two halves to. */
const KEY_PAIR_OPERATIONS: Readonly<Record<string, readonly [KeyOperation, KeyOperation]>> = Object.freeze({
  jws: ['sign', 'verify'],
  key_transport: ['unwrapKey', 'wrapKey'],
  direct_agreement: ['deriveKey', 'deriveKey'],
  agreement_with_wrapping: ['deriveKey', 'deriveKey'],
});
