/**
 * PBES2 password-based key derivation.
 *
 * A KEK is derived from a password with PBKDF2 and then used for AES key
 * wrapping. This is receive-only: creation would require a reviewed policy and
 * at least sixteen fresh random salt octets, and offering it here would invite
 * new objects to be produced under a construction whose security rests on
 * password strength.
 *
 * The salt is `UTF8(alg) || 0x00 || decoded-p2s`. The algorithm prefix binds the
 * derived key to the identifier that named it, so a KEK derived for one PBES2
 * variant cannot be reused under another. The prefix does not count toward the
 * eight-octet minimum on the decoded salt input.
 *
 * The iteration count is attacker-supplied and is bounded before any derivation
 * runs. An unbounded count is a denial-of-service vector: the work is performed
 * by the recipient at the sender's choosing. Bounding it does not make a weak
 * password safe. A captured object permits offline guessing at whatever rate
 * the attacker can afford, unconstrained by these limits.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';
import { attempt, importRaw } from '../../internal/crypto/webcrypto.ts';

export interface Pbes2Parameters {
  readonly hash: string;
  /** Derived KEK size, which is also the AES-KW variant's key size. */
  readonly keyBytes: number;
  /** The AES key-wrapping algorithm this variant applies after derivation. */
  readonly wrappingAlgorithm: string;
}

const PBES2_ALGORITHMS: Readonly<Record<string, Pbes2Parameters>> = Object.freeze({
  'PBES2-HS256+A128KW': { hash: 'SHA-256', keyBytes: 16, wrappingAlgorithm: 'A128KW' },
  'PBES2-HS384+A192KW': { hash: 'SHA-384', keyBytes: 24, wrappingAlgorithm: 'A192KW' },
  'PBES2-HS512+A256KW': { hash: 'SHA-512', keyBytes: 32, wrappingAlgorithm: 'A256KW' },
});

export function pbes2Parameters(algorithm: string): Pbes2Parameters | undefined {
  return PBES2_ALGORITHMS[algorithm];
}

/** Smallest decoded `p2s` the construction accepts, excluding the prefix. */
export const MIN_SALT_INPUT_BYTES = 8;
/** Largest decoded `p2s` accepted, bounding the work a sender can impose. */
export const MAX_SALT_INPUT_BYTES = 64;

export const MIN_ITERATIONS = 100_000;
export const MAX_ITERATIONS = 1_000_000;

export type Pbes2Rejection =
  | 'unsupported_algorithm'
  | 'salt_too_short'
  | 'salt_too_long'
  | 'iterations_below_minimum'
  | 'iterations_above_maximum';

export type SaltCheck = { readonly ok: true } | { readonly ok: false; readonly reason: Pbes2Rejection };

/**
 * Validates the public work-factor parameters before any derivation.
 *
 * These are checked together and up front because both are attacker-supplied
 * and both bound the work this side performs. Rejecting them here means a
 * hostile object never reaches PBKDF2 at all.
 */
export function checkWorkFactor(algorithm: string, saltInput: Uint8Array, iterations: number): SaltCheck {
  if (pbes2Parameters(algorithm) === undefined) {
    return { ok: false, reason: 'unsupported_algorithm' };
  }
  if (saltInput.length < MIN_SALT_INPUT_BYTES) {
    return { ok: false, reason: 'salt_too_short' };
  }
  if (saltInput.length > MAX_SALT_INPUT_BYTES) {
    return { ok: false, reason: 'salt_too_long' };
  }
  if (iterations < MIN_ITERATIONS) {
    // A low count is a weakened construction, not merely an unusual choice.
    return { ok: false, reason: 'iterations_below_minimum' };
  }
  if (iterations > MAX_ITERATIONS) {
    return { ok: false, reason: 'iterations_above_maximum' };
  }
  return { ok: true };
}

/**
 * Builds the PBKDF2 salt.
 *
 * The zero octet separates the algorithm name from the salt input so that no
 * two distinct pairs can produce the same salt; without it, a name ending in
 * the salt's leading bytes would collide with a shorter name and longer salt.
 */
export function buildSalt(algorithm: string, saltInput: Uint8Array): Uint8Array {
  const name = new TextEncoder().encode(algorithm);
  const salt = new Uint8Array(name.length + 1 + saltInput.length);
  salt.set(name, 0);
  salt[name.length] = 0x00;
  salt.set(saltInput, name.length + 1);
  return salt;
}

/**
 * Derives the KEK from an explicit password.
 *
 * The password arrives as octets. A text-facing adapter converts with UTF-8 and
 * must not trim or normalize: doing so would silently accept a different
 * password than the user supplied, and would make two visually identical
 * passwords derive different keys depending on which adapter ran.
 */
export async function derivePbes2Key(
  algorithm: string,
  password: Uint8Array,
  saltInput: Uint8Array,
  iterations: number,
): Promise<BackendResult<Uint8Array>> {
  const parameters = pbes2Parameters(algorithm);
  if (parameters === undefined) {
    return backendError('unsupported');
  }

  // The bounds are enforced here as well as at the call site: this function
  // performs the expensive work, so it must not depend on a caller having
  // checked first.
  const bounded = checkWorkFactor(algorithm, saltInput, iterations);
  if (!bounded.ok) {
    return backendError('operation_failed');
  }

  const result = await attempt(async () => {
    const handle = await importRaw(password, 'PBKDF2', ['deriveBits']);
    return crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: toBufferSource(buildSalt(algorithm, saltInput)),
        iterations,
        hash: parameters.hash,
      },
      handle,
      parameters.keyBytes * 8,
    );
  });

  return result.ok ? backendOk(new Uint8Array(result.value)) : result;
}
