/**
 * WebCrypto provider adapter.
 *
 * WebCrypto is the primary backend. It is preferred over the runtime's own
 * cryptography module for three reasons established by qualification:
 *
 * - It rejects an EC private JWK whose public point does not match the private
 *   scalar. The Node module accepts that key and echoes the supplied
 *   coordinates back on export, so a mismatched pair can only be caught there
 *   by recomputing the point separately.
 * - It produces ECDSA signatures as fixed-width `R || S`, which is the JOSE
 *   wire form, with no DER conversion step to get wrong.
 * - Its algorithm surface is consistent across the runtimes this library
 *   supports, where the native module's cipher list is not: one runtime's
 *   provider offers no AES key wrapping at all.
 *
 * It does not cover everything. Ed448, X448, and secp256k1 are absent from at
 * least one supported runtime, and deriving an EC public point from a private
 * scalar has no WebCrypto equivalent, so those keep a native implementation.
 *
 * Every operation here is asynchronous because WebCrypto has no synchronous
 * form.
 */

import { toBufferSource } from '../bytes.ts';
import { backendError, backendOk, type BackendResult } from './backend.ts';

/**
 * Runs a WebCrypto operation, mapping a rejection onto a normalized failure.
 *
 * A provider rejection is never allowed to propagate as an exception: callers
 * must distinguish a cryptographic outcome from an operational fault, and an
 * uncaught error would collapse that distinction at whatever boundary happened
 * to catch it.
 */
export async function attempt<T>(operation: () => Promise<T>): Promise<BackendResult<T>> {
  try {
    return backendOk(await operation());
  } catch {
    return backendError('operation_failed');
  }
}

/**
 * Runs a verification-shaped operation, where a provider rejection means the
 * input did not verify rather than that the provider failed.
 *
 * This is separated from `attempt` so the two outcomes cannot be conflated by
 * accident: returning `false` from a genuine outage would report a forgery, and
 * reporting an outage for a bad signature would mask an attack.
 */
export async function attemptVerify(operation: () => Promise<boolean>): Promise<BackendResult<boolean>> {
  try {
    return backendOk(await operation());
  } catch {
    return backendOk(false);
  }
}

export async function importRaw(
  bytes: Uint8Array,
  algorithm: AlgorithmIdentifier | HmacImportParams | AesKeyAlgorithm,
  usages: readonly KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toBufferSource(bytes), algorithm, false, usages as KeyUsage[]);
}

/**
 * Imports a JWK.
 *
 * `extractable` stays false unless a caller needs the octets back, so key
 * material cannot be read out of a handle that had no reason to expose it.
 */
export async function importJwk(
  jwk: JsonWebKey,
  algorithm: AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams,
  usages: readonly KeyUsage[],
  extractable = false,
): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, algorithm, extractable, usages as KeyUsage[]);
}
