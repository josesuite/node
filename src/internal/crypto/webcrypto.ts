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

const HANDLE_CACHE = new WeakMap<object, Promise<CryptoKey>>();

/**
 * Memoizes the provider handle for a long-lived key record.
 *
 * Importing a key is a substantial share of the cost of an operation: for EC and
 * RSA verification the import is comparable to the signature arithmetic itself,
 * and it is repeated for every object processed under the same configured key.
 *
 * The cache is keyed on the identity of the record rather than on its contents,
 * so no key material is hashed, compared, or retained as a lookup key. The
 * entries are weak, so a handle lives exactly as long as the record a caller
 * still holds. An absent token means the caller has no such record, and the
 * import is simply not reused.
 *
 * Soundness depends on a record being bound to one algorithm and one operation
 * for its whole lifetime, which is what makes a single handle per record the
 * correct handle: there is no second interpretation of the same record for a
 * cached handle to be wrongly reused under. A record whose binding could be
 * widened later must not be used as a token here.
 *
 * The pending promise is cached rather than the resolved handle, so concurrent
 * operations on one key share a single import instead of racing to perform
 * several. A rejected import is evicted, because a transient provider fault must
 * not become a permanently cached failure.
 */
export function importCached(token: object | undefined, load: () => Promise<CryptoKey>): Promise<CryptoKey> {
  if (token === undefined) {
    return load();
  }

  const cached = HANDLE_CACHE.get(token);
  if (cached !== undefined) {
    return cached;
  }

  const pending = load();
  HANDLE_CACHE.set(token, pending);
  // Eviction is attached without awaiting, so the caller still receives the
  // original promise and a rejection is not reported as an unhandled one here.
  pending.catch(() => {
    if (HANDLE_CACHE.get(token) === pending) {
      HANDLE_CACHE.delete(token);
    }
  });
  return pending;
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

export { encodeBase64url as base64url } from '../encoding/base64url.ts';
