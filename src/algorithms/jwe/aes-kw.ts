/**
 * AES key wrapping.
 *
 * RFC 3394 wrapping with the default initial value. The integrity check is the
 * recovery of those eight fixed octets: an unwrap that produces different ones
 * means the key or the wrapped bytes are wrong, and no key material is
 * released. There is no padded variant here, because substituting one would
 * change which lengths are accepted.
 *
 * Wrapping uses the provider's `id-aes*-wrap` ciphers, which every supported
 * runtime exposes and which back the runtime's own AES-KW implementation. The
 * output is verified against the RFC 3394 test vectors.
 */

import { createCipheriv, createSecretKey } from 'node:crypto';

import { ownedBytes, toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';

/** Bytes RFC 3394 adds to the wrapped output. */
export const KW_OVERHEAD_BYTES = 8;

interface KwParameters {
  readonly kekBytes: number;
  /** Native cipher name; the `id-` spelling is present on every supported line. */
  readonly cipher: string;
}

const KW_ALGORITHMS: Readonly<Record<string, KwParameters>> = Object.freeze({
  A128KW: { kekBytes: 16, cipher: 'id-aes128-wrap' },
  A192KW: { kekBytes: 24, cipher: 'id-aes192-wrap' },
  A256KW: { kekBytes: 32, cipher: 'id-aes256-wrap' },
});

/** KEK size the identifier requires, or `undefined` when it names no wrapping. */
export function aesKwKeySize(algorithm: string): number | undefined {
  return KW_ALGORITHMS[algorithm]?.kekBytes;
}

/**
 * The initial value RFC 3394 fixes, supplied explicitly as the cipher's IV so
 * the integrity check is bound to exactly these octets.
 */
const DEFAULT_IV = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6]);

async function importKek(kek: Uint8Array, usage: 'wrapKey' | 'unwrapKey'): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', toBufferSource(kek), 'AES-KW', false, [usage]);
}

export async function wrapAesKw(
  algorithm: string,
  kek: Uint8Array,
  cek: Uint8Array,
): Promise<BackendResult<Uint8Array>> {
  const parameters = KW_ALGORITHMS[algorithm];
  if (parameters === undefined) {
    return backendError('unsupported');
  }
  if (kek.length !== parameters.kekBytes) {
    return backendError('operation_failed');
  }
  // RFC 3394 operates on whole 64-bit blocks and requires at least two of them.
  if (cek.length < 16 || cek.length % 8 !== 0) {
    return backendError('operation_failed');
  }

  try {
    const cipher = createCipheriv(parameters.cipher, createSecretKey(kek), DEFAULT_IV);
    const wrapped = ownedBytes(Buffer.concat([cipher.update(cek), cipher.final()]));

    if (wrapped.length !== cek.length + KW_OVERHEAD_BYTES) {
      return backendError('operation_failed');
    }

    return backendOk(wrapped);
  } catch {
    return backendError('operation_failed');
  }
}

/**
 * Unwraps, returning `undefined` when the integrity check fails.
 *
 * A failed check is an authentication outcome rather than a provider fault, and
 * it is reported identically for a wrong KEK and for modified wrapped bytes so
 * the two cannot be told apart.
 */
export async function unwrapAesKw(
  algorithm: string,
  kek: Uint8Array,
  wrapped: Uint8Array,
): Promise<BackendResult<Uint8Array | undefined>> {
  const kekBytes = aesKwKeySize(algorithm);
  if (kekBytes === undefined) {
    return backendError('unsupported');
  }
  if (kek.length !== kekBytes) {
    return backendError('operation_failed');
  }
  // Length is public, so a wrapped value that cannot have come from this
  // construction is rejected before any key operation.
  if (wrapped.length < 24 || wrapped.length % 8 !== 0) {
    return backendOk(undefined);
  }

  let unwrappingKey: CryptoKey;
  try {
    unwrappingKey = await importKek(kek, 'unwrapKey');
  } catch {
    return backendError('operation_failed');
  }

  try {
    // `unwrapKey` verifies the integrity octets and rejects when they do not
    // match, which is the expected path for a wrong key. The recovered key is
    // imported as extractable so its octets can be returned; it is raw key
    // material to this layer, not a usable algorithm key.
    const recovered = await crypto.subtle.unwrapKey(
      'raw',
      toBufferSource(wrapped),
      unwrappingKey,
      'AES-KW',
      { name: 'HMAC', hash: 'SHA-256' },
      true,
      ['sign'],
    );

    return backendOk(new Uint8Array(await crypto.subtle.exportKey('raw', recovered)));
  } catch {
    return backendOk(undefined);
  }
}

/** Returns the RFC 3394 initial value used by the integrity check. */
export function defaultIntegrityValue(): Uint8Array {
  return new Uint8Array(DEFAULT_IV);
}
