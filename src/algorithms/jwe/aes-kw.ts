/**
 * AES key wrapping.
 *
 * RFC 3394 wrapping with the default initial value. The integrity check is the
 * recovery of those eight fixed octets: an unwrap that produces different ones
 * means the key or the wrapped bytes are wrong, and no key material is
 * released. There is no padded variant here, because substituting one would
 * change which lengths are accepted.
 *
 * This uses WebCrypto rather than the provider's cipher list. The supported
 * backends differ: one exposes an `aes256-wrap` cipher
 * and the other exposes none at all, so a cipher-based implementation would
 * leave a required capability unavailable on a supported runtime. WebCrypto
 * implements the same construction on both and was verified to produce
 * byte-identical output. The cost is that wrapping is asynchronous.
 */

import { toBufferSource } from '../../internal/bytes.ts';
import { backendError, backendOk, type BackendResult } from '../../internal/crypto/backend.ts';

/** Bytes RFC 3394 adds to the wrapped output. */
export const KW_OVERHEAD_BYTES = 8;

const KEK_SIZES: Readonly<Record<string, number>> = Object.freeze({
  A128KW: 16,
  A192KW: 24,
  A256KW: 32,
});

/** KEK size the identifier requires, or `undefined` when it names no wrapping. */
export function aesKwKeySize(algorithm: string): number | undefined {
  return KEK_SIZES[algorithm];
}

/**
 * The initial value RFC 3394 fixes. WebCrypto applies it internally and offers
 * no way to override it, which is the behaviour this library wants.
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
  const kekBytes = aesKwKeySize(algorithm);
  if (kekBytes === undefined) {
    return backendError('unsupported');
  }
  if (kek.length !== kekBytes) {
    return backendError('operation_failed');
  }
  // RFC 3394 operates on whole 64-bit blocks and requires at least two of them.
  if (cek.length < 16 || cek.length % 8 !== 0) {
    return backendError('operation_failed');
  }

  try {
    const wrappingKey = await importKek(kek, 'wrapKey');
    // The CEK is imported under a placeholder type purely so it can be handed
    // to `wrapKey`; wrapping treats it as opaque octets, and the type carries
    // no meaning for the wrapped bytes.
    const target = await crypto.subtle.importKey('raw', toBufferSource(cek), { name: 'HMAC', hash: 'SHA-256' }, true, [
      'sign',
    ]);
    const wrapped = new Uint8Array(await crypto.subtle.wrapKey('raw', target, wrappingKey, 'AES-KW'));

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
